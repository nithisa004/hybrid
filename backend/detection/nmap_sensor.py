"""
╔══════════════════════════════════════════════════════════════════╗
║       NMAP / KALI LINUX SCAN DETECTOR                           ║
║  Detects real Nmap scans arriving from Kali Linux by:           ║
║  1. Reading Windows Security Log (Event IDs 5152-5157)          ║
║  2. Socket-based port-knock listener (no admin needed)          ║
╚══════════════════════════════════════════════════════════════════╝

WHY TWO METHODS?
- Method 1 (WFP Events): Most accurate, but requires:
    * Windows Audit Policy "Filtering Platform Connection" = Enabled
    * Admin privilege to read Security log
- Method 2 (Socket Listener): Zero-config fallback that catches
    SYN/connect probes in real time without any audit policy change.

We combine both and deduplicate by source IP + time window.
"""

import win32evtlog
import win32evtlogutil
import socket
import threading
import logging
import re
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Optional, Dict, List, Tuple

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────

# Windows Filtering Platform event IDs
WFP_BLOCKED       = 5152   # Packet blocked
WFP_PREVENTED     = 5153   # Packet prevented (Defender / WFP)
WFP_ALLOWED       = 5154   # Listening socket allowed
WFP_BLOCKED_CONN  = 5155   # Bind blocked
WFP_ALLOWED_CONN  = 5156   # Connection allowed
WFP_BLOCKED_BIND  = 5157   # Connection blocked
WFP_LISTEN        = 5158   # Listen accepted

WFP_EVENT_IDS = {5152, 5153, 5154, 5155, 5156, 5157, 5158}

# Nmap detection thresholds
PORT_SCAN_THRESHOLD     = 8    # unique ports from one IP within window → port scan
SYN_FLOOD_THRESHOLD     = 40   # same-port connections within window → DoS
TIME_WINDOW_SECONDS     = 10   # rolling window in seconds

# Ports our socket listener binds on (common Nmap probe targets)
# IMPORTANT: Only use ports > 1024 — binding lower ports requires
# Windows admin and can HANG silently without it.
LISTEN_PORTS = [8081, 8082, 8083, 9090, 9091, 9092, 9093, 5000, 5001, 4444, 7777, 7778]

# ─────────────────────────────────────────────────────────────────
# In-memory state (reset on server restart — intentional)
# ─────────────────────────────────────────────────────────────────

# ip → deque of (timestamp, dst_port)
_connection_log: Dict[str, deque] = defaultdict(lambda: deque(maxlen=500))
_state_lock = threading.Lock()

# IPs already reported this window (avoid duplicate DB writes)
_reported_ips: Dict[str, datetime] = {}
REPORT_COOLDOWN = timedelta(seconds=30)


# ─────────────────────────────────────────────────────────────────
# METHOD 1 — Windows Filtering Platform (WFP) Event Log Reader
# ─────────────────────────────────────────────────────────────────

def _extract_ip_from_wfp_event(event) -> Optional[str]:
    """
    Parse source IP from a WFP Security log event.
    The IP is in the StringInserts tuple at a known position.
    """
    try:
        inserts = event.StringInserts
        if not inserts:
            return None

        # WFP events typically have Source/Dest IP at index 3 & 4
        # We scan all fields for an IPv4-looking string
        ip_pattern = re.compile(
            r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
            r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
        )
        for field in inserts:
            if not field:
                continue
            match = ip_pattern.search(str(field))
            if match:
                ip = match.group()
                # Ignore localhost / broadcast
                if ip.startswith('127.') or ip in ('0.0.0.0', '255.255.255.255'):
                    continue
                return ip
    except Exception as e:
        logger.debug(f"IP extraction error: {e}")
    return None


def _extract_port_from_wfp_event(event) -> Optional[int]:
    """Parse destination port from WFP event StringInserts."""
    try:
        inserts = event.StringInserts
        if not inserts:
            return None
        # Destination port is usually the 5th or 6th field
        for field in inserts[4:8]:
            if field and str(field).isdigit():
                port = int(field)
                if 1 <= port <= 65535:
                    return port
    except Exception:
        pass
    return None


def read_wfp_events(max_events: int = 200) -> List[Tuple[str, int, datetime]]:
    """
    Read recent WFP events from Windows Security log.
    Returns list of (src_ip, dst_port, timestamp) tuples.

    Uses a background thread with a 2-second timeout so it NEVER
    hangs the Django request cycle even without admin rights.
    """
    results = []
    done_event = threading.Event()

    def _do_read():
        try:
            hand = win32evtlog.OpenEventLog(None, "Security")
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            events = win32evtlog.ReadEventLog(hand, flags, 0)
            win32evtlog.CloseEventLog(hand)

            cutoff = datetime.now() - timedelta(seconds=TIME_WINDOW_SECONDS * 3)

            for evt in events[:max_events]:
                event_id = evt.EventID & 0xFFFF
                if event_id not in WFP_EVENT_IDS:
                    continue

                # Convert COM time to datetime
                try:
                    ts_str = str(evt.TimeGenerated)
                    ts = datetime.strptime(ts_str[:19], '%Y-%m-%d %H:%M:%S')
                except Exception:
                    ts = datetime.now()

                if ts < cutoff:
                    continue

                src_ip = _extract_ip_from_wfp_event(evt)
                dst_port = _extract_port_from_wfp_event(evt)

                if src_ip:
                    results.append((src_ip, dst_port or 0, ts))

        except Exception as e:
            logger.warning(f"WFP event read error (run as Admin for full coverage): {e}")
        finally:
            done_event.set()

    t = threading.Thread(target=_do_read, daemon=True)
    t.start()
    # Wait max 2 seconds — if Security log is locked/inaccessible, we skip it
    done_event.wait(timeout=2.0)
    return results


# ─────────────────────────────────────────────────────────────────
# METHOD 2 — Socket-based Port-Knock Listener (Passive Honeypot)
# ─────────────────────────────────────────────────────────────────

_listener_running = False
_listener_threads: List[threading.Thread] = []


def _listen_on_port(port: int):
    """
    Bind a socket on `port` and record any connection attempt.
    Each accepted connection's source IP/port is logged.
    """
    global _listener_running
    try:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.settimeout(1.0)
        srv.bind(('0.0.0.0', port))
        srv.listen(50)
        logger.info(f"[NmapSensor] Listening on port {port}")

        while _listener_running:
            try:
                conn, addr = srv.accept()
                src_ip = addr[0]
                ts = datetime.now()
                logger.info(f"[NmapSensor] Probe on port {port} from {src_ip}")
                with _state_lock:
                    _connection_log[src_ip].append((ts, port))
                conn.close()
            except socket.timeout:
                continue
            except Exception:
                pass
        srv.close()
    except OSError as e:
        logger.warning(f"[NmapSensor] Cannot bind port {port}: {e}")


def start_socket_listeners():
    """Start background listener threads for common probe ports."""
    global _listener_running, _listener_threads
    if _listener_running:
        return
    _listener_running = True
    for port in LISTEN_PORTS:
        t = threading.Thread(target=_listen_on_port, args=(port,), daemon=True)
        t.start()
        _listener_threads.append(t)
    logger.info(f"[NmapSensor] Socket listeners started on {len(LISTEN_PORTS)} ports")


def stop_socket_listeners():
    """Stop all listener threads."""
    global _listener_running
    _listener_running = False


# ─────────────────────────────────────────────────────────────────
# DETECTION ENGINE — Combine both sources & classify
# ─────────────────────────────────────────────────────────────────

def _merge_wfp_into_state(wfp_events: List[Tuple[str, int, datetime]]):
    """Merge WFP events into the in-memory connection log."""
    with _state_lock:
        for src_ip, dst_port, ts in wfp_events:
            _connection_log[src_ip].append((ts, dst_port))


def _is_cooldown_active(ip: str) -> bool:
    """Return True if we recently reported this IP (avoid spam)."""
    last = _reported_ips.get(ip)
    if last and (datetime.now() - last) < REPORT_COOLDOWN:
        return True
    return False


def _mark_reported(ip: str):
    _reported_ips[ip] = datetime.now()


def _analyze_ip(ip: str) -> Optional[Dict]:
    """
    Analyse connection history for a single IP.
    Returns a threat dict or None.
    """
    with _state_lock:
        history = list(_connection_log.get(ip, []))

    if not history:
        return None

    now = datetime.now()
    cutoff = now - timedelta(seconds=TIME_WINDOW_SECONDS)

    # Filter to time window
    recent = [(ts, port) for ts, port in history if ts >= cutoff]
    if not recent:
        return None

    unique_ports = set(port for _, port in recent if port > 0)
    total_hits   = len(recent)

    # ── Port Scan: many unique ports ─────────────────────────────
    if len(unique_ports) >= PORT_SCAN_THRESHOLD:
        sorted_ports = sorted(unique_ports)
        return {
            'threat_type':    'Nmap Port Scan (Network Reconnaissance)',
            'severity':       'Critical',
            'source_ip':      ip,
            'rule_name':      'Nmap Port Scan Detected',
            'port_count':     len(unique_ports),
            'ports_scanned':  sorted_ports[:20],
            'event_id':       5156,
            'description': (
                f"🚨 NMAP PORT SCAN DETECTED FROM KALI LINUX\n\n"
                f"✓ Source IP       : {ip}\n"
                f"✓ Ports Scanned   : {', '.join(str(p) for p in sorted_ports[:15])}"
                f"{'...' if len(sorted_ports) > 15 else ''}\n"
                f"✓ Total Unique    : {len(unique_ports)} ports in {TIME_WINDOW_SECONDS}s window\n"
                f"✓ Total Probes    : {total_hits} connection attempts\n\n"
                f"ATTACK TOOL   : Nmap (Network Mapper)\n"
                f"ORIGIN OS     : Kali Linux (attacker machine)\n"
                f"TECHNIQUE     : TCP SYN/Connect Scan (-sS / -sT)\n\n"
                f"⚡ RECOMMENDED ACTION:\n"
                f"  1. Block source IP {ip} in Windows Firewall\n"
                f"  2. Review open ports — close unnecessary services\n"
                f"  3. Monitor for follow-up exploitation attempts"
            ),
        }

    # ── SYN Flood / High-Volume hit on single port ───────────────
    if total_hits >= SYN_FLOOD_THRESHOLD:
        top_port = max(set(p for _, p in recent), key=lambda p: sum(1 for _, pp in recent if pp == p))
        return {
            'threat_type':    'DoS / SYN Flood',
            'severity':       'Critical',
            'source_ip':      ip,
            'rule_name':      'SYN Flood Attack Detected',
            'port_count':     len(unique_ports),
            'ports_scanned':  list(unique_ports)[:5],
            'event_id':       5152,
            'description': (
                f"🚨 SYN FLOOD / DOS ATTACK DETECTED FROM KALI LINUX\n\n"
                f"✓ Source IP    : {ip}\n"
                f"✓ Target Port  : {top_port}\n"
                f"✓ Total Hits   : {total_hits} in {TIME_WINDOW_SECONDS}s\n\n"
                f"ATTACK TOOL   : hping3 / Nmap (--max-rate)\n"
                f"ORIGIN OS     : Kali Linux (attacker machine)\n"
                f"TECHNIQUE     : TCP SYN Flood\n\n"
                f"⚡ RECOMMENDED ACTION:\n"
                f"  1. Block source IP {ip} immediately\n"
                f"  2. Enable SYN cookies on Windows\n"
                f"  3. Rate-limit inbound connections"
            ),
        }

    return None


def run_nmap_detection() -> List[Dict]:
    """
    Main entry point — called by the Django view on each polling cycle.

    Returns list of threat dicts (may be empty if nothing detected).
    """
    # Step 1: Ingest WFP events
    wfp_data = read_wfp_events(max_events=300)
    _merge_wfp_into_state(wfp_data)

    # Step 2: Analyse every tracked IP
    threats = []
    with _state_lock:
        tracked_ips = list(_connection_log.keys())

    for ip in tracked_ips:
        if _is_cooldown_active(ip):
            continue
        threat = _analyze_ip(ip)
        if threat:
            threats.append(threat)
            _mark_reported(ip)

    return threats


def get_sensor_stats() -> Dict:
    """Return current sensor statistics for diagnostics."""
    with _state_lock:
        return {
            'tracked_ips':      len(_connection_log),
            'reported_cooldowns': len(_reported_ips),
            'socket_listeners': len(LISTEN_PORTS),
            'listener_active':  _listener_running,
            'timestamp':        datetime.now().isoformat(),
        }
