from rest_framework.decorators import api_view
from rest_framework.response import Response
from logs.models import Log
import win32evtlog
from collections import Counter
import socket
import datetime
from django.utils import timezone
from .alerts import send_threat_alert
from .threat_extractor import extract_threat_indicators, should_block_threat, whitelist_ip
from .firewall_service import FirewallManager
from . import nmap_sensor
import logging

logger = logging.getLogger(__name__)

import threading
import time

# ── Globals for Background Polling ──────────────────────────
_EVENT_BUFFER = []
_BUFFER_LOCK = threading.Lock()
_WORKER_RUNNING = False

# Rule: EventID -> (Rule Name, Description, Severity)
WINDOWS_RULES = {
    4625:  ("Brute Force - Failed Login",       "Failed logon attempt detected. Rule: 10+ failures = Brute Force attack.", "High"),
    1102:  ("Anti-Forensics - Audit Log Cleared","Security audit log was cleared. Classic attacker anti-forensics move.", "Critical"),
    104:   ("Anti-Forensics - System Log Cleared","System log was wiped. Potential attempt to destroy evidence.", "High"),
    7045:  ("Persistence - New Service Installed","A new Windows service was installed. Common malware persistence technique.", "High"),
    4624:  ("Remote Desktop Login (RDP)",        "An RDP login was detected. Monitor for unauthorized remote access.", "High"),
    4720:  ("Privilege Escalation - New User",   "A new user account was created. Potential persistence/backdoor.", "Medium"), 
    4728:  ("Privilege Escalation - Group Add",  "A user was added to a privileged security group.", "Medium"),
    4732:  ("Privilege Escalation - Local Group","A member was added to a local security-enabled group.", "Medium"),
    4672:  ("Activity: Special Privileges",      "Special privileges assigned to new logon.", "Info"),
    4740:  ("Account Locked Out",                "A user account was locked out. Sign of targeted brute force attack.", "Medium"),
    6008:  ("System Instability - Unexpected Shutdown", "System shut down unexpectedly.", "Medium"),
    2013:  ("Resource Exhaustion - Disk Full",    "Disk space critically low. Potential Denial of Service.", "Medium"),
    2004:  ("Firewall Rule Modified",             "A rule was added to Windows Firewall.", "Medium"),
    6:     ("Code Integrity - Driver Blocked",    "A driver was blocked by Windows Code Integrity. Possible rootkit.", "High"),
    106:   ("Persistence - Scheduled Task Created","A scheduled task was registered.", "Medium"),
}

def _event_log_worker():
    """Background thread that periodically polls Event Logs."""
    global _EVENT_BUFFER
    while _WORKER_RUNNING:
        try:
            temp_events = []
            if _HAS_ADMIN:
                for log_name in ["Security", "System", "Application"]:
                    temp_events.extend(read_event_log(log_name, batch_size=50))
            else:
                for log_name in ["System", "Application"]:
                    temp_events.extend(read_event_log(log_name, batch_size=30))
            
            with _BUFFER_LOCK:
                _EVENT_BUFFER = temp_events
        except Exception:
            pass
        time.sleep(10)  # Polling interval

def start_event_worker():
    global _WORKER_RUNNING
    if not _WORKER_RUNNING:
        _WORKER_RUNNING = True
        t = threading.Thread(target=_event_log_worker, daemon=True)
        t.start()
        logger.info("Background Event Log Worker started (10s polling interval)")

# Start the worker thread on module load
start_event_worker()

# Start Nmap Scan Listeners (fallback Method 2 — Honeypot Mode)
try:
    nmap_sensor.start_socket_listeners() 
except Exception as e:
    logger.error(f"Failed to start Nmap listeners: {e}")

def get_hostname():
    try:
        return socket.gethostname()
    except:
        return "LOCALHOST"


def read_event_log(log_name, batch_size=100):
    """Safely read a Windows event log (called by worker thread)."""
    result = []
    try:
        hand = win32evtlog.OpenEventLog(None, log_name)
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        result.extend(win32evtlog.ReadEventLog(hand, flags, 0)[:batch_size])
        win32evtlog.CloseEventLog(hand)
    except Exception:
        pass
    return result


def _is_admin() -> bool:
    """Check if this process is running as Windows Administrator."""
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

# Check once at startup — avoids re-checking every request
_HAS_ADMIN = _is_admin()
if _HAS_ADMIN:
    logger.info("Running as Administrator — Security log access available")
else:
    logger.warning("Not running as Administrator — Security log skipped (System/Application only)")


@api_view(['POST'])
def detect_log(request):
    """
    Reads events from the background buffer and processes them.
    Response is instant (<10ms) to ensure simulation scripts don't time out.
    """
    hostname = get_hostname()
    
    # Read from background buffer
    with _BUFFER_LOCK:
        all_events = list(_EVENT_BUFFER)
    
    if not all_events:
        msg = "Real-time monitoring active" + (" (Running without Admin)" if not _HAS_ADMIN else "")
        return Response({
            "message": f"{msg} — Waiting for events in buffer.",
            "threats_found": 0,
            "log": {"id": 0}
        })
    
    # ── Step 2: Aggregate for Pattern Analysis ───────────────────────
    event_id_counts = Counter([e.EventID & 0xFFFF for e in all_events])
    source_counts   = Counter([e.SourceName or "Unknown" for e in all_events])

    processed_logs = []
    seen_keys = set()

    for evt in all_events:
        event_id   = evt.EventID & 0xFFFF
        source     = evt.SourceName or "Windows System"
        key        = (event_id, source)

        if key in seen_keys:
            continue

        count          = event_id_counts[event_id]
        src_frequency  = source_counts[source]
        is_threat      = False
        rule_name      = ""
        description    = ""
        threat_type    = ""
        severity       = "Info"

        # ── RULE 1: Brute Force (10+ failed logins in batch) ──────────
        if event_id == 4625:
            if count >= 10:
                is_threat   = True
                rule_name   = "Brute Force Attack"
                threat_type = "Credential Attack"
                severity    = "High"
                description = f"🔐 BRUTE FORCE DETECTED\n\n✓ Detected {count} failed login attempts (Event ID 4625)\n✓ This volume indicates an automated attack simulation.\n\nAttacker Source: Unknown (from Windows Logs)"
            else:
                is_threat   = False
                rule_name   = "Failed Login Attempt"
                threat_type = "System Activity"
                severity    = "Info"
                description = f"A failed login attempt was recorded (Event ID 4625). Count: {count}."

        # ── RULE 1.5: Port Scan (Nmap) ──────────
        elif event_id in [5152, 5153, 5154, 5156, 5158]:
            if count >= 15:
                is_threat   = True
                rule_name   = "Port Scan Detected (Nmap)"
                threat_type = "Network Reconnaissance"
                severity    = "High"
                description = f"🚨 PORT SCAN DETECTED\n\n✓ Detected {count} network connection events (Event ID {event_id})\n✓ This high volume of filtering platform events strongly indicates an Nmap port scan from Kali Linux."
            else:
                is_threat   = False
                rule_name   = "Network Activity"
                threat_type = "Network Flow"
                severity    = "Info"
                description = f"Routine network connection event (ID {event_id})."

        # ── RULE 2: DoS Pattern (25+ events from single source) ──────
        # Only mark as threat if extremely high volume (25+), otherwise it's activity
        elif src_frequency >= 25 and event_id not in WINDOWS_RULES:
            is_threat   = True
            rule_name   = "Denial of Service Pattern"
            threat_type = "DoS / Flood"
            severity    = "High"
            description = f"🔥 DoS ATTACK DETECTED\n\nSource '{source}' generated {src_frequency} suspicious events in rapid succession."
        elif src_frequency >= 10 and event_id not in WINDOWS_RULES:
            # Lower volume (10-24 events) is just activity, not a threat yet
            is_threat   = False
            rule_name   = "High Volume Activity"
            threat_type = "System Activity"
            severity    = "Info"
            description = f"Source '{source}' generated {src_frequency} events. Monitoring."

        # ── RULE 3: Only Genuine Attack Event IDs Are Threats ────────
        # Most events are just system activity, not actual threats
        elif event_id in WINDOWS_RULES:
            r_name, r_desc, r_sev = WINDOWS_RULES[event_id]
            
            # ONLY these event IDs are genuine threats that need immediate attention
            # All others are just system activity (Info level)
            GENUINE_THREATS = {
                1102,    # Audit log cleared (anti-forensics)
                104,     # System log cleared (anti-forensics)
                7045,    # Service installed (persistence)
                6,       # Driver blocked (rootkit attempt)
            }
            
            if event_id in GENUINE_THREATS:
                # These are real attacks that happened - mark as threats
                is_threat   = True
                severity    = "High"  # Cap at High (not Critical unless context)
                rule_name   = r_name
                threat_type = r_name
                description = f"🚨 THREAT DETECTED: {r_name}\n\n{r_desc}"
            else:
                # Everything else is routine system activity
                is_threat   = False
                severity    = "Info"
                rule_name   = f"Activity: {r_name}"
                threat_type = "System Activity"
                description = f"{r_name}\n\n{r_desc}"

        # ── RULE 4: Sensor-Specific Network Events ──────────────────
        elif source.startswith("Network"):
            is_threat   = False
            rule_name   = "Network Activity Detected"
            threat_type = "Network Flow"
            severity    = "Info"
            description = f"Network traffic was observed from source: {source}."

        # ── Step 3: Save to Database ─────────────────────────────────
        # We save ALL events. Threats stay forever, Info logs are capped.
        final_name = f"[{severity}] {rule_name}" if is_threat else f"Activity: {rule_name if rule_name else source}"
        
        log = Log.objects.create(
            name        = final_name,
            severity    = severity,
            status      = "Awaiting action" if severity in ["High", "Critical"] else "Monitoring",
            verdict     = "None",
            assignee    = "Rule Engine" if severity in ["High", "Critical"] else "Auto-Monitor",
            source      = source,
            event_id    = event_id,
            description = description,
            threat_type = threat_type,
            host        = hostname,
            process_name = source,
            process_user = "SYSTEM",
            result      = rule_name if is_threat else "Normal",
        )
        
        # ── 🔒 AUTO-BLOCKING: EXTRACT THREAT INDICATORS & BLOCK ─────
        block_log = {
            'blocked_ip': None,
            'block_status': 'pending',
            'firewall_error': None
        }
        
        if is_threat and severity in ["High", "Critical"]:
            try:
                # Extract threat indicators (IP, ports, etc.)
                indicators = extract_threat_indicators(
                    description=description,
                    event_id=event_id,
                    threat_type=threat_type
                )
                
                source_ip = indicators.get('source_ip')
                
                # Check if IP should be blocked
                if source_ip and not whitelist_ip(source_ip):
                    # Determine if we should auto-block
                    if should_block_threat(severity, event_id, threat_type):
                        logger.warning(f"🔥 AUTO-BLOCKING IP: {source_ip} - Reason: {indicators.get('block_reason', 'Threat detected')}")
                        
                        # Execute firewall block
                        firewall_result = FirewallManager.block_ip(
                            ip=source_ip,
                            direction="both",
                            severity=severity
                        )
                        
                        # Update block log
                        block_log['blocked_ip'] = source_ip
                        block_log['block_status'] = 'applied' if firewall_result['success'] else 'failed'
                        block_log['firewall_error'] = None if firewall_result['success'] else firewall_result['errors']
                        
                        # Update log entry with block info
                        log.blocked_ip = source_ip
                        log.is_firewall_blocked = firewall_result['success']
                        log.blocked_at = timezone.now()
                        log.block_status = block_log['block_status']
                        log.save()
                        
                        if firewall_result['success']:
                            logger.info(f"✓ Firewall rules created: {firewall_result['rule_names']}")
                            # Update threat description with blocking confirmation
                            log.description += f"\n\n🔒 FIREWALL ACTION: IP {source_ip} has been BLOCKED in Windows Firewall"
                            log.save()
                        else:
                            logger.error(f"✗ Firewall blocking failed: {firewall_result['errors']}")
                
            except Exception as e:
                logger.error(f"Error in auto-blocking: {str(e)}")
                block_log['firewall_error'] = str(e)
        
        processed_logs.append(log)
        seen_keys.add(key)
        
        if is_threat:
            send_threat_alert(log)

    # ── Step 4: Maintenance ───
    # Keep Info logs light
    info_ids = Log.objects.filter(severity='Info').values_list('id', flat=True).order_by('-timestamp')[100:]
    if info_ids:
        Log.objects.filter(id__in=info_ids).delete()

    return Response({
        "message": f"Processed {len(processed_logs)} events. {sum(1 for l in processed_logs if l.severity != 'Info')} threats found.",
        "threats_found": sum(1 for l in processed_logs if l.severity != 'Info'),
        "log": {"id": processed_logs[0].id if processed_logs else 0}
    })


# ═══════════════════════════════════════════════════════════════
# 🔒 MANUAL BLOCKING API — For Dashboard "Block" Button
# ═══════════════════════════════════════════════════════════════

@api_view(['POST'])
def manual_block_ip(request):
    """
    Manually block an IP address (called from dashboard "Block" button).
    
    POST /api/block/
    {
        "threat_id": 123,
        "ip": "192.168.1.100"
    }
    """
    try:
        threat_id = request.data.get('threat_id')
        ip = request.data.get('ip')
        
        if not ip:
            return Response({'error': 'IP address required'}, status=400)
        
        # Get the threat log
        try:
            threat_log = Log.objects.get(id=threat_id)
        except Log.DoesNotExist:
            return Response({'error': f'Threat ID {threat_id} not found'}, status=404)
        
        # Block the IP
        firewall_result = FirewallManager.block_ip(ip, direction="both", severity=threat_log.severity)
        
        # Update log with block info
        threat_log.blocked_ip = ip
        threat_log.is_firewall_blocked = firewall_result['success']
        threat_log.blocked_at = timezone.now()
        threat_log.block_status = 'applied' if firewall_result['success'] else 'failed'
        threat_log.firewall_rule_id = ', '.join(firewall_result.get('rule_names', []))
        threat_log.save()
        
        if firewall_result['success']:
            logger.info(f"🔒 MANUAL BLOCK: IP {ip} blocked for threat {threat_id}")
            threat_log.description += f"\n\n🔒 MANUALLY BLOCKED by admin: IP {ip} has been BLOCKED in Windows Firewall"
            threat_log.save()
            
            return Response({
                'success': True,
                'message': f'IP {ip} has been BLOCKED in Windows Firewall ✓',
                'rules_created': firewall_result['rule_names'],
                'threat_id': threat_id
            })
        else:
            logger.error(f"❌ MANUAL BLOCK FAILED: {firewall_result['errors']}")
            
            return Response({
                'success': False,
                'message': f'Failed to block IP: {firewall_result["errors"]}',
                'threat_id': threat_id
            }, status=500)
    
    except Exception as e:
        logger.error(f"Error in manual_block_ip: {str(e)}")
        return Response({'error': str(e)}, status=500)


@api_view(['POST'])
def manual_unblock_ip(request):
    """
    Manually unblock an IP address (called from dashboard).
    
    POST /api/unblock/
    {
        "threat_id": 123,
        "ip": "192.168.1.100"
    }
    """
    try:
        threat_id = request.data.get('threat_id')
        ip = request.data.get('ip')
        
        if not ip:
            return Response({'error': 'IP address required'}, status=400)
        
        # Get the threat log
        try:
            threat_log = Log.objects.get(id=threat_id)
        except Log.DoesNotExist:
            return Response({'error': f'Threat ID {threat_id} not found'}, status=404)
        
        # Unblock the IP
        firewall_result = FirewallManager.unblock_ip(ip)
        
        # Update log with unblock info
        threat_log.is_firewall_blocked = False
        threat_log.block_status = 'removed'
        threat_log.save()
        
        if firewall_result['success']:
            logger.info(f"🔓 MANUAL UNBLOCK: IP {ip} unblocked for threat {threat_id}")
            threat_log.description += f"\n\n🔓 MANUALLY UNBLOCKED by admin: Firewall rules removed"
            threat_log.save()
            
            return Response({
                'success': True,
                'message': f'IP {ip} has been UNBLOCKED ✓',
                'threat_id': threat_id
            })
        else:
            logger.error(f"❌ MANUAL UNBLOCK FAILED: {firewall_result['errors']}")
            
            return Response({
                'success': False,
                'message': f'Failed to unblock IP: {firewall_result["errors"]}',
                'threat_id': threat_id
            }, status=500)
    
    except Exception as e:
        logger.error(f"Error in manual_unblock_ip: {str(e)}")
        return Response({'error': str(e)}, status=500)


# ═══════════════════════════════════════════════════════════════
# 🌐 NMAP / KALI LINUX SCAN DETECTOR
# Reads real Windows Filtering Platform events (5152-5157) AND
# uses an in-process TCP socket listener as a fallback.
# ═══════════════════════════════════════════════════════════════

@api_view(['POST', 'GET'])
def detect_nmap_scan(request):
    """
    Detect real Nmap port scans originating from Kali Linux.

    GET  /detect/nmap/   → returns sensor stats (diagnostics)
    POST /detect/nmap/   → runs full detection cycle, saves threats to DB

    The sensor combines:
      1) Windows WFP event log (Event IDs 5152-5157)
      2) In-process TCP socket listeners on common ports
    """
    hostname = get_hostname()

    # ── Diagnostics-only (GET) ───────────────────────────────────
    if request.method == 'GET':
        stats = nmap_sensor.get_sensor_stats()
        return Response({'sensor_stats': stats, 'status': 'Nmap sensor is active'})

    # ── Full detection cycle (POST) ──────────────────────────────
    threats_detected = nmap_sensor.run_nmap_detection()

    saved_threats = []

    for threat in threats_detected:
        src_ip      = threat.get('source_ip', 'Unknown')
        severity    = threat.get('severity', 'High')
        rule_name   = threat.get('rule_name', 'Nmap Port Scan')
        threat_type = threat.get('threat_type', 'Network Reconnaissance')
        description = threat.get('description', '')
        event_id    = threat.get('event_id', 5156)
        ports       = threat.get('ports_scanned', [])

        logger.warning(f"🔍 NMAP SCAN DETECTED — Source: {src_ip} | Ports: {ports}")

        # Save to DB
        log = Log.objects.create(
            name        = f"[{severity}] {rule_name}",
            severity    = severity,
            status      = "Awaiting action",
            verdict     = "None",
            assignee    = "Nmap Sensor",
            source      = f"Kali Linux ({src_ip})",
            event_id    = event_id,
            description = description,
            threat_type = threat_type,
            host        = hostname,
            process_name = "nmap / hping3",
            process_user = "KALI_ATTACKER",
            result      = rule_name,
            blocked_ip  = None,
        )

        # ── Auto-block the attacker IP ───────────────────────────
        if src_ip and src_ip != 'Unknown' and not whitelist_ip(src_ip):
            try:
                fw_result = FirewallManager.block_ip(
                    ip=src_ip,
                    direction="both",
                    severity=severity
                )
                if fw_result['success']:
                    log.blocked_ip         = src_ip
                    log.is_firewall_blocked = True
                    log.blocked_at         = timezone.now()
                    log.block_status       = 'applied'
                    log.description       += (
                        f"\n\n🔒 FIREWALL ACTION: IP {src_ip} has been "
                        f"BLOCKED in Windows Firewall automatically."
                    )
                    log.save()
                    logger.info(f"🔒 Auto-blocked Kali IP: {src_ip}")
                else:
                    logger.error(f"Firewall block failed: {fw_result['errors']}")
            except Exception as fe:
                logger.error(f"Firewall error for {src_ip}: {fe}")

        log.save()
        saved_threats.append(log)

        # Send email alert
        try:
            send_threat_alert(log)
        except Exception:
            pass

    return Response({
        'message': (
            f"Nmap sensor ran. {len(saved_threats)} Kali attack(s) detected and logged."
            if saved_threats else
            "Nmap sensor active — no port scans detected in current window."
        ),
        'threats_found': len(saved_threats),
        'threats': [
            {
                'id':          t.id,
                'name':        t.name,
                'severity':    t.severity,
                'source':      t.source,
                'threat_type': t.threat_type,
                'blocked':     t.is_firewall_blocked,
            }
            for t in saved_threats
        ],
        'sensor_stats': nmap_sensor.get_sensor_stats(),
    })