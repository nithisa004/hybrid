from rest_framework.decorators import api_view
from rest_framework.response import Response
from logs.models import Log
import win32evtlog
from collections import Counter
import socket
import datetime
from .alerts import send_threat_alert

# ============================================================
# 🧱 SECURITY RULE ENGINE — 15+ Attack Pattern Rules
# ML folder is preserved and untouched. Detection is rule-based only.
# ============================================================

# Rule: EventID -> (Rule Name, Description, Severity)
WINDOWS_RULES = {
    4625:  ("Brute Force - Failed Login",       "Failed logon attempt detected. Rule: 5+ failures = Brute Force attack.", "High"),
    1102:  ("Anti-Forensics - Audit Log Cleared","Security audit log was cleared. Classic attacker anti-forensics move.", "Critical"),
    104:   ("Anti-Forensics - System Log Cleared","System log was wiped. Potential attempt to destroy evidence.", "High"),
    7045:  ("Persistence - New Service Installed","A new Windows service was installed. Common malware persistence technique.", "High"),
    4720:  ("Persistence - New Account Created",  "A new user account was created. Attackers create backdoor accounts for re-entry.", "High"),
    4728:  ("Privilege Escalation - Group Member Added", "A user was added to a privileged security group. Verify authorization.", "High"),
    4732:  ("Privilege Escalation - Local Group Change", "A member was added to a local security-enabled group.", "High"),
    4672:  ("Privilege Escalation - Special Privileges", "Special privileges assigned to new logon. Potential UAC bypass.", "High"),
    4740:  ("Account Locked Out",                "A user account was locked out. Sign of targeted brute force attack.", "Medium"),
    6008:  ("System Instability - Unexpected Shutdown", "System shut down unexpectedly. Could be DoS, crash, or physical attack.", "Medium"),
    7000:  ("Critical Service Failure",           "A critical Windows service failed to start. Investigate potential disruption.", "Medium"),
    7001:  ("Service Dependency Failure",         "A service failed because of a dependent service failure.", "Medium"),
    2013:  ("Resource Exhaustion - Disk Full",    "Disk space critically low. Potential Denial of Service via log flooding.", "Medium"),
    29:    ("Infrastructure - Time Sync Failure", "System time sync failed. Potential NTP-based protocol attack or MITM.", "Medium"),
    35:    ("Infrastructure - Time Sync Warning", "NTP time sync source is unverified.", "Low"),
    2004:  ("Firewall Rule Modified",             "A rule was added to Windows Firewall. Verify this was authorized.", "Medium"),
    6:     ("Code Integrity - Driver Blocked",    "A driver was blocked from loading by Windows Code Integrity. Possible rootkit.", "High"),
    106:   ("Persistence - Scheduled Task Created","A scheduled task was registered. Common persistence and lateral movement mechanism.", "Medium"),
}


def get_hostname():
    try:
        return socket.gethostname()
    except:
        return "LOCALHOST"


def read_event_log(log_name, batch_size=100):
    """Safely read a Windows event log. Returns empty list on access error."""
    try:
        hand = win32evtlog.OpenEventLog(None, log_name)
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        return win32evtlog.ReadEventLog(hand, flags, 0)[:batch_size]
    except Exception:
        return []


@api_view(['POST'])
def detect_log(request):
    hostname = get_hostname()

    # ── Step 1: Read Windows Event Logs ─────────────────────────────
    system_events  = read_event_log('System',   100)
    security_events = read_event_log('Security', 100)
    all_events = system_events + security_events

    if not all_events:
        return Response({"message": "No events read (try running as Administrator for Security log access).", "threats": 0})

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

        # ── RULE 1: Brute Force (5+ failed logins in batch) ──────────
        if event_id == 4625:
            if count >= 5:
                is_threat   = True
                rule_name   = "Brute Force Attack"
                threat_type = "Credential Attack"
                severity    = "High"
                description = f"BRUTE FORCE DETECTED\n\nDetected {count} failed login attempts (Event ID 4625). This volume indicates an automated attack."
            else:
                is_threat   = False
                rule_name   = "Failed Login Attempt"
                threat_type = "System Activity"
                severity    = "Info"
                description = f"A failed login attempt was recorded for source: {source}."

        # ── RULE 2: DoS Pattern (10+ events from single source) ──────
        elif src_frequency >= 10 and event_id not in WINDOWS_RULES:
            is_threat   = True
            rule_name   = "Denial of Service Pattern"
            threat_type = "DoS / Flood"
            severity    = "High"
            description = f"DoS PATTERN DETECTED\n\nSource '{source}' generated {src_frequency} events in the current window."

        # ── RULE 3: Specific Windows Security Event IDs ───────────
        elif event_id in WINDOWS_RULES:
            r_name, r_desc, r_sev = WINDOWS_RULES[event_id]
            
            # Decide if it's a "Threat" or just "Activity"
            # Routine IDs (Privileges, Processes, User Creation) are 'Info' unless flagged otherwise
            if event_id in [4672, 4688, 4732, 4720]:
                is_threat   = False
                severity    = "Info"
            else:
                is_threat   = True
                severity    = r_sev
            
            rule_name   = r_name
            threat_type = r_name
            description = f"SECURITY RULE TRIGGERED: {r_name}\n\n{r_desc}"

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