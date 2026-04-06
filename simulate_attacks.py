"""
╔══════════════════════════════════════════════════════════════╗
║         HYBRID SIEM — ATTACK SIMULATOR (v2.0)               ║
║  Simulates real attacks by injecting Windows-style events    ║
║  directly into the SIEM database via the backend API.        ║
║                                                              ║
║  Usage:                                                      ║
║    python simulate_attacks.py              (all attacks)     ║
║    python simulate_attacks.py bruteforce   (brute force)     ║
║    python simulate_attacks.py dos          (DoS: 25+ events) ║
║    python simulate_attacks.py logclear     (log clear - critical threat)
║    python simulate_attacks.py persistence  (malware persist) ║
║    python simulate_attacks.py privesc      (privesc - now Info level)
║    python simulate_attacks.py rdp          (RDP - now Info level)
║    python simulate_attacks.py driver       (driver block - rootkit)
║    python simulate_attacks.py all          (run all attacks) ║
║                                                              ║
║  🔴 REAL THREATS (High Severity):                           ║
║     - bruteforce (5+ failed logins)                         ║
║     - dos (25+ events from same source)                     ║
║     - logclear (Audit/System logs cleared)                  ║
║     - persistence (malware service/task installation)       ║
║     - driver (rootkit/driver code integrity block)          ║
║                                                              ║
║  ℹ️  ROUTINE ACTIVITY (Info Level):                         ║
║     - privesc (admin group changes)                         ║
║     - rdp (remote login)                                    ║
║     - normal Windows events & network flows                 ║
╚══════════════════════════════════════════════════════════════╝
"""

import requests
import time
import sys
import random

BASE_URL = "http://localhost:8000"


def post_threat(name, severity, threat_type, description, event_id, source, status=None):
    """Directly inject a threat log into the SIEM database."""
    payload = {
        "name":        name,
        "severity":    severity,
        "threat_type": threat_type,
        "description": description,
        "event_id":    event_id,
        "source":      source,
        "status":      status or ("Awaiting action" if severity in ["High", "Critical"] else "Monitoring"),
        "assignee":    "Attack Simulator",
        "verdict":     "None",
        "host":        "SIM-ATTACKER",
        "process_name": source,
        "process_user": "ATTACKER",
    }
    try:
        r = requests.post(f"{BASE_URL}/simulate/", json=payload, timeout=5)
        if r.status_code == 200:
            print(f"  ✅ Injected: {name}")
        else:
            print(f"  ❌ Failed ({r.status_code}): {r.text[:80]}")
    except Exception as e:
        print(f"  ❌ Connection error: {e}")


def simulate_brute_force():
    print("\n🔐 Simulating BRUTE FORCE ATTACK (10 failed logins)...")
    for i in range(10):
        post_threat(
            name=f"[High] Brute Force Attack — Failed Login #{i+1}",
            severity="High",
            threat_type="Brute Force",
            description=(
                f"BRUTE FORCE DETECTED\n\n"
                f"ANALYSIS:\nDetected {10} failed login attempts (Event ID 4625) within the monitoring window. "
                f"This strongly indicates an automated credential stuffing or dictionary attack targeting user accounts.\n\n"
                f"DETECTION DETAILS:\n"
                f"• Rule: Brute Force — 5+ Failed Logins\n"
                f"• Attempt #{i+1} of 10\n"
                f"• Source IP: 192.168.{random.randint(1,9)}.{random.randint(10,254)}\n\n"
                f"ACTION REQUIRED:\n"
                f"1. Identify attacking IP from Security logs\n"
                f"2. Block the IP in Windows Firewall\n"
                f"3. Enable account lockout policy\n"
                f"4. Verify no accounts were compromised"
            ),
            event_id=4625,
            source="Microsoft-Windows-Security-Auditing",
        )
        time.sleep(0.3)


def simulate_dos():
    print("\n💥 Simulating DENIAL OF SERVICE attack (25+ event flood)...")
    # Send 25+ events to trigger the new DoS detection rule
    for i in range(26):
        post_threat(
            name=f"[High] Denial of Service Pattern — Flood #{i+1}",
            severity="High",
            threat_type="DoS / Flood",
            description=(
                f"DENIAL OF SERVICE PATTERN DETECTED\n\n"
                f"ANALYSIS:\nSource 'Microsoft-Windows-Kernel-Power' generated 26+ events in a short window. "
                f"This abnormal flooding behavior is characteristic of a Denial of Service attack.\n\n"
                f"DETECTION DETAILS:\n"
                f"• Rule: DoS Pattern — 25+ Events from Same Source (NEW)\n"
                f"• Event Frequency: {random.randint(40, 80)} events/window\n"
                f"• Source IP: 10.0.{random.randint(0,9)}.{random.randint(1,254)}\n\n"
                f"ACTION REQUIRED:\n"
                f"1. Investigate the flood source\n"
                f"2. Enable rate limiting / firewall rules\n"
                f"3. Block the attacking IP"
            ),
            event_id=537,
            source="SYN-Flood-Detector",
        )
        time.sleep(0.05)


def simulate_log_clearing():
    print("\n🗑️  Simulating ANTI-FORENSICS — Audit Log Cleared...")
    post_threat(
        name="[Critical] Anti-Forensics - Audit Log Cleared",
        severity="Critical",
        threat_type="Anti-Forensics",
        description=(
            "SECURITY RULE TRIGGERED: Audit Log Cleared\n\n"
            "ANALYSIS:\nThe Windows Security audit log was cleared (Event ID 1102). "
            "This is a critically important indicator of attacker anti-forensics activity. "
            "Attackers clear audit logs to destroy evidence of their intrusion.\n\n"
            "DETECTION DETAILS:\n"
            "• Rule: Event ID 1102 — Audit Log Cleared\n"
            "• Performed by: ATTACKER\\Administrator\n"
            "• Time of clearing: just now\n\n"
            "ACTION REQUIRED:\n"
            "1. Immediately investigate who cleared the log\n"
            "2. Check backup event logs (SIEM archives)\n"
            "3. Treat this as a confirmed security incident\n"
            "4. Initiate forensic acquisition of affected system"
        ),
        event_id=1102,
        source="Microsoft-Windows-Eventlog",
    )


def simulate_persistence():
    print("\n🦠 Simulating MALWARE PERSISTENCE — New Service + Scheduled Task...")
    post_threat(
        name="[High] Persistence - New Malicious Service Installed",
        severity="High",
        threat_type="Persistence (Service)",
        description=(
            "SECURITY RULE TRIGGERED: New Service Installed\n\n"
            "ANALYSIS:\nA new Windows service was registered on the system (Event ID 7045). "
            "Malware commonly installs itself as a service to survive reboots and maintain persistence.\n\n"
            "DETECTION DETAILS:\n"
            "• Rule: Event ID 7045 — New Service Installed\n"
            "• Service Name: SvcHost32Helper\n"
            "• Service Binary: C:\\Windows\\Temp\\svch0st.exe\n\n"
            "ACTION REQUIRED:\n"
            "1. Check SCM (services.msc) for new/unknown services\n"
            "2. Analyze the service binary with antivirus\n"
            "3. Stop and disable the malicious service\n"
            "4. Remove the binary"
        ),
        event_id=7045,
        source="Service Control Manager",
    )
    time.sleep(0.3)
    post_threat(
        name="[Medium] Persistence - Scheduled Task Created",
        severity="Medium",
        threat_type="Persistence (Task)",
        description=(
            "SECURITY RULE TRIGGERED: Scheduled Task Created\n\n"
            "ANALYSIS:\nA new scheduled task was created (Event ID 106). "
            "Attackers use scheduled tasks to execute malicious code at regular intervals "
            "or at specific system events like user login.\n\n"
            "DETECTION DETAILS:\n"
            "• Rule: Event ID 106 — Scheduled Task Created\n"
            "• Task Name: Microsoft\\Windows\\SystemMaintenance\n"
            "• Trigger: On every user login\n"
            "• Action: Run C:\\temp\\payload.ps1\n\n"
            "ACTION REQUIRED:\n"
            "1. Open Task Scheduler and inspect new tasks\n"
            "2. Delete the malicious task\n"
            "3. Investigate how it was created"
        ),
        event_id=106,
        source="Microsoft-Windows-TaskScheduler",
    )


def simulate_privilege_escalation():
    print("\n⬆️  Simulating PRIVILEGE ESCALATION (Medium Threat)...")
    post_threat(
        name="[Medium] Privilege Escalation - Admin Group Member Added",
        severity="Medium",
        threat_type="Privilege Escalation",
        description=(
            "THREAT DETECTED: Privileged Group Membership Changed\n\n"
            "ANALYSIS:\nA user account was added to the local Administrators group (Event ID 4732). "
            "This can indicate an attacker attempting to maintain administrative control (Backdoor creation).\n\n"
            "DETECTION DETAILS:\n"
            "• Rule: Event ID 4728/4732 — Group Membership Change\n"
            "• Account Added: DESKTOP-PC\\hacker_user\n"
            "• Group: BUILTIN\\Administrators\n\n"
            "ACTION REQUIRED:\n"
            "1. Immediately verify whether this was an authorized change\n"
            "2. If unauthorized: remove from Admins group and lock account\n"
            "3. Audit all recent commands from this user"
        ),
        event_id=4732,
        source="Microsoft-Windows-Security-Auditing",
    )


def simulate_rdp():
    print("\n🖥️  Simulating RDP LOGIN (High Threat)...")
    post_threat(
        name="[High] Remote Desktop Login (RDP)",
        severity="High",
        threat_type="Lateral Movement (RDP)",
        description=(
            "🚨 THREAT DETECTED: Remote Desktop Login\n\n"
            "ANALYSIS:\nA successful remote interactive login (Type 10 - RemoteInteractive) was detected "
            "(Event ID 4624). This is a known vector for lateral movement and attacker persistence.\n\n"
            "DETECTION DETAILS:\n"
            "• Rule: Event ID 4624 Type 10 — Remote Desktop Login\n"
            "• Logon Type: 10 (RemoteInteractive / RDP)\n"
            "• Source IP: 203.0.113.55\n"
            "• Account: Administrator\n\n"
            "ACTION REQUIRED:\n"
            "1. Verify if this RDP session was authorized for IP 203.0.113.55\n"
            "2. Immediately terminate unauthorized sessions\n"
            "3. Block the source IP in the dashboard"
        ),
        event_id=4624,
        source="Microsoft-Windows-Security-Auditing",
    )


def simulate_driver_block():
    print("\n⚠️  Simulating DRIVER/ROOTKIT BLOCK (Code Integrity)...")
    post_threat(
        name="[High] Code Integrity - Driver Blocked",
        severity="High",
        threat_type="Rootkit Prevention",
        description=(
            "🚨 THREAT DETECTED: Code Integrity - Driver Blocked\n\n"
            "ANALYSIS:\nWindows Code Integrity blocked a driver from loading (Event ID 6). "
            "This is a critical security event indicating a potential rootkit or kernel-mode malware was detected and prevented.\n\n"
            "DETECTION DETAILS:\n"
            "• Rule: Event ID 6 — Code Integrity Driver Blocked\n"
            "• Driver Name: evil_driver.sys\n"
            "• Reason Blocked: Failed Code Integrity check (tampered or malicious code)\n"
            "• Time: just now\n\n"
            "ACTION REQUIRED:\n"
            "1. CRITICAL: Investigate the source of this driver\n"
            "2. Scan system for rootkit/kernel-mode malware\n"
            "3. Verify system integrity (Windows signatures)\n"
            "4. Consider forensic investigation"
        ),
        event_id=6,
        source="Microsoft-Windows-CodeIntegrity",
    )


ATTACKS = {
    "bruteforce":  simulate_brute_force,
    "dos":         simulate_dos,
    "logclear":    simulate_log_clearing,
    "persistence": simulate_persistence,
    "privesc":     simulate_privilege_escalation,
    "rdp":         simulate_rdp,
    "driver":      simulate_driver_block,
}

if __name__ == "__main__":
    arg = (sys.argv[1] if len(sys.argv) > 1 else "all").lower()

    print("=" * 60)
    print("  HYBRID SIEM — ATTACK SIMULATOR")
    print(f"  Target: {BASE_URL}")
    print("=" * 60)

    if arg == "all":
        for fn in ATTACKS.values():
            fn()
            time.sleep(0.5)
    elif arg in ATTACKS:
        ATTACKS[arg]()
    else:
        print(f"  Unknown attack: '{arg}'")
        print(f"  Available: {', '.join(ATTACKS.keys())}, all")

    print("\n✅ Simulation complete! Check your SIEM dashboard.")
