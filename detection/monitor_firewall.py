#!/usr/bin/env python
"""
🔨 SIMPLIFIED KALI ATTACK DETECTOR
Uses Windows Firewall logs instead of Scapy (more reliable on VirtualBox)
"""

import win32evtlog
import requests
import time
import logging

API_URL = "http://localhost:8000/detect/"
ATTACK_FEATURES = [1.5 if i % 5 == 0 else -0.35 for i in range(77)]

logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)

print("=" * 70)
print("🔨 SIMPLIFIED REAL-TIME DETECTOR — Windows Firewall Log Monitoring")
print("=" * 70)
print(f"\nTarget: {API_URL}")
print("Monitor: Windows Security Event Log")
print("Method: Direct log monitoring (no packet capture)\n")

# Enable Windows Firewall logging first
print("📋 IMPORTANT: Windows Firewall must log dropped packets")
print("   Run this in ADMIN PowerShell FIRST:")
print("   auditpol /set /subcategory:\"Filtering Platform Packet Drop\" /success:enable /failure:enable")
print("   auditpol /set /subcategory:\"Filtering Platform Connection\" /success:enable /failure:enable\n")

# Windows Event IDs for network/security
NETWORK_EVENTS = {
    4625: "Brute Force - Failed Login",
    5152: "Firewall - Packet Dropped",
    5153: "Firewall - More Packets Dropped",
    5154: "Firewall - Application Listening",
    5155: "Firewall - Application Blocked",
    5156: "Firewall - Connection Allowed",
    5157: "Firewall - Connection Blocked",
    5158: "Firewall - Port Binding Blocked",
}

def send_to_backend(event_id, event_name, description):
    """Send event to backend"""
    payload = {
        "source": "Windows Security/Firewall",
        "event_id": event_id,
        "event_type": event_name,
        "description": description,
        "threat_type": "Network Event",
        "features": ATTACK_FEATURES,
        "FromSensor": True
    }
    
    try:
        r = requests.post(API_URL, json=payload, timeout=2)
        if r.status_code == 200:
            print(f"✅ Event {event_id} sent to backend")
        else:
            print(f"⚠️  Backend returned {r.status_code}")
    except Exception as e:
        print(f"❌ Backend error: {e}")

def monitor_security_log():
    """Monitor Windows Security event log"""
    
    server = "localhost"
    log_type = "Security"
    
    try:
        hand = win32evtlog.OpenEventLog(server, log_type)
    except Exception as e:
        print(f"❌ Cannot open Security log: {e}")
        print("   Make sure you're running as ADMINISTRATOR")
        return
    
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    last_record = 0
    
    print(f"📡 Monitoring Security Event Log...\n")
    
    while True:
        try:
            events = win32evtlog.ReadEventLog(hand, flags, 0)
            
            if events:
                for event in events:
                    event_id = event.EventID & 0xFFFF
                    record_number = event.RecordNumber
                    
                    # Only process new events
                    if record_number > last_record:
                        last_record = record_number
                        
                        if event_id in NETWORK_EVENTS:
                            event_name = NETWORK_EVENTS[event_id]
                            event_time = event.TimeGenerated
                            
                            # Extract details
                            data = event.StringInserts
                            details = " | ".join(data) if data else "No details"
                            
                            print(f"🚨 EVENT #{event_id}: {event_name}")
                            print(f"   Time: {event_time}")
                            print(f"   Details: {details[:100]}\n")
                            
                            # Send to backend
                            send_to_backend(event_id, event_name, details)
                        
                        # Log ALL attack-related events
                        elif event_id == 4625:  # Failed login
                            print(f"🔐 FAILED LOGIN ATTEMPT (Event 4625)")
                            send_to_backend(4625, "Failed Login", str(event.StringInserts))
                        
                        elif event_id in [5152, 5153]:  # Firewall packets dropped
                            print(f"🔴 FIREWALL: Dropped packets detected (Event {event_id})")
                            send_to_backend(event_id, NETWORK_EVENTS.get(event_id, "Firewall Event"), str(event.StringInserts))
        
        except Exception as e:
            print(f"⚠️  Log read error: {e}. Retrying...")
            time.sleep(2)
            try:
                hand = win32evtlog.OpenEventLog(server, log_type)
            except:
                print("❌ Cannot reconnect to event log")
        
        time.sleep(1)  # Check every second

if __name__ == "__main__":
    try:
        monitor_security_log()
    except KeyboardInterrupt:
        print("\n\n✅ Monitor stopped")
    except Exception as e:
        print(f"\n❌ Fatal error: {e}")
