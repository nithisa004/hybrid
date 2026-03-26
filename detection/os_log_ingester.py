import win32evtlog
import requests
import time

server = "localhost"
log_type = "Security"
API_URL = "http://localhost:8000/detect/"

# Precise feature samples for simulation (77 features)
NORMAL_FEATURES = [-0.35] * 77
# Slightly elevated features for suspicious but common events (reduced false positives)
SUSPICIOUS_FEATURES = [0.2 if i % 5 == 0 else -0.35 for i in range(77)]
# High-confidence attack pattern
ATTACK_FEATURES = [1.5 if i % 5 == 0 else -0.35 for i in range(77)]
ANOMALY_FEATURES = [5.0] * 77 # Out of distribution

handle = win32evtlog.OpenEventLog(server, log_type)
flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

print("🔐 Real-Time Hybrid SIEM Ingester Started (FP Reduction Mode)...")
print(f"Monitoring Windows Events and feeding to: {API_URL}\n")

important_events = {
    4624: ("Login Success", NORMAL_FEATURES),
    4625: ("Failed Login", NORMAL_FEATURES),  # Normal system activity
    4648: ("Explicit Credential Logon", NORMAL_FEATURES),  # Normal for service accounts
    4720: ("User Account Created", NORMAL_FEATURES),  # Legitimate admin action
    4722: ("Account Enabled", NORMAL_FEATURES),
    4672: ("Admin Privileges Assigned", NORMAL_FEATURES),  # Common on Windows
}

while True:
    events = win32evtlog.ReadEventLog(handle, flags, 0)
    if events:
        for event in events:
            event_id = event.EventID
            if event_id in important_events:
                event_name, features = important_events[event_id]
                
                print(f"Detected: {event_name} (ID: {event_id})")
                
                # Send to Backend
                payload = {
                    "source": "Windows Event Log",
                    "event_id": event_id,
                    "event_type": event_name,
                    "features": features
                }
                
                try:
                    res = requests.post(API_URL, json=payload)
                    if res.status_code == 200:
                        analysis = res.json()['log']
                        print(f"Analysis: {analysis['result']} | XGBoost: {analysis['xgb_prediction']} | AE Score: {analysis['anomaly_score']:.4f}")
                    else:
                        print(f"API Error: {res.status_code}")
                except Exception as e:
                    print(f"Connection to backend failed: {e}")
                
                print("-" * 50)
    time.sleep(1) # Interval to prevent CPU spike
