import win32evtlog
import requests
import threading
import time
from nic_capture import start_sniffing
from feature_mapper import map_to_ml_features

API_URL = "http://localhost:8000/detect/"

# Precise feature samples for simulation
NORMAL_FEATURES = [-0.35] * 77
# Slightly elevated features for suspicious but common events (reduced false positives)
SUSPICIOUS_FEATURES = [0.2 if i % 5 == 0 else -0.35 for i in range(77)]
# High-confidence attack pattern
ATTACK_FEATURES = [1.5 if i % 5 == 0 else -0.35 for i in range(77)]

print("🚀 Real-Time Hybrid SIEM Active Sensor Started (FP Reduction Mode)...")
print(f"Feeding Windows & Network logs to: {API_URL}\n")

# =========================
# NETWORK PACKET PROCESSING
# =========================
def process_packet(packet_features):
    ml_features = map_to_ml_features(packet_features)
    
    payload = {
        "source": f"Network ({packet_features.get('src_ip', 'local')})",
        "event_id": packet_features.get('protocol', 0),
        "event_type": "Network Traffic Scan",
        "features": ml_features,
        "FromSensor": True
    }
    
    try:
        requests.post(API_URL, json=payload, timeout=0.5)
    except:
        pass

# Start Network Sniffer in its own thread
threading.Thread(target=start_sniffing, args=("Wi-Fi",), daemon=True).start()

# =========================
# WINDOWS LOG PROCESSING
# =========================
server = "localhost"
log_type = "Security"
handle = win32evtlog.OpenEventLog(server, log_type)
flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

important_events = {
    4625: ("Failed Login", NORMAL_FEATURES),  # Normal system activity
    4688: ("Process Created", NORMAL_FEATURES),  # Normal processes run regularly
    4672: ("Admin Privileges", NORMAL_FEATURES),  # Common on Windows systems
    4720: ("User Created", NORMAL_FEATURES)  # Legitimate admin action
}

while True:
    try:
        events = win32evtlog.ReadEventLog(handle, flags, 0)
    except Exception as e:
        print(f"⚠️ Event Log Error: {e}. Re-opening...")
        time.sleep(2)
        try:
            handle = win32evtlog.OpenEventLog(server, log_type)
            continue
        except:
            continue

    if events:
        for event in events:
            event_id = event.EventID & 0xFFFF
            if event_id in important_events:
                event_name, features = important_events[event_id]
                
                print(f"🚨 OS Event: {event_name} (ID: {event_id})")
                
                payload = {
                    "source": "Windows OS",
                    "event_id": event_id,
                    "event_type": event_name,
                    "features": features,
                    "FromSensor": True
                }
                
                try:
                    requests.post(API_URL, json=payload, timeout=1)
                except Exception as e:
                    print(f"API Error: {e}")
                
    time.sleep(2)
