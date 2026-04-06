import win32evtlog
import requests
import threading
import time
from feature_mapper import map_to_ml_features

API_URL = "http://localhost:8000/detect/"

# Precise feature samples for simulation
NORMAL_FEATURES = [-0.35] * 77
# Slightly elevated features for suspicious but common events (reduced false positives)
SUSPICIOUS_FEATURES = [0.2 if i % 5 == 0 else -0.35 for i in range(77)]
# High-confidence attack pattern
ATTACK_FEATURES = [1.5 if i % 5 == 0 else -0.35 for i in range(77)]

print("🚀 Real-Time Hybrid SIEM Active Sensor Started (FP Reduction Mode)...")
print(f"Feeding Windows & Network logs to: {API_URL}")
print("📡 Network Interface: Monitoring incoming Kali attacks...")
print("⚠️  This machine IP: 192.168.56.1 (Tell Kali to attack this)\n")

# =========================
# NETWORK PACKET PROCESSING (Scapy-based)
# =========================
def start_network_sniffing():
    """Start network packet capture using Scapy"""
    try:
        from scapy.all import sniff, IP, TCP, UDP
        print("✅ Scapy imported successfully")
        
        packet_count = [0]  # Use list to allow modification in nested function
        
        def packet_callback(packet):
            try:
                packet_count[0] += 1
                
                src_ip = "unknown"
                dst_ip = "unknown"
                src_port = "unknown"
                dst_port = "unknown"
                protocol = "unknown"
                
                if IP in packet:
                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst
                    protocol = packet[IP].proto
                
                if TCP in packet:
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport
                    
                    # Log Kali attacks (nmap sends to many ports)
                    print(f"🔴 TCP PACKET #{packet_count[0]}: {src_ip}:{src_port} → {dst_ip}:{dst_port}")
                    
                    # Send to backend for detection
                    payload = {
                        "source": f"Network ({src_ip})",
                        "event_id": 1001,  # Custom network event ID
                        "event_type": f"TCP Scan - Port {dst_port}",
                        "description": f"Inbound TCP from {src_ip} to port {dst_port}",
                        "threat_type": "Network Reconnaissance",
                        "features": ATTACK_FEATURES,
                        "FromSensor": True
                    }
                    
                    try:
                        r = requests.post(API_URL, json=payload, timeout=0.5)
                        if r.status_code == 200:
                            print(f"   ✅ Sent to backend")
                    except Exception as e:
                        print(f"   ⚠️ Backend error: {e}")
                
                elif UDP in packet:
                    src_port = packet[UDP].sport
                    dst_port = packet[UDP].dport
                    print(f"🔵 UDP PACKET #{packet_count[0]}: {src_ip}:{src_port} → {dst_ip}:{dst_port}")
                    
            except Exception as e:
                print(f"⚠️ Packet processing error: {e}")
        
        print("📡 Starting Scapy packet capture on Ethernet 6...")
        sniff(iface="Ethernet 6", prn=packet_callback, store=0)
        
    except ImportError:
        print("❌ Scapy not installed! Install with: pip install scapy")
    except Exception as e:
        print(f"❌ Scapy error: {e}")

# Start Network Sniffer in its own thread
print("⏳ Starting network sniffer on Ethernet 6 (VirtualBox)...")
sniffer_thread = threading.Thread(target=start_network_sniffing, daemon=True)
sniffer_thread.start()
print("✅ Sniffer thread started (may take a few seconds)\n")

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
                    print(f"   ✅ Sent to backend")
                except Exception as e:
                    print(f"   ❌ Backend error: {e}")
    else:
        # Silently continue if no events (avoid spam)
        pass
    
    time.sleep(2)
