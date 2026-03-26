import requests
from scapy.all import sniff, IP, TCP, UDP
from feature_mapper import map_to_ml_features

API_URL = "http://localhost:8000/detect/"

def extract_packet_features(packet):
    features = {}
    if IP in packet:
        features['src_ip'] = packet[IP].src
        features['dst_ip'] = packet[IP].dst
        features['protocol'] = packet[IP].proto
    if TCP in packet:
        features['src_port'] = packet[TCP].sport
        features['dst_port'] = packet[TCP].dport
    if UDP in packet:
        features['src_port'] = packet[UDP].sport
        features['dst_port'] = packet[UDP].dport
    features['packet_size'] = len(packet)
    return features

def process_and_send(packet):
    raw_features = extract_packet_features(packet)
    ml_features = map_to_ml_features(raw_features)
    
    payload = {
        "source": f"NIC ({raw_features.get('src_ip', 'local')})",
        "event_id": raw_features.get('protocol', 0),
        "event_type": "Network Traffic Scan",
        "features": ml_features
    }
    
    try:
        requests.post(API_URL, json=payload, timeout=1)
    except:
        pass

def start_sniffing(iface="Wi-Fi"):
    print(f"📡 Capturing NIC Traffic on {iface} and feeding SIEM...")
    sniff(iface=iface, prn=process_and_send, store=0)