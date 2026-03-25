from scapy.all import sniff, IP, TCP, UDP

def extract_packet_features(packet):
    features = {}

    if IP in packet:
        features['src_ip'] = packet[IP].src
        features['dst_ip'] = packet[IP].dst
        features['protocol'] = packet[IP].proto

    if TCP in packet:
        features['src_port'] = packet[TCP].sport
        features['dst_port'] = packet[TCP].dport
        features['flags'] = str(packet[TCP].flags)

    if UDP in packet:
        features['src_port'] = packet[UDP].sport
        features['dst_port'] = packet[UDP].dport

    features['packet_size'] = len(packet)

    return features


def start_sniffing(callback):
    print("📡 Capturing NIC Traffic...")
    sniff(iface="Wi-Fi", prn=lambda pkt: callback(extract_packet_features(pkt)), store=0)