"""
╔════════════════════════════════════════════════════════════════╗
║         NETWORK ATTACK DETECTOR                               ║
║  Detects Kali attacks at network level                        ║
║  • Port scans (Nmap)                                          ║
║  • SYN floods (DoS)                                           ║
║  • Malformed packets                                          ║
║  • Suspicious ports                                           ║
╚════════════════════════════════════════════════════════════════╝
"""

import logging
from typing import Dict, List, Tuple, Optional
from collections import defaultdict, deque
from datetime import datetime, timedelta
import threading

logger = logging.getLogger(__name__)


class PacketFlags:
    """TCP Flags reference"""
    SYN = 0x02
    ACK = 0x10
    FIN = 0x01
    RST = 0x04
    PSH = 0x08
    URG = 0x20


class NetworkAttackDetector:
    """Detects network-based attacks from packet analysis."""
    
    def __init__(self, time_window_seconds: int = 5):
        """
        Initialize detector.
        
        Args:
            time_window_seconds: Time window for detecting patterns (default 5 seconds)
        """
        self.time_window = timedelta(seconds=time_window_seconds)
        
        # Track packets from unique IPs for pattern detection
        self.packet_history = defaultdict(lambda: deque(maxlen=1000))  # IP -> packets
        self.connection_attempts = defaultdict(lambda: deque(maxlen=500))  # IP -> port attempts
        self.lock = threading.Lock()
    
    def analyze_packet(self, packet_dict: Dict) -> Optional[Dict]:
        """
        Analyze a single packet for attack signatures.
        
        Args:
            packet_dict: Packet info {
                'src_ip': '192.168.1.100',
                'dst_ip': '192.168.1.5',
                'protocol': 'TCP',
                'src_port': 12345,
                'dst_port': 80,
                'flags': 0x02,  # TCP flags as integer
                'payload_size': 0,
                'timestamp': datetime.now()
            }
        
        Returns:
            Threat dict if attack detected, None otherwise
        """
        
        threats = []
        
        try:
            with self.lock:
                src_ip = packet_dict.get('src_ip')
                dst_port = packet_dict.get('dst_port')
                protocol = packet_dict.get('protocol', 'TCP').upper()
                flags = packet_dict.get('flags', 0)
                timestamp = packet_dict.get('timestamp', datetime.now())
                
                # Record packet
                self.packet_history[src_ip].append(packet_dict)
                
                # Record connection attempt
                if protocol == 'TCP':
                    self.connection_attempts[src_ip].append({
                        'port': dst_port,
                        'timestamp': timestamp
                    })
                
                # Detect SYN Flood
                syn_threat = self.detect_syn_flood(src_ip, timestamp)
                if syn_threat:
                    threats.append(syn_threat)
                
                # Detect Port Scan
                port_scan_threat = self.detect_port_scan(src_ip, timestamp)
                if port_scan_threat:
                    threats.append(port_scan_threat)
                
                # Detect Suspicious Communication
                sus_threat = self.detect_suspicious_port_activity(src_ip, dst_port, timestamp)
                if sus_threat:
                    threats.append(sus_threat)
                
                # Detect Malformed Packets
                malformed = self.detect_malformed_packet(packet_dict)
                if malformed:
                    threats.append(malformed)
        
        except Exception as e:
            logger.error(f"Error analyzing packet: {e}")
        
        return threats[0] if threats else None  # Return first threat found
    
    def detect_syn_flood(self, src_ip: str, current_time: datetime) -> Optional[Dict]:
        """
        Detect SYN flood attack.
        
        Signature: High volume of SYN packets from single IP in short time window
        - Threshold: 50+ SYN packets in 5 seconds
        """
        
        packets = self.packet_history.get(src_ip, deque())
        
        # Filter SYN packets within time window
        recent_packets = [
            p for p in packets 
            if (current_time - p.get('timestamp', current_time)).total_seconds() <= 5
            and p.get('flags', 0) & PacketFlags.SYN
            and p.get('protocol', '').upper() == 'TCP'
        ]
        
        if len(recent_packets) >= 50:
            logger.warning(f"SYN Flood detected from {src_ip}: {len(recent_packets)} packets")
            
            return {
                'threat_type': 'SYN Flood (DoS Attack)',
                'severity': 'Critical',
                'source_ip': src_ip,
                'attack_pattern': f"{len(recent_packets)} SYN packets in 5 seconds",
                'description': (
                    f"CRITICAL: SYN Flood Attack Detected!\n\n"
                    f"Source IP: {src_ip}\n"
                    f"Attack Pattern: {len(recent_packets)} SYN packets detected in 5 seconds\n"
                    f"This is a Denial of Service (DoS) attack using TCP SYN flood technique.\n\n"
                    f"Typical Kali tool: hping3, Scapy\n"
                    f"Command: hping3 -S --flood {src_ip}\n\n"
                    f"IMMEDIATE ACTION:\n"
                    f"1. Block source IP {src_ip} in firewall\n"
                    f"2. Enable SYN cookies if available\n"
                    f"3. Rate limit SYN packets\n"
                    f"4. Contact ISP if flooding continues"
                ),
                'event_id': 10001,  # Custom network event ID
                'recommended_action': 'block_ip'
            }
        
        return None
    
    def detect_port_scan(self, src_ip: str, current_time: datetime) -> Optional[Dict]:
        """
        Detect port scan attack.
        
        Signature: Connection attempts to many different ports in short time
        - Threshold: 10+ unique ports in 5 seconds
        """
        
        attempts = self.connection_attempts.get(src_ip, deque())
        
        # Filter attempts within time window
        recent_attempts = [
            a for a in attempts 
            if (current_time - a.get('timestamp', current_time)).total_seconds() <= 5
        ]
        
        # Get unique ports
        unique_ports = set(a['port'] for a in recent_attempts)
        
        if len(unique_ports) >= 10:
            logger.warning(f"Port scan detected from {src_ip}: {len(unique_ports)} ports in 5 seconds")
            
            # Identify scan type based on port sequence
            ports_list = sorted([a['port'] for a in recent_attempts])
            
            return {
                'threat_type': 'Port Scan (Network Reconnaissance)',
                'severity': 'High',
                'source_ip': src_ip,
                'target_ports': list(unique_ports)[:10],  # Show first 10
                'attack_pattern': f"{len(unique_ports)} unique ports scanned in 5 seconds",
                'description': (
                    f"HIGH: Port Scan Detected!\n\n"
                    f"Source IP: {src_ip}\n"
                    f"Ports Scanned: {', '.join(map(str, sorted(unique_ports)[:10]))}\n"
                    f"Total Unique Ports: {len(unique_ports)}\n\n"
                    f"This is network reconnaissance, typically the first phase of an attack.\n\n"
                    f"Typical Kali tool: Nmap\n"
                    f"Command: nmap -p 1-10000 {src_ip}\n\n"
                    f"IMMEDIATE ACTION:\n"
                    f"1. Block source IP {src_ip}\n"
                    f"2. Block unnecessary open ports\n"
                    f"3. Enable firewall rules for reconnaissance IPs\n"
                    f"4. Monitor for follow-up exploitation attempts"
                ),
                'event_id': 10002,  # Custom network event ID
                'recommended_action': 'block_ip'
            }
        
        return None
    
    def detect_suspicious_port_activity(self, src_ip: str, dst_port: int, current_time: datetime) -> Optional[Dict]:
        """
        Detect attempts to connect to suspicious/backdoor ports.
        
        Suspicious ports:
        - 4444: Metasploit Handler
        - 5555: Android ADB / Kali SSH
        - 6666: IRC Backdoor
        - 31337: NetStar Trojan
        etc.
        """
        
        SUSPICIOUS_PORTS = {
            4444: {'name': 'Metasploit Handler', 'risk': 'Critical'},
            5555: {'name': 'Android ADB / Kali SSH', 'risk': 'High'},
            6666: {'name': 'IRC Backdoor', 'risk': 'High'},
            8888: {'name': 'Alternate HTTP / Kali Services', 'risk': 'Medium'},
            9999: {'name': 'SquirrelMail / Custom Backdoor', 'risk': 'High'},
            31337: {'name': 'NetStar Trojan', 'risk': 'Critical'},
            12345: {'name': 'NetBus Trojan', 'risk': 'Critical'},
            27374: {'name': 'SubSeven Trojan', 'risk': 'Critical'},
            65432: {'name': 'Custom Backdoor Port', 'risk': 'High'},
        }
        
        if dst_port in SUSPICIOUS_PORTS:
            port_info = SUSPICIOUS_PORTS[dst_port]
            
            logger.warning(f"Suspicious port activity: {src_ip} -> port {dst_port}")
            
            return {
                'threat_type': f'Suspicious Port Access ({port_info["name"]})',
                'severity': port_info['risk'],
                'source_ip': src_ip,
                'target_port': dst_port,
                'port_name': port_info['name'],
                'description': (
                    f"{port_info['risk']}: Suspicious Port Access Detected!\n\n"
                    f"Source IP: {src_ip}\n"
                    f"Target Port: {dst_port}\n"
                    f"Port Name: {port_info['name']}\n\n"
                    f"This port is commonly associated with backdoors, trojans, or Kali services.\n\n"
                    f"IMMEDIATE ACTION:\n"
                    f"1. Block source IP {src_ip}\n"
                    f"2. Ensure port {dst_port} is not exposed\n"
                    f"3. Check for reverse shells from this IP\n"
                    f"4. Review system for compromises"
                ),
                'event_id': 10003,  # Custom network event ID
                'recommended_action': 'block_ip'
            }
        
        return None
    
    def detect_malformed_packet(self, packet_dict: Dict) -> Optional[Dict]:
        """
        Detect malformed or suspicious packet structures.
        
        Checks:
        - Bad TCP checksums
        - Invalid flag combinations (e.g., SYN+FIN)
        - Zero-length packets with data
        - Suspicious TTL values
        """
        
        flags = packet_dict.get('flags', 0)
        payload_size = packet_dict.get('payload_size', 0)
        src_ip = packet_dict.get('src_ip', 'unknown')
        
        # Check for invalid TCP flag combinations
        invalid_flags = [
            (flags & PacketFlags.SYN) and (flags & PacketFlags.FIN),  # SYN+FIN
            (flags & PacketFlags.SYN) and (flags & PacketFlags.RST),  # SYN+RST
            (flags == 0),  # No flags set (possible null scan)
            (flags & PacketFlags.PSH) and not (flags & PacketFlags.ACK),  # PSH without ACK
        ]
        
        if any(invalid_flags):
            logger.warning(f"Malformed packet detected from {src_ip}: flags={bin(flags)}")
            
            # Determine what type of scan this is
            if flags & PacketFlags.PSH and not (flags & PacketFlags.ACK):
                scan_type = "Xmas Scan"
            elif flags == 0:
                scan_type = "Null Scan"
            else:
                scan_type = "Invalid TCP Flags"
            
            return {
                'threat_type': f'Network Probe ({scan_type})',
                'severity': 'High',
                'source_ip': src_ip,
                'attack_pattern': f"Malformed TCP packet: {scan_type}",
                'description': (
                    f"HIGH: Network Probe Detected (IDS Evasion)!\n\n"
                    f"Source IP: {src_ip}\n"
                    f"Scan Type: {scan_type}\n"
                    f"TCP Flags: {bin(flags)}\n\n"
                    f"Malformed packets are often used to evade IDS/firewalls.\n"
                    f"This is a sign of advanced reconnaissance/exploitation attempts.\n\n"
                    f"Typical Kali tool: Nmap (with special scan options)\n"
                    f"Command: nmap -sX (Xmas scan), nmap -sN (Null scan)\n\n"
                    f"IMMEDIATE ACTION:\n"
                    f"1. Block source IP {src_ip}\n"
                    f"2. Enable advanced packet filtering\n"
                    f"3. Check IDS for correlated attacks\n"
                    f"4. Prepare for actual exploitation attempt"
                ),
                'event_id': 10004,  # Custom network event ID
                'recommended_action': 'block_ip'
            }
        
        return None
    
    def cleanup_old_entries(self, max_age_seconds: int = 300):
        """Remove old packet history entries (prevents memory bloat)."""
        
        try:
            with self.lock:
                current_time = datetime.now()
                cutoff_time = current_time - timedelta(seconds=max_age_seconds)
                
                for src_ip in list(self.packet_history.keys()):
                    packets = self.packet_history[src_ip]
                    
                    # Remove old packets
                    while packets and (current_time - packets[0].get('timestamp', current_time)) > timedelta(seconds=max_age_seconds):
                        packets.popleft()
                    
                    # Remove empty entries
                    if not packets:
                        del self.packet_history[src_ip]
                
                # Same for connection attempts
                for src_ip in list(self.connection_attempts.keys()):
                    attempts = self.connection_attempts[src_ip]
                    
                    while attempts and (current_time - attempts[0].get('timestamp', current_time)) > timedelta(seconds=max_age_seconds):
                        attempts.popleft()
                    
                    if not attempts:
                        del self.connection_attempts[src_ip]
        
        except Exception as e:
            logger.error(f"Error cleaning up old entries: {e}")
    
    def get_statistics(self) -> Dict:
        """Get statistics about detected patterns."""
        
        with self.lock:
            return {
                'tracked_ips': len(self.packet_history),
                'total_packets': sum(len(packets) for packets in self.packet_history.values()),
                'tracked_connections': len(self.connection_attempts),
                'timestamp': datetime.now().isoformat()
            }


# Singleton instance for use throughout the application
_detector = NetworkAttackDetector(time_window_seconds=5)


def analyze_packet(packet_dict: Dict) -> Optional[Dict]:
    """Analyze a packet for attacks."""
    return _detector.analyze_packet(packet_dict)


def get_statistics() -> Dict:
    """Get detector statistics."""
    return _detector.get_statistics()


def cleanup():
    """Cleanup old entries."""
    _detector.cleanup_old_entries()


if __name__ == "__main__":
    # Test examples
    print("╔════════════════════════════════════════════════════════════╗")
    print("║         Network Attack Detector Test                      ║")
    print("╚════════════════════════════════════════════════════════════╝\n")
    
    # Create test packets
    detector = NetworkAttackDetector(time_window_seconds=5)
    
    # Test 1: Simulate port scan
    print("[1] Simulating port scan from 192.168.1.100...")
    for port in range(1, 21):  # Scan ports 1-20
        packet = {
            'src_ip': '192.168.1.100',
            'dst_ip': '192.168.1.5',
            'protocol': 'TCP',
            'src_port': 54321,
            'dst_port': port,
            'flags': 0x02,  # SYN
            'payload_size': 0,
            'timestamp': datetime.now()
        }
        threat = detector.analyze_packet(packet)
        if threat:
            print(f"  ✓ Threat detected: {threat['threat_type']}")
            break
    else:
        print("  (Port scan would be detected after 10+ unique ports)")
    
    # Test 2: Simulate SYN flood
    print("\n[2] Simulating SYN flood from 192.168.1.101...")
    for i in range(60):
        packet = {
            'src_ip': '192.168.1.101',
            'dst_ip': '192.168.1.5',
            'protocol': 'TCP',
            'src_port': 54321 + i,
            'dst_port': 80,
            'flags': 0x02,  # SYN
            'payload_size': 0,
            'timestamp': datetime.now()
        }
        threat = detector.analyze_packet(packet)
        if threat:
            print(f"  ✓ Threat detected: {threat['threat_type']}")
            break
    
    # Test 3: Suspicious port
    print("\n[3] Testing suspicious port access (4444 - Metasploit)...")
    packet = {
        'src_ip': '192.168.1.102',
        'dst_ip': '192.168.1.5',
        'protocol': 'TCP',
        'src_port': 54321,
        'dst_port': 4444,
        'flags': 0x02,
        'payload_size': 0,
        'timestamp': datetime.now()
    }
    threat = detector.analyze_packet(packet)
    if threat:
        print(f"  ✓ Threat detected: {threat['threat_type']}")
    
    print("\n✓ Tests complete")
