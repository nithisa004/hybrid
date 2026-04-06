"""
╔════════════════════════════════════════════════════════════════╗
║        THREAT INDICATOR EXTRACTOR                             ║
║  Extracts malicious IPs, ports, and protocols from threats    ║
╚════════════════════════════════════════════════════════════════╝
"""

import re
import logging
from typing import Dict, Optional, List

logger = logging.getLogger(__name__)

# IP extraction regex patterns
IPV4_PATTERN = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
IPV6_PATTERN = r'(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}'
PORT_PATTERN = r'[Pp]ort\s*[:=]?\s*(\d{1,5})|:(\d{1,5})'
KALI_TOOLS = {
    'nmap': {'threat_type': 'Port Scan', 'severity': 'High'},
    'metasploit': {'threat_type': 'Exploitation', 'severity': 'Critical'},
    'hydra': {'threat_type': 'Brute Force', 'severity': 'High'},
    'sqlmap': {'threat_type': 'SQL Injection', 'severity': 'High'},
    'wireshark': {'threat_type': 'Network Sniffing', 'severity': 'Medium'},
    'hping3': {'threat_type': 'DoS Attack', 'severity': 'Critical'},
    'aircrack': {'threat_type': 'Wireless Attack', 'severity': 'High'},
}

# Suspicious ports (commonly exploited)
SUSPICIOUS_PORTS = {
    4444: 'Metasploit Handler',
    5555: 'Android ADB / Kali SSH',
    6666: 'IRC Backdoor',
    8888: 'Alternate HTTP',
    9999: 'SquirrelMail',
    31337: 'NetStar Trojan',
    12345: 'NetBus Trojan',
    27374: 'SubSeven Trojan',
    65432: 'Custom Backdoor Port',
}


def extract_ipv4_addresses(text: str) -> List[str]:
    """Extract all IPv4 addresses from text."""
    if not text:
        return []
    matches = re.findall(IPV4_PATTERN, text)
    # Filter out common non-threat IPs
    filtered = [ip for ip in matches if not ip.startswith('127.') and ip != '0.0.0.0' and ip != '255.255.255.255']
    return list(set(filtered))  # Remove duplicates


def extract_ports(text: str) -> List[int]:
    """Extract all port numbers from text."""
    if not text:
        return []
    matches = re.findall(PORT_PATTERN, text)
    ports = []
    for match in matches:
        port_num = int(match[0]) if match[0] else int(match[1])
        if 1 <= port_num <= 65535:
            ports.append(port_num)
    return list(set(ports))  # Remove duplicates


def detect_kali_tool_usage(text: str) -> Optional[str]:
    """Identify if Kali tool signature is present in threat description."""
    text_lower = text.lower()
    for tool, info in KALI_TOOLS.items():
        if tool in text_lower:
            return tool
    return None


def get_port_risk_level(port: int) -> str:
    """Determine risk level for a given port."""
    if port in SUSPICIOUS_PORTS:
        return 'CRITICAL'
    elif port < 1024:  # Privileged ports
        return 'HIGH'
    elif port in [22, 23, 3306, 5432, 27017]:  # Common service ports
        return 'HIGH'
    else:
        return 'LOW'


def extract_threat_indicators(
    description: str, 
    event_id: int, 
    threat_type: str = "",
    source_ip: Optional[str] = None
) -> Dict:
    """
    Extract comprehensive threat indicators from a threat description.
    
    Args:
        description: Threat description text
        event_id: Windows event ID
        threat_type: Type of threat (e.g., "Brute Force", "Port Scan")
        source_ip: Optional source IP (if already known)
    
    Returns:
        Dict with keys: source_ip, ports, kali_tool, severity, block_reason
    """
    
    indicators = {
        'source_ip': source_ip,
        'ports': [],
        'kali_tool': None,
        'severity': 'Medium',
        'block_reason': '',
        'is_kali_attack': False,
        'suspicious_ports': []
    }
    
    try:
        # Extract IPs
        if not source_ip:
            ips = extract_ipv4_addresses(description)
            if ips:
                indicators['source_ip'] = ips[0]  # Primary threat source
                logger.info(f"Extracted IP: {ips[0]}")
        
        # Extract ports
        ports = extract_ports(description)
        indicators['ports'] = ports
        
        # Check for suspicious ports
        suspicious = [p for p in ports if p in SUSPICIOUS_PORTS]
        indicators['suspicious_ports'] = suspicious
        
        # Detect Kali tool usage
        kali_tool = detect_kali_tool_usage(description)
        if kali_tool:
            indicators['kali_tool'] = kali_tool
            indicators['is_kali_attack'] = True
            indicators['severity'] = 'Critical'
            logger.warning(f"Detected Kali tool: {kali_tool}")
        
        # Rule-based severity detection
        if event_id == 4625:  # Brute force
            if len([p for p in ports if p in [22, 3306, 5432]]) > 0:
                indicators['severity'] = 'Critical'
            else:
                indicators['severity'] = 'High'
            indicators['block_reason'] = f"Brute force attack detected (Event {event_id})"
        
        elif event_id in [10000, 10001]:  # Network-based (custom event IDs for network anomalies)
            if ports:
                if any(p in SUSPICIOUS_PORTS for p in ports):
                    indicators['severity'] = 'Critical'
                else:
                    indicators['severity'] = 'High'
            indicators['block_reason'] = "Network attack pattern detected"
        
        elif 'syn' in description.lower() or 'flood' in description.lower():
            indicators['severity'] = 'Critical'
            indicators['block_reason'] = "SYN Flood / DoS attack detected"
        
        elif 'port scan' in description.lower():
            indicators['severity'] = 'High'
            indicators['block_reason'] = "Network reconnaissance (port scan) detected"
        
        else:
            indicators['block_reason'] = f"Threat detected: {threat_type or 'Unknown'}"
        
        logger.info(f"Threat indicators extracted: {indicators}")
        
    except Exception as e:
        logger.error(f"Error extracting threat indicators: {e}")
        indicators['error'] = str(e)
    
    return indicators


def should_block_threat(severity: str, event_id: int, threat_type: str) -> bool:
    """
    Determine if a threat should be automatically blocked.
    
    Args:
        severity: Threat severity (Low, Medium, High, Critical)
        event_id: Windows event ID
        threat_type: Type of threat
    
    Returns:
        True if threat should be auto-blocked, False otherwise
    """
    # Auto-block Critical and High severity network threats
    if severity in ['Critical', 'High']:
        # Network-based threats
        if any(x in threat_type.lower() for x in ['ddos', 'syn', 'port scan', 'flooding', 'exploit']):
            return True
        
        # Credential attacks
        if event_id in [4625] and 'brute' in threat_type.lower():
            return True
        
        # Malware/persistence
        if any(x in threat_type.lower() for x in ['malware', 'backdoor', 'trojan', 'rootkit']):
            return True
    
    return False


def whitelist_ip(ip: str) -> bool:
    """
    Check if IP is whitelisted (trusted).
    
    Common whitelisted ranges:
    - 127.0.0.0/8 (Localhost)
    - 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 (Private networks - adjust as needed)
    """
    whitelist = [
        '127.0.0.1',
        '127.0.0.0/8',
        # '10.0.0.0/8',        # Uncomment to whitelist internal network
        # '192.168.0.0/16',    # (adjust as needed)
    ]
    
    # Simple check - can be enhanced with ipaddress library
    if ip.startswith('127.'):
        return True
    
    return False


def extract_kali_metadata(description: str) -> Dict:
    """
    Extract specific metadata from Kali attacks.
    
    Returns:
        Dict with: tool_name, target_service, technique
    """
    metadata = {
        'tool_name': None,
        'target_service': None,
        'technique': None
    }
    
    try:
        # Detect Kali tool
        tool = detect_kali_tool_usage(description)
        metadata['tool_name'] = tool
        
        # Extract target service
        if 'ssh' in description.lower():
            metadata['target_service'] = 'SSH'
        elif 'http' in description.lower():
            metadata['target_service'] = 'HTTP/HTTPS'
        elif 'sql' in description.lower():
            metadata['target_service'] = 'Database'
        elif 'ftp' in description.lower():
            metadata['target_service'] = 'FTP'
        
        # Extract technique
        if 'brute' in description.lower():
            metadata['technique'] = 'Brute Force'
        elif 'injection' in description.lower():
            metadata['technique'] = 'Injection Attack'
        elif 'scan' in description.lower():
            metadata['technique'] = 'Reconnaissance'
        elif 'exploit' in description.lower():
            metadata['technique'] = 'Exploitation'
        
    except Exception as e:
        logger.error(f"Error extracting Kali metadata: {e}")
    
    return metadata
