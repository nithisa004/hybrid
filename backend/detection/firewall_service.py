"""
╔════════════════════════════════════════════════════════════════╗
║          WINDOWS FIREWALL AUTO-BLOCKING SERVICE               ║
║  Automatically creates and manages firewall blocking rules    ║
╚════════════════════════════════════════════════════════════════╝
"""

import subprocess
import logging
import re
from typing import Dict, List, Optional, Tuple
from datetime import datetime

logger = logging.getLogger(__name__)


class FirewallManager:
    """Manages Windows Firewall rules via netsh or PowerShell."""
    
    RULE_PREFIX = "HybridSIEM"
    
    @staticmethod
    def is_valid_ip(ip: str) -> bool:
        """Validate IPv4 address format."""
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(part) <= 255 for part in parts)
        except:
            return False
    
    @staticmethod
    def is_valid_port(port: int) -> bool:
        """Validate port number."""
        return 1 <= port <= 65535
    
    @staticmethod
    def execute_command(command: str, timeout: int = 10) -> Tuple[bool, str, str]:
        """
        Execute a shell command with error handling.
        
        Returns:
            (success: bool, stdout: str, stderr: str)
        """
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            success = result.returncode == 0
            
            if not success:
                logger.warning(f"Command failed: {command}\nError: {result.stderr}")
            
            return success, result.stdout, result.stderr
            
        except subprocess.TimeoutExpired:
            logger.error(f"Command timeout: {command}")
            return False, "", "Command execution timeout"
        except Exception as e:
            logger.error(f"Command execution error: {e}")
            return False, "", str(e)
    
    @classmethod
    def block_ip(cls, ip: str, direction: str = "in", severity: str = "High") -> Dict:
        """
        Block an IP address in Windows Firewall (inbound and outbound).
        
        Args:
            ip: IP address to block (e.g., "192.168.1.100")
            direction: "in" (inbound), "out" (outbound), or "both"
            severity: Threat severity (affects rule priority)
        
        Returns:
            Dict with: success (bool), rule_names (list), errors (list)
        """
        
        result = {
            'success': False,
            'rule_names': [],
            'errors': [],
            'timestamp': datetime.now().isoformat()
        }
        
        # Validate IP
        if not cls.is_valid_ip(ip):
            result['errors'].append(f"Invalid IP address: {ip}")
            logger.error(f"Invalid IP: {ip}")
            return result
        
        # Normalize direction
        directions = ["in", "out"] if direction == "both" else [direction]
        
        try:
            # Create rules for each direction
            for dir_type in directions:
                rule_name = f"{cls.RULE_PREFIX}_Block_{dir_type}_{ip.replace('.', '_')}"
                
                # netsh command to add firewall rule
                # Using PowerShell wrapper for better compatibility
                cmd = f'''powershell -Command "
                    if(-not(Get-NetFirewallRule -DisplayName '{rule_name}' -ErrorAction SilentlyContinue)) {{
                        New-NetFirewallRule -DisplayName '{rule_name}' `
                            -Direction {('Inbound' if dir_type == 'in' else 'Outbound')} `
                            -Action Block `
                            -RemoteAddress {ip} `
                            -Profile Any `
                            -Enabled True `
                            -Description 'Auto-blocked by Hybrid SIEM - Threat detection' `
                            -ErrorAction Stop | Out-Null
                        Write-Host 'RULE_CREATED'
                    }} else {{
                        Write-Host 'RULE_EXISTS'
                    }}
                "'''
                
                success, stdout, stderr = cls.execute_command(cmd, timeout=15)
                
                if success:
                    result['rule_names'].append(rule_name)
                    logger.info(f"Firewall rule created/updated: {rule_name}")
                else:
                    result['errors'].append(f"Failed to create rule for {dir_type}: {stderr}")
                    logger.error(f"Failed to create firewall rule {rule_name}: {stderr}")
            
            result['success'] = len(result['rule_names']) > 0
            
        except Exception as e:
            result['errors'].append(str(e))
            logger.error(f"Exception in block_ip: {e}")
        
        return result
    
    @classmethod
    def unblock_ip(cls, ip: str) -> Dict:
        """
        Unblock an IP address (remove firewall rules).
        
        Args:
            ip: IP address to unblock
        
        Returns:
            Dict with: success (bool), removed_rules (list), errors (list)
        """
        
        result = {
            'success': False,
            'removed_rules': [],
            'errors': [],
            'timestamp': datetime.now().isoformat()
        }
        
        if not cls.is_valid_ip(ip):
            result['errors'].append(f"Invalid IP address: {ip}")
            return result
        
        try:
            # PowerShell command to remove rules
            cmd = f'''powershell -Command "
                $rules = Get-NetFirewallRule -DisplayName '{cls.RULE_PREFIX}_Block_*_{ip.replace('.', '_')}' -ErrorAction SilentlyContinue
                if($rules) {{
                    $rules | Remove-NetFirewallRule -ErrorAction Stop
                    Write-Host 'RULES_REMOVED:' ($rules | Measure-Object).Count
                }} else {{
                    Write-Host 'NO_RULES_FOUND'
                }}
            "'''
            
            success, stdout, stderr = cls.execute_command(cmd, timeout=15)
            
            if success:
                if "NO_RULES_FOUND" not in stdout:
                    result['success'] = True
                    result['removed_rules'].append(ip)
                    logger.info(f"Firewall rules removed for IP: {ip}")
                else:
                    logger.info(f"No rules found for IP: {ip}")
            else:
                result['errors'].append(stderr)
                logger.error(f"Failed to remove rules for {ip}: {stderr}")
            
        except Exception as e:
            result['errors'].append(str(e))
            logger.error(f"Exception in unblock_ip: {e}")
        
        return result
    
    @classmethod
    def block_port(cls, port: int, protocol: str = "TCP", direction: str = "in") -> Dict:
        """
        Block a specific port in Windows Firewall.
        
        Args:
            port: Port number (1-65535)
            protocol: "TCP", "UDP", or "Both"
            direction: "in" (inbound) or "out" (outbound)
        
        Returns:
            Dict with: success (bool), rule_name (str), errors (list)
        """
        
        result = {
            'success': False,
            'rule_name': None,
            'errors': [],
            'timestamp': datetime.now().isoformat()
        }
        
        if not cls.is_valid_port(port):
            result['errors'].append(f"Invalid port: {port}")
            return result
        
        try:
            rule_name = f"{cls.RULE_PREFIX}_Block_Port_{port}"
            
            cmd = f'''powershell -Command "
                if(-not(Get-NetFirewallRule -DisplayName '{rule_name}' -ErrorAction SilentlyContinue)) {{
                    New-NetFirewallRule -DisplayName '{rule_name}' `
                        -Direction {('Inbound' if direction == 'in' else 'Outbound')} `
                        -Action Block `
                        -Protocol {protocol} `
                        -LocalPort {port} `
                        -Profile Any `
                        -Enabled True `
                        -Description 'Auto-blocked suspicious port by Hybrid SIEM' `
                        -ErrorAction Stop | Out-Null
                    Write-Host 'PORT_BLOCKED'
                }} else {{
                    Write-Host 'RULE_EXISTS'
                }}
            "'''
            
            success, stdout, stderr = cls.execute_command(cmd, timeout=15)
            
            if success:
                result['success'] = True
                result['rule_name'] = rule_name
                logger.info(f"Port blocked: {port}/{protocol}")
            else:
                result['errors'].append(stderr)
                logger.error(f"Failed to block port {port}: {stderr}")
            
        except Exception as e:
            result['errors'].append(str(e))
            logger.error(f"Exception in block_port: {e}")
        
        return result
    
    @classmethod
    def get_active_rules(cls) -> Dict:
        """
        Get all active Hybrid SIEM firewall rules.
        
        Returns:
            Dict with: rules (list), count (int), errors (list)
        """
        
        result = {
            'rules': [],
            'count': 0,
            'errors': [],
            'timestamp': datetime.now().isoformat()
        }
        
        try:
            cmd = f'''powershell -Command "
                Get-NetFirewallRule -DisplayName '{cls.RULE_PREFIX}_*' -ErrorAction SilentlyContinue | `
                    Select-Object DisplayName, Direction, Action, Enabled | `
                    ConvertTo-Json
            "'''
            
            success, stdout, stderr = cls.execute_command(cmd, timeout=15)
            
            if success and stdout.strip():
                try:
                    import json
                    rules_data = json.loads(stdout)
                    if isinstance(rules_data, list):
                        result['rules'] = rules_data
                    elif isinstance(rules_data, dict):
                        result['rules'] = [rules_data]
                    result['count'] = len(result['rules'])
                except:
                    result['errors'].append("Failed to parse rules JSON")
                    logger.warning("Could not parse firewall rules JSON")
            else:
                if stderr:
                    result['errors'].append(stderr)
                logger.info(f"No active {cls.RULE_PREFIX} rules found")
            
        except Exception as e:
            result['errors'].append(str(e))
            logger.error(f"Exception in get_active_rules: {e}")
        
        return result
    
    @classmethod
    def clear_all_rules(cls) -> Dict:
        """
        Remove all Hybrid SIEM firewall rules.
        
        CAUTION: This is irreversible!
        
        Returns:
            Dict with: success (bool), removed_count (int), errors (list)
        """
        
        result = {
            'success': False,
            'removed_count': 0,
            'errors': [],
            'timestamp': datetime.now().isoformat()
        }
        
        try:
            cmd = f'''powershell -Command "
                $rules = Get-NetFirewallRule -DisplayName '{cls.RULE_PREFIX}_*' -ErrorAction SilentlyContinue
                if($rules) {{
                    $count = ($rules | Measure-Object).Count
                    $rules | Remove-NetFirewallRule -ErrorAction Stop
                    Write-Host 'REMOVED:' $count
                }} else {{
                    Write-Host 'REMOVED: 0'
                }}
            "'''
            
            success, stdout, stderr = cls.execute_command(cmd, timeout=30)
            
            if success:
                # Extract count from output
                match = re.search(r'REMOVED:\s*(\d+)', stdout)
                if match:
                    count = int(match.group(1))
                    result['success'] = True
                    result['removed_count'] = count
                    logger.info(f"Cleared {count} firewall rules")
            else:
                result['errors'].append(stderr)
                logger.error(f"Failed to clear rules: {stderr}")
            
        except Exception as e:
            result['errors'].append(str(e))
            logger.error(f"Exception in clear_all_rules: {e}")
        
        return result


# Simpler functions for direct use
def block_ip(ip: str, severity: str = "High") -> bool:
    """Quick function to block an IP. Returns True if successful."""
    result = FirewallManager.block_ip(ip, direction="both", severity=severity)
    return result['success']


def unblock_ip(ip: str) -> bool:
    """Quick function to unblock an IP. Returns True if successful."""
    result = FirewallManager.unblock_ip(ip)
    return result['success']


def get_blocked_ips() -> List[str]:
    """Get list of all blocked IPs from active rules."""
    rules = FirewallManager.get_active_rules()
    blocked_ips = []
    
    for rule in rules.get('rules', []):
        # Extract IP from rule name (format: HybridSIEM_Block_in/out_IP)
        match = re.search(r'(\d+_\d+_\d+_\d+)', rule.get('DisplayName', ''))
        if match:
            ip = match.group(1).replace('_', '.')
            blocked_ips.append(ip)
    
    return list(set(blocked_ips))  # Remove duplicates


if __name__ == "__main__":
    # Test examples (run as Administrator)
    print("╔════════════════════════════════════════════════════════════╗")
    print("║         Firewall Service Test                            ║")
    print("╚════════════════════════════════════════════════════════════╝\n")
    
    # Test 1: Block an IP
    print("[1] Testing IP blocking...")
    result = FirewallManager.block_ip("192.168.1.100", direction="both")
    print(f"Result: {result}\n")
    
    # Test 2: Get active rules
    print("[2] Getting active rules...")
    rules = FirewallManager.get_active_rules()
    print(f"Active rules: {rules['count']}\n")
    
    # Test 3: Unblock IP
    print("[3] Testing IP unblocking...")
    result = FirewallManager.unblock_ip("192.168.1.100")
    print(f"Result: {result}\n")
    
    print("✓ Tests complete (run as Administrator)")
