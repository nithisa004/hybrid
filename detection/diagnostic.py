#!/usr/bin/env python
"""
🔍 KALI ATTACK DETECTION DIAGNOSTIC TOOL
Tests all components of the real-time detection system
"""

import sys
import os
import subprocess

print("=" * 60)
print("  HYBRID SIEM — DIAGNOSTIC CHECKER")
print("=" * 60)

# Test 1: Check Scapy installation
print("\n1️⃣  CHECKING SCAPY INSTALLATION...")
try:
    from scapy.all import sniff, IP, TCP, UDP
    print("   ✅ Scapy is installed and working")
except ImportError:
    print("   ❌ Scapy NOT installed!")
    print("   Fix: pip install scapy")
    sys.exit(1)

# Test 2: Check pywin32
print("\n2️⃣  CHECKING PYWIN32 INSTALLATION...")
try:
    import win32evtlog
    print("   ✅ pywin32 is installed and working")
except ImportError:
    print("   ❌ pywin32 NOT installed!")
    print("   Fix: pip install pywin32")
    sys.exit(1)

# Test 3: Check requests
print("\n3️⃣  CHECKING REQUESTS LIBRARY...")
try:
    import requests
    print("   ✅ requests is installed and working")
except ImportError:
    print("   ❌ requests NOT installed!")
    print("   Fix: pip install requests")
    sys.exit(1)

# Test 4: Check backend connectivity
print("\n4️⃣  CHECKING BACKEND CONNECTIVITY...")
try:
    r = requests.get("http://localhost:8000/logs/", timeout=2)
    if r.status_code == 200:
        print("   ✅ Backend is running and responding")
    else:
        print(f"   ⚠️  Backend returned status {r.status_code}")
except requests.exceptions.ConnectionError:
    print("   ❌ Cannot reach backend at http://localhost:8000")
    print("   Fix: Start backend with: cd d:\\hybrid\\backend && python manage.py runserver")
    sys.exit(1)
except Exception as e:
    print(f"   ⚠️  Backend error: {e}")

# Test 5: List network adapters
print("\n5️⃣  CHECKING NETWORK ADAPTERS...")
try:
    result = subprocess.run(
        ["powershell", "-Command", "Get-NetAdapter | Select-Object Name, Status"],
        capture_output=True,
        text=True
    )
    adapters = result.stdout
    print("   Available adapters:")
    print(adapters)
    
    if "Ethernet 6" in adapters and "Up" in adapters:
        print("   ✅ Ethernet 6 is available and UP")
    else:
        print("   ⚠️  Ethernet 6 may not be up. Check your VirtualBox network settings")
except Exception as e:
    print(f"   ⚠️  Could not list adapters: {e}")

# Test 6: Simulate packet capture
print("\n6️⃣  TESTING PACKET CAPTURE (5 seconds)...")
print("   📡 Listening for packets on Ethernet 6...")
print("   💡 Tip: Run 'ping 192.168.56.1' from Kali in another terminal")

try:
    packet_count = [0]
    
    def count_packets(pkt):
        packet_count[0] += 1
        if IP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst
            print(f"      📦 Captured packet {packet_count[0]}: {src} → {dst}")
    
    # Sniff for 5 seconds
    sniff(iface="Ethernet 6", prn=count_packets, timeout=5, store=0)
    
    if packet_count[0] > 0:
        print(f"   ✅ Captured {packet_count[0]} packets successfully!")
    else:
        print("   ⚠️  No packets captured in 5 seconds")
        print("   Possible causes:")
        print("      - Adapter 'Ethernet 6' name is wrong")
        print("      - No traffic on the adapter")
        print("      - Firewall blocking")
except Exception as e:
    print(f"   ❌ Packet capture failed: {e}")
    print("   Make sure you're running this in an ADMIN terminal")
    sys.exit(1)

# Test 7: Test API data sending
print("\n7️⃣  TESTING API DATA SENDING...")
try:
    test_payload = {
        "source": "Diagnostic Test",
        "event_id": 9999,
        "event_type": "Diagnostic Packet",
        "description": "Testing packet capture and API integration",
        "threat_type": "Test",
        "features": [-0.35] * 77,
        "FromSensor": True
    }
    
    r = requests.post("http://localhost:8000/detect/", json=test_payload, timeout=2)
    print(f"   API Response: {r.status_code}")
    
    if r.status_code == 200:
        print("   ✅ API data sending works!")
    else:
        print(f"   ⚠️  API returned {r.status_code}: {r.text[:100]}")
except Exception as e:
    print(f"   ❌ API error: {e}")

print("\n" + "=" * 60)
print("✅ DIAGNOSTIC COMPLETE!")
print("=" * 60)
print("\nNext steps:")
print("1. Ensure Backend is running: python manage.py runserver")
print("2. Run realtime_detection.py in ADMIN terminal")
print("3. From Kali, run: nmap -sS 192.168.56.1")
print("4. Check Dashboard: http://localhost:4200")
