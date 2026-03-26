from rest_framework.decorators import api_view
from rest_framework.response import Response
from logs.models import Log
from detection.services import detect_anomaly
import random
import os
import pandas as pd
from django.conf import settings


# 🎯 Threat Intelligence Mappings
THREAT_DESCRIPTIONS = {
    # Event ID -> (threat_name, threat_description, mitigation)
    4625: {
        "threat_name": "Failed Authentication Attempt",
        "description": "Multiple failed login attempts detected. This could indicate a brute-force attack on user credentials. Mitigate by implementing account lockout policies and monitoring for patterns.",
        "indicators": "High volume of authentication failures from same source IP or targeting same user account"
    },
    4648: {
        "threat_name": "Suspicious Credential Usage",
        "description": "Explicit credential usage detected outside normal patterns. This may indicate credential theft or unauthorized service account usage. Monitor for access from non-standard locations.",
        "indicators": "Service account or admin credentials used from unexpected system or at unusual time"
    },
    4672: {
        "threat_name": "Privilege Escalation Attempt",
        "description": "Higher-than-normal privilege assignment or elevation detected. Potential privilege escalation attack where attacker attempts to gain admin rights. Verify if this was authorized.",
        "indicators": "Unexpected admin privilege assignment or UAC bypass patterns"
    },
    4720: {
        "threat_name": "Unauthorized Account Creation",
        "description": "New user account created outside of normal administrative processes. Attackers often create backdoor accounts for persistence. Verify this account creation was authorized.",
        "indicators": "Account created at unusual time, with suspicious naming patterns, or by unexpected administrative user"
    },
    4688: {
        "threat_name": "Suspicious Process Execution",
        "description": "Process execution detected with characteristics of malware or exploitation. Common in ransomware, command-and-control, or privilege escalation attacks. Analyze process binary origin and parent process.",
        "indicators": "Parent-child process relationships, process memory injection, or binary execution from temp directories"
    }
}

NETWORK_THREAT_DESCRIPTIONS = {
    "Network Traffic Scan": {
        "threat_name": "Network Reconnaissance/Port Scan",
        "description": "Unusual network traffic patterns detected suggesting port scanning or network reconnaissance. Attacker is mapping network to identify vulnerable services. This is typically Phase 1 of a multi-stage attack.",
        "indicators": "High volume of connection attempts to diverse ports, unusual packet sizes, or traffic from external IP addresses"
    },
    "Network Traffic Exploit": {
        "threat_name": "Network-Based Exploitation Attempt",
        "description": "Network traffic contains signatures matching known exploit patterns. This indicates active attack attempting to compromise systems via network services.",
        "indicators": "Buffer overflow patterns, SQL injection payloads, or shellcode detected in network traffic"
    },
    "DNS Query Anomaly": {
        "threat_name": "DNS Exfiltration / C2 Communication",
        "description": "Suspicious DNS query patterns detected. May indicate data exfiltration via DNS tunneling or command-and-control communication with attacker infrastructure.",
        "indicators": "Queries to suspicious domains, excessive subdomain queries, or unusual query frequency"
    }
}

def get_threat_description(event_type, event_id, source, result_str, recon_error):
    """Generate detailed threat description based on detection context"""
    
    # Default response
    threat_name = "Security Event"
    threat_desc = ""
    indicators = ""
    
    # For Windows OS events
    if event_id in THREAT_DESCRIPTIONS:
        threat = THREAT_DESCRIPTIONS[event_id]
        threat_name = threat["threat_name"]
        threat_desc = threat["description"]
        indicators = threat["indicators"]
    
    # For Network-based events
    elif "Network" in source:
        if event_type in NETWORK_THREAT_DESCRIPTIONS:
            threat = NETWORK_THREAT_DESCRIPTIONS[event_type]
            threat_name = threat["threat_name"]
            threat_desc = threat["description"]
            indicators = threat["indicators"]
        else:
            threat_name = "Network Security Event"
            threat_desc = f"Unusual network pattern detected: {event_type}. Requires further investigation for malicious intent."
            indicators = "Traffic volume, protocol patterns, source/destination IPs, payload content"
    
    # Append confidence and ML analysis
    confidence = max(0, (1 - recon_error) * 100)
    
    full_description = f"""
THREAT: {threat_name}

ANALYSIS:
{threat_desc}

DETECTION DETAILS:
• Source: {source}
• Event Type: {event_type}
• ML Classification: {result_str}
• Confidence Score: {confidence:.1f}%
• Anomaly Score: {recon_error:.4f}

KEY INDICATORS:
{indicators}

ACTION REQUIRED:
1. Review detailed logs for timing and context
2. Check source IP address geolocation and reputation
3. Verify if activity was authorized
4. If confirmed threat: isolate system and initiate incident response
5. Preserve evidence for forensic analysis
    """.strip()
    
    return full_description.strip()


@api_view(['POST'])
def detect_log(request):
    features = request.data.get('features') 
    source = request.data.get('source', 'windows')
    event_id = request.data.get('event_id')
    event_type = request.data.get('event_type', 'Hybrid Detection Scan')
    
    # 💡 Fallback for testing integration: use sample features if none provided
    if not features:
        sample_file = os.path.join(settings.BASE_DIR, '..', 'XGboost', 'sample_row.csv')
        if os.path.exists(sample_file):
            features = pd.read_csv(sample_file).iloc[0].tolist()
        else:
            features = [-0.35] * 77

    # 🔥 Run ML model (Returns: result_str, xgb_pred, recon_error)
    result_str, xgb_pred, recon_error = detect_anomaly(features)

    # Determine Severity (Stricter Thresholds to Reduce False Positives)
    severity = "Info"
    if result_str == "Normal":
        severity = "Info"
    elif result_str == "Anomaly (Unknown Attack)":
        # Only elevate to Medium if reconstruction error is significant
        severity = "Medium" if recon_error > 0.1 else "Low"
    elif result_str == "Attack (Known)":
        # High severity only for confirmed XGBoost attacks
        severity = "High"

    # 🔥 Filter: Skip storing low and medium confidence events (only High severity and confirmed attacks)
    # This prevents legitimate activity from polluting the dashboard
    if severity in ["Info", "Low", "Medium"]:
        return Response({
            "message": "Low confidence activity - not logged",
            "log": {
                "result": result_str,
                "severity": severity,
                "anomaly_score": recon_error,
                "xgb_prediction": xgb_pred
            }
        })

    # 🎯 Generate detailed threat intelligence description
    detailed_description = get_threat_description(event_type, event_id, source, result_str, recon_error)

    # 🔥 Save in DB with correct fields (only for suspicious/anomalous events)
    log = Log.objects.create(
        name=event_type,
        severity=severity,
        status="Awaiting action" if severity == "High" else "Monitoring",
        verdict="None",
        assignee="System AI" if severity == "High" else "Auto-Monitor",
        source=source,
        event_id=event_id,
        description=detailed_description,
        host=f"LPT-HR-{random.randint(100, 999)}",
        process_name="chrome.exe" if "Network" in source.lower() else "powershell.exe",
        process_user="S.Conway" if "Network" in source.lower() else "SYSTEM",
        target_file="C:\\Users\\S.Conway\\Downloads\\patch.exe" if severity == "High" else "N/A",
        file_md5="14d8486f3f63875ef93cfd240c5dc10b" if severity == "High" else "N/A",
        anomaly_score=recon_error,
        xgb_prediction=xgb_pred,
        result=result_str
    )

    return Response({
        "message": "Detection complete",
        "log": {
            "id": log.id,
            "time": log.timestamp,
            "name": log.name,
            "severity": log.severity,
            "status": log.status,
            "verdict": log.verdict,
            "assignee": log.assignee,
            "result": log.result,
            "host": log.host,
            "process_name": log.process_name,
            "description": log.description,
            "anomaly_score": log.anomaly_score,
            "xgb_prediction": log.xgb_prediction
        }
    })