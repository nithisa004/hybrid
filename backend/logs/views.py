from rest_framework.decorators import api_view
from rest_framework.response import Response
from logs.models import Log
from django.utils.dateparse import parse_datetime
from django.http import FileResponse
import io
from datetime import datetime, timedelta
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
import re
import os
import subprocess
from detection.alerts import send_threat_alert

@api_view(['POST'])
def block_threat(request, log_id):
    admin_password = request.data.get('admin_password')
    
    if admin_password != 'admin123':
        return Response({"error": "Unauthorized: Invalid admin password"}, status=403)

    try:
        log = Log.objects.get(id=log_id)
        
        # --- NEW: Improved Firewall Blocking Logic ---
        ip_extracted = False
        target_ip = None
        
        # Regex to find all IP addresses in description and source
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        all_ips = re.findall(ip_pattern, f"{log.description} {log.source}")
        
        # Prioritize the first non-local IP address
        for ip in all_ips:
            if ip not in ['127.0.0.1', '0.0.0.0'] and not ip.startswith('169.254'):
                target_ip = ip
                break
        
        if target_ip:
            # Execute netsh command with PowerShell UAC elevation (RunAs)
            # Using single quotes for the main command to avoid escaping issues
            rule_name = f"HybridSIEM_Block_{log.id}"
            ps_cmd = f"Start-Process netsh -ArgumentList 'advfirewall firewall add rule name=\"{rule_name}\" dir=in action=block remoteip={target_ip}' -Verb RunAs"
            full_cmd = f"powershell -Command {ps_cmd}"
            
            # Use subprocess to run and capture basic info if needed
            os.system(full_cmd) 
            ip_extracted = True
            print(f"DEBUG: Triggered UAC elevation for IP: {target_ip}")
        # ----------------------------------------------

        log.status = "Blocked"
        log.verdict = "True Positive"
        log.assignee = "System Admin"
        log.save()
        
        message = "Threat Block"
        if ip_extracted:
            message += f" (IP {target_ip} sent to Firewall via UAC prompt)"
        else:
            message += " (No valid IP found to block)"
            
        return Response({
            "message": message, 
            "status": "Blocked", 
            "verdict": "True Positive", 
            "assignee": "System Admin",
            "debug_ip": target_ip
        })
    except Log.DoesNotExist:
        return Response({"error": "Log not found"}, status=404)

@api_view(['POST'])
def deny_threat(request, log_id):
    admin_password = request.data.get('admin_password')
    print(f"DEBUG: deny_threat called for ID {log_id}. Received password: '{admin_password}'")
    
    if admin_password != 'admin123':
        return Response({"error": "Unauthorized: Invalid admin password"}, status=403)

    try:
        log = Log.objects.get(id=log_id)
        log.status = "Denied"
        log.verdict = "False Positive"
        log.assignee = "System Admin"
        log.save()
        return Response({"message": "Threat deny", "status": "Denied", "verdict": "False Positive", "assignee": "System Admin"})
    except Log.DoesNotExist:
        return Response({"error": "Log not found"}, status=404)

@api_view(['GET'])
def get_logs(request):
    # ?since=<ISO timestamp> — only return logs from the current session onwards
    since_param = request.query_params.get('since', None)

    logs = Log.objects.all().order_by('-timestamp')

    if since_param:
        since_dt = parse_datetime(since_param)
        if since_dt:
            logs = logs.filter(timestamp__gte=since_dt)

    data = [
        {
            "id": log.id,
            "time": log.timestamp,
            "name": log.name,
            "severity": log.severity,
            "status": log.status,
            "verdict": log.verdict,
            "assignee": log.assignee,
            "description": log.description,
            "threat_type": log.threat_type,
            "host": log.host,
            "process_name": log.process_name,
            "process_user": log.process_user,
            "target_file": log.target_file,
            "file_md5": log.file_md5,
            "anomaly_score": log.anomaly_score,
            "xgb_prediction": log.xgb_prediction,
            "result": log.result,
            "open": False
        }
        for log in logs
    ]

    return Response(data)

@api_view(['POST'])
def simulate_threat(request):
    """Injects a simulated threat directly into the database."""
    try:
        log = Log.objects.create(
            name=request.data.get('name', 'Simulated Threat'),
            severity=request.data.get('severity', 'Low'),
            status=request.data.get('status', 'Awaiting action'),
            verdict=request.data.get('verdict', 'None'),
            assignee=request.data.get('assignee', 'Attack Simulator'),
            source=request.data.get('source', 'Manual'),
            event_id=request.data.get('event_id', 0),
            description=request.data.get('description', ''),
            threat_type=request.data.get('threat_type', 'Unknown'),
            host=request.data.get('host', 'LOCALHOST'),
            process_name=request.data.get('process_name', 'N/A'),
            process_user=request.data.get('process_user', 'N/A'),
            target_file=request.data.get('target_file', 'N/A'),
            file_md5=request.data.get('file_md5', 'N/A'),
            anomaly_score=request.data.get('anomaly_score', 0.0),
            xgb_prediction=request.data.get('xgb_prediction', 0),
            result=request.data.get('threat_type', 'Attack')
        )
        
        # Trigger an alert if the simulated threat is high/critical severity
        if log.severity in ["High", "Critical"]:
            send_threat_alert(log)
            print(f"DEBUG: Alert sent for simulation: {log.name}")
            
        return Response({"message": "Simulation successful", "id": log.id})
    except Exception as e:
        return Response({"error": str(e)}, status=400)

@api_view(['GET'])
def export_weekly_pdf(request):
    """Generates a professional PDF security report for the last 7 days."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    elements = []
    styles = getSampleStyleSheet()

    # Title & Header
    elements.append(Paragraph("🛡️ SECURITY NEXUS - WEEKLY THREAT REPORT", styles['Title']))
    elements.append(Spacer(1, 12))

    # Timeframe
    now = datetime.now()
    last_week = now - timedelta(days=7)
    elements.append(Paragraph(f"Reporting Period: <b>{last_week.strftime('%Y-%m-%d')}</b> to <b>{now.strftime('%Y-%m-%d')}</b>", styles['Normal']))
    elements.append(Spacer(1, 24))

    # Query Logs (Only non-routine threats)
    threat_logs = Log.objects.filter(timestamp__gte=last_week).exclude(severity='Info').order_by('-timestamp')
    total_threats = threat_logs.count()
    
    # ── 1. Summary Section ──
    elements.append(Paragraph("1. Executive Summary", styles['Heading2']))
    
    high_count     = threat_logs.filter(severity='High').count()
    critical_count = threat_logs.filter(severity='Critical').count()
    medium_count   = threat_logs.filter(severity='Medium').count()
    low_count      = threat_logs.filter(severity='Low').count()

    summary_data = [
        ["Threat Metric", "Count"],
        ["Total Threats Captured", total_threats],
        ["Critical Severity", critical_count],
        ["High Severity", high_count],
        ["Medium/Low Severity", medium_count + low_count],
    ]
    
    summary_table = Table(summary_data, colWidths=[250, 100])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
    ]))
    elements.append(summary_table)
    elements.append(Spacer(1, 30))

    # ── 2. Detailed Threat Activity ──
    elements.append(Paragraph("2. Top Security Threats Detected", styles['Heading2']))
    
    data = [["Time", "Threat Name", "Severity", "Hostname"]]
    
    # Analyze the most recent 50 threats
    for log in threat_logs[:50]:
        clean_name = log.name.replace('[High] ', '').replace('[Critical] ', '').replace('[Medium] ', '')
        data.append([
            log.timestamp.strftime('%m/%d %H:%M'),
            (clean_name[:40] + '..') if len(clean_name) > 40 else clean_name,
            log.severity,
            log.host
        ])

    if len(data) > 1:
        details_table = Table(data, colWidths=[100, 220, 80, 80])
        details_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#1A2B44")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (1, 0), (1, -1), 'LEFT'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ]))
        elements.append(details_table)
    else:
        elements.append(Paragraph("<i>No significant threats detected in the last reporting period.</i>", styles['Normal']))

    # Footer
    elements.append(Spacer(1, 40))
    elements.append(Paragraph("--- End of Report ---", styles['Normal']))
    elements.append(Paragraph(f"Generated at: {now.strftime('%Y-%m-%d %H:%M')} by Hybrid SIEM Engine.", styles['Italic']))

    doc.build(elements)
    buffer.seek(0)
    return FileResponse(buffer, as_attachment=True, filename=f"Hybrid_SIEM_Weekly_Report_{now.strftime('%Y%m%d')}.pdf")