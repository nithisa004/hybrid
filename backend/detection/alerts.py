from django.core.mail import send_mail
from django.conf import settings
import logging

logger = logging.getLogger(__name__)

def send_threat_alert(log):
    """
    Sends an email alert for a detected threat.
    """
    try:
        subject = f"🚨 HYBRID SIEM ALERT: [{log.severity}] {log.name}"
        
        message = (
            f"A security threat has been detected and logged by the Hybrid SIEM Rule Engine.\n\n"
            f"--- THREAT DETAILS ---\n"
            f"Rule Triggered: {log.name}\n"
            f"Severity Level: {log.severity}\n"
            f"Threat Type:    {log.threat_type}\n"
            f"Event ID:       {log.event_id}\n"
            f"Source Service: {log.source}\n"
            f"Hostname:       {log.host}\n"
            f"Status:         {log.status}\n\n"
            f"--- ANALYSIS ---\n"
            f"{log.description}\n\n"
            f"--- ACTION REQUIRED ---\n"
            f"Log into the SIEM Dashboard to investigate and take action.\n\n"
            f"This is an automated alert from your Hybrid SIEM System."
        )

        recipient_list = [settings.RECIPIENT_EMAIL]
        
        send_mail(
            subject,
            message,
            settings.EMAIL_HOST_USER,
            recipient_list,
            fail_silently=False,
        )
        logger.info(f"Alert email sent to {settings.RECIPIENT_EMAIL} for threat ID {log.id}")
        return True
    except Exception as e:
        logger.error(f"Failed to send email alert: {str(e)}")
        return False
