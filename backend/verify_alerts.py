import os
import django
import sys

# Setup Django environment
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'backend.settings')
django.setup()

from logs.models import Log
from detection.alerts import send_threat_alert

def main():
    print("🚀 Starting Alert System Verification Test...")
    
    # Create a dummy log entry for testing
    test_log = Log.objects.create(
        name="[TEST] Simulated Brute Force",
        severity="High",
        status="Testing Alert System",
        verdict="None",
        assignee="Test Engine",
        source="SystemTest",
        event_id=4625,
        description="This is a test alert to verify that the Gmail SMTP configuration is working correctly.",
        threat_type="Credential Attack",
        host="VERIFY-PC"
    )
    
    print(f"✅ Created test log with ID: {test_log.id}")
    print(f"📧 Attempting to send email to {test_log.name}...")
    
    success = send_threat_alert(test_log)
    
    if success:
        print("\n✨ SUCCESS! The alert email was sent successfully.")
        print("Please check nithisadevij@gmail.com for the alert.")
    else:
        print("\n❌ FAILED! The alert email could not be sent.")
        print("Check the console output for error messages.")

if __name__ == "__main__":
    main()
