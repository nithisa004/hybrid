import smtplib
from email.mime.text import MIMEText

print("Starting Simple SMTP Test...")
try:
    msg = MIMEText("This is a direct test of the Gmail SMTP connection.")
    msg['Subject'] = "Hybrid SIEM - SMTP Direct Test"
    msg['From'] = "nithisadevi@gmail.com"
    msg['To'] = "nithisadevij@gmail.com"

    print("Connecting to smtp.gmail.com:587...")
    server = smtplib.SMTP("smtp.gmail.com", 587, timeout=15)
    print("Sending EHLO...")
    server.ehlo()
    print("Starting TLS...")
    server.starttls()
    print("Logging in...")
    server.login("nithisadevi@gmail.com", "hvzznlgxbjdvyscj")
    print("Sending mail...")
    server.sendmail("nithisadevi@gmail.com", ["nithisadevij@gmail.com"], msg.as_string())
    server.quit()
    print("✨ SMTP Test Successful!")
except Exception as e:
    print(f"❌ SMTP Test Failed: {str(e)}")
