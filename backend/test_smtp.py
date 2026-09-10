import smtplib
from email.mime.text import MIMEText

# Credentials from your .env
HOST = "smtp.office365.com"
PORT = 587
USER = "notifications@jafaricredit.co.ke"
PASSWORD = "Centum456!"
TO = "p.mwaura@jafaricredit.co.ke"  # Send to yourself for testing

print(f"Connecting to {HOST}:{PORT}...")

try:
    with smtplib.SMTP(HOST, PORT, timeout=30) as server:
        print("Connected. Starting TLS...")
        server.starttls()
        print("TLS started. Logging in...")
        server.login(USER, PASSWORD)
        print("✅ Login successful!")
        
        msg = MIMEText("This is a test email from the SMTP test script.")
        msg['Subject'] = "SMTP Test - Jafari Report"
        msg['From'] = USER
        msg['To'] = TO
        
        server.send_message(msg)
        print(f"✅ Test email sent to {TO}")
        print("Check your inbox!")
        
except smtplib.SMTPAuthenticationError as e:
    print(f"\n❌ AUTHENTICATION FAILED")
    print(f"   Error code: {e.smtp_code}")
    print(f"   Error message: {e.smtp_error.decode() if isinstance(e.smtp_error, bytes) else e.smtp_error}")
    print(f"\n💡 Interpretation:")
    print(f"   - 535 5.7.8        → Wrong username or password")
    print(f"   - 535 5.7.139      → Basic Auth disabled by Microsoft (need OAuth or SMTP AUTH enabled)")
    print(f"   - 530 5.7.57       → Client not authenticated")
    
except smtplib.SMTPException as e:
    print(f"\n❌ SMTP ERROR: {e}")
    
except Exception as e:
    print(f"\n❌ UNEXPECTED ERROR: {type(e).__name__}: {e}")