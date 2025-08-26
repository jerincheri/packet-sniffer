import yaml
from datetime import datetime

def load_config():
    try:
        with open('config.yaml', 'r') as f:
            return yaml.safe_load(f)
    except:
        return {'email': {'to_addr': 'test@example.com'}}

def send_email_alert(alert_type, severity, src_ip, description):
    config = load_config()
    
    print(f"📧 [SIMULATED] Email would be sent to: {config['email']['to_addr']}")
    print(f"   Subject: 🚨 Network Alert: {alert_type} detected")
    print(f"   Body: {description}")
    print(f"   From: {src_ip} | Severity: {severity}")
    print("---")
    
    # For now, we'll just simulate email sending
    # Uncomment the real code later when email is configured
    """
    try:
        import smtplib
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart
        
        email_config = config['email']
        msg = MIMEMultipart()
        msg['From'] = email_config['from_addr']
        msg['To'] = email_config['to_addr']
        msg['Subject'] = f"🚨 Network Alert: {alert_type} detected"
        
        body = f"Network Security Alert!\n\nType: {alert_type}\nSeverity: {severity}\nSource IP: {src_ip}\nTime: {datetime.now()}\nDescription: {description}"
        msg.attach(MIMEText(body, 'plain'))
        
        server = smtplib.SMTP(email_config['smtp_server'], email_config['smtp_port'])
        server.starttls()
        server.login(email_config['username'], email_config['password'])
        server.send_message(msg)
        server.quit()
        print(f"📧 Email alert sent for {alert_type}")
    except Exception as e:
        print(f"❌ Failed to send email: {e}")
    """
