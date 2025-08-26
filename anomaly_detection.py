from collections import defaultdict
import time
from datetime import datetime
import sqlite3

# Global variables for tracking
packet_count = defaultdict(int)
port_scan_cache = defaultdict(lambda: defaultdict(int))
start_time = time.time()

# Database connection
conn = sqlite3.connect('network_traffic.db')
c = conn.cursor()

# Create alerts table if it doesn't exist
c.execute('''CREATE TABLE IF NOT EXISTS alerts
             (id INTEGER PRIMARY KEY AUTOINCREMENT,
              timestamp TEXT,
              alert_type TEXT,
              severity TEXT,
              src_ip TEXT,
              description TEXT)''')
conn.commit()

def log_alert(description, alert_type, severity, src_ip):
    """Log alerts to database"""
    timestamp = datetime.now().isoformat()
    c.execute('''INSERT INTO alerts 
                 (timestamp, alert_type, severity, src_ip, description) 
                 VALUES (?, ?, ?, ?, ?)''',
              (timestamp, alert_type, severity, src_ip, description))
    conn.commit()
    print(f"🚨 ALERT: {description}")

def check_anomalies(pkt):
    """Check for various network anomalies"""
    global packet_count, port_scan_cache, start_time
    
    if not pkt.haslayer('IP'):
        return

    src_ip = pkt['IP'].src
    current_time = time.time()

    # Flooding detection (packet rate)
    packet_count[src_ip] += 1
    
    # Check every 10 seconds
    if current_time - start_time > 10:
        for ip, count in packet_count.items():
            if count > 1000:  # Threshold: 1000 packets/10sec
                alert_msg = f"Flooding detected from {ip} with {count} packets/10s"
                log_alert(alert_msg, "Flooding", "High", ip)
        
        # Reset counters
        packet_count.clear()
        start_time = current_time

    # Port scan detection (SYN packets to multiple ports)
    if pkt.haslayer('TCP') and pkt['TCP'].flags == 'S':  # SYN packet
        dport = pkt['TCP'].dport
        port_scan_cache[src_ip][dport] += 1
        
        # If more than 10 unique ports contacted
        if len(port_scan_cache[src_ip]) > 10:
            ports = list(port_scan_cache[src_ip].keys())
            alert_msg = f"Port scan detected from {src_ip} on ports: {ports}"
            log_alert(alert_msg, "Port Scan", "High", src_ip)
            port_scan_cache[src_ip].clear()
