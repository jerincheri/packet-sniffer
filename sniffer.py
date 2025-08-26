import sqlite3
from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime

# Create SQLite database and table
conn = sqlite3.connect('network_traffic.db')
c = conn.cursor()

c.execute('''CREATE TABLE IF NOT EXISTS packets
             (id INTEGER PRIMARY KEY AUTOINCREMENT,
              timestamp TEXT, 
              src_ip TEXT, 
              dst_ip TEXT,
              sport INTEGER, 
              dport INTEGER, 
              protocol TEXT,
              length INTEGER, 
              flags TEXT)''')
conn.commit()

def packet_callback(pkt):
    if IP in pkt:
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        protocol = pkt[IP].proto
        length = len(pkt)
        timestamp = datetime.now().isoformat()

        sport = None
        dport = None
        flags = None

        if TCP in pkt:
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
            flags = str(pkt[TCP].flags)
        elif UDP in pkt:
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport
        elif ICMP in pkt:
            pass

        # Insert into database
        c.execute('''INSERT INTO packets 
                     (timestamp, src_ip, dst_ip, sport, dport, protocol, length, flags) 
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                  (timestamp, src_ip, dst_ip, sport, dport, protocol, length, flags))
        conn.commit()

        print(f"[+] Captured: {src_ip} -> {dst_ip} : {dport}")

# Start sniffing
print("[*] Starting packet sniffer...")
print("[*] Press Ctrl+C to stop")
try:
    sniff(prn=packet_callback, store=0)
except KeyboardInterrupt:
    print("\n[*] Stopping sniffer...")
    conn.close()
