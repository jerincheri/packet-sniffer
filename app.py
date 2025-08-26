from flask import Flask, render_template, jsonify
import sqlite3
from datetime import datetime, timedelta
import json

app = Flask(__name__)

def get_db_connection():
    conn = sqlite3.connect('network_traffic.db')
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/')
def dashboard():
    return render_template('dashboard.html')

@app.route('/api/stats')
def get_stats():
    conn = get_db_connection()
    
    # Get packet count in last 1 hour
    one_hour_ago = (datetime.now() - timedelta(hours=1)).isoformat()
    packet_count = conn.execute(
        "SELECT COUNT(*) FROM packets WHERE timestamp > ?", 
        (one_hour_ago,)
    ).fetchone()[0]
    
    # Get alert count in last 24 hours
    one_day_ago = (datetime.now() - timedelta(hours=24)).isoformat()
    alert_count = conn.execute(
        "SELECT COUNT(*) FROM alerts WHERE timestamp > ?", 
        (one_day_ago,)
    ).fetchone()[0]
    
    # Get top source IPs
    top_ips = conn.execute(
        "SELECT src_ip, COUNT(*) as count FROM packets GROUP BY src_ip ORDER BY count DESC LIMIT 5"
    ).fetchall()
    
    # Get protocol distribution
    protocols = conn.execute(
        "SELECT protocol, COUNT(*) as count FROM packets GROUP BY protocol"
    ).fetchall()
    
    conn.close()
    
    return jsonify({
        'packet_count': packet_count,
        'alert_count': alert_count,
        'top_ips': [dict(ip) for ip in top_ips],
        'protocols': [dict(proto) for proto in protocols]
    })

@app.route('/api/recent-packets')
def recent_packets():
    conn = get_db_connection()
    packets = conn.execute(
        "SELECT * FROM packets ORDER BY timestamp DESC LIMIT 50"
    ).fetchall()
    conn.close()
    return jsonify([dict(packet) for packet in packets])

@app.route('/api/recent-alerts')
def recent_alerts():
    conn = get_db_connection()
    alerts = conn.execute(
        "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 10"
    ).fetchall()
    conn.close()
    return jsonify([dict(alert) for alert in alerts])

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
