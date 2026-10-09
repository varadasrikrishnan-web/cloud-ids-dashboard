from flask import Flask, jsonify
from flask_cors import CORS
import psutil
import uuid
import threading
import time
import requests
from datetime import datetime, timezone

app = Flask(__name__)
# Enable CORS for frontend communication
CORS(app)

# Global State for the Dashboard
stats = {
    "total": 0,
    "active": 0,
    "blocked": 0,
    "attackTypes": {},
    "geoSources": {}
}

# Queue of new real alerts to send to the frontend
unread_alerts = []
# Keep track of connections we've already alerted on to prevent spam
seen_connections = set()
# Track how many connections come from a single IP to detect DoS behavior
connection_counts = {}

def get_geo_location(ip):
    """Fetches real geographic location for an IP address"""
    if ip.startswith(("192.168.", "10.", "127.", "172.", "::1", "fe80:")):
        return "Local Network"
    try:
        # Free GeoIP lookup
        res = requests.get(f"http://ip-api.com/json/{ip}", timeout=2).json()
        if res.get("status") == "success":
            return f'{res.get("city", "Unknown")}, {res.get("country", "Unknown")}'
    except:
        pass
    return "Unknown External"

def monitor_network():
    """Background thread that constantly scans your computer's REAL network traffic"""
    global stats, unread_alerts, connection_counts
    while True:
        try:
            # Scan all active internet connections on your actual Windows machine
            connections = psutil.net_connections(kind='inet')
            
            for conn in connections:
                # We only care about connections with a remote address
                if conn.status in ['ESTABLISHED', 'SYN_RECV'] and conn.raddr:
                    remote_ip = conn.raddr.ip
                    remote_port = conn.raddr.port
                    
                    # Ignore purely local loopback noise
                    if remote_ip.startswith(("127.", "::1")):
                        continue

                    conn_id = f"{remote_ip}:{remote_port}"
                    if conn_id in seen_connections:
                        continue
                    
                    seen_connections.add(conn_id)
                    connection_counts[remote_ip] = connection_counts.get(remote_ip, 0) + 1
                    
                    # --- REAL INTRUSION DETECTION HEURISTICS ---
                    alert_type = None
                    severity = "info"
                    
                    # 1. DoS / Port Scan Detection (Too many connections from one IP)
                    if connection_counts[remote_ip] > 15:
                        alert_type = "High Connection Volume (Possible DoS)"
                        severity = "critical"
                    
                    # 2. SYN Flood / Half-Open connection
                    elif conn.status == 'SYN_RECV':
                        alert_type = "Half-Open Connection (SYN Flood)"
                        severity = "critical"
                    
                    # 3. Sensitive Port Access (Hackers trying to SSH or RDP into your PC)
                    elif conn.laddr.port in [22, 3389, 21, 23, 445]:
                        alert_type = "Sensitive Port Access (SSH/RDP/SMB)"
                        severity = "warning"
                    
                    # 4. Standard Traffic
                    else:
                        alert_type = "New External Connection"
                        severity = "info"

                    # Get real geography
                    geo = get_geo_location(remote_ip)
                    
                    # Create the real alert
                    alert = {
                        "id": f"ALRT-{uuid.uuid4().hex[:6].upper()}",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "type": alert_type,
                        "source_ip": remote_ip,
                        "geo": geo,
                        "severity": severity,
                        "action": "Logged",
                        "description": f"Real traffic: Local port {conn.laddr.port} <-> Remote IP {remote_ip}"
                    }
                    
                    unread_alerts.append(alert)
                    
                    # Update global dashboard statistics
                    stats["total"] += 1
                    if severity in ["critical", "warning"]:
                        stats["active"] += 1
                    
                    stats["attackTypes"][alert_type] = stats["attackTypes"].get(alert_type, 0) + 1
                    if geo != "Local Network":
                        stats["geoSources"][geo] = stats["geoSources"].get(geo, 0) + 1
                        
        except Exception as e:
            # Silently continue if we hit Windows permission errors on certain system processes
            pass 
        
        # Poll every 3 seconds
        time.sleep(3)

@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    global unread_alerts
    # Send only the new alerts to the dashboard, then clear the queue
    alerts_to_send = unread_alerts[:]
    unread_alerts.clear()
    return jsonify(alerts_to_send)

@app.route('/api/stats', methods=['GET'])
def get_stats():
    return jsonify(stats)

if __name__ == '__main__':
    # 1. Start the real network scanner in the background
    monitor_thread = threading.Thread(target=monitor_network, daemon=True)
    monitor_thread.start()
    
    # 2. Start the API server to feed the frontend dashboard
    app.run(port=5000, debug=False, use_reloader=False)
