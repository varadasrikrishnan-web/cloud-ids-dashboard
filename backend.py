from flask import Flask, jsonify
from flask_cors import CORS
import random
import uuid
from datetime import datetime, timezone

app = Flask(__name__)
# Enable CORS for all routes so the frontend can fetch data without issues
CORS(app)

# Global State
stats = {
    "total": 0,
    "active": 0,
    "blocked": 0,
    "attackTypes": {
        "DDoS Attempt": 0,
        "SQL Injection": 0,
        "Cross-Site Scripting (XSS)": 0,
        "Brute Force": 0,
        "Port Scan": 0,
        "Malware": 0
    },
    "geoSources": {
        "Mumbai": 0,
        "Delhi": 0,
        "Bengaluru": 0,
        "Chennai": 0,
        "Hyderabad": 0,
        "Pune": 0,
        "Kolkata": 0
    }
}

attack_types = list(stats["attackTypes"].keys())
geo_sources = list(stats["geoSources"].keys())
severities = ["critical", "warning", "info"]

def get_random_ip():
    return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)}"

@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    # Simulate generating 1 to 3 new alerts per request
    num_alerts = random.randint(1, 3)
    new_alerts = []
    
    for _ in range(num_alerts):
        a_type = random.choice(attack_types)
        geo = random.choice(geo_sources)
        
        # Bias severity based on attack type
        if a_type in ["DDoS Attempt", "SQL Injection", "Malware"]:
            severity = "critical" if random.random() > 0.4 else "warning"
        elif a_type == "Brute Force":
            severity = "warning"
        else:
            severity = random.choice(severities)
            
        action = "Blocked" if severity == "critical" else "Logged"
        
        alert = {
            "id": f"ALRT-{uuid.uuid4().hex[:6].upper()}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "type": a_type,
            "source_ip": get_random_ip(),
            "geo": geo,
            "severity": severity,
            "action": action,
            "description": f"Detected suspicious {a_type} activity originating from {geo}."
        }
        new_alerts.append(alert)
        
        # Update backend stats
        stats["total"] += 1
        if severity in ["critical", "warning"]:
            stats["active"] += 1
        if action == "Blocked":
            stats["blocked"] += 1
        stats["attackTypes"][a_type] += 1
        stats["geoSources"][geo] += 1
        
    return jsonify(new_alerts)

@app.route('/api/stats', methods=['GET'])
def get_stats():
    return jsonify(stats)

if __name__ == '__main__':
    # Run the Flask server on port 5000
    app.run(port=5000, debug=True)
