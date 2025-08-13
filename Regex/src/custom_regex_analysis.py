import re
from collections import Counter, defaultdict
from datetime import datetime

# === Threat Detection Regex Patterns ===
patterns = {
    "brute_force": [
        r"Failed\s+password\s+for\s+user\s+['\"]?(?:admin|root|test|[a-zA-Z0-9_\-]+)['\"]?",
        r"Invalid\s+user\s+[a-zA-Z0-9_\-]+"
    ],
    "web_attack": [
        r"(?i)(/etc/passwd)",
        r"(?i)(\.\./|\.\.\%2f|%2Fetc%2Fshadow)",
        r"(?i)(boot\.ini)",
        r"(?i)(select\s+\*\s+from)",
        r"(?i)(union\s+select)",
        r"(?i)(nikto\s+scan\s+detected)",
        r"(?i)(' or '1'='1)",
        r"(?i)(\%27\%20or\%20\%271\%27\%3D\%271)"
    ],
    "malicious_ip": [
        r"198\.167\.140\.21",  # known malicious
    ],
    "application_error": [
        r"(?i)(database\s+connection\s+timed\s+out)",
        r"(?i)(php-fpm.*sigsegv)",
        r"(?i)(nullpointerexception)",
        r"(?i)(configerror)",
        r"(?i)(unexpected\s+token)",
        r"(?i)(kafka\s+producer\s+flush\s+failed)"
    ]
}

# === Aggregation thresholds ===
thresholds = {
    "brute_force": 50,  # events/IP/day
    "low_slow": 5       # events/IP/day
}

# === Detection Logic ===
def analyze_logs(logs):
    detections = []
    counts_by_ip = defaultdict(int)
    
    for log in logs:
        ts, level, ip, msg = log
        
        # Track brute force counts
        if any(re.search(p, msg) for p in patterns["brute_force"]):
            counts_by_ip[ip] += 1
        
        # Match all categories
        for category, pats in patterns.items():
            if any(re.search(p, msg) for p in pats):
                detections.append({
                    "timestamp": ts,
                    "ip": ip,
                    "category": category,
                    "message": msg
                })
    
    # Aggregate-based alerts
    for ip, count in counts_by_ip.items():
        if count >= thresholds["brute_force"]:
            detections.append({
                "timestamp": None,
                "ip": ip,
                "category": "brute_force_high_volume",
                "message": f"{count} failed login attempts"
            })
        elif thresholds["low_slow"] <= count < thresholds["brute_force"]:
            detections.append({
                "timestamp": None,
                "ip": ip,
                "category": "low_and_slow_attack",
                "message": f"{count} failed login attempts over long period"
            })
    
    return detections
