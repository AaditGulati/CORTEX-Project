from database import get_session
from datetime import datetime, timedelta
import json


# ----------------------------
# RULE 1: Brute Force
# ----------------------------
def detect_brute_force(user_id):
    conn = get_session()
    cursor = conn.cursor()

    five_minutes_ago = (datetime.utcnow() - timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute("""
        SELECT COUNT(*) FROM login_attempts
        WHERE user_id = ?
        AND status = 'FAIL'
        AND timestamp >= ?
    """, (user_id, five_minutes_ago))

    count = cursor.fetchone()[0]
    conn.close()

    if count >= 5:
        return {
            "rule_name": "Brute Force",
            "risk_points": 30
        }

    return None


# ----------------------------
# RULE 2: Time Anomaly
# ----------------------------
def detect_time_anomaly(user_id, login_hour):
    conn = get_session()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT login_start_hour, login_end_hour
        FROM user_baseline
        WHERE user_id = ?
    """, (user_id,))

    baseline = cursor.fetchone()
    conn.close()

    if baseline:
        start_hour, end_hour = baseline
        if login_hour < start_hour or login_hour > end_hour:
            return {
                "rule_name": "Abnormal Login Time",
                "risk_points": 20
            }

    return None


# ----------------------------
# RULE 3: Unknown IP
# ----------------------------
def detect_unknown_ip(user_id, current_ip):
    conn = get_session()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT known_ips FROM user_baseline
        WHERE user_id = ?
    """, (user_id,))

    result = cursor.fetchone()
    conn.close()

    if result and result[0]:
        known_ips = json.loads(result[0])
        if current_ip not in known_ips:
            return {
                "rule_name": "Unknown IP",
                "risk_points": 20
            }

    return None


# ----------------------------
# RULE 4: New Device
# ----------------------------
def detect_new_device(user_id, current_device):
    conn = get_session()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT known_devices FROM user_baseline
        WHERE user_id = ?
    """, (user_id,))

    result = cursor.fetchone()
    conn.close()

    if result and result[0]:
        known_devices = json.loads(result[0])
        if current_device not in known_devices:
            return {
                "rule_name": "New Device",
                "risk_points": 20
            }

    return None


# ----------------------------
# RULE 5: SQL Injection
# ----------------------------
def detect_sql_injection(input_text):
    if not input_text:
        return None

    patterns = [
        "'", "--", ";",
        " OR ", " AND ",
        "SELECT", "DROP", "INSERT", "DELETE", "UNION"
    ]

    for pattern in patterns:
        if pattern.lower() in input_text.lower():
            return {
                "rule_name": "SQL Injection Attempt",
                "risk_points": 80
            }

    return None


# ----------------------------
# MAIN RULE ENGINE
# ----------------------------
def run_rules(user_id, ip, device, timestamp, user_input=None):
    results = []
    login_hour = timestamp.hour

    rule_checks = [
        detect_brute_force(user_id),
        detect_time_anomaly(user_id, login_hour),
        detect_unknown_ip(user_id, ip),
        detect_new_device(user_id, device),
        detect_sql_injection(user_input)
    ]

    for rule in rule_checks:
        if rule:
            results.append(rule)
    print("RULE RESULTS:", results)
    return results

