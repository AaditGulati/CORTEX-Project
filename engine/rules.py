from database import get_db_connection
from datetime import datetime, timedelta
import json


def detect_brute_force(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()

    five_minutes_ago = datetime.now() - timedelta(minutes=5)

    cursor.execute("""
        SELECT COUNT(*) FROM login_attempts
        WHERE user_id = ?
        AND status = 'FAIL'
        AND timestamp >= ?
    """, (user_id, five_minutes_ago))

    count = cursor.fetchone()[0]
    conn.close()

    if count >= 5:
        return {"rule": "Brute Force", "risk_points": 40}

    return None


def detect_time_anomaly(user_id, login_hour):
    conn = get_db_connection()
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
            return {"rule": "Abnormal Login Time", "risk_points": 20}

    return None


def detect_unknown_ip(user_id, current_ip):
    conn = get_db_connection()
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
            return {"rule": "Unknown IP", "risk_points": 20}

    return None


def detect_new_device(user_id, current_device):
    conn = get_db_connection()
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
            return {"rule": "New Device", "risk_points": 20}

    return None


def run_all_rules(user_id, ip, device, timestamp):
    results = []

    login_hour = timestamp.hour

    rule_checks = [
        detect_brute_force(user_id),
        detect_time_anomaly(user_id, login_hour),
        detect_unknown_ip(user_id, ip),
        detect_new_device(user_id, device),
    ]

    for rule in rule_checks:
        if rule:
            results.append(rule)

    return results