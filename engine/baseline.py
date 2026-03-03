from datetime import datetime, timedelta
from database import get_db_connection


BASELINE_TIME_THRESHOLD = 4      # hours deviation allowed
BASELINE_FREQ_THRESHOLD = 5      # logins per hour allowed


def get_recent_login_history(user_id, limit=20):
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT timestamp
        FROM login_attempts
        WHERE user_id = ?
        AND status = 'SUCCESS'
        ORDER BY timestamp DESC
        LIMIT ?
    """, (user_id, limit))

    logs = cursor.fetchall()
    conn.close()

    return logs


def calculate_average_login_hour(logs):
    hours = []

    for log in logs:
        timestamp = log["timestamp"]
        dt = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
        hours.append(dt.hour)

    if not hours:
        return None

    return sum(hours) / len(hours)


def detect_time_deviation(user_id, current_time):
    logs = get_recent_login_history(user_id)
    avg_hour = calculate_average_login_hour(logs)

    if avg_hour is None:
        return False, 0

    deviation = abs(current_time.hour - avg_hour)

    if deviation > BASELINE_TIME_THRESHOLD:
        # Reduced from 30 → 15
        return True, 15

    return False, 0


def detect_frequency_spike(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()

    one_hour_ago = datetime.utcnow() - timedelta(hours=1)

    cursor.execute("""
        SELECT COUNT(*) as count
        FROM login_attempts
        WHERE user_id = ?
        AND timestamp >= ?
    """, (user_id, one_hour_ago.strftime("%Y-%m-%d %H:%M:%S")))

    result = cursor.fetchone()
    conn.close()

    if result["count"] > BASELINE_FREQ_THRESHOLD:
        # Reduced from 40 → 20
        return True, 20

    return False, 0


def run_baseline_engine(user_id):
    current_time = datetime.utcnow()

    time_flag, time_score = detect_time_deviation(user_id, current_time)
    freq_flag, freq_score = detect_frequency_spike(user_id)

    total_score = time_score + freq_score

    return {
        "time_anomaly": time_flag,
        "frequency_anomaly": freq_flag,
        "baseline_score": total_score
    }