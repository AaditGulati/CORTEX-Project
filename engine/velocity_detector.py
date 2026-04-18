"""
CORTEX – Module 9: Velocity Attack Detection

Detects distributed slow attacks — attackers who space attempts
over time to evade traditional brute force detection.

Monitors login velocity per IP and per user within a sliding window.
"""

from database import get_db_connection
from config import (
    VELOCITY_IP_WINDOW_MINUTES,
    VELOCITY_IP_THRESHOLD,
    VELOCITY_USER_THRESHOLD
)
from datetime import datetime, timedelta


def run_velocity_check(user_id, ip_address):
    """
    Check login velocity for both IP-based and user-based patterns.

    Args:
        user_id: The user's database ID.
        ip_address: The request IP address.

    Returns:
        list: List of triggered velocity rule dicts (same format as Module 4).
    """
    triggered = []

    # Check IP velocity
    ip_result = _check_ip_velocity(ip_address)
    if ip_result:
        triggered.append(ip_result)

    # Check user velocity
    user_result = _check_user_velocity(user_id)
    if user_result:
        triggered.append(user_result)

    return triggered


def _check_ip_velocity(ip_address):
    """
    Count login attempts from same IP in the velocity window.
    If IP attempts > threshold → trigger VELOCITY_IP rule.
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    window_start = (
        datetime.utcnow() - timedelta(minutes=VELOCITY_IP_WINDOW_MINUTES)
    ).strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute("""
        SELECT COUNT(*) as attempt_count
        FROM login_attempts
        WHERE ip_address = ?
        AND timestamp >= ?
    """, (ip_address, window_start))

    row = cursor.fetchone()
    conn.close()

    count = row["attempt_count"] if row else 0

    if count > VELOCITY_IP_THRESHOLD:
        return {
            "name": "Velocity IP",
            "weight": 25,
            "detail": f"{count} attempts from IP {ip_address} in {VELOCITY_IP_WINDOW_MINUTES} min"
        }

    return None


def _check_user_velocity(user_id):
    """
    Count login attempts for same user in the velocity window.
    If user attempts > threshold → trigger VELOCITY_USER rule.
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    window_start = (
        datetime.utcnow() - timedelta(minutes=VELOCITY_IP_WINDOW_MINUTES)
    ).strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute("""
        SELECT COUNT(*) as attempt_count
        FROM login_attempts
        WHERE user_id = ?
        AND timestamp >= ?
    """, (user_id, window_start))

    row = cursor.fetchone()
    conn.close()

    count = row["attempt_count"] if row else 0

    if count > VELOCITY_USER_THRESHOLD:
        return {
            "name": "Velocity User",
            "weight": 20,
            "detail": f"{count} attempts for user {user_id} in {VELOCITY_IP_WINDOW_MINUTES} min"
        }

    return None
