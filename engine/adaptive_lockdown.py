from datetime import datetime, timedelta
from database import get_db_connection
import time


# -------------------------------
# LOCK LEVEL DETERMINATION
# -------------------------------

def determine_lock_level(risk_score):
    if risk_score >= 70:
        return 3
    elif risk_score >= 40:
        return 2
    elif risk_score >= 20:
        return 1
    else:
        return 0


# -------------------------------
# CHECK IF ACCOUNT IS LOCKED
# -------------------------------

def check_account_lock(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT is_locked, lock_until FROM users WHERE id = ?",
        (user_id,)
    )

    row = cursor.fetchone()
    conn.close()

    if not row:
        return False, None

    is_locked, lock_until = row

    if is_locked and lock_until:
        lock_until_time = datetime.fromisoformat(lock_until)

        if datetime.utcnow() < lock_until_time:
            return True, lock_until_time
        else:
            reset_account_lock(user_id)
            return False, None

    return False, None


# -------------------------------
# CHECK IF IP IS LOCKED
# -------------------------------

def check_ip_lock(ip_address):
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT lock_until FROM ip_lockdowns WHERE ip_address = ? ORDER BY id DESC LIMIT 1",
        (ip_address,)
    )

    row = cursor.fetchone()
    conn.close()

    if not row:
        return False, None

    lock_until_time = datetime.fromisoformat(row[0])

    if datetime.utcnow() < lock_until_time:
        return True, lock_until_time

    return False, None


# -------------------------------
# APPLY ACCOUNT LOCK
# -------------------------------

def apply_account_lock(user_id, level):
    conn = get_db_connection()
    cursor = conn.cursor()

    if level == 2:
        lock_duration = timedelta(minutes=10)
    elif level == 3:
        lock_duration = timedelta(minutes=30)
    else:
        conn.close()
        return

    lock_until = datetime.utcnow() + lock_duration

    cursor.execute(
        """
        UPDATE users
        SET is_locked = 1,
            lock_until = ?,
            lock_level = ?
        WHERE id = ?
        """,
        (lock_until.isoformat(), level, user_id)
    )

    conn.commit()
    conn.close()


# -------------------------------
# APPLY IP LOCK
# -------------------------------

def apply_ip_lock(ip_address, level):
    conn = get_db_connection()
    cursor = conn.cursor()

    if level == 3:
        lock_duration = timedelta(minutes=30)
    else:
        lock_duration = timedelta(minutes=15)

    lock_until = datetime.utcnow() + lock_duration

    cursor.execute(
        """
        INSERT INTO ip_lockdowns (ip_address, lock_until, severity, reason)
        VALUES (?, ?, ?, ?)
        """,
        (
            ip_address,
            lock_until.isoformat(),
            level,
            "High Risk Authentication Activity"
        )
    )

    conn.commit()
    conn.close()


# -------------------------------
# RESET ACCOUNT LOCK
# -------------------------------

def reset_account_lock(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        UPDATE users
        SET is_locked = 0,
            lock_until = NULL,
            lock_level = 0
        WHERE id = ?
        """,
        (user_id,)
    )

    conn.commit()
    conn.close()


# -------------------------------
# APPLY PROGRESSIVE DELAY (LEVEL 1)
# -------------------------------

def apply_delay(risk_score):
    delay_seconds = min(5, 2 + (risk_score // 10))
    print(f"Level 1 detected. Applying {delay_seconds}s delay.")
    time.sleep(delay_seconds)


# -------------------------------
# MAIN ADAPTIVE ENFORCEMENT
# -------------------------------

def evaluate_lockdown(user_id, ip_address, risk_score):
    level = determine_lock_level(risk_score)

    # Level 1 → Progressive Delay
    if level == 1:
        apply_delay(risk_score)

    # Level 2 → Account Lock
    elif level == 2:
        apply_account_lock(user_id, level)

    # Level 3 → Account + IP Lock
    elif level == 3:
        apply_account_lock(user_id, level)
        apply_ip_lock(ip_address, level)

    return level