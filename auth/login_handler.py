from werkzeug.security import generate_password_hash, check_password_hash
from database import get_session, close_session


def register_user(username, password):
    conn = get_session()
    cursor = conn.cursor()

    hashed_password = generate_password_hash(password)

    try:
        cursor.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, hashed_password)
        )
        conn.commit()
        result = {"status": "REGISTERED"}
    except:
        result = {"status": "EXISTS"}

    close_session(conn)
    return result


def handle_login(username, password, ip, device):
    """
    1. Verify credentials
    2. Insert login_attempts record
    3. Return structured result
    """

    conn = get_session()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()

    if user and check_password_hash(user["password_hash"], password):
        status = "SUCCESS"
        user_id = user["id"]
    else:
        status = "FAIL"
        user_id = user["id"] if user else None

    cursor.execute("""
        INSERT INTO login_attempts (user_id, ip_address, device_info, status)
        VALUES (?, ?, ?, ?)
    """, (user_id, ip, device, status))

    conn.commit()
    close_session(conn)

    return {
        "user_id": user_id,
        "status": status
    }