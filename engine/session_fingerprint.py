"""
CORTEX – Module 11: Session Fingerprinting

Builds a richer device identity than just User-Agent string by
combining multiple request headers into a SHA-256 fingerprint hash.
Makes device identification far harder to spoof.
"""

import hashlib
from database import get_db_connection
from datetime import datetime


def build_fingerprint(request_headers):
    """
    Build a SHA-256 fingerprint hash from request header values.

    Components:
        - User-Agent
        - Accept-Language
        - Accept-Encoding
        - X-Forwarded-For (if present)

    Args:
        request_headers: Flask request.headers object.

    Returns:
        str: SHA-256 hex digest fingerprint hash.
    """
    components = [
        request_headers.get("User-Agent", ""),
        request_headers.get("Accept-Language", ""),
        request_headers.get("Accept-Encoding", ""),
        request_headers.get("X-Forwarded-For", "")
    ]

    combined = "|".join(components)
    fingerprint_hash = hashlib.sha256(combined.encode("utf-8")).hexdigest()

    return fingerprint_hash


def check_fingerprint(user_id, fingerprint_hash, request_headers):
    """
    Check if a fingerprint is known for a user.
    If unknown → returns a triggered rule dict.
    If known → updates last_seen and increments seen_count.
    On new fingerprint → inserts a new record.

    Args:
        user_id: The user's database ID.
        fingerprint_hash: The SHA-256 fingerprint hash.
        request_headers: Flask request.headers for extracting metadata.

    Returns:
        dict or None: Triggered rule dict if unknown fingerprint, None if known.
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    # Check if fingerprint exists for this user
    cursor.execute("""
        SELECT id, seen_count
        FROM device_fingerprints
        WHERE user_id = ? AND fingerprint_hash = ?
    """, (user_id, fingerprint_hash))

    row = cursor.fetchone()

    if row:
        # Known fingerprint — update last_seen and increment count
        cursor.execute("""
            UPDATE device_fingerprints
            SET last_seen = ?,
                seen_count = seen_count + 1
            WHERE id = ?
        """, (
            datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            row["id"]
        ))

        conn.commit()
        conn.close()
        return None  # Known fingerprint, no rule triggered

    else:
        # Unknown fingerprint — insert new record
        user_agent = request_headers.get("User-Agent", "")
        language = request_headers.get("Accept-Language", "")

        cursor.execute("""
            INSERT INTO device_fingerprints
            (user_id, fingerprint_hash, user_agent, language)
            VALUES (?, ?, ?, ?)
        """, (user_id, fingerprint_hash, user_agent, language))

        conn.commit()
        conn.close()

        # Check if this is the user's FIRST ever fingerprint
        # If so, don't flag it — it's their initial device
        conn2 = get_db_connection()
        cursor2 = conn2.cursor()

        cursor2.execute("""
            SELECT COUNT(*) as fp_count
            FROM device_fingerprints
            WHERE user_id = ?
        """, (user_id,))

        count = cursor2.fetchone()["fp_count"]
        conn2.close()

        if count <= 1:
            # First fingerprint ever — don't flag
            return None

        return {
            "name": "Unknown Fingerprint",
            "weight": 15,
            "detail": f"Login from unrecognized device fingerprint: {fingerprint_hash[:16]}..."
        }
