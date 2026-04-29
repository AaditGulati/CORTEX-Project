"""
CORTEX – Module 7: Risk Decay Mechanism

Prevents permanent high-risk labeling by reducing cumulative risk
over time for users who demonstrate clean login behavior.

Triggered ONLY when: login is SUCCESS + zero rules triggered.
"""

from database import get_db_connection
from config import DECAY_FACTOR
from datetime import datetime


def apply_risk_decay(user_id):
    """
    Reduce cumulative risk for users with clean logins.

    Args:
        user_id: The user's database ID.

    Returns:
        dict: { "decayed": bool, "old_risk": int, "new_risk": int }
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    # Fetch current cumulative risk
    cursor.execute("""
        SELECT cumulative_risk
        FROM risk_memory
        WHERE user_id = ?
    """, (user_id,))

    row = cursor.fetchone()

    if not row or row["cumulative_risk"] <= 0:
        conn.close()
        return {
            "decayed": False,
            "old_risk": 0,
            "new_risk": 0
        }

    old_risk = row["cumulative_risk"]
    new_risk = max(0, old_risk - DECAY_FACTOR)

    # Update risk_memory with decayed value
    cursor.execute("""
        UPDATE risk_memory
        SET cumulative_risk = ?,
            last_updated = ?
        WHERE user_id = ?
    """, (new_risk, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), user_id))

    conn.commit()
    conn.close()

    return {
        "decayed": True,
        "old_risk": old_risk,
        "new_risk": new_risk
    }
