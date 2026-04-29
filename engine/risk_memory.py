"""
CORTEX - Risk memory / history.
"""
from database import get_db_connection
from datetime import datetime


ESCALATION_WEIGHT = 0.3  # 30% historical influence


def apply_risk_memory(user_id, current_score):
    """
    Apply historical cumulative risk influence.
    final_score = current_score + (historical_avg × weight)
    """

    conn = get_db_connection()
    cursor = conn.cursor()

    # Fetch historical memory
    cursor.execute("""
        SELECT cumulative_risk, event_count
        FROM risk_memory
        WHERE user_id = ?
    """, (user_id,))
    row = cursor.fetchone()

    if row:
        cumulative_risk = row["cumulative_risk"]
        event_count = row["event_count"]

        historical_avg = cumulative_risk / event_count if event_count > 0 else 0
    else:
        cumulative_risk = 0
        event_count = 0
        historical_avg = 0

    # Apply escalation formula
    final_score = current_score + (historical_avg * ESCALATION_WEIGHT)

    # Update risk memory
    update_risk_memory(user_id, cumulative_risk + current_score, event_count + 1)

    conn.close()

    return int(final_score)


def update_risk_memory(user_id, new_cumulative, new_count):
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO risk_memory (user_id, cumulative_risk, event_count, last_updated)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(user_id) DO UPDATE SET
            cumulative_risk = ?,
            event_count = ?,
            last_updated = ?
    """, (
        user_id,
        new_cumulative,
        new_count,
        datetime.now(),
        new_cumulative,
        new_count,
        datetime.now()
    ))

    conn.commit()
    conn.close()