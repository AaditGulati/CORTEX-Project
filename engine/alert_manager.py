"""
CORTEX – Alert Manager
Allows analysts to dismiss or resolve enforcement log alerts.
"""

from database import get_db_connection


def migrate_alerts_table():
    """Add alert_status column to enforcement_logs if not already present."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("ALTER TABLE enforcement_logs ADD COLUMN alert_status TEXT DEFAULT 'OPEN'")
        conn.commit()
        print("Alert status column added.")
    except Exception:
        pass  # Column already exists
    conn.close()


def get_open_alerts(severity_filter=None, action_filter=None, page=1, per_page=25):
    """Fetch alerts with optional filters."""
    conn = get_db_connection()
    cursor = conn.cursor()

    conditions = ["(el.alert_status IS NULL OR el.alert_status = 'OPEN')"]
    params = []

    if severity_filter:
        conditions.append("el.severity = ?")
        params.append(severity_filter)
    if action_filter:
        conditions.append("el.enforcement_action = ?")
        params.append(action_filter)

    where = "WHERE " + " AND ".join(conditions)
    offset = (page - 1) * per_page

    cursor.execute(f"SELECT COUNT(*) as cnt FROM enforcement_logs el {where}", params)
    total = cursor.fetchone()["cnt"]

    cursor.execute(f"""
        SELECT el.*, u.username
        FROM enforcement_logs el
        LEFT JOIN users u ON u.id = el.user_id
        {where}
        ORDER BY el.timestamp DESC
        LIMIT ? OFFSET ?
    """, params + [per_page, offset])

    import json
    logs = []
    for row in cursor.fetchall():
        entry = dict(row)
        if entry.get("explanation"):
            try:
                entry["explanation"] = json.loads(entry["explanation"])
            except Exception:
                pass
        if entry.get("triggered_rules"):
            try:
                entry["triggered_rules"] = json.loads(entry["triggered_rules"])
            except Exception:
                pass
        entry["alert_status"] = entry.get("alert_status") or "OPEN"
        logs.append(entry)

    conn.close()
    return {"logs": logs, "total": total, "page": page, "per_page": per_page,
            "total_pages": (total + per_page - 1) // per_page}


def dismiss_alert(log_id):
    """Mark a single alert as DISMISSED."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE enforcement_logs SET alert_status = 'DISMISSED' WHERE id = ?", (log_id,)
    )
    conn.commit()
    affected = cursor.rowcount
    conn.close()
    return affected > 0


def resolve_alert(log_id, analyst_note=None):
    """Mark a single alert as RESOLVED with an optional analyst note."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # Store note inside explanation JSON if provided
    if analyst_note:
        cursor.execute("SELECT explanation FROM enforcement_logs WHERE id = ?", (log_id,))
        row = cursor.fetchone()
        if row and row["explanation"]:
            import json
            try:
                exp = json.loads(row["explanation"])
                exp["analyst_note"] = analyst_note
                exp["resolved_at"] = __import__('datetime').datetime.utcnow().isoformat()
                cursor.execute(
                    "UPDATE enforcement_logs SET explanation = ?, alert_status = 'RESOLVED' WHERE id = ?",
                    (json.dumps(exp), log_id)
                )
            except Exception:
                cursor.execute(
                    "UPDATE enforcement_logs SET alert_status = 'RESOLVED' WHERE id = ?", (log_id,)
                )
        else:
            cursor.execute(
                "UPDATE enforcement_logs SET alert_status = 'RESOLVED' WHERE id = ?", (log_id,)
            )
    else:
        cursor.execute(
            "UPDATE enforcement_logs SET alert_status = 'RESOLVED' WHERE id = ?", (log_id,)
        )

    conn.commit()
    affected = cursor.rowcount
    conn.close()
    return affected > 0


def bulk_dismiss(log_ids):
    """Dismiss multiple alerts at once."""
    conn = get_db_connection()
    cursor = conn.cursor()
    placeholders = ",".join("?" * len(log_ids))
    cursor.execute(
        f"UPDATE enforcement_logs SET alert_status = 'DISMISSED' WHERE id IN ({placeholders})",
        log_ids
    )
    conn.commit()
    affected = cursor.rowcount
    conn.close()
    return affected


def get_alert_stats():
    """Count of OPEN / RESOLVED / DISMISSED alerts."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT
            SUM(CASE WHEN alert_status = 'OPEN' OR alert_status IS NULL THEN 1 ELSE 0 END) as open_count,
            SUM(CASE WHEN alert_status = 'RESOLVED' THEN 1 ELSE 0 END) as resolved_count,
            SUM(CASE WHEN alert_status = 'DISMISSED' THEN 1 ELSE 0 END) as dismissed_count
        FROM enforcement_logs
    """)
    row = cursor.fetchone()
    conn.close()
    return {
        "open": row["open_count"] or 0,
        "resolved": row["resolved_count"] or 0,
        "dismissed": row["dismissed_count"] or 0
    }