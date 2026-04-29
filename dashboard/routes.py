"""
CORTEX – Module 14: Admin Dashboard Routes
"""

from flask import Blueprint, render_template, request, jsonify, abort
from database import get_db_connection
from config import ADMIN_TOKEN
from engine.adaptive_lockdown import reset_account_lock
from engine.threat_intel import refresh_threat_feeds
import json

from engine.alert_manager import (
    migrate_alerts_table, get_open_alerts,
    dismiss_alert, resolve_alert, bulk_dismiss, get_alert_stats
)

dashboard_bp = Blueprint(
    "dashboard", __name__,
    template_folder="templates",
    static_folder="static",
    static_url_path="/dashboard/static"
)

# Run DB migration on startup — safe to call repeatedly
migrate_alerts_table()


# -----------------------------------------------
# AUTH MIDDLEWARE
# -----------------------------------------------

@dashboard_bp.before_request
def check_admin_auth():
    if request.path.startswith("/dashboard/static"):
        return None

    token = (
        request.headers.get("X-Admin-Token") or
        request.args.get("token") or
        request.cookies.get("cortex_admin_token")
    )

    if token != ADMIN_TOKEN:
        if request.path == "/admin/auth":
            return None
        if request.method == "GET" and not request.is_json:
            return render_template("login.html"), 401
        return jsonify({"error": "Unauthorized. Invalid admin token."}), 401


# -----------------------------------------------
# ADMIN AUTH
# -----------------------------------------------

@dashboard_bp.route("/admin/auth", methods=["POST"])
def admin_auth():
    data = request.get_json() or {}
    token = data.get("token", "")
    if token == ADMIN_TOKEN:
        response = jsonify({"status": "authenticated"})
        response.set_cookie("cortex_admin_token", token, httponly=True, max_age=86400)
        return response
    return jsonify({"error": "Invalid token"}), 401


# -----------------------------------------------
# DASHBOARD PAGES
# -----------------------------------------------

@dashboard_bp.route("/admin")
def overview():
    return render_template("overview.html")

@dashboard_bp.route("/admin/users")
def users():
    return render_template("users.html")

@dashboard_bp.route("/admin/logs")
def logs_page():
    return render_template("logs.html")

@dashboard_bp.route("/admin/threats")
def threats():
    return render_template("threats.html")

@dashboard_bp.route("/admin/system")
def system():
    return render_template("system.html")

@dashboard_bp.route("/admin/alerts")
def alerts_page():
    return render_template("alerts.html")


# -----------------------------------------------
# API ENDPOINTS — Dashboard Data
# -----------------------------------------------

@dashboard_bp.route("/admin/stats")
def admin_stats():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) as cnt FROM users")
    total_users = cursor.fetchone()["cnt"]

    cursor.execute("""
        SELECT
            COUNT(*) as total,
            SUM(CASE WHEN status = 'SUCCESS' THEN 1 ELSE 0 END) as success,
            SUM(CASE WHEN status = 'FAIL' THEN 1 ELSE 0 END) as fail
        FROM login_attempts
        WHERE timestamp >= datetime('now', '-24 hours')
    """)
    login_stats = cursor.fetchone()

    cursor.execute("""
        SELECT COUNT(*) as cnt FROM users
        WHERE is_locked = 1 AND lock_until > datetime('now')
    """)
    active_account_locks = cursor.fetchone()["cnt"]

    cursor.execute("""
        SELECT COUNT(*) as cnt FROM ip_lockdowns
        WHERE lock_until > datetime('now')
    """)
    active_ip_locks = cursor.fetchone()["cnt"]

    cursor.execute("""
        SELECT AVG(risk_score) as avg_risk
        FROM enforcement_logs
        WHERE timestamp >= datetime('now', '-24 hours')
    """)
    avg_risk_row = cursor.fetchone()
    avg_risk = round(avg_risk_row["avg_risk"] or 0, 1)

    cursor.execute("""
        SELECT u.id, u.username, rm.cumulative_risk, rm.last_updated
        FROM risk_memory rm
        JOIN users u ON u.id = rm.user_id
        ORDER BY rm.cumulative_risk DESC
        LIMIT 5
    """)
    top_risk_users = [dict(row) for row in cursor.fetchall()]

    cursor.execute("""
        SELECT el.*, u.username
        FROM enforcement_logs el
        LEFT JOIN users u ON u.id = el.user_id
        ORDER BY el.timestamp DESC
        LIMIT 10
    """)
    recent_actions = [dict(row) for row in cursor.fetchall()]

    conn.close()

    return jsonify({
        "total_users": total_users,
        "logins_24h": {
            "total": login_stats["total"] or 0,
            "success": login_stats["success"] or 0,
            "fail": login_stats["fail"] or 0
        },
        "active_locks": {
            "account": active_account_locks,
            "ip": active_ip_locks
        },
        "avg_risk_today": avg_risk,
        "top_risk_users": top_risk_users,
        "recent_actions": recent_actions
    })


@dashboard_bp.route("/admin/users/data")
def users_data():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            u.id, u.username, u.created_at, u.is_locked, u.lock_until, u.lock_level,
            rm.cumulative_risk, rm.event_count, rm.last_updated,
            (SELECT COUNT(*) FROM login_attempts la WHERE la.user_id = u.id) as total_logins,
            (SELECT timestamp FROM login_attempts la
             WHERE la.user_id = u.id ORDER BY la.timestamp DESC LIMIT 1) as last_login
        FROM users u
        LEFT JOIN risk_memory rm ON rm.user_id = u.id
        ORDER BY COALESCE(rm.cumulative_risk, 0) DESC
    """)

    users = []
    for row in cursor.fetchall():
        cumulative_risk = row["cumulative_risk"] or 0
        if cumulative_risk <= 30:
            severity = "LOW"
        elif cumulative_risk <= 60:
            severity = "MEDIUM"
        else:
            severity = "HIGH"

        users.append({
            "id": row["id"],
            "username": row["username"],
            "created_at": row["created_at"],
            "last_login": row["last_login"],
            "cumulative_risk": cumulative_risk,
            "severity": severity,
            "is_locked": row["is_locked"],
            "lock_until": row["lock_until"],
            "lock_level": row["lock_level"],
            "total_logins": row["total_logins"],
            "event_count": row["event_count"] or 0
        })

    conn.close()
    return jsonify({"users": users})


@dashboard_bp.route("/admin/users/<int:user_id>/history")
def user_history(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    if not user:
        conn.close()
        return jsonify({"error": "User not found"}), 404

    cursor.execute("""
        SELECT * FROM login_attempts
        WHERE user_id = ?
        ORDER BY timestamp DESC
        LIMIT 50
    """, (user_id,))
    login_history = [dict(row) for row in cursor.fetchall()]

    cursor.execute("""
        SELECT * FROM enforcement_logs
        WHERE user_id = ?
        ORDER BY timestamp DESC
        LIMIT 50
    """, (user_id,))
    enforcement_history = [dict(row) for row in cursor.fetchall()]

    # FIX: single fetchone, no double-read TypeError
    cursor.execute("SELECT * FROM risk_memory WHERE user_id = ?", (user_id,))
    rm_row = cursor.fetchone()
    risk_memory = dict(rm_row) if rm_row else None

    conn.close()

    return jsonify({
        "user": dict(user),
        "login_history": login_history,
        "enforcement_history": enforcement_history,
        "risk_memory": risk_memory
    })


@dashboard_bp.route("/admin/logs/data")
def logs_data():
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 25, type=int)
    severity_filter = request.args.get("severity", "")
    action_filter = request.args.get("action", "")
    offset = (page - 1) * per_page

    conn = get_db_connection()
    cursor = conn.cursor()

    conditions = []
    params = []

    if severity_filter:
        conditions.append("el.severity = ?")
        params.append(severity_filter)
    if action_filter:
        conditions.append("el.enforcement_action = ?")
        params.append(action_filter)

    where_clause = ("WHERE " + " AND ".join(conditions)) if conditions else ""

    cursor.execute(
        f"SELECT COUNT(*) as cnt FROM enforcement_logs el {where_clause}", params
    )
    total = cursor.fetchone()["cnt"]

    cursor.execute(f"""
        SELECT el.*, u.username
        FROM enforcement_logs el
        LEFT JOIN users u ON u.id = el.user_id
        {where_clause}
        ORDER BY el.timestamp DESC
        LIMIT ? OFFSET ?
    """, params + [per_page, offset])

    logs = []
    for row in cursor.fetchall():
        log_entry = dict(row)
        if log_entry.get("explanation"):
            try:
                log_entry["explanation"] = json.loads(log_entry["explanation"])
            except (json.JSONDecodeError, TypeError):
                pass
        if log_entry.get("triggered_rules"):
            try:
                log_entry["triggered_rules"] = json.loads(log_entry["triggered_rules"])
            except (json.JSONDecodeError, TypeError):
                pass
        logs.append(log_entry)

    conn.close()

    return jsonify({
        "logs": logs,
        "total": total,
        "page": page,
        "per_page": per_page,
        "total_pages": (total + per_page - 1) // per_page
    })


@dashboard_bp.route("/admin/threats/data")
def threats_data():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT triggered_rules, risk_score, ip_address
        FROM enforcement_logs
        WHERE timestamp >= datetime('now', '-24 hours')
        AND triggered_rules IS NOT NULL
        AND triggered_rules != '[]'
    """)

    rule_counts = {}
    attacking_ips = {}

    for row in cursor.fetchall():
        try:
            rules = json.loads(row["triggered_rules"])
            for rule in rules:
                name = rule.get("rule_name", rule.get("name", "Unknown"))
                points = rule.get("risk_points", rule.get("weight", 0))
                if name not in rule_counts:
                    rule_counts[name] = {"count": 0, "total_points": 0}
                rule_counts[name]["count"] += 1
                rule_counts[name]["total_points"] += points
        except (json.JSONDecodeError, TypeError):
            pass

        ip = row["ip_address"]
        if ip:
            if ip not in attacking_ips:
                attacking_ips[ip] = {"attempts": 0, "total_risk": 0}
            attacking_ips[ip]["attempts"] += 1
            attacking_ips[ip]["total_risk"] += row["risk_score"] or 0

    sorted_rules = [
        {"rule_name": k, "count": v["count"], "total_points": v["total_points"]}
        for k, v in sorted(rule_counts.items(), key=lambda x: x[1]["count"], reverse=True)
    ]
    sorted_ips = [
        {"ip": k, "attempts": v["attempts"], "total_risk": v["total_risk"]}
        for k, v in sorted(attacking_ips.items(), key=lambda x: x[1]["total_risk"], reverse=True)
    ][:10]

    cursor.execute("""
        SELECT ip_address, lock_until, reason
        FROM ip_lockdowns
        WHERE lock_until > datetime('now')
    """)
    blocked_ips = [dict(row) for row in cursor.fetchall()]

    conn.close()
    return jsonify({"rules": sorted_rules, "top_ips": sorted_ips, "blocked_ips": blocked_ips})


@dashboard_bp.route("/admin/system/data")
def system_data():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) as cnt FROM enforcement_logs")
    total_logs = cursor.fetchone()["cnt"]

    cursor.execute("""
        SELECT COUNT(*) as cnt FROM enforcement_logs
        WHERE decay_applied = 1 AND timestamp >= datetime('now', '-24 hours')
    """)
    decay_events = cursor.fetchone()["cnt"]

    cursor.execute("SELECT MAX(added_at) as last_update FROM threat_feeds")
    feed_row = cursor.fetchone()
    feed_last_updated = feed_row["last_update"] if feed_row else "Never"

    cursor.execute("SELECT COUNT(*) as cnt FROM threat_feeds")
    feed_entries = cursor.fetchone()["cnt"]

    cursor.execute("SELECT COUNT(*) as cnt FROM login_attempts")
    total_attempts = cursor.fetchone()["cnt"]

    cursor.execute("SELECT COUNT(*) as cnt FROM users")
    total_users = cursor.fetchone()["cnt"]

    import os
    from config import DATABASE
    db_size = os.path.getsize(DATABASE) if os.path.exists(DATABASE) else 0

    conn.close()

    return jsonify({
        "total_logs": total_logs,
        "decay_events_today": decay_events,
        "feed_last_updated": feed_last_updated,
        "feed_entries": feed_entries,
        "total_attempts": total_attempts,
        "total_users": total_users,
        "db_size_bytes": db_size,
        "db_size_readable": _format_bytes(db_size)
    })


def _format_bytes(size):
    for unit in ["B", "KB", "MB", "GB"]:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


# -----------------------------------------------
# ADMIN ACTION ENDPOINTS — Users
# -----------------------------------------------

@dashboard_bp.route("/admin/unlock/<int:user_id>", methods=["POST"])
def unlock_user(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    conn.close()
    if not user:
        return jsonify({"error": "User not found"}), 404
    reset_account_lock(user_id)
    return jsonify({"status": "unlocked", "user_id": user_id, "username": user["username"]})


@dashboard_bp.route("/admin/lock/<int:user_id>", methods=["POST"])
def lock_user(user_id):
    """Manually lock a user account for 24 hours."""
    from datetime import datetime, timedelta
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    if not user:
        conn.close()
        return jsonify({"error": "User not found"}), 404
    lock_until = (datetime.utcnow() + timedelta(hours=24)).strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute(
        "UPDATE users SET is_locked = 1, lock_until = ?, lock_level = 2 WHERE id = ?",
        (lock_until, user_id)
    )
    conn.commit()
    conn.close()
    return jsonify({"status": "locked", "user_id": user_id, "username": user["username"], "lock_until": lock_until})


@dashboard_bp.route("/admin/users/<int:user_id>/reset-risk", methods=["POST"])
def reset_user_risk(user_id):
    """Reset a user's cumulative risk score to zero."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    if not user:
        conn.close()
        return jsonify({"error": "User not found"}), 404
    cursor.execute(
        "UPDATE risk_memory SET cumulative_risk = 0, event_count = 0 WHERE user_id = ?",
        (user_id,)
    )
    conn.commit()
    conn.close()
    return jsonify({"status": "reset", "user_id": user_id, "username": user["username"]})


@dashboard_bp.route("/admin/users/<int:user_id>/delete", methods=["POST"])
def delete_user(user_id):
    """Permanently delete a user and all associated data."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    if not user:
        conn.close()
        return jsonify({"error": "User not found"}), 404

    username = user["username"]

    # Delete all related records across every table
    cursor.execute("DELETE FROM login_attempts WHERE user_id = ?", (user_id,))
    cursor.execute("DELETE FROM risk_memory WHERE user_id = ?", (user_id,))
    cursor.execute("DELETE FROM user_baseline WHERE user_id = ?", (user_id,))
    cursor.execute("DELETE FROM threat_analysis WHERE user_id = ?", (user_id,))
    cursor.execute("DELETE FROM enforcement_logs WHERE user_id = ?", (user_id,))
    cursor.execute("DELETE FROM device_fingerprints WHERE user_id = ?", (user_id,))
    cursor.execute("DELETE FROM user_location_cache WHERE user_id = ?", (user_id,))
    cursor.execute("DELETE FROM adaptive_state WHERE user_id = ?", (user_id,))

    # Finally, delete the user record
    cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))

    conn.commit()
    conn.close()
    return jsonify({"status": "deleted", "user_id": user_id, "username": username})


# -----------------------------------------------
# ADMIN ACTION ENDPOINTS — IPs
# -----------------------------------------------

@dashboard_bp.route("/admin/ip/unblock", methods=["POST"])
def unblock_ip():
    data = request.get_json() or {}
    ip = data.get("ip", "")
    if not ip:
        return jsonify({"error": "IP address required"}), 400
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM ip_lockdowns WHERE ip_address = ?", (ip,))
    deleted = cursor.rowcount
    conn.commit()
    conn.close()
    return jsonify({"status": "unblocked", "ip": ip, "entries_removed": deleted})


@dashboard_bp.route("/admin/ip/block", methods=["POST"])
def block_ip():
    """Manually block an IP address."""
    from datetime import datetime, timedelta
    data = request.get_json() or {}
    ip = data.get("ip", "")
    hours = data.get("hours", 24)
    reason = data.get("reason", "Manual block by analyst")
    if not ip:
        return jsonify({"error": "IP address required"}), 400
    lock_until = (datetime.utcnow() + timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%S")
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM ip_lockdowns WHERE ip_address = ?", (ip,))
    cursor.execute(
        "INSERT INTO ip_lockdowns (ip_address, lock_until, severity, reason) VALUES (?, ?, ?, ?)",
        (ip, lock_until, 3, reason)
    )
    conn.commit()
    conn.close()
    return jsonify({"status": "blocked", "ip": ip, "lock_until": lock_until, "reason": reason})


# -----------------------------------------------
# ADMIN ACTION ENDPOINTS — Logs
# -----------------------------------------------

@dashboard_bp.route("/admin/logs/<int:log_id>/delete", methods=["POST"])
def delete_log(log_id):
    """Permanently delete a single enforcement log entry."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM enforcement_logs WHERE id = ?", (log_id,))
    deleted = cursor.rowcount
    conn.commit()
    conn.close()
    if deleted:
        return jsonify({"status": "deleted", "id": log_id})
    return jsonify({"error": "Log not found"}), 404


@dashboard_bp.route("/admin/logs/clear", methods=["POST"])
def clear_logs():
    """Clear all enforcement logs. Requires confirm: CLEAR_ALL."""
    data = request.get_json() or {}
    if data.get("confirm") != "CLEAR_ALL":
        return jsonify({"error": "Send confirm: CLEAR_ALL to proceed"}), 400
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM enforcement_logs")
    deleted = cursor.rowcount
    conn.commit()
    conn.close()
    return jsonify({"status": "cleared", "entries_removed": deleted})


@dashboard_bp.route("/admin/feeds/refresh")
def feeds_refresh():
    result = refresh_threat_feeds()
    return jsonify(result)


# -----------------------------------------------
# ALERT MANAGEMENT ENDPOINTS
# -----------------------------------------------

@dashboard_bp.route("/admin/alerts/stats")
def alerts_stats():
    return jsonify(get_alert_stats())


@dashboard_bp.route("/admin/alerts/data")
def alerts_data():
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 25, type=int)
    severity = request.args.get("severity", "")
    action = request.args.get("action", "")
    return jsonify(get_open_alerts(severity, action, page, per_page))


@dashboard_bp.route("/admin/alerts/<int:log_id>/dismiss", methods=["POST"])
def dismiss_alert_route(log_id):
    ok = dismiss_alert(log_id)
    return jsonify({"success": ok, "id": log_id, "status": "DISMISSED"})


@dashboard_bp.route("/admin/alerts/<int:log_id>/resolve", methods=["POST"])
def resolve_alert_route(log_id):
    data = request.get_json(silent=True) or {}
    note = data.get("note", "")
    ok = resolve_alert(log_id, note)
    return jsonify({"success": ok, "id": log_id, "status": "RESOLVED"})


@dashboard_bp.route("/admin/alerts/bulk-dismiss", methods=["POST"])
def bulk_dismiss_route():
    data = request.get_json() or {}
    ids = data.get("ids", [])
    if not ids:
        return jsonify({"error": "No IDs provided"}), 400
    count = bulk_dismiss(ids)
    return jsonify({"dismissed": count})