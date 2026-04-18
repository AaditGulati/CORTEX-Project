"""
CORTEX – Module 14: Admin Dashboard Routes

Server-rendered Flask dashboard for monitoring and managing the
CORTEX threat intelligence system. Protected by admin token auth.
"""

from flask import Blueprint, render_template, request, jsonify, abort
from database import get_db_connection
from config import ADMIN_TOKEN
from engine.adaptive_lockdown import reset_account_lock
from engine.threat_intel import refresh_threat_feeds
import json


dashboard_bp = Blueprint(
    "dashboard", __name__,
    template_folder="templates",
    static_folder="static",
    static_url_path="/dashboard/static"
)


# -----------------------------------------------
# AUTH MIDDLEWARE — Protect all /admin/* routes
# -----------------------------------------------

@dashboard_bp.before_request
def check_admin_auth():
    """Check admin token via header or query param."""
    # Allow static files without auth
    if request.path.startswith("/dashboard/static"):
        return None

    token = (
        request.headers.get("X-Admin-Token") or
        request.args.get("token") or
        request.cookies.get("cortex_admin_token")
    )

    if token != ADMIN_TOKEN:
        # Serve login page if no valid token
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
    """Validate admin token and set cookie."""
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
    """Overview panel — key metrics and recent activity."""
    return render_template("overview.html")


@dashboard_bp.route("/admin/users")
def users():
    """User risk monitor panel."""
    return render_template("users.html")


@dashboard_bp.route("/admin/logs")
def logs_page():
    """Enforcement log viewer."""
    return render_template("logs.html")


@dashboard_bp.route("/admin/threats")
def threats():
    """Threat map panel."""
    return render_template("threats.html")


@dashboard_bp.route("/admin/system")
def system():
    """System health panel."""
    return render_template("system.html")


# -----------------------------------------------
# API ENDPOINTS — Dashboard Data
# -----------------------------------------------

@dashboard_bp.route("/admin/stats")
def admin_stats():
    """JSON stats for the overview dashboard."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # Total users
    cursor.execute("SELECT COUNT(*) as cnt FROM users")
    total_users = cursor.fetchone()["cnt"]

    # Logins in last 24h
    cursor.execute("""
        SELECT
            COUNT(*) as total,
            SUM(CASE WHEN status = 'SUCCESS' THEN 1 ELSE 0 END) as success,
            SUM(CASE WHEN status = 'FAIL' THEN 1 ELSE 0 END) as fail
        FROM login_attempts
        WHERE timestamp >= datetime('now', '-24 hours')
    """)
    login_stats = cursor.fetchone()

    # Active account locks
    cursor.execute("""
        SELECT COUNT(*) as cnt FROM users
        WHERE is_locked = 1 AND lock_until > datetime('now')
    """)
    active_account_locks = cursor.fetchone()["cnt"]

    # Active IP locks
    cursor.execute("""
        SELECT COUNT(*) as cnt FROM ip_lockdowns
        WHERE lock_until > datetime('now')
    """)
    active_ip_locks = cursor.fetchone()["cnt"]

    # Average risk score today
    cursor.execute("""
        SELECT AVG(risk_score) as avg_risk
        FROM enforcement_logs
        WHERE timestamp >= datetime('now', '-24 hours')
    """)
    avg_risk_row = cursor.fetchone()
    avg_risk = round(avg_risk_row["avg_risk"] or 0, 1)

    # Top 5 highest-risk users
    cursor.execute("""
        SELECT u.id, u.username, rm.cumulative_risk, rm.last_updated
        FROM risk_memory rm
        JOIN users u ON u.id = rm.user_id
        ORDER BY rm.cumulative_risk DESC
        LIMIT 5
    """)
    top_risk_users = [dict(row) for row in cursor.fetchall()]

    # Recent enforcement actions (last 10)
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
    """JSON data for user risk monitor."""
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
    """Full login history and risk timeline for a user."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # User info
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    if not user:
        conn.close()
        return jsonify({"error": "User not found"}), 404

    # Login history
    cursor.execute("""
        SELECT * FROM login_attempts
        WHERE user_id = ?
        ORDER BY timestamp DESC
        LIMIT 50
    """, (user_id,))
    login_history = [dict(row) for row in cursor.fetchall()]

    # Enforcement history
    cursor.execute("""
        SELECT * FROM enforcement_logs
        WHERE user_id = ?
        ORDER BY timestamp DESC
        LIMIT 50
    """, (user_id,))
    enforcement_history = [dict(row) for row in cursor.fetchall()]

    # Risk memory
    cursor.execute("SELECT * FROM risk_memory WHERE user_id = ?", (user_id,))
    risk_memory = dict(cursor.fetchone()) if cursor.fetchone() else None

    # Re-query risk_memory properly
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
    """Paginated enforcement logs with filtering."""
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 25, type=int)
    severity_filter = request.args.get("severity", "")
    action_filter = request.args.get("action", "")
    offset = (page - 1) * per_page

    conn = get_db_connection()
    cursor = conn.cursor()

    # Build dynamic query with filters
    conditions = []
    params = []

    if severity_filter:
        conditions.append("el.severity = ?")
        params.append(severity_filter)
    if action_filter:
        conditions.append("el.enforcement_action = ?")
        params.append(action_filter)

    where_clause = ""
    if conditions:
        where_clause = "WHERE " + " AND ".join(conditions)

    # Get total count
    cursor.execute(
        f"SELECT COUNT(*) as cnt FROM enforcement_logs el {where_clause}",
        params
    )
    total = cursor.fetchone()["cnt"]

    # Get page data
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
        # Parse explanation JSON if present
        if log_entry.get("explanation"):
            try:
                log_entry["explanation"] = json.loads(log_entry["explanation"])
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
    """Threat map data — triggered rules in last 24h."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # Rule trigger counts in last 24h
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

    # Sort rules by count
    sorted_rules = [
        {"rule_name": k, "count": v["count"], "total_points": v["total_points"]}
        for k, v in sorted(rule_counts.items(), key=lambda x: x[1]["count"], reverse=True)
    ]

    # Top attacking IPs
    sorted_ips = [
        {"ip": k, "attempts": v["attempts"], "total_risk": v["total_risk"]}
        for k, v in sorted(attacking_ips.items(), key=lambda x: x[1]["total_risk"], reverse=True)
    ][:10]

    conn.close()

    return jsonify({
        "rules": sorted_rules,
        "top_ips": sorted_ips
    })


@dashboard_bp.route("/admin/system/data")
def system_data():
    """System health data."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # Total enforcement logs
    cursor.execute("SELECT COUNT(*) as cnt FROM enforcement_logs")
    total_logs = cursor.fetchone()["cnt"]

    # Risk decay events today
    cursor.execute("""
        SELECT COUNT(*) as cnt FROM enforcement_logs
        WHERE decay_applied = 1
        AND timestamp >= datetime('now', '-24 hours')
    """)
    decay_events = cursor.fetchone()["cnt"]

    # Last threat feed update
    cursor.execute("""
        SELECT MAX(added_at) as last_update FROM threat_feeds
    """)
    feed_row = cursor.fetchone()
    feed_last_updated = feed_row["last_update"] if feed_row else "Never"

    # Total threat feed entries
    cursor.execute("SELECT COUNT(*) as cnt FROM threat_feeds")
    feed_entries = cursor.fetchone()["cnt"]

    # Total login attempts
    cursor.execute("SELECT COUNT(*) as cnt FROM login_attempts")
    total_attempts = cursor.fetchone()["cnt"]

    # Total users
    cursor.execute("SELECT COUNT(*) as cnt FROM users")
    total_users = cursor.fetchone()["cnt"]

    # DB file size
    import os
    from config import DATABASE
    db_size = 0
    if os.path.exists(DATABASE):
        db_size = os.path.getsize(DATABASE)

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
    """Convert bytes to human-readable string."""
    for unit in ["B", "KB", "MB", "GB"]:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


# -----------------------------------------------
# ADMIN ACTION ENDPOINTS
# -----------------------------------------------

@dashboard_bp.route("/admin/unlock/<int:user_id>", methods=["POST"])
def unlock_user(user_id):
    """Manually unlock a user account."""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT id, username FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    conn.close()

    if not user:
        return jsonify({"error": "User not found"}), 404

    reset_account_lock(user_id)

    return jsonify({
        "status": "unlocked",
        "user_id": user_id,
        "username": user["username"]
    })


@dashboard_bp.route("/admin/ip/unblock", methods=["POST"])
def unblock_ip():
    """Manually unblock an IP address."""
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

    return jsonify({
        "status": "unblocked",
        "ip": ip,
        "entries_removed": deleted
    })


@dashboard_bp.route("/admin/feeds/refresh")
def feeds_refresh():
    """Refresh threat intelligence feeds."""
    result = refresh_threat_feeds()
    return jsonify(result)
