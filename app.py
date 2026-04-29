"""
CORTEX – Context-Aware Authentication Threat Intelligence System
Main Application Entry Point

Full Login Pipeline (Modules 1-13):
  POST /login
  → check_ip_lock()               [Module 6]
  → check_threat_intel()           [Module 12]
  → handle_login()                 [Module 2]
  → check_account_lock()           [Module 6]
  → build_fingerprint() + check    [Module 11]
  → run_baseline_engine()          [Module 3]
  → run_rules()                    [Module 4]
  → run_velocity_check()           [Module 9]
  → check_impossible_travel()      [Module 10]
  → calculate_risk()               [Module 5]
  → evaluate_lockdown()            [Module 6]
  → apply_risk_decay() (if clean)  [Module 7]
  → generate_explanation()         [Module 13]
  → log_enforcement()              [Module 8]
  → return response
"""


from flask import Flask, request, jsonify
from database import init_db
from auth.login_handler import handle_login, register_user
from engine.baseline import run_baseline_engine, update_user_baseline
from engine.adaptive_lockdown import (
    evaluate_lockdown,
    check_account_lock,
    check_ip_lock
)
from engine.rules import run_rules
from engine.risk_scoring import calculate_risk
from engine.risk_decay import apply_risk_decay
from engine.enforcement_logger import log_enforcement
from engine.velocity_detector import run_velocity_check
from engine.travel_detector import check_impossible_travel
from engine.session_fingerprint import build_fingerprint, check_fingerprint
from engine.threat_intel import check_threat_intel, seed_threat_feeds
from explainability.explainer import generate_explanation, get_latest_explanation
from dashboard.routes import dashboard_bp
from datetime import datetime

app = Flask(__name__)

from flask_cors import CORS
CORS(app)
# Register dashboard blueprint
app.register_blueprint(dashboard_bp)


@app.route("/")
def home():
    return "CORTEX Core Engine Running"


# -----------------------------------------------
# POST /register — Register user
# -----------------------------------------------

@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()

    return jsonify(
        register_user(
            data["username"],
            data["password"]
        )
    )


# -----------------------------------------------
# POST /login — Full Pipeline Login
# -----------------------------------------------

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    ip = request.remote_addr
    device = request.headers.get("User-Agent")

    # Track variables for enforcement logging
    user_id = None
    risk_score = 0
    severity = "LOW"
    triggered = []
    formatted_rules = []
    enforcement_action = "ALLOWED"
    decay_result = {"decayed": False}
    lock_level = 0

    # -----------------------------------------------
    # Module 6 – IP Pre-check
    # -----------------------------------------------
    is_ip_locked, ip_lock_until = check_ip_lock(ip)

    if is_ip_locked:
        # Log the blocked attempt
        log_enforcement(
            user_id=None, ip_address=ip, risk_score=0,
            severity="HIGH", triggered_rules=[],
            enforcement_action="IP_BLOCKED", decay_applied=0,
            explanation={"decision": "IP_BLOCKED",
                         "reason_summary": f"IP blocked until {ip_lock_until}"}
        )
        return jsonify({
            "status": "ip_blocked",
            "message": f"IP blocked until {ip_lock_until}"
        }), 403

    # -----------------------------------------------
    # Module 12 – Threat Intel Pre-check
    # -----------------------------------------------
    threat_result = check_threat_intel(ip)
    if threat_result:
        triggered.append(threat_result)

    # -----------------------------------------------
    # Module 2 – Authentication
    # -----------------------------------------------
    data = request.json if request.is_json else request.form
    username = data.get("username", "")
    password = data.get("password", "")
    user_input = f"{username} {password}"

    result = handle_login(username, password, ip, device)
    user_id = result.get("user_id")

    # -----------------------------------------------
    # Check IP Lockdown First
    # -----------------------------------------------
    is_ip_locked, ip_lock_until = check_ip_lock(ip)
    if is_ip_locked:
        return jsonify({
            "status": "blocked",
            "message": "IP address blocked due to critical risk."
        }), 403

    triggered = []
    baseline_result = {"baseline_score": 0}

    # -----------------------------------------------
    # Module 4 — Rule Engine (Run for ALL requests)
    # -----------------------------------------------
    rule_results = run_rules(user_id, ip, device, datetime.utcnow(), user_input)
    triggered.extend(rule_results)

    # -----------------------------------------------
    # User-specific modules (Run only if user found)
    # -----------------------------------------------
    if user_id:
        # Check Account Lock
        is_locked, lock_until = check_account_lock(user_id)
        if is_locked:
            log_enforcement(
                user_id=user_id, ip_address=ip, risk_score=0,
                severity="HIGH", triggered_rules=[],
                enforcement_action="LOCKED", decay_applied=0,
                explanation={"decision": "LOCKED",
                             "reason_summary": f"Account locked until {lock_until}"}
            )
            return jsonify({
                "status": "locked",
                "message": f"Account locked until {lock_until}"
            }), 403

        # Fingerprinting
        fingerprint_hash = build_fingerprint(request.headers)
        fingerprint_result = check_fingerprint(user_id, fingerprint_hash, request.headers)
        if fingerprint_result:
            triggered.append(fingerprint_result)

        # Baseline
        baseline_result = run_baseline_engine(user_id)

        # Velocity
        velocity_results = run_velocity_check(user_id, ip)
        triggered.extend(velocity_results)

        # Impossible Travel
        travel_result = check_impossible_travel(user_id, ip)
        if travel_result:
            triggered.append(travel_result)

    # -----------------------------------------------
    # Format all triggered rules
    # -----------------------------------------------
    formatted_rules = [
        {
            "rule_name": rule.get("rule_name", rule.get("name", "Unknown")),
            "risk_points": rule.get("risk_points", rule.get("weight", 0))
        }
        for rule in triggered
    ]

    if baseline_result["baseline_score"] > 0:
        formatted_rules.append({
            "rule_name": "Behavioral Anomaly",
            "risk_points": baseline_result["baseline_score"]
        })

    # -----------------------------------------------
    # Module 5 – Risk Scoring
    # -----------------------------------------------
    risk_score, severity = calculate_risk(user_id, formatted_rules)

    # -----------------------------------------------
    # Module 6 – Adaptive Enforcement
    # -----------------------------------------------
    lock_level = evaluate_lockdown(user_id, ip, risk_score)

    if lock_level >= 3:
        enforcement_action = "IP_BLOCKED"
    elif lock_level >= 2:
        enforcement_action = "LOCKED"
    elif lock_level == 1:
        enforcement_action = "DELAYED"
    else:
        enforcement_action = "ALLOWED"

    # -----------------------------------------------
    # Module 3b – Update Baseline (after rules check)
    # -----------------------------------------------
    if user_id and result.get("status") == "SUCCESS":
        update_user_baseline(user_id, ip, device)

    # -----------------------------------------------
    # Module 7 – Risk Decay (only on clean logins)
    # -----------------------------------------------
    decay_result = {}
    if user_id and result.get("status") == "SUCCESS" and len(triggered) == 0:
        decay_result = apply_risk_decay(user_id)
        if decay_result["decayed"]:
            print("Risk Decay Applied:",
                  f"{decay_result['old_risk']} → {decay_result['new_risk']}")

    # -----------------------------------------------
    # Module 13 – Explainability
    # -----------------------------------------------
    explanation = generate_explanation(
        user_id, risk_score, severity,
        formatted_rules, enforcement_action
    )

    # -----------------------------------------------
    # Module 8 – Enforcement Logging
    # -----------------------------------------------
    log_enforcement(
        user_id=user_id,
        ip_address=ip,
        risk_score=risk_score,
        severity=severity,
        triggered_rules=formatted_rules,
        enforcement_action=enforcement_action,
        decay_applied=1 if decay_result.get("decayed") else 0,
        explanation=explanation
    )

    # Return block based on risk level
    if lock_level >= 3:
        return jsonify({"status": "blocked", "message": "IP address blocked due to critical risk", "explanation": explanation}), 403
    elif lock_level >= 2 and user_id:
        return jsonify({"status": "locked", "message": "Account locked due to high risk", "explanation": explanation}), 403

    # If authentication failed
    if not user_id:
        return jsonify(result)

    # -----------------------------------------------
    # Build and return response
    # -----------------------------------------------
    if lock_level >= 2:
        return jsonify({
            "status": "locked",
            "message": "Account temporarily locked due to suspicious activity.",
            "risk_score": risk_score,
            "severity": severity,
            "triggered_rules": formatted_rules,
            "explanation": explanation
        }), 403

    # Enrich successful response
    response_data = {
        **result,
        "risk_score": risk_score,
        "severity": severity,
        "triggered_rules": formatted_rules,
        "enforcement_action": enforcement_action,
        "explanation": explanation
    }

    if decay_result.get("decayed"):
        response_data["risk_decay"] = decay_result

    return jsonify(response_data)


# -----------------------------------------------
# GET /explain/<user_id>/latest — Latest Explanation
# -----------------------------------------------

@app.route("/explain/<int:user_id>/latest", methods=["GET"])
def explain_latest(user_id):
    explanation = get_latest_explanation(user_id)

    if not explanation:
        return jsonify({
            "error": "No explanation found for this user."
        }), 404

    return jsonify(explanation)


# -----------------------------------------------
# GET /user/<user_id>/risk — Current Risk Score + History
# -----------------------------------------------

@app.route("/user/<int:user_id>/risk", methods=["GET"])
def user_risk(user_id):
    from database import get_db_connection

    conn = get_db_connection()
    cursor = conn.cursor()

    # Current risk memory
    cursor.execute("""
        SELECT cumulative_risk, event_count, last_updated
        FROM risk_memory WHERE user_id = ?
    """, (user_id,))
    risk_mem = cursor.fetchone()

    # Recent threat analysis history
    cursor.execute("""
        SELECT risk_score, severity, triggered_rules, timestamp
        FROM threat_analysis
        WHERE user_id = ?
        ORDER BY timestamp DESC
        LIMIT 20
    """, (user_id,))
    history = [dict(row) for row in cursor.fetchall()]

    conn.close()

    if not risk_mem:
        return jsonify({
            "user_id": user_id,
            "cumulative_risk": 0,
            "event_count": 0,
            "history": history
        })

    return jsonify({
        "user_id": user_id,
        "cumulative_risk": risk_mem["cumulative_risk"],
        "event_count": risk_mem["event_count"],
        "last_updated": risk_mem["last_updated"],
        "history": history
    })


# -----------------------------------------------
# POST /user/<user_id>/delete — Self-Service Profile Deletion
# -----------------------------------------------

@app.route("/user/<int:user_id>/delete", methods=["POST"])
def delete_user_self(user_id):
    from database import get_db_connection

    conn = get_db_connection()
    cursor = conn.cursor()

    # Verify user exists
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

    # Delete the user record itself
    cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))

    conn.commit()
    conn.close()

    return jsonify({
        "status": "deleted",
        "user_id": user_id,
        "username": username,
        "message": f"User '{username}' and all associated data have been permanently deleted."
    })


# -----------------------------------------------
# Application Startup
# -----------------------------------------------

if __name__ == "__main__":
    init_db()
    seed_threat_feeds()
    app.run(debug=True)

