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
    result = handle_login(
        data["username"],
        data["password"],
        ip,
        device
    )

    user_id = result.get("user_id")

    if not user_id:
        # Unknown user or failed login — log and return
        log_enforcement(
            user_id=None, ip_address=ip, risk_score=0,
            severity="LOW", triggered_rules=[],
            enforcement_action="ALLOWED", decay_applied=0,
            explanation={"decision": "ALLOWED",
                         "reason_summary": "Login failed — invalid credentials."}
        )
        return jsonify(result)

    # -----------------------------------------------
    # Module 6 – Account Pre-check
    # -----------------------------------------------
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

    # -----------------------------------------------
    # Module 11 – Session Fingerprinting
    # -----------------------------------------------
    fingerprint_hash = build_fingerprint(request.headers)
    fingerprint_result = check_fingerprint(user_id, fingerprint_hash, request.headers)
    if fingerprint_result:
        triggered.append(fingerprint_result)

    # -----------------------------------------------
    # Module 3 – Baseline Analysis
    # -----------------------------------------------
    baseline_result = run_baseline_engine(user_id)
    print("Baseline Result:", baseline_result)

    # -----------------------------------------------
    # Module 4 – Rule Engine
    # -----------------------------------------------
    rule_results = run_rules(user_id, ip, device, datetime.utcnow())
    triggered.extend(rule_results)
    print("Rule Engine Triggered:", rule_results)

    # -----------------------------------------------
    # Module 9 – Velocity Detection
    # -----------------------------------------------
    velocity_results = run_velocity_check(user_id, ip)
    triggered.extend(velocity_results)
    if velocity_results:
        print("Velocity Rules:", velocity_results)

    # -----------------------------------------------
    # Module 10 – Impossible Travel Detection
    # -----------------------------------------------
    travel_result = check_impossible_travel(user_id, ip)
    if travel_result:
        triggered.append(travel_result)
        print("Impossible Travel:", travel_result)

    # -----------------------------------------------
    # Format all triggered rules for risk scoring
    # -----------------------------------------------
    formatted_rules = [
        {
            "rule_name": rule.get("name", "Unknown"),
            "risk_points": rule.get("weight", 0)
        }
        for rule in triggered
    ]

    # Add baseline anomaly as a rule if detected
    if baseline_result["baseline_score"] > 0:
        formatted_rules.append({
            "rule_name": "Behavioral Anomaly",
            "risk_points": baseline_result["baseline_score"]
        })

    print("All Triggered Rules:", formatted_rules)

    # -----------------------------------------------
    # Module 5 – Risk Scoring
    # -----------------------------------------------
    risk_score, severity = calculate_risk(user_id, formatted_rules)
    print("Final Risk Score:", risk_score, "| Severity:", severity)

    # -----------------------------------------------
    # Module 6 – Adaptive Enforcement
    # -----------------------------------------------
    lock_level = evaluate_lockdown(user_id, ip, risk_score)
    print("Lock Level:", lock_level)

    # Determine enforcement action
    if lock_level >= 3:
        enforcement_action = "IP_BLOCKED"
    elif lock_level >= 2:
        enforcement_action = "LOCKED"
    elif lock_level >= 1:
        enforcement_action = "WARNED"
    else:
        enforcement_action = "ALLOWED"

    # -----------------------------------------------
    # Module 3b – Update Baseline (after rules check)
    # -----------------------------------------------
    if result["status"] == "SUCCESS":
        update_user_baseline(user_id, ip, device)

    # -----------------------------------------------
    # Module 7 – Risk Decay (only on clean logins)
    # -----------------------------------------------
    if result["status"] == "SUCCESS" and len(triggered) == 0:
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
# Application Startup
# -----------------------------------------------

if __name__ == "__main__":
    init_db()
    seed_threat_feeds()
    app.run(debug=True)