from flask import Flask, request, jsonify
from database import init_db
from auth.login_handler import handle_login, register_user
from engine.baseline import run_baseline_engine
from engine.adaptive_lockdown import (
    evaluate_lockdown,
    check_account_lock,
    check_ip_lock
)

app = Flask(__name__)


@app.route("/")
def home():
    return "CORTEX Core Engine Running"


@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()

    return jsonify(
        register_user(
            data["username"],
            data["password"]
        )
    )


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    ip = request.remote_addr
    device = request.headers.get("User-Agent")

    # -------------------------------
    # Module 6 – IP Pre-check
    # -------------------------------
    is_ip_locked, ip_lock_until = check_ip_lock(ip)

    if is_ip_locked:
        return jsonify({
            "status": "ip_blocked",
            "message": f"IP blocked until {ip_lock_until}"
        }), 403

    result = handle_login(
        data["username"],
        data["password"],
        ip,
        device
    )

    if result.get("user_id"):

        user_id = result["user_id"]

        # -------------------------------
        # Module 6 – Account Pre-check
        # -------------------------------
        is_locked, lock_until = check_account_lock(user_id)

        if is_locked:
            return jsonify({
                "status": "locked",
                "message": f"Account locked until {lock_until}"
            }), 403

        # -------------------------------
        # Module 3 – Baseline
        # -------------------------------
        baseline_result = run_baseline_engine(user_id)
        print("Baseline Result:", baseline_result)

        # -------------------------------
        # Module 4 – Rule Engine
        # -------------------------------
        from engine.rules import run_rules
        from datetime import datetime

        triggered = run_rules(
            user_id,
            ip,
            device,
            datetime.now()
        )

        print("Triggered Rules:", triggered)

        formatted_rules = [
            {
                "rule_name": rule["name"],
                "risk_points": rule["weight"]
            }
            for rule in triggered
        ]

        if baseline_result["baseline_score"] > 0:
            formatted_rules.append({
                "rule_name": "Behavioral Anomaly",
                "risk_points": baseline_result["baseline_score"]
            })

        # -------------------------------
        # Module 5 – Risk Scoring
        # -------------------------------
        from engine.risk_scoring import calculate_risk

        final_score, severity = calculate_risk(user_id, formatted_rules)

        print("Final Risk Score:", final_score)
        print("Severity:", severity)

        # -------------------------------
        # Module 6 – Adaptive Enforcement
        # -------------------------------
        lock_level = evaluate_lockdown(user_id, ip, final_score)

        print("Lock Level:", lock_level)

        if lock_level >= 2:
            return jsonify({
                "status": "locked",
                "message": "Account temporarily locked due to suspicious activity.",
                "risk_score": final_score,
                "severity": severity
            }), 403

    return jsonify(result)


if __name__ == "__main__":
    init_db()
    app.run(debug=True)