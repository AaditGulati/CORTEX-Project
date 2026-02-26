from flask import Flask, request, jsonify
from database import init_db
from auth.login_handler import handle_login, register_user
from engine.baseline import run_baseline_engine

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

    result = handle_login(
        data["username"],
        data["password"],
        ip,
        device
    )

    if result.get("user_id"):

        user_id = result["user_id"]

        # Module 3 – Baseline
        baseline_result = run_baseline_engine(user_id)
        print("Baseline Result:", baseline_result)

        # Module 4 – Rule Engine
        from engine.rules import run_rules
        from datetime import datetime

        triggered = run_rules(
            user_id,
            ip,
            device,
            datetime.now()
        )

        print("Triggered Rules:", triggered)

        # 🔥 Convert rule format for risk scoring
        formatted_rules = [
            {
                "rule_name": rule["name"],
                "risk_points": rule["weight"]
            }
            for rule in triggered
        ]

        # Add baseline score as contextual rule
        if baseline_result["baseline_score"] > 0:
            formatted_rules.append({
                "rule_name": "Behavioral Anomaly",
                "risk_points": baseline_result["baseline_score"]
            })

        # Module 5 – Risk Scoring
        from engine.risk_scoring import calculate_risk

        final_score, severity = calculate_risk(user_id, formatted_rules)

        print("Final Risk Score:", final_score)
        print("Severity:", severity)

    return jsonify(result)


if __name__ == "__main__":
    init_db()
    app.run(debug=True)