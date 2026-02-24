from flask import Flask, request, jsonify
from database import init_db
from auth.login_handler import handle_login, register_user

app = Flask(__name__)


@app.route("/")
def home():
    return "CORTEX Core Engine Running"


@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()
    return jsonify(register_user(data["username"], data["password"]))


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    ip = request.remote_addr
    device = request.headers.get("User-Agent")

    result = handle_login(data["username"], data["password"], ip, device)
    from engine.rules import run_rules
    from datetime import datetime

    triggered = run_rules(result["user_id"], ip, device, datetime.now())
    print("Triggered Rules:", triggered)
    return jsonify(result)


if __name__ == "__main__":
    init_db()
    app.run(debug=True)