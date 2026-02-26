"""
CORTEX - Risk scoring logic.
"""
from database import get_db_connection
from engine.risk_memory import apply_risk_memory


def calculate_risk(user_id, rule_outputs):
    """
    Calculate final risk score after rule evaluation
    and apply contextual risk memory escalation.
    """

    # Step 1: Sum rule risk points
    current_risk = sum(rule["risk_points"] for rule in rule_outputs)

    # Step 2: Apply risk memory escalation
    final_score = apply_risk_memory(user_id, current_risk)

    # Step 3: Classify severity
    if final_score <= 30:
        severity = "LOW"
    elif final_score <= 60:
        severity = "MEDIUM"
    else:
        severity = "HIGH"

    # Step 4: Store in threat_analysis table
    store_threat_analysis(user_id, final_score, severity, rule_outputs)

    return final_score, severity


def store_threat_analysis(user_id, score, severity, rule_outputs):
    conn = get_db_connection()
    cursor = conn.cursor()

    triggered_rules = ", ".join(
        rule["rule_name"] for rule in rule_outputs if rule["risk_points"] > 0
    )

    cursor.execute("""
        INSERT INTO threat_analysis (user_id, risk_score, severity, triggered_rules)
        VALUES (?, ?, ?, ?)
    """, (user_id, score, severity, triggered_rules))

    conn.commit()
    conn.close()