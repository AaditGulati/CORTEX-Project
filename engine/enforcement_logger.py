"""
CORTEX – Module 8: Enforcement Logging

Full auditability of every enforcement decision made by CORTEX.
Logs every login attempt outcome regardless of success or failure.
"""

import json
from database import get_db_connection


def log_enforcement(user_id, ip_address, risk_score, severity,
                    triggered_rules, enforcement_action, decay_applied=0,
                    explanation=None):
    """
    Log an enforcement decision to the enforcement_logs table.

    Args:
        user_id: The user's database ID (can be None for unknown users).
        ip_address: The request IP address.
        risk_score: Final calculated risk score.
        severity: Risk severity level (LOW/MEDIUM/HIGH).
        triggered_rules: List of triggered rule dicts.
        enforcement_action: One of ALLOWED, WARNED, LOCKED, IP_BLOCKED.
        decay_applied: 1 if risk decay was applied, 0 otherwise.
        explanation: JSON string of the explainability output.

    Returns:
        dict: { "logged": True, "log_id": int }
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    # Serialize triggered rules to JSON string
    if isinstance(triggered_rules, list):
        rules_json = json.dumps(triggered_rules)
    else:
        rules_json = str(triggered_rules)

    # Serialize explanation to JSON if it's a dict
    explanation_json = None
    if explanation:
        if isinstance(explanation, dict):
            explanation_json = json.dumps(explanation)
        else:
            explanation_json = str(explanation)

    cursor.execute("""
        INSERT INTO enforcement_logs
        (user_id, ip_address, risk_score, severity, triggered_rules,
         enforcement_action, decay_applied, explanation)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        user_id,
        ip_address,
        risk_score,
        severity,
        rules_json,
        enforcement_action,
        decay_applied,
        explanation_json
    ))

    log_id = cursor.lastrowid
    conn.commit()
    conn.close()

    return {
        "logged": True,
        "log_id": log_id
    }
