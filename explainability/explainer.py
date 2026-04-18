"""
CORTEX – Module 13: Explainability Engine

Generates human-readable explanations for every enforcement decision.
Critical for auditability and academic defense — no black box outputs.
"""

from database import get_db_connection
import json


# Rule-specific explanation templates
RULE_EXPLANATIONS = {
    "Brute Force": "Multiple failed login attempts detected in a short time window from the same source.",
    "Abnormal Login Time": "Login attempt occurred outside the user's established behavioral time pattern.",
    "Unknown IP": "Login originated from an IP address not previously associated with this account.",
    "New Device": "Login from a device (User-Agent) not previously seen for this account.",
    "Behavioral Anomaly": "Login behavior deviates significantly from the user's established baseline patterns.",
    "Velocity IP": "Unusually high number of login attempts from this IP address within the monitoring window.",
    "Velocity User": "Unusually high number of login attempts for this user account within the monitoring window.",
    "Impossible Travel": "Login from a geographically impossible location given the previous login's time and location.",
    "Unknown Fingerprint": "Login from an unrecognized device fingerprint (combination of browser and system characteristics).",
    "Threat Intel Hit": "Login IP address matches a known malicious IP range in the threat intelligence database.",
}

# Severity-based recommended actions
RECOMMENDED_ACTIONS = {
    "LOW": "No immediate action required. Continue monitoring user activity.",
    "MEDIUM": "Review recent login activity. Consider requiring identity verification on next login.",
    "HIGH": "Verify identity via secondary channel before unlocking. Investigate login source.",
}

# Enforcement action descriptions
ACTION_DESCRIPTIONS = {
    "ALLOWED": "Login was permitted after risk assessment.",
    "WARNED": "Login was permitted with a progressive delay applied due to moderate risk.",
    "LOCKED": "Account temporarily locked due to high-risk login activity.",
    "IP_BLOCKED": "Account locked and IP address blocked due to critical-risk activity.",
}


def generate_explanation(user_id, risk_score, severity, triggered_rules,
                         enforcement_action):
    """
    Generate a structured, human-readable explanation for an enforcement decision.

    Args:
        user_id: The user's database ID.
        risk_score: Final calculated risk score.
        severity: Risk severity level (LOW/MEDIUM/HIGH).
        triggered_rules: List of triggered rule dicts with 'rule_name' and 'risk_points'.
        enforcement_action: The enforcement action taken (ALLOWED/WARNED/LOCKED/IP_BLOCKED).

    Returns:
        dict: Structured explanation with decision summary, risk breakdown,
              and recommended action.
    """
    # Build risk breakdown
    risk_breakdown = []
    for rule in triggered_rules:
        rule_name = rule.get("rule_name", rule.get("name", "Unknown Rule"))
        risk_points = rule.get("risk_points", rule.get("weight", 0))
        detail = rule.get("detail", "")

        explanation_text = RULE_EXPLANATIONS.get(
            rule_name,
            detail if detail else f"Rule '{rule_name}' was triggered."
        )

        # If we have a specific detail, append it
        if detail and rule_name in RULE_EXPLANATIONS:
            explanation_text = f"{RULE_EXPLANATIONS[rule_name]} Detail: {detail}"

        risk_breakdown.append({
            "rule": rule_name,
            "points": risk_points,
            "explanation": explanation_text
        })

    # Build reason summary
    reason_summary = ACTION_DESCRIPTIONS.get(
        enforcement_action,
        f"Enforcement action '{enforcement_action}' was applied."
    )

    # Build recommended action
    recommended_action = RECOMMENDED_ACTIONS.get(
        severity,
        "Review account activity and assess threat level."
    )

    explanation = {
        "decision": enforcement_action,
        "reason_summary": reason_summary,
        "risk_breakdown": risk_breakdown,
        "total_risk": risk_score,
        "severity": severity,
        "recommended_action": recommended_action
    }

    return explanation


def get_latest_explanation(user_id):
    """
    Retrieve the latest enforcement explanation for a user.

    Args:
        user_id: The user's database ID.

    Returns:
        dict or None: The parsed explanation dict, or None if not found.
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT explanation, risk_score, severity, enforcement_action,
               triggered_rules, timestamp
        FROM enforcement_logs
        WHERE user_id = ?
        AND explanation IS NOT NULL
        ORDER BY timestamp DESC
        LIMIT 1
    """, (user_id,))

    row = cursor.fetchone()
    conn.close()

    if not row:
        return None

    try:
        explanation = json.loads(row["explanation"])
        explanation["log_timestamp"] = row["timestamp"]
        return explanation
    except (json.JSONDecodeError, TypeError):
        # Fallback: build a basic explanation from available data
        return {
            "decision": row["enforcement_action"],
            "reason_summary": "Explanation data unavailable.",
            "risk_breakdown": [],
            "total_risk": row["risk_score"],
            "severity": row["severity"],
            "recommended_action": "Review enforcement logs for details.",
            "log_timestamp": row["timestamp"]
        }
