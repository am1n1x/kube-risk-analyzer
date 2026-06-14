import json
from sqlalchemy import text
from sqlalchemy.orm import Session
from .models import RiskRule

def sync_rules_to_db(db: Session, file_path: str = "rules.json"):
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read().strip()
            rules = json.loads(content) if content else []
    except (FileNotFoundError, json.JSONDecodeError):
        rules = []

    db.query(RiskRule).delete()

    for rule in rules:
        description = rule.get("description")
        category = rule.get("category", "rbac")
        key = rule.get("key")

        dangerous_verbs = rule.get("dangerous_verbs", [])
        if isinstance(dangerous_verbs, list):
            dangerous_verbs = ",".join(dangerous_verbs)

        dangerous_resources = rule.get("dangerous_resources", [])
        if isinstance(dangerous_resources, list):
            dangerous_resources = ",".join(dangerous_resources)

        db_rule = RiskRule(
            description=description,
            category=category,
            key=key,
            dangerous_verbs=dangerous_verbs,
            dangerous_resources=dangerous_resources,
            severity=rule.get("severity", "MEDIUM")
        )
        db.add(db_rule)

    db.commit()

    # Backfill severity on existing findings using description-to-severity mapping from rules
    desc_to_severity = {r.description: r.severity for r in db.query(RiskRule).all()}
    # CRITICAL CHAIN and BAS findings are always CRITICAL
    db.execute(
        text(
            "UPDATE findings SET severity = 'CRITICAL' "
            "WHERE (risk_description LIKE 'CRITICAL CHAIN:%' OR risk_description LIKE '%SUCCESS (CRITICAL)%') "
            "AND severity = 'MEDIUM'"
        )
    )
    for desc, sev in desc_to_severity.items():
        if sev != "MEDIUM":
            db.execute(
                text("UPDATE findings SET severity = :sev WHERE risk_description = :desc AND severity = 'MEDIUM'"),
                {"sev": sev, "desc": desc},
            )
    db.commit()
