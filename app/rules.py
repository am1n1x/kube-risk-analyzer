import json
from sqlalchemy import text
from sqlalchemy.orm import Session
from .models import RiskRule


def sync_rules_to_db(db: Session, file_path: str = "rules.json"):
    # If the table already has records the user may have edited them — don't overwrite.
    if db.query(RiskRule).count() > 0:
        return

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read().strip()
            rules = json.loads(content) if content else []
    except (FileNotFoundError, json.JSONDecodeError):
        rules = []

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
            severity=rule.get("severity", "MEDIUM"),
            remediation=rule.get("remediation"),
        )
        db.add(db_rule)

    db.commit()
