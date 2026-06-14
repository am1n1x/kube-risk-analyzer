def evaluate_rbac_rule(role_verbs: list[str], role_resources: list[str], db_rules) -> list[tuple]:
    """Returns list of (description, severity) tuples for matched rules."""
    findings = []

    role_verbs_set = set(role_verbs)
    role_resources_set = set(role_resources)

    for rule in db_rules:
        danger_verbs = []
        if rule.dangerous_verbs:
            danger_verbs = [v.strip() for v in rule.dangerous_verbs.split(",")]

        danger_resources = []
        if rule.dangerous_resources:
            danger_resources = [r.strip() for r in rule.dangerous_resources.split(",")]

        verbs_match = False
        if "*" in role_verbs or "*" in danger_verbs:
            verbs_match = True
        elif set(danger_verbs) & role_verbs_set:
            verbs_match = True

        if not verbs_match and danger_verbs:
            continue

        resources_match = False
        if "*" in role_resources or "*" in danger_resources:
            resources_match = True
        elif set(danger_resources) & role_resources_set:
            resources_match = True

        if verbs_match and resources_match:
            findings.append((rule.description, getattr(rule, "severity", "MEDIUM")))

    return findings


def analyze_rbac_bindings(bindings: list[dict], roles: dict, cluster_roles: dict, db_rbac_rules) -> list[dict]:
    all_findings = []

    for binding in bindings:
        role_ref = binding.get("roleRef", {})
        kind = role_ref.get("kind")
        name = role_ref.get("name")

        namespace = binding.get("metadata", {}).get("namespace", "default")

        target_role = None
        if kind == "Role":
            target_role = roles.get(f"Role/{namespace}/{name}")
        elif kind == "ClusterRole":
            target_role = cluster_roles.get(f"ClusterRole/{name}")

        if not target_role:
            continue

        for rule in target_role.get("rules", []):
            role_verbs = rule.get("verbs", [])
            role_resources = rule.get("resources", [])

            dangers = evaluate_rbac_rule(role_verbs, role_resources, db_rbac_rules)

            for description, severity in dangers:
                subjects = binding.get("subjects") or []
                for subject in subjects:
                    subject_str = f"{subject.get('kind', 'Unknown')}:{subject.get('name', 'Unknown')}"
                    role_str = f"{kind}/{name}"

                    finding = {
                        "subject": subject_str,
                        "role": role_str,
                        "risk_description": description,
                        "severity": severity,
                    }
                    if finding not in all_findings:
                        all_findings.append(finding)

    return all_findings


def get_sa_rbac_dangers(sa_name: str, namespace: str, bindings: list[dict], roles: dict, cluster_roles: dict, db_rules) -> list[tuple]:
    """Returns list of (description, severity) tuples for the given ServiceAccount."""
    dangers_found = []
    seen = set()

    for binding in bindings:
        subjects = binding.get("subjects") or []
        for subject in subjects:
            subj_ns = subject.get("namespace", binding.get("metadata", {}).get("namespace", "default"))
            if subject.get("kind") == "ServiceAccount" and subject.get("name") == sa_name and subj_ns == namespace:
                role_ref = binding.get("roleRef", {})
                kind = role_ref.get("kind")
                name = role_ref.get("name")

                binding_ns = binding.get("metadata", {}).get("namespace", "default")

                target_role = None
                if kind == "Role":
                    target_role = roles.get(f"Role/{binding_ns}/{name}")
                elif kind == "ClusterRole":
                    target_role = cluster_roles.get(f"ClusterRole/{name}")

                if target_role:
                    for rule in target_role.get("rules", []):
                        role_verbs = rule.get("verbs", [])
                        role_resources = rule.get("resources", [])
                        dangers = evaluate_rbac_rule(role_verbs, role_resources, db_rules)
                        for d, sev in dangers:
                            if d not in seen:
                                seen.add(d)
                                dangers_found.append((d, sev))

    return dangers_found
