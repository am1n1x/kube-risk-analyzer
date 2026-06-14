def analyze_services(services: list[dict], db_network_rules) -> list[dict]:
    all_findings = []

    nodeport_desc = "NodePort service exposed"
    nodeport_sev = "MEDIUM"
    lb_desc = "LoadBalancer service exposed"
    lb_sev = "MEDIUM"
    db_desc = "Database exposed"
    db_sev = "CRITICAL"

    for rule in db_network_rules:
        desc_lower = rule.description.lower()
        sev = getattr(rule, "severity", "MEDIUM")
        if "nodeport" in desc_lower:
            nodeport_desc = rule.description
            nodeport_sev = sev
        elif "loadbalancer" in desc_lower:
            lb_desc = rule.description
            lb_sev = sev
        elif "база данных" in desc_lower:
            db_desc = rule.description
            db_sev = sev

    db_ports = {5432, 3306, 27017, 6379}

    for svc in services:
        service_name = svc.get("metadata", {}).get("name", "Unknown")
        spec = svc.get("spec", {})
        service_type = spec.get("type", "ClusterIP")
        ports = spec.get("ports", [])

        dangers = []
        if service_type == "NodePort":
            dangers.append((nodeport_desc, nodeport_sev))
        elif service_type == "LoadBalancer":
            dangers.append((lb_desc, lb_sev))

        for p in ports:
            port_num = p.get("port")
            target_port = p.get("targetPort")

            if (port_num in db_ports or target_port in db_ports) and service_type in ["NodePort", "LoadBalancer"]:
                exposed_port = port_num if port_num in db_ports else target_port
                dangers.append((
                    f"КРИТИЧЕСКИЙ РИСК: База данных {exposed_port} доступна извне! ({db_desc})",
                    db_sev,
                ))

        for danger_desc, danger_sev in dangers:
            all_findings.append({
                "subject": f"Service: {service_name}",
                "role": f"Type: {service_type}",
                "risk_description": danger_desc,
                "severity": danger_sev,
            })

    return all_findings
