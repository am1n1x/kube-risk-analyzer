def _path_matches(data, path_parts: list[str]) -> bool:
    if isinstance(data, list):
        return any(_path_matches(item, path_parts) for item in data)
    if not path_parts:
        return bool(data)
    if isinstance(data, dict) and path_parts[0] in data:
        return _path_matches(data[path_parts[0]], path_parts[1:])
    return False

def analyze_pod_workload(pod_data: dict, db_workload_rules) -> list[tuple]:
    """Returns list of (description, severity) tuples for matched workload rules."""
    dangers_found = []
    for rule in db_workload_rules:
        if rule.key:
            path_parts = rule.key.split('.')
            if _path_matches(pod_data, path_parts):
                dangers_found.append((rule.description, getattr(rule, "severity", "MEDIUM")))
    return dangers_found
