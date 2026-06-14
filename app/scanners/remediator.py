import copy

_WORKLOAD_KINDS = {"Deployment", "DaemonSet", "StatefulSet", "ReplicaSet", "Job"}


def remediate_pod_spec(spec: dict) -> None:
    """Mutate a pod spec in-place to conform to PSS Restricted profile."""
    for field in ("hostNetwork", "hostPID", "hostIPC"):
        if field in spec:
            spec[field] = False

    pod_sc = spec.setdefault("securityContext", {})
    pod_sc["runAsNonRoot"] = True

    for container_list_key in ("containers", "initContainers"):
        for container in spec.get(container_list_key, []):
            csc = container.setdefault("securityContext", {})
            csc["privileged"] = False
            csc["allowPrivilegeEscalation"] = False
            caps = csc.setdefault("capabilities", {})
            caps["drop"] = ["ALL"]
            caps.pop("add", None)


def remediate_item(item: dict) -> dict:
    """Return a deep copy of the K8s object with its pod spec hardened."""
    item = copy.deepcopy(item)
    kind = item.get("kind", "")

    if kind == "Pod":
        remediate_pod_spec(item.get("spec", {}))
    elif kind in _WORKLOAD_KINDS:
        remediate_pod_spec(
            item.get("spec", {}).get("template", {}).get("spec", {})
        )
    elif kind == "CronJob":
        remediate_pod_spec(
            item.get("spec", {})
                .get("jobTemplate", {})
                .get("spec", {})
                .get("template", {})
                .get("spec", {})
        )

    return item
