from kubernetes import client, config
from kubernetes.stream import stream

def simulate_token_theft(pod_name: str, namespace: str = "default") -> dict:
    try:
        config.load_kube_config()
    except config.ConfigException:
        try:
            config.load_incluster_config()
        except config.ConfigException:
            return {
                "pod": pod_name,
                "namespace": namespace,
                "attack": "read_sa_token",
                "success": False,
                "details": "Could not connect to Kubernetes cluster."
            }

    core_v1 = client.CoreV1Api()
    exec_command = ["/bin/sh", "-c", "cat /var/run/secrets/kubernetes.io/serviceaccount/token"]

    try:
        response = stream(
            core_v1.connect_get_namespaced_pod_exec,
            pod_name,
            namespace,
            command=exec_command,
            stderr=True,
            stdin=False,
            stdout=True,
            tty=False
        )

        if response and response.strip().startswith("ey"):
            snippet = response.strip()[:15] + "..."
            return {
                "pod": pod_name,
                "namespace": namespace,
                "attack": "read_sa_token",
                "success": True,
                "details": f"Successfully extracted ServiceAccount token: {snippet}"
            }
        else:
            return {
                "pod": pod_name,
                "namespace": namespace,
                "attack": "read_sa_token",
                "success": False,
                "details": f"Attack blocked or failed. Output: {response.strip() if response else 'None'}"
            }

    except Exception as e:
        return {
            "pod": pod_name,
            "namespace": namespace,
            "attack": "read_sa_token",
            "success": False,
            "details": f"Attack blocked or failed with error: {str(e)}"
        }
