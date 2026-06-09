from kubernetes import client, config

def get_live_k8s_data() -> dict:
    try:
        config.load_kube_config()
    except config.ConfigException:
        config.load_incluster_config()

    api_client = client.ApiClient()
    core_v1 = client.CoreV1Api()
    rbac_v1 = client.RbacAuthorizationV1Api()

    def serialize(items):
        return [api_client.sanitize_for_serialization(item) for item in items]

    pods = serialize(core_v1.list_pod_for_all_namespaces().items)
    services = serialize(core_v1.list_service_for_all_namespaces().items)
    roles = serialize(rbac_v1.list_role_for_all_namespaces().items)
    cluster_roles = serialize(rbac_v1.list_cluster_role().items)
    role_bindings = serialize(rbac_v1.list_role_binding_for_all_namespaces().items)
    cluster_role_bindings = serialize(rbac_v1.list_cluster_role_binding().items)

    return {
        "pods": pods,
        "services": services,
        "roles": roles,
        "cluster_roles": cluster_roles,
        "role_bindings": role_bindings,
        "cluster_role_bindings": cluster_role_bindings
    }
