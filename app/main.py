from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
import yaml
from . import models, schemas
from .database import engine, SessionLocal, get_db
from .rules import sync_rules_to_db
from .scanners.rbac import analyze_rbac_bindings, get_sa_rbac_dangers
from .scanners.workload import analyze_pod_workload
from .scanners.network import analyze_services
from .k8s_client import get_live_k8s_data
from .bas import simulate_token_theft

models.Base.metadata.create_all(bind=engine)

templates = Jinja2Templates(directory="templates")

@asynccontextmanager
async def lifespan(app: FastAPI):
    db = SessionLocal()
    try:
        sync_rules_to_db(db)
        yield
    finally:
        db.close()

app = FastAPI(title="Kube Risk Analyzer API", lifespan=lifespan)

@app.get("/")
def read_root(request: Request):
    return templates.TemplateResponse(request=request, name="index.html")

@app.get("/health")
def health_check():
    return {"status": "ok"}

@app.get("/rules", response_model=list[schemas.RiskRuleSchema])
def get_rules(db: Session = Depends(get_db)):
    rules = db.query(models.RiskRule).all()
    return rules

@app.post("/scan/offline")
def scan_offline(db: Session = Depends(get_db)):
    scan = models.ScanHistory(target_name="cluster_dump.yaml")
    db.add(scan)
    db.commit()
    db.refresh(scan)

    with open("cluster_dump.yaml", "r", encoding="utf-8") as f:
        docs = yaml.safe_load_all(f)
        items = []
        for doc in docs:
            if not doc:
                continue
            if doc.get("kind") == "List":
                items.extend(doc.get("items", []))
            else:
                items.append(doc)

    roles = {}
    cluster_roles = {}
    bindings = []
    pods = []
    services = []

    for item in items:
        kind = item.get("kind")
        name = item.get("metadata", {}).get("name")
        namespace = item.get("metadata", {}).get("namespace", "default")

        if kind == "Role":
            roles[f"Role/{namespace}/{name}"] = item
        elif kind == "ClusterRole":
            cluster_roles[f"ClusterRole/{name}"] = item
        elif kind in ["RoleBinding", "ClusterRoleBinding"]:
            bindings.append(item)
        elif kind == "Pod":
            pods.append(item)
        elif kind == "Service":
            services.append(item)

    rbac_rules = db.query(models.RiskRule).filter(models.RiskRule.category == 'rbac').all()
    workload_rules = db.query(models.RiskRule).filter(models.RiskRule.category == 'workload').all()
    network_rules = db.query(models.RiskRule).filter(models.RiskRule.category == 'network').all()

    findings = analyze_rbac_bindings(bindings, roles, cluster_roles, rbac_rules)
    findings_count = len(findings)

    for finding_data in findings:
        finding = models.Finding(
            scan_id=scan.id,
            subject=finding_data["subject"],
            role=finding_data["role"],
            risk_description=finding_data["risk_description"]
        )
        db.add(finding)

    for pod in pods:
        pod_name = pod.get("metadata", {}).get("name", "Unknown")
        pod_ns = pod.get("metadata", {}).get("namespace", "default")
        spec = pod.get("spec", {})
        sa_name = spec.get("serviceAccountName", "default")

        containers = spec.get("containers", [])
        images = ", ".join([c.get("image", "Unknown") for c in containers])

        workload_dangers = analyze_pod_workload(pod, workload_rules)
        sa_rbac_dangers = get_sa_rbac_dangers(sa_name, pod_ns, bindings, roles, cluster_roles, rbac_rules)

        for danger in workload_dangers:
            finding = models.Finding(
                scan_id=scan.id,
                subject=f"Pod: {pod_name}",
                role=images,
                risk_description=danger
            )
            db.add(finding)
            findings_count += 1

        if workload_dangers and sa_rbac_dangers:
            correlated = models.Finding(
                scan_id=scan.id,
                subject=f"Pod: {pod_name}",
                role=f"SA:{sa_name} | images: {images}",
                risk_description=f"CRITICAL CHAIN: Pod is vulnerable ({', '.join(workload_dangers)}) and its ServiceAccount '{sa_name}' has dangerous RBAC rights ({', '.join(sa_rbac_dangers)})"
            )
            db.add(correlated)
            findings_count += 1

    net_findings = analyze_services(services, network_rules)
    for net_f in net_findings:
        finding = models.Finding(
            scan_id=scan.id,
            subject=net_f["subject"],
            role=net_f["role"],
            risk_description=net_f["risk_description"]
        )
        db.add(finding)
        findings_count += 1

    db.commit()

    return {"scan_id": scan.id, "findings_count": findings_count, "status": "success"}


@app.post("/scan/live")
def scan_live(db: Session = Depends(get_db)):
    scan = models.ScanHistory(target_name="Live Cluster (Minikube)")
    db.add(scan)
    db.commit()
    db.refresh(scan)

    try:
        k8s_data = get_live_k8s_data()
    except Exception as e:
        db.delete(scan)
        db.commit()
        raise HTTPException(status_code=503, detail=f"Failed to connect to Kubernetes cluster: {e}")

    roles = {}
    for r in k8s_data.get('roles', []):
        namespace = r.get('metadata', {}).get('namespace', 'default')
        name = r.get('metadata', {}).get('name')
        roles[f"Role/{namespace}/{name}"] = r

    cluster_roles = {}
    for cr in k8s_data.get('cluster_roles', []):
        name = cr.get('metadata', {}).get('name')
        cluster_roles[f"ClusterRole/{name}"] = cr

    bindings = k8s_data.get('role_bindings', []) + k8s_data.get('cluster_role_bindings', [])
    pods = k8s_data.get('pods', [])
    services = k8s_data.get('services', [])

    rbac_rules = db.query(models.RiskRule).filter(models.RiskRule.category == 'rbac').all()
    workload_rules = db.query(models.RiskRule).filter(models.RiskRule.category == 'workload').all()
    network_rules = db.query(models.RiskRule).filter(models.RiskRule.category == 'network').all()

    findings = analyze_rbac_bindings(bindings, roles, cluster_roles, rbac_rules)
    findings_count = len(findings)

    for finding_data in findings:
        finding = models.Finding(
            scan_id=scan.id,
            subject=finding_data["subject"],
            role=finding_data["role"],
            risk_description=finding_data["risk_description"]
        )
        db.add(finding)

    for pod in pods:
        pod_name = pod.get("metadata", {}).get("name", "Unknown")
        pod_ns = pod.get("metadata", {}).get("namespace", "default")
        spec = pod.get("spec", {})
        sa_name = spec.get("serviceAccountName", "default")

        containers = spec.get("containers", [])
        images = ", ".join([c.get("image", "Unknown") for c in containers])

        workload_dangers = analyze_pod_workload(pod, workload_rules)
        sa_rbac_dangers = get_sa_rbac_dangers(sa_name, pod_ns, bindings, roles, cluster_roles, rbac_rules)

        for danger in workload_dangers:
            finding = models.Finding(
                scan_id=scan.id,
                subject=f"Pod: {pod_name}",
                role=images,
                risk_description=danger
            )
            db.add(finding)
            findings_count += 1

        if workload_dangers and sa_rbac_dangers:
            correlated = models.Finding(
                scan_id=scan.id,
                subject=f"Pod: {pod_name}",
                role=f"SA:{sa_name} | images: {images}",
                risk_description=f"CRITICAL CHAIN: Pod is vulnerable ({', '.join(workload_dangers)}) and its ServiceAccount '{sa_name}' has dangerous RBAC rights ({', '.join(sa_rbac_dangers)})"
            )
            db.add(correlated)
            findings_count += 1

    net_findings = analyze_services(services, network_rules)
    for net_f in net_findings:
        finding = models.Finding(
            scan_id=scan.id,
            subject=net_f["subject"],
            role=net_f["role"],
            risk_description=net_f["risk_description"]
        )
        db.add(finding)
        findings_count += 1

    db.commit()

    return {"scan_id": scan.id, "status": "success", "findings_count": findings_count}


@app.get("/scans/{scan_id}", response_model=list[schemas.FindingSchema])
def get_scan(scan_id: int, db: Session = Depends(get_db)):
    findings = db.query(models.Finding).filter(models.Finding.scan_id == scan_id).all()
    return findings

@app.get("/scans", response_model=list[schemas.ScanHistorySchema])
def get_scans(db: Session = Depends(get_db)):
    scans = db.query(models.ScanHistory).order_by(models.ScanHistory.id.desc()).all()
    return scans


@app.post("/bas/simulate/{namespace}/{pod_name}")
def simulate_bas(namespace: str, pod_name: str, db: Session = Depends(get_db)):
    scan = models.ScanHistory(target_name=f"BAS Simulation: {namespace}/{pod_name}")
    db.add(scan)
    db.commit()
    db.refresh(scan)

    result = simulate_token_theft(pod_name, namespace)

    if result["success"]:
        risk_desc = f"🚨 SUCCESS (CRITICAL): {result['details']}"
    else:
        risk_desc = f"✅ BLOCKED: {result['details']}"

    finding = models.Finding(
        scan_id=scan.id,
        subject=f"Pod: {pod_name} (Active Exploit)",
        role=f"Namespace: {namespace}",
        risk_description=risk_desc,
    )
    db.add(finding)
    db.commit()

    return {**result, "scan_id": scan.id}
