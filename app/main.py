from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends, HTTPException, Request, Body, Query
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
from .bas import simulate_token_theft, simulate_custom_script

models.Base.metadata.create_all(bind=engine)

templates = Jinja2Templates(directory="templates")

_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

def _severity_key(finding):
    return _SEVERITY_ORDER.get(getattr(finding, "severity", "MEDIUM"), 2)


@asynccontextmanager
async def lifespan(app: FastAPI):
    db = SessionLocal()
    try:
        sync_rules_to_db(db)
        yield
    finally:
        db.close()

app = FastAPI(title="Kube Risk Analyzer API", lifespan=lifespan)


# ── Utility ───────────────────────────────────────────────────────────────────

@app.get("/")
def read_root(request: Request):
    return templates.TemplateResponse(request=request, name="index.html")

@app.get("/health")
def health_check():
    return {"status": "ok"}


# ── Cluster info ──────────────────────────────────────────────────────────────

@app.get("/cluster/pods")
def get_cluster_pod_list():
    try:
        k8s_data = get_live_k8s_data()
        pods = []
        for pod in k8s_data.get("pods", []):
            meta = pod.get("metadata", {})
            status = pod.get("status", {})
            spec = pod.get("spec", {})
            pods.append({
                "name": meta.get("name"),
                "namespace": meta.get("namespace", "default"),
                "phase": status.get("phase", "Unknown"),
                "node": spec.get("nodeName", ""),
            })
        return {"pods": pods, "source": "live"}
    except Exception as e:
        return {"pods": [], "source": "unavailable", "error": str(e)}


# ── Rules CRUD ────────────────────────────────────────────────────────────────

@app.get("/rules", response_model=list[schemas.RiskRuleSchema])
def get_rules(db: Session = Depends(get_db)):
    return db.query(models.RiskRule).all()

@app.post("/rules", response_model=schemas.RiskRuleSchema, status_code=201)
def create_rule(rule: schemas.RiskRuleCreate, db: Session = Depends(get_db)):
    db_rule = models.RiskRule(**rule.model_dump())
    db.add(db_rule)
    db.commit()
    db.refresh(db_rule)
    return db_rule

@app.put("/rules/{rule_id}", response_model=schemas.RiskRuleSchema)
def update_rule(rule_id: int, rule: schemas.RiskRuleUpdate, db: Session = Depends(get_db)):
    db_rule = db.query(models.RiskRule).filter(models.RiskRule.id == rule_id).first()
    if not db_rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    for field, value in rule.model_dump(exclude_none=True).items():
        setattr(db_rule, field, value)
    db.commit()
    db.refresh(db_rule)
    return db_rule

@app.delete("/rules/{rule_id}", status_code=204)
def delete_rule(rule_id: int, db: Session = Depends(get_db)):
    db_rule = db.query(models.RiskRule).filter(models.RiskRule.id == rule_id).first()
    if not db_rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    db.delete(db_rule)
    db.commit()


# ── Scans ─────────────────────────────────────────────────────────────────────

@app.get("/scans", response_model=list[schemas.ScanHistorySchema])
def get_scans(db: Session = Depends(get_db)):
    return db.query(models.ScanHistory).order_by(models.ScanHistory.id.desc()).all()

@app.get("/scans/{scan_id}", response_model=list[schemas.FindingSchema])
def get_scan(scan_id: int, db: Session = Depends(get_db)):
    findings = db.query(models.Finding).filter(models.Finding.scan_id == scan_id).all()
    return sorted(findings, key=_severity_key)

@app.delete("/scans/{scan_id}", status_code=204)
def delete_scan(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(models.ScanHistory).filter(models.ScanHistory.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    db.delete(scan)  # cascade="all, delete-orphan" removes findings automatically
    db.commit()


# ── Offline scan ──────────────────────────────────────────────────────────────

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
        db.add(models.Finding(
            scan_id=scan.id,
            subject=finding_data["subject"],
            role=finding_data["role"],
            risk_description=finding_data["risk_description"],
            severity=finding_data.get("severity", "MEDIUM"),
        ))

    for pod in pods:
        pod_name = pod.get("metadata", {}).get("name", "Unknown")
        pod_ns = pod.get("metadata", {}).get("namespace", "default")
        spec = pod.get("spec", {})
        sa_name = spec.get("serviceAccountName", "default")
        images = ", ".join([c.get("image", "Unknown") for c in spec.get("containers", [])])

        workload_dangers = analyze_pod_workload(pod, workload_rules)
        sa_rbac_dangers = get_sa_rbac_dangers(sa_name, pod_ns, bindings, roles, cluster_roles, rbac_rules)

        for danger_desc, danger_sev in workload_dangers:
            db.add(models.Finding(
                scan_id=scan.id,
                subject=f"Pod: {pod_name}",
                role=images,
                risk_description=danger_desc,
                severity=danger_sev,
            ))
            findings_count += 1

        if workload_dangers and sa_rbac_dangers:
            db.add(models.Finding(
                scan_id=scan.id,
                subject=f"Pod: {pod_name}",
                role=f"SA:{sa_name} | images: {images}",
                risk_description=(
                    f"CRITICAL CHAIN: Pod is vulnerable ({', '.join(d for d, _ in workload_dangers)}) "
                    f"and its ServiceAccount '{sa_name}' has dangerous RBAC rights "
                    f"({', '.join(d for d, _ in sa_rbac_dangers)})"
                ),
                severity="CRITICAL",
            ))
            findings_count += 1

    for net_f in analyze_services(services, network_rules):
        db.add(models.Finding(
            scan_id=scan.id,
            subject=net_f["subject"],
            role=net_f["role"],
            risk_description=net_f["risk_description"],
            severity=net_f.get("severity", "MEDIUM"),
        ))
        findings_count += 1

    db.commit()
    return {"scan_id": scan.id, "findings_count": findings_count, "status": "success"}


# ── Live scan ─────────────────────────────────────────────────────────────────

@app.post("/scan/live")
def scan_live(
    namespace: str | None = Query(default=None),
    pod_name: str | None = Query(default=None),
    db: Session = Depends(get_db),
):
    if pod_name and namespace:
        target_name = f"Live Pod: {namespace}/{pod_name}"
    elif namespace:
        target_name = f"Live Namespace: {namespace}"
    else:
        target_name = "Live Cluster"

    scan = models.ScanHistory(target_name=target_name)
    db.add(scan)
    db.commit()
    db.refresh(scan)

    try:
        k8s_data = get_live_k8s_data()
    except Exception as e:
        db.delete(scan)
        db.commit()
        raise HTTPException(status_code=503, detail=f"Failed to connect to Kubernetes cluster: {e}")

    # Build full roles/cluster_roles dicts — needed for RBAC correlation in all modes
    roles = {}
    for r in k8s_data.get('roles', []):
        r_ns = r.get('metadata', {}).get('namespace', 'default')
        r_name = r.get('metadata', {}).get('name')
        roles[f"Role/{r_ns}/{r_name}"] = r

    cluster_roles = {}
    for cr in k8s_data.get('cluster_roles', []):
        cr_name = cr.get('metadata', {}).get('name')
        cluster_roles[f"ClusterRole/{cr_name}"] = cr

    all_bindings = k8s_data.get('role_bindings', []) + k8s_data.get('cluster_role_bindings', [])

    # Filter pods
    pods = k8s_data.get('pods', [])
    if namespace:
        pods = [p for p in pods if p.get('metadata', {}).get('namespace') == namespace]
    if pod_name:
        pods = [p for p in pods if p.get('metadata', {}).get('name') == pod_name]

    # Filter services (skip for single-pod scope)
    if pod_name:
        services = []
    else:
        services = k8s_data.get('services', [])
        if namespace:
            services = [s for s in services if s.get('metadata', {}).get('namespace') == namespace]

    # RBAC bindings to scan (skip full RBAC for single-pod scope)
    if pod_name:
        rbac_bindings = []
    elif namespace:
        rbac_bindings = [
            b for b in all_bindings
            if b.get('metadata', {}).get('namespace') == namespace
            or b.get('kind') == 'ClusterRoleBinding'
        ]
    else:
        rbac_bindings = all_bindings

    rbac_rules = db.query(models.RiskRule).filter(models.RiskRule.category == 'rbac').all()
    workload_rules = db.query(models.RiskRule).filter(models.RiskRule.category == 'workload').all()
    network_rules = db.query(models.RiskRule).filter(models.RiskRule.category == 'network').all()

    findings_count = 0

    # RBAC scan (full cluster or namespace scope)
    if not pod_name:
        rbac_findings = analyze_rbac_bindings(rbac_bindings, roles, cluster_roles, rbac_rules)
        findings_count += len(rbac_findings)
        for f in rbac_findings:
            db.add(models.Finding(
                scan_id=scan.id,
                subject=f["subject"],
                role=f["role"],
                risk_description=f["risk_description"],
                severity=f.get("severity", "MEDIUM"),
            ))

    # Workload scan + SA RBAC correlation
    for pod in pods:
        p_name = pod.get("metadata", {}).get("name", "Unknown")
        p_ns = pod.get("metadata", {}).get("namespace", "default")
        spec = pod.get("spec", {})
        sa_name = spec.get("serviceAccountName", "default")
        images = ", ".join([c.get("image", "Unknown") for c in spec.get("containers", [])])

        workload_dangers = analyze_pod_workload(pod, workload_rules)
        sa_rbac_dangers = get_sa_rbac_dangers(sa_name, p_ns, all_bindings, roles, cluster_roles, rbac_rules)

        for danger_desc, danger_sev in workload_dangers:
            db.add(models.Finding(
                scan_id=scan.id,
                subject=f"Pod: {p_name}",
                role=images,
                risk_description=danger_desc,
                severity=danger_sev,
            ))
            findings_count += 1

        if workload_dangers and sa_rbac_dangers:
            db.add(models.Finding(
                scan_id=scan.id,
                subject=f"Pod: {p_name}",
                role=f"SA:{sa_name} | images: {images}",
                risk_description=(
                    f"CRITICAL CHAIN: Pod is vulnerable ({', '.join(d for d, _ in workload_dangers)}) "
                    f"and its ServiceAccount '{sa_name}' has dangerous RBAC rights "
                    f"({', '.join(d for d, _ in sa_rbac_dangers)})"
                ),
                severity="CRITICAL",
            ))
            findings_count += 1

    # Network scan (full cluster or namespace scope)
    if not pod_name:
        for net_f in analyze_services(services, network_rules):
            db.add(models.Finding(
                scan_id=scan.id,
                subject=net_f["subject"],
                role=net_f["role"],
                risk_description=net_f["risk_description"],
                severity=net_f.get("severity", "MEDIUM"),
            ))
            findings_count += 1

    db.commit()
    return {"scan_id": scan.id, "status": "success", "findings_count": findings_count}


# ── BAS Scripts CRUD ──────────────────────────────────────────────────────────

@app.get("/scripts", response_model=list[schemas.BasScriptSchema])
def get_scripts(db: Session = Depends(get_db)):
    return db.query(models.BasScript).order_by(models.BasScript.id).all()

@app.post("/scripts", response_model=schemas.BasScriptSchema, status_code=201)
def create_script(script: schemas.BasScriptCreate, db: Session = Depends(get_db)):
    db_script = models.BasScript(**script.model_dump())
    db.add(db_script)
    db.commit()
    db.refresh(db_script)
    return db_script

@app.put("/scripts/{script_id}", response_model=schemas.BasScriptSchema)
def update_script(script_id: int, script: schemas.BasScriptUpdate, db: Session = Depends(get_db)):
    db_script = db.query(models.BasScript).filter(models.BasScript.id == script_id).first()
    if not db_script:
        raise HTTPException(status_code=404, detail="Script not found")
    for field, value in script.model_dump(exclude_none=True).items():
        setattr(db_script, field, value)
    db.commit()
    db.refresh(db_script)
    return db_script

@app.delete("/scripts/{script_id}", status_code=204)
def delete_script(script_id: int, db: Session = Depends(get_db)):
    db_script = db.query(models.BasScript).filter(models.BasScript.id == script_id).first()
    if not db_script:
        raise HTTPException(status_code=404, detail="Script not found")
    db.delete(db_script)
    db.commit()


# ── BAS simulate ──────────────────────────────────────────────────────────────

@app.post("/bas/simulate/{namespace}/{pod_name}")
def simulate_bas(
    namespace: str,
    pod_name: str,
    req: schemas.BASSimulateRequest = Body(default=schemas.BASSimulateRequest()),
    db: Session = Depends(get_db),
):
    script_content = None
    script_label = "Token Theft"
    if req.script_id:
        db_script = db.query(models.BasScript).filter(models.BasScript.id == req.script_id).first()
        if not db_script:
            raise HTTPException(status_code=404, detail="Script not found")
        script_content = db_script.script_content
        script_label = db_script.name

    scan = models.ScanHistory(target_name=f"BAS Simulation: {namespace}/{pod_name} [{script_label}]")
    db.add(scan)
    db.commit()
    db.refresh(scan)

    if script_content:
        result = simulate_custom_script(pod_name, namespace, script_content)
    else:
        result = simulate_token_theft(pod_name, namespace)

    if result["success"]:
        risk_desc = f"🚨 SUCCESS (CRITICAL): {result['details']}"
        severity = "CRITICAL"
    else:
        risk_desc = f"✅ BLOCKED: {result['details']}"
        severity = "LOW"

    db.add(models.Finding(
        scan_id=scan.id,
        subject=f"Pod: {pod_name} (Active Exploit)",
        role=f"Namespace: {namespace}",
        risk_description=risk_desc,
        severity=severity,
    ))
    db.commit()
    return {**result, "scan_id": scan.id}
