from contextlib import asynccontextmanager
import csv
import io
import json
import os
from datetime import datetime
from fastapi import FastAPI, Depends, HTTPException, Request, Body, Query
from fastapi.responses import Response
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
from .bas import (
    simulate_token_theft,
    simulate_custom_script,
    simulate_container_socket_escape,
    simulate_host_filesystem_access,
    simulate_privilege_recon,
    simulate_env_secret_leak,
)

models.Base.metadata.create_all(bind=engine)

templates = Jinja2Templates(directory="templates")

DUMPS_DIR = "dumps"
os.makedirs(DUMPS_DIR, exist_ok=True)

_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


BAS_SIMULATION_MAP = {
    "token_theft": simulate_token_theft,
    "socket_escape": simulate_container_socket_escape,
    "host_filesystem": simulate_host_filesystem_access,
    "privilege_recon": simulate_privilege_recon,
    "env_leak": simulate_env_secret_leak,
}


def _severity_key(finding):
    return _SEVERITY_ORDER.get(getattr(finding, "severity", "MEDIUM"), 2)


def _pod_display_status(status: dict) -> str:
    """Return the most specific pod status visible to the user.

    kubectl derives CrashLoopBackOff, ImagePullBackOff, etc. from
    containerStatuses[*].state.waiting.reason, not from status.phase
    (which remains "Running" even when containers are crash-looping).
    """
    for cs in (status.get("containerStatuses") or []) + (status.get("initContainerStatuses") or []):
        state = cs.get("state") or {}
        waiting = state.get("waiting") or {}
        reason = waiting.get("reason", "")
        if reason:
            return reason
        terminated = state.get("terminated") or {}
        t_reason = terminated.get("reason", "")
        if t_reason and t_reason != "Completed":
            return t_reason
    return status.get("phase", "Unknown")


def _write_dump(items: list, prefix: str) -> str:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{prefix}_{ts}.yaml"
    path = os.path.join(DUMPS_DIR, filename)
    with open(path, "w", encoding="utf-8") as f:
        yaml.dump(
            {"apiVersion": "v1", "kind": "List", "items": items},
            f, allow_unicode=True, default_flow_style=False,
        )
    return filename


@asynccontextmanager
async def lifespan(app: FastAPI):
    db = SessionLocal()
    try:
        sync_rules_to_db(db)
        # Seed example BAS script if table is empty
        if db.query(models.BasScript).count() == 0:
            db.add(models.BasScript(
                name="Cloud Metadata Theft",
                description="Simulates attacking cloud metadata endpoints (IMDSv1/IMDSv2) to leak instance credentials.",
                script_content=(
                    "curl -s -m 2 -H 'Metadata: true' "
                    "http://metadata.google.internal/computeMetadata/v1/instance/"
                    "service-accounts/default/token 2>&1 || "
                    "curl -s -m 2 http://169.254.169.254/latest/meta-data/ 2>&1"
                ),
            ))
            db.commit()
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
                "phase": _pod_display_status(status),
                "node": spec.get("nodeName", ""),
                "sa": spec.get("serviceAccountName", "default"),
            })
        return {"pods": pods, "source": "live"}
    except Exception as e:
        return {"pods": [], "source": "unavailable", "error": str(e)}


@app.get("/dumps")
def list_dumps():
    files = sorted(
        [f for f in os.listdir(DUMPS_DIR) if f.endswith((".yaml", ".yml"))],
        reverse=True,
    ) if os.path.exists(DUMPS_DIR) else []
    if os.path.exists("cluster_dump.yaml") and "cluster_dump.yaml" not in files:
        files.append("cluster_dump.yaml")
    return files


@app.post("/dump/live")
def dump_live(
    namespace: str | None = Query(default=None),
    pod_name: str | None = Query(default=None),
):
    try:
        k8s_data = get_live_k8s_data()
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Failed to connect to K8s: {e}")

    pods = k8s_data.get("pods", [])
    services = k8s_data.get("services", [])
    roles = k8s_data.get("roles", [])
    cluster_roles = k8s_data.get("cluster_roles", [])
    role_bindings = k8s_data.get("role_bindings", [])
    cluster_role_bindings = k8s_data.get("cluster_role_bindings", [])

    if namespace:
        pods = [p for p in pods if p.get("metadata", {}).get("namespace") == namespace]
        services = [s for s in services if s.get("metadata", {}).get("namespace") == namespace]
        roles = [r for r in roles if r.get("metadata", {}).get("namespace") == namespace]
        role_bindings = [b for b in role_bindings if b.get("metadata", {}).get("namespace") == namespace]
    if pod_name:
        pods = [p for p in pods if p.get("metadata", {}).get("name") == pod_name]

    items = pods + services + roles + cluster_roles + role_bindings + cluster_role_bindings

    if pod_name and namespace:
        prefix = f"pod_{namespace}_{pod_name}"
    elif namespace:
        prefix = f"ns_{namespace}"
    else:
        prefix = "cluster"

    filename = _write_dump(items, prefix)
    return {"filename": filename, "items_count": len(items)}


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


# ── Scan exports ──────────────────────────────────────────────────────────────

def _get_scan_or_404(scan_id: int, db: Session) -> models.ScanHistory:
    scan = db.query(models.ScanHistory).filter(models.ScanHistory.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@app.get("/scans/{scan_id}/export/json")
def export_scan_json(scan_id: int, db: Session = Depends(get_db)):
    scan = _get_scan_or_404(scan_id, db)
    data = [
        {"severity": f.severity, "subject": f.subject, "role": f.role, "risk_description": f.risk_description}
        for f in sorted(scan.findings, key=_severity_key)
    ]
    return Response(
        content=json.dumps({"scan_id": scan_id, "target": scan.target_name, "date": str(scan.scan_date), "findings": data}, ensure_ascii=False, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="scan_{scan_id}_findings.json"'},
    )


@app.get("/scans/{scan_id}/export/csv")
def export_scan_csv(scan_id: int, db: Session = Depends(get_db)):
    scan = _get_scan_or_404(scan_id, db)
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["Severity", "Subject", "Context", "Risk Description"])
    for f in sorted(scan.findings, key=_severity_key):
        writer.writerow([f.severity, f.subject, f.role, f.risk_description])
    return Response(
        content=buf.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="scan_{scan_id}_findings.csv"'},
    )


@app.get("/scans/{scan_id}/export/markdown")
def export_scan_markdown(scan_id: int, db: Session = Depends(get_db)):
    scan = _get_scan_or_404(scan_id, db)
    findings = sorted(scan.findings, key=_severity_key)

    def esc(s: str) -> str:
        return s.replace("|", "\\|").replace("\n", " ")

    lines = [
        "# Kube Risk Analyzer — Scan Report",
        "",
        f"**Scan ID:** {scan.id}  ",
        f"**Target:** {scan.target_name}  ",
        f"**Date:** {scan.scan_date.strftime('%Y-%m-%d %H:%M:%S UTC')}  ",
        f"**Total Findings:** {len(findings)}  ",
        "",
        "## Findings",
        "",
        "| Severity | Subject | Context | Risk Description |",
        "|----------|---------|---------|-----------------|",
    ]
    for f in findings:
        lines.append(f"| {f.severity} | {esc(f.subject)} | {esc(f.role)} | {esc(f.risk_description)} |")

    return Response(
        content="\n".join(lines) + "\n",
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="scan_{scan_id}_report.md"'},
    )


@app.get("/scans/{scan_id}/export/sarif")
def export_scan_sarif(scan_id: int, db: Session = Depends(get_db)):
    scan = _get_scan_or_404(scan_id, db)
    findings = sorted(scan.findings, key=_severity_key)

    _level = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note"}

    rules: dict[str, dict] = {}
    results = []
    for f in findings:
        rule_id = f"KRA-{f.severity[:3]}-{abs(hash(f.risk_description)) % 9000 + 1000}"
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": f.risk_description[:80].replace(" ", "_"),
                "shortDescription": {"text": f.risk_description},
                "defaultConfiguration": {"level": _level.get(f.severity, "warning")},
                "properties": {"tags": ["security", f.severity.lower()]},
            }
        results.append({
            "ruleId": rule_id,
            "level": _level.get(f.severity, "warning"),
            "message": {"text": f.risk_description},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.subject, "uriBaseId": "%SRCROOT%"},
                    "region": {"startLine": 1},
                },
                "logicalLocations": [{"name": f.role, "kind": "member"}],
            }],
            "properties": {"severity": f.severity, "subject": f.subject, "context": f.role},
        })

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Kube Risk Analyzer",
                    "version": "1.0.0",
                    "informationUri": "https://github.com/kube-risk-analyzer",
                    "rules": list(rules.values()),
                }
            },
            "results": results,
            "automationDetails": {
                "id": f"scan/{scan_id}",
                "description": {"text": f"Scan of {scan.target_name} on {scan.scan_date}"},
            },
        }],
    }
    return Response(
        content=json.dumps(sarif, ensure_ascii=False, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="scan_{scan_id}_sarif.json"'},
    )


# ── Offline scan ──────────────────────────────────────────────────────────────

@app.post("/scan/offline")
def scan_offline(
    filename: str | None = Query(default=None),
    db: Session = Depends(get_db),
):
    if filename:
        safe = os.path.basename(filename)
        path_in_dumps = os.path.join(DUMPS_DIR, safe)
        if os.path.exists(path_in_dumps):
            filepath = path_in_dumps
        elif os.path.exists(safe):
            filepath = safe
        else:
            raise HTTPException(status_code=404, detail=f"Dump file not found: {safe}")
        target_name = safe
    else:
        filepath = "cluster_dump.yaml"
        target_name = "cluster_dump.yaml"
        if not os.path.exists(filepath):
            raise HTTPException(status_code=404, detail="No dump file found. Generate one first.")

    scan = models.ScanHistory(target_name=target_name)
    db.add(scan)
    db.commit()
    db.refresh(scan)

    with open(filepath, "r", encoding="utf-8") as f:
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

    # RBAC bindings scope:
    # - pod scope       → bindings referencing the pod's specific ServiceAccount
    # - namespace scope → namespace RoleBindings + ClusterRoleBindings whose
    #                     subjects include a ServiceAccount from that namespace
    # - full            → everything
    if pod_name:
        pod_sa = pods[0].get('spec', {}).get('serviceAccountName', 'default') if pods else None
        pod_ns_sa = pods[0].get('metadata', {}).get('namespace', namespace or 'default') if pods else (namespace or 'default')
        rbac_bindings = [
            b for b in all_bindings
            if pod_sa and any(
                s.get('kind') == 'ServiceAccount' and
                s.get('name') == pod_sa and
                s.get('namespace') == pod_ns_sa
                for s in (b.get('subjects') or [])
            )
        ]
    elif namespace:
        rbac_bindings = [
            b for b in all_bindings
            if b.get('metadata', {}).get('namespace') == namespace
            or (
                not b.get('metadata', {}).get('namespace') and
                any(
                    s.get('kind') == 'ServiceAccount' and s.get('namespace') == namespace
                    for s in (b.get('subjects') or [])
                )
            )
        ]
    else:
        rbac_bindings = all_bindings

    rbac_rules = db.query(models.RiskRule).filter(models.RiskRule.category == 'rbac').all()
    workload_rules = db.query(models.RiskRule).filter(models.RiskRule.category == 'workload').all()
    network_rules = db.query(models.RiskRule).filter(models.RiskRule.category == 'network').all()

    findings_count = 0

    # RBAC scan — runs for all scopes; for pod scope only covers that pod's SA
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
    # Resolve simulation function and label
    sim_func = None
    script_label = "Token Theft"

    if req.script_id:
        db_script = db.query(models.BasScript).filter(models.BasScript.id == req.script_id).first()
        if not db_script:
            raise HTTPException(status_code=404, detail="Script not found")
        sim_func = lambda pn, ns: simulate_custom_script(pn, ns, db_script.script_content)
        script_label = db_script.name
    elif req.simulation_type and req.simulation_type in BAS_SIMULATION_MAP:
        sim_func = BAS_SIMULATION_MAP[req.simulation_type]
        label_map = {
            "token_theft": "Token Theft",
            "socket_escape": "Socket Escape",
            "host_filesystem": "Host Filesystem Access",
            "privilege_recon": "Privilege Recon",
            "env_leak": "Env Secret Leak",
        }
        script_label = label_map.get(req.simulation_type, req.simulation_type.replace("_", " ").title())
    else:
        sim_func = simulate_token_theft

    scan = models.ScanHistory(target_name=f"BAS Simulation: {namespace}/{pod_name} [{script_label}]")
    db.add(scan)
    db.commit()
    db.refresh(scan)

    result = sim_func(pod_name, namespace)

    if result["success"]:
        severity = result.get("severity", "CRITICAL")
        risk_desc = f"🚨 SUCCESS ({severity}): {result['details']}"
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
