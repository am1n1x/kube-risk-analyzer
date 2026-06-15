from contextlib import asynccontextmanager
import csv
import io
import json
import os
import sqlite3
import tempfile
import uuid
from datetime import datetime
from fastapi import FastAPI, BackgroundTasks, Depends, HTTPException, Request, Body, Query, Response as FastAPIResponse
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
import yaml
from . import models, schemas
from .database import SessionLocal, get_db
from .rules import sync_rules_to_db
from .scanners.rbac import analyze_rbac_bindings, get_sa_rbac_dangers
from .scanners.workload import analyze_pod_workload
from .scanners.network import analyze_services
from .scanners.remediator import remediate_item
from .k8s_client import get_live_k8s_data
from .bas import simulate_custom_script
from .auth_utils import hash_password, verify_password

templates = Jinja2Templates(directory="templates")

DUMPS_DIR = "dumps"
os.makedirs(DUMPS_DIR, exist_ok=True)

BACKUPS_DIR = "backups"
os.makedirs(BACKUPS_DIR, exist_ok=True)

DB_PATH = "kube_risk.db"

_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


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
        # Seed default admin user if table is empty
        if db.query(models.User).count() == 0:
            admin = models.User(
                username="admin",
                password_hash=hash_password("KubeRisk2026!"),
            )
            db.add(admin)
            db.commit()
            print("[kube-risk-analyzer] Default admin user created (username: admin)")
        # Seed default BAS scripts if table is empty
        if db.query(models.BasScript).count() == 0:
            defaults = [
                models.BasScript(
                    name="Token Theft",
                    description="Reads the mounted ServiceAccount token from the pod.",
                    script_content="cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>&1",
                    is_default=True, is_enabled=True,
                ),
                models.BasScript(
                    name="Container Socket Escape",
                    description="Detects mounted container runtime sockets (docker/containerd/crio).",
                    script_content="ls -la /var/run/docker.sock /run/containerd/containerd.sock /var/run/crio/crio.sock 2>&1",
                    is_default=True, is_enabled=True,
                ),
                models.BasScript(
                    name="Host Filesystem Access",
                    description="Probes hostPath mounts and node-level credential locations.",
                    script_content="ls -la /host /etc/shadow 2>&1",
                    is_default=True, is_enabled=True,
                ),
                models.BasScript(
                    name="Privilege Recon",
                    description="Checks for root user and CAP_SYS_ADMIN capability.",
                    script_content="id 2>&1; cat /proc/self/status | grep -i CapEff 2>&1",
                    is_default=True, is_enabled=True,
                ),
                models.BasScript(
                    name="Env Secret Leak",
                    description="Harvests environment variables matching secret patterns (PASSWORD, SECRET, TOKEN, etc.).",
                    script_content="env | grep -E 'PASSWORD|SECRET|TOKEN|APIKEY|AWS_' 2>&1",
                    is_default=True, is_enabled=True,
                ),
                models.BasScript(
                    name="Cloud Metadata Theft",
                    description="Simulates attacking cloud metadata endpoints (IMDSv1/IMDSv2) to leak instance credentials.",
                    script_content=(
                        "curl -s -m 2 -H 'Metadata: true' "
                        "http://metadata.google.internal/computeMetadata/v1/instance/"
                        "service-accounts/default/token 2>&1 || "
                        "curl -s -m 2 http://169.254.169.254/latest/meta-data/ 2>&1"
                    ),
                    is_default=False, is_enabled=True,
                ),
            ]
            for s in defaults:
                db.add(s)
            db.commit()
        yield
    finally:
        db.close()

app = FastAPI(title="Kube Risk Analyzer API", lifespan=lifespan)
app.mount("/static", StaticFiles(directory="app/static"), name="static")


# ── Auth dependency ───────────────────────────────────────────────────────────

def get_current_user(request: Request, db: Session = Depends(get_db)) -> models.User:
    session_id = request.cookies.get("kra_session")
    if not session_id:
        raise HTTPException(status_code=401, detail="Not authenticated")
    session = db.query(models.Session).filter(models.Session.session_id == session_id).first()
    if not session:
        raise HTTPException(status_code=401, detail="Invalid or expired session")
    return session.user


# ── Auth endpoints ────────────────────────────────────────────────────────────

@app.post("/auth/login")
def login(body: schemas.LoginRequest, response: FastAPIResponse, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.username == body.username).first()
    if not user or not verify_password(body.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    session_id = str(uuid.uuid4())
    db.add(models.Session(session_id=session_id, user_id=user.id))
    db.commit()
    response.set_cookie(
        key="kra_session",
        value=session_id,
        httponly=True,
        samesite="lax",
        secure=False,  # set True when TLS is terminated by the app itself
    )
    return {"status": "success", "username": user.username}


@app.post("/auth/logout")
def logout(request: Request, response: FastAPIResponse, db: Session = Depends(get_db)):
    session_id = request.cookies.get("kra_session")
    if session_id:
        db.query(models.Session).filter(models.Session.session_id == session_id).delete()
        db.commit()
    response.delete_cookie(key="kra_session")
    return {"status": "logged out"}


# ── Utility ───────────────────────────────────────────────────────────────────

@app.get("/")
def read_root(request: Request):
    return templates.TemplateResponse(request=request, name="index.html")

@app.get("/health")
def health_check():
    return {"status": "ok"}


# ── Database backup ───────────────────────────────────────────────────────────

@app.get("/db/backup/download")
def backup_download(background_tasks: BackgroundTasks, _: models.User = Depends(get_current_user)):
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
    tmp_path = tmp.name
    tmp.close()

    src = sqlite3.connect(DB_PATH)
    dst = sqlite3.connect(tmp_path)
    src.backup(dst)
    dst.close()
    src.close()

    filename = f"kube_risk_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
    background_tasks.add_task(os.remove, tmp_path)
    return FileResponse(
        path=tmp_path,
        media_type="application/octet-stream",
        filename=filename,
        background=background_tasks,
    )


@app.post("/db/backup/server")
def backup_server(_: models.User = Depends(get_current_user)):
    filename = f"kube_risk_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
    dest_path = os.path.join(BACKUPS_DIR, filename)

    src = sqlite3.connect(DB_PATH)
    dst = sqlite3.connect(dest_path)
    src.backup(dst)
    dst.close()
    src.close()

    return {"status": "success", "filename": filename}


# ── Cluster info ──────────────────────────────────────────────────────────────

@app.get("/cluster/pods")
def get_cluster_pod_list(_: models.User = Depends(get_current_user)):
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
def list_dumps(_: models.User = Depends(get_current_user)):
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
    _: models.User = Depends(get_current_user),
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

    # sanitize_for_serialization strips kind/apiVersion from each item — restore them
    for item in pods:
        item["kind"] = "Pod"
        item["apiVersion"] = "v1"
    for item in services:
        item["kind"] = "Service"
        item["apiVersion"] = "v1"
    for item in roles:
        item["kind"] = "Role"
        item["apiVersion"] = "rbac.authorization.k8s.io/v1"
    for item in cluster_roles:
        item["kind"] = "ClusterRole"
        item["apiVersion"] = "rbac.authorization.k8s.io/v1"
    for item in role_bindings:
        item["kind"] = "RoleBinding"
        item["apiVersion"] = "rbac.authorization.k8s.io/v1"
    for item in cluster_role_bindings:
        item["kind"] = "ClusterRoleBinding"
        item["apiVersion"] = "rbac.authorization.k8s.io/v1"

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
def get_rules(db: Session = Depends(get_db), _: models.User = Depends(get_current_user)):
    return db.query(models.RiskRule).all()

@app.post("/rules", response_model=schemas.RiskRuleSchema, status_code=201)
def create_rule(rule: schemas.RiskRuleCreate, db: Session = Depends(get_db), _: models.User = Depends(get_current_user)):
    db_rule = models.RiskRule(**rule.model_dump())
    db.add(db_rule)
    db.commit()
    db.refresh(db_rule)
    return db_rule

@app.put("/rules/{rule_id}", response_model=schemas.RiskRuleSchema)
def update_rule(rule_id: int, rule: schemas.RiskRuleUpdate, db: Session = Depends(get_db), _: models.User = Depends(get_current_user)):
    db_rule = db.query(models.RiskRule).filter(models.RiskRule.id == rule_id).first()
    if not db_rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    for field, value in rule.model_dump(exclude_none=True).items():
        setattr(db_rule, field, value)
    db.commit()
    db.refresh(db_rule)
    return db_rule

@app.delete("/rules/{rule_id}", status_code=204)
def delete_rule(rule_id: int, db: Session = Depends(get_db), _: models.User = Depends(get_current_user)):
    db_rule = db.query(models.RiskRule).filter(models.RiskRule.id == rule_id).first()
    if not db_rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    db.delete(db_rule)
    db.commit()


# ── Scans ─────────────────────────────────────────────────────────────────────

@app.get("/scans", response_model=list[schemas.ScanHistorySchema])
def get_scans(db: Session = Depends(get_db), _: models.User = Depends(get_current_user)):
    return db.query(models.ScanHistory).order_by(models.ScanHistory.id.desc()).all()

@app.get("/scans/{scan_id}", response_model=list[schemas.FindingSchema])
def get_scan(scan_id: int, db: Session = Depends(get_db), _: models.User = Depends(get_current_user)):
    findings = db.query(models.Finding).filter(models.Finding.scan_id == scan_id).all()
    return sorted(findings, key=_severity_key)

@app.delete("/scans/{scan_id}", status_code=204)
def delete_scan(scan_id: int, db: Session = Depends(get_db), _: models.User = Depends(get_current_user)):
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
def export_scan_json(scan_id: int, db: Session = Depends(get_db), _: models.User = Depends(get_current_user)):
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
def export_scan_csv(scan_id: int, db: Session = Depends(get_db), _: models.User = Depends(get_current_user)):
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
def export_scan_markdown(scan_id: int, db: Session = Depends(get_db), _: models.User = Depends(get_current_user)):
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
def export_scan_sarif(scan_id: int, db: Session = Depends(get_db), _: models.User = Depends(get_current_user)):
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


@app.get("/scans/{scan_id}/export/remediated-yaml")
def export_remediated_yaml(scan_id: int, db: Session = Depends(get_db), _: models.User = Depends(get_current_user)):
    scan = _get_scan_or_404(scan_id, db)

    target = scan.target_name
    if not target.endswith(".yaml") and not target.endswith(".yml"):
        raise HTTPException(
            status_code=400,
            detail="Algorithmic remediation is only available for offline YAML scans.",
        )

    safe = os.path.basename(target)
    path_in_dumps = os.path.join(DUMPS_DIR, safe)
    if os.path.exists(path_in_dumps):
        filepath = path_in_dumps
    elif os.path.exists(safe):
        filepath = safe
    else:
        raise HTTPException(status_code=404, detail=f"Source YAML file not found: {safe}")

    with open(filepath, "r", encoding="utf-8") as f:
        raw_docs = list(yaml.safe_load_all(f))

    remediated = []
    for doc in raw_docs:
        if not doc:
            continue
        if doc.get("kind") == "List":
            doc["items"] = [remediate_item(i) for i in doc.get("items", [])]
            remediated.append(doc)
        else:
            remediated.append(remediate_item(doc))

    output = yaml.safe_dump_all(remediated, allow_unicode=True, default_flow_style=False)
    filename = f"remediated_{safe}"
    return Response(
        content=output,
        media_type="application/x-yaml",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ── Offline scan ──────────────────────────────────────────────────────────────

@app.post("/scan/offline")
def scan_offline(
    filename: str | None = Query(default=None),
    db: Session = Depends(get_db),
    _: models.User = Depends(get_current_user),
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

    rbac_rules = db.query(models.RiskRule).filter(
        models.RiskRule.category == 'rbac',
        models.RiskRule.is_enabled,
    ).all()
    workload_rules = db.query(models.RiskRule).filter(
        models.RiskRule.category == 'workload',
        models.RiskRule.is_enabled,
    ).all()
    network_rules = db.query(models.RiskRule).filter(
        models.RiskRule.category == 'network',
        models.RiskRule.is_enabled,
    ).all()

    findings = analyze_rbac_bindings(bindings, roles, cluster_roles, rbac_rules)
    findings_count = len(findings)

    for finding_data in findings:
        db.add(models.Finding(
            scan_id=scan.id,
            subject=finding_data["subject"],
            role=finding_data["role"],
            risk_description=finding_data["risk_description"],
            severity=finding_data.get("severity", "MEDIUM"),
            remediation=finding_data.get("remediation"),
        ))

    for pod in pods:
        pod_name = pod.get("metadata", {}).get("name", "Unknown")
        pod_ns = pod.get("metadata", {}).get("namespace", "default")
        spec = pod.get("spec", {})
        sa_name = spec.get("serviceAccountName", "default")
        images = ", ".join([c.get("image", "Unknown") for c in spec.get("containers", [])])

        workload_dangers = analyze_pod_workload(pod, workload_rules)
        sa_rbac_dangers = get_sa_rbac_dangers(sa_name, pod_ns, bindings, roles, cluster_roles, rbac_rules)

        for danger_desc, danger_sev, danger_rem in workload_dangers:
            db.add(models.Finding(
                scan_id=scan.id,
                subject=f"Pod: {pod_name}",
                role=images,
                risk_description=danger_desc,
                severity=danger_sev,
                remediation=danger_rem,
            ))
            findings_count += 1

        if workload_dangers and sa_rbac_dangers:
            workload_rem = next((r for _, _, r in workload_dangers if r), None)
            rbac_rem = next((r for _, _, r in sa_rbac_dangers if r), None)
            chain_rem = None
            if workload_rem or rbac_rem:
                parts = []
                if workload_rem:
                    parts.append(f"### Workload Fix\n{workload_rem}")
                if rbac_rem:
                    parts.append(f"### RBAC Fix\n{rbac_rem}")
                chain_rem = "\n\n".join(parts)
            db.add(models.Finding(
                scan_id=scan.id,
                subject=f"Pod: {pod_name}",
                role=f"SA:{sa_name} | images: {images}",
                risk_description=(
                    f"CRITICAL CHAIN: Pod is vulnerable ({', '.join(d for d, _, __ in workload_dangers)}) "
                    f"and its ServiceAccount '{sa_name}' has dangerous RBAC rights "
                    f"({', '.join(d for d, _, __ in sa_rbac_dangers)})"
                ),
                severity="CRITICAL",
                remediation=chain_rem,
            ))
            findings_count += 1

    for net_f in analyze_services(services, network_rules):
        db.add(models.Finding(
            scan_id=scan.id,
            subject=net_f["subject"],
            role=net_f["role"],
            risk_description=net_f["risk_description"],
            severity=net_f.get("severity", "MEDIUM"),
            remediation=net_f.get("remediation"),
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
    _: models.User = Depends(get_current_user),
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

    rbac_rules = db.query(models.RiskRule).filter(
        models.RiskRule.category == 'rbac',
        models.RiskRule.is_enabled,
    ).all()
    workload_rules = db.query(models.RiskRule).filter(
        models.RiskRule.category == 'workload',
        models.RiskRule.is_enabled,
    ).all()
    network_rules = db.query(models.RiskRule).filter(
        models.RiskRule.category == 'network',
        models.RiskRule.is_enabled,
    ).all()

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
            remediation=f.get("remediation"),
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

        for danger_desc, danger_sev, danger_rem in workload_dangers:
            db.add(models.Finding(
                scan_id=scan.id,
                subject=f"Pod: {p_name}",
                role=images,
                risk_description=danger_desc,
                severity=danger_sev,
                remediation=danger_rem,
            ))
            findings_count += 1

        if workload_dangers and sa_rbac_dangers:
            workload_rem = next((r for _, _, r in workload_dangers if r), None)
            rbac_rem = next((r for _, _, r in sa_rbac_dangers if r), None)
            chain_rem = None
            if workload_rem or rbac_rem:
                parts = []
                if workload_rem:
                    parts.append(f"### Workload Fix\n{workload_rem}")
                if rbac_rem:
                    parts.append(f"### RBAC Fix\n{rbac_rem}")
                chain_rem = "\n\n".join(parts)
            db.add(models.Finding(
                scan_id=scan.id,
                subject=f"Pod: {p_name}",
                role=f"SA:{sa_name} | images: {images}",
                risk_description=(
                    f"CRITICAL CHAIN: Pod is vulnerable ({', '.join(d for d, _, __ in workload_dangers)}) "
                    f"and its ServiceAccount '{sa_name}' has dangerous RBAC rights "
                    f"({', '.join(d for d, _, __ in sa_rbac_dangers)})"
                ),
                severity="CRITICAL",
                remediation=chain_rem,
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
                remediation=net_f.get("remediation"),
            ))
            findings_count += 1

    db.commit()
    return {"scan_id": scan.id, "status": "success", "findings_count": findings_count}


# ── BAS Scripts CRUD ──────────────────────────────────────────────────────────

@app.get("/scripts", response_model=list[schemas.BasScriptSchema])
def get_scripts(db: Session = Depends(get_db), _: models.User = Depends(get_current_user)):
    return db.query(models.BasScript).order_by(models.BasScript.id).all()

@app.post("/scripts", response_model=schemas.BasScriptSchema, status_code=201)
def create_script(script: schemas.BasScriptCreate, db: Session = Depends(get_db), _: models.User = Depends(get_current_user)):
    db_script = models.BasScript(**script.model_dump())
    db.add(db_script)
    db.commit()
    db.refresh(db_script)
    return db_script

@app.put("/scripts/{script_id}", response_model=schemas.BasScriptSchema)
def update_script(script_id: int, script: schemas.BasScriptUpdate, db: Session = Depends(get_db), _: models.User = Depends(get_current_user)):
    db_script = db.query(models.BasScript).filter(models.BasScript.id == script_id).first()
    if not db_script:
        raise HTTPException(status_code=404, detail="Script not found")
    for field, value in script.model_dump(exclude_none=True).items():
        setattr(db_script, field, value)
    db.commit()
    db.refresh(db_script)
    return db_script

@app.delete("/scripts/{script_id}", status_code=204)
def delete_script(script_id: int, db: Session = Depends(get_db), _: models.User = Depends(get_current_user)):
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
    _: models.User = Depends(get_current_user),
):
    # Resolve script from DB
    script = None
    if req.script_id:
        script = db.query(models.BasScript).filter(models.BasScript.id == req.script_id).first()
        if not script:
            raise HTTPException(status_code=404, detail="Script not found")
    else:
        script = db.query(models.BasScript).filter(
            models.BasScript.is_default,
            models.BasScript.name == "Token Theft",
        ).first()
        if not script:
            # Fallback: any default script
            script = db.query(models.BasScript).filter(
                models.BasScript.is_default,
            ).first()
        if not script:
            raise HTTPException(status_code=404, detail="No default BAS script found in database. Seed the database first.")

    if not script.is_enabled:
        raise HTTPException(
            status_code=400,
            detail=f"Simulation '{script.name}' has been disabled by an administrator.",
        )

    scan = models.ScanHistory(target_name=f"BAS Simulation: {namespace}/{pod_name} [{script.name}]")
    db.add(scan)
    db.commit()
    db.refresh(scan)

    result = simulate_custom_script(pod_name, namespace, script.script_content)

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


# ── Admission webhook ─────────────────────────────────────────────────────────

_WEBHOOK_WORKLOAD_KINDS = {"Deployment", "DaemonSet", "StatefulSet", "ReplicaSet", "Job"}

@app.post("/admission/validate")
async def admission_validate(request: Request, db: Session = Depends(get_db)):
    payload = await request.json()

    uid = payload.get("request", {}).get("uid", "")
    k8s_object = payload.get("request", {}).get("object", {})
    kind = k8s_object.get("kind", "")
    meta = k8s_object.get("metadata", {})
    name = meta.get("name") or meta.get("generateName", "unknown")
    namespace = payload.get("request", {}).get("namespace", "default")

    if kind in _WEBHOOK_WORKLOAD_KINDS:
        target_to_scan = k8s_object.get("spec", {}).get("template", {})
    elif kind == "CronJob":
        target_to_scan = (
            k8s_object.get("spec", {})
                      .get("jobTemplate", {})
                      .get("spec", {})
                      .get("template", {})
        )
    else:
        target_to_scan = k8s_object

    workload_rules = db.query(models.RiskRule).filter(
        models.RiskRule.category == "workload",
        models.RiskRule.is_enabled,
    ).all()

    workload_dangers = analyze_pod_workload(target_to_scan, workload_rules)

    if workload_dangers:
        scan = models.ScanHistory(target_name=f"Admission Blocked: {kind} {namespace}/{name}")
        db.add(scan)
        db.commit()
        db.refresh(scan)

        for danger_desc, danger_sev, danger_rem in workload_dangers:
            db.add(models.Finding(
                scan_id=scan.id,
                subject=f"{kind}: {name}",
                role="Admission Control",
                risk_description=f"BLOCKED: {danger_desc}",
                severity="CRITICAL",
                remediation=danger_rem,
            ))
        db.commit()

        return {
            "apiVersion": "admission.k8s.io/v1",
            "kind": "AdmissionReview",
            "response": {
                "uid": uid,
                "allowed": False,
                "status": {
                    "message": (
                        "Kube Risk Analyzer blocked this deployment: "
                        + ", ".join(d for d, _, __ in workload_dangers)
                    ),
                },
            },
        }

    return {
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "response": {
            "uid": uid,
            "allowed": True,
        },
    }
