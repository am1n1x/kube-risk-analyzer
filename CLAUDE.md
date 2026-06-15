### AI SYSTEM CONTEXT: kube-risk-analyzer

**Target AI:** Please read this conceptual overview carefully before modifying or writing any code. This document explains the *"Why"*, *"How"*, and *"Where"* of the project to save your context tokens.

#### 1. Project Identity & Goal
**`kube-risk-analyzer`** is an advanced, hybrid Kubernetes security tool combining **CSPM** (Cloud Security Posture Management - static analysis) and **BAS** (Breach & Attack Simulation - active exploitation). 
Objective: Reduce False Positives in security alerts by proving misconfigurations are exploitable (Attack Path Mapping), targeting Container Breakouts, Privilege Escalation, and Network Exposure.

#### 2. Architectural Paradigms (Strict Rules)
- **Data Source Agnosticism**: Scanner engines (`app/scanners/`) accept plain Python dictionaries representing K8s objects. The exact same scanner code processes both offline YAML dumps and live K8s API responses.
- **Database over Hardcode**: Security rules are in `rules.json` and synced to the `RiskRule` SQLite table **only on first startup** (when the `risk_rules` table is empty). Rules are never overwritten on restart — edit `rules.json` and clear the table to re-seed.
- **Air-Gapped Ready (Vendoring)**: The frontend works completely offline. ALL JS/CSS assets are vendored in `app/static/`. Do NOT introduce CDN links — no external internet is available at runtime. Vendored files: `css/daisyui.min.css`, `js/tailwindcss.js`, `js/alpine.min.js`, `js/chart.js`, `js/vis-network.min.js`.
- **SQLite WAL Mode**: To support concurrent async reads/writes, WAL (Write-Ahead Logging) mode is explicitly enabled in `database.py` via SQLAlchemy pool events. Also enables `PRAGMA foreign_keys=ON`.
- **Alembic Migrations**: Schema changes are managed exclusively via Alembic (`alembic upgrade head`). `models.Base.metadata.create_all()` is NOT called anywhere. There are currently **two** migration files: `2528ca9dd5f1` (initial 4 tables) and `c93e831e5815` (auth tables: `users`, `sessions`). When adding a new migration, always run `alembic revision --autogenerate` and verify the generated upgrade body is non-empty.
- **Authentication on every protected endpoint**: All API endpoints except `GET /`, `GET /health`, and `POST /admission/validate` require a valid session cookie (`kra_session`). Always add `_: models.User = Depends(get_current_user)` to new endpoints. The admission webhook is exempt because it is called by the K8s API server, not a browser.

#### 3. Database Schema (SQLAlchemy ORM — `app/models.py`)

The database has **6 tables** total.

**`RiskRule`** (`risk_rules` table):
| Column | Type | Notes |
|---|---|---|
| `id` | Integer, PK, indexed | Auto-increment |
| `description` | String | Human-readable rule text (Russian) |
| `dangerous_verbs` | String, nullable | Comma-separated, e.g. `"get,list,watch"` |
| `dangerous_resources` | String, nullable | Comma-separated, e.g. `"secrets,pods"` |
| `category` | String, default=`"rbac"` | One of: `rbac`, `workload`, `network` |
| `key` | String, nullable | Dot-path for workload rules, e.g. `spec.containers.securityContext.privileged` |
| `severity` | String, default=`"MEDIUM"` | One of: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` |
| `is_enabled` | Boolean, default=`True` | Soft-disable toggle; disabled rules are excluded from all scans |
| `remediation` | String, nullable | Markdown+YAML remediation guidance (Russian) |

**`ScanHistory`** (`scan_history` table):
| Column | Type | Notes |
|---|---|---|
| `id` | Integer, PK, indexed | Auto-increment |
| `scan_date` | DateTime | Default: `datetime.now(timezone.utc)` |
| `target_name` | String | `"cluster_dump.yaml"` / `"Live Cluster"` / `"Live Namespace: {ns}"` / `"Live Pod: {ns}/{pod}"` / `"BAS Simulation: {ns}/{pod} [{script}]"` / `"Admission Blocked: {kind} {ns}/{name}"` |
| `findings` | relationship | One-to-many → `Finding`, cascade delete |

**`Finding`** (`findings` table):
| Column | Type | Notes |
|---|---|---|
| `id` | Integer, PK, indexed | Auto-increment |
| `scan_id` | Integer, FK → `scan_history.id` | |
| `subject` | String | e.g. `"ServiceAccount:default"`, `"Pod: nginx-pod"`, `"Pod: nginx-pod (Active Exploit)"` |
| `role` | String | e.g. `"ClusterRole/cluster-admin"`, `"Type: NodePort"`, `"Namespace: default"` |
| `risk_description` | String | Free-text finding details. CRITICAL chains prefixed with `"CRITICAL CHAIN:..."` or `"🚨 SUCCESS (CRITICAL):..."` |
| `severity` | String, default=`"MEDIUM"` | One of: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` |
| `remediation` | String, nullable | Propagated from the matched `RiskRule.remediation`; CRITICAL CHAINs get combined workload+rbac remediation |
| `scan` | relationship | Many-to-one → `ScanHistory` |

**`BasScript`** (`bas_scripts` table):
| Column | Type | Notes |
|---|---|---|
| `id` | Integer, PK, indexed | Auto-increment |
| `name` | String | Short label shown in UI and scan target name |
| `description` | String, nullable | Human-readable description |
| `script_content` | String | Shell command/script executed inside the pod via `kubectl exec` |
| `is_default` | Boolean, default=`False` | Built-in scripts seeded on startup |
| `is_enabled` | Boolean, default=`True` | Soft-disable; disabled scripts cannot be run |

**`User`** (`users` table):
| Column | Type | Notes |
|---|---|---|
| `id` | Integer, PK, indexed | Auto-increment |
| `username` | String, unique, indexed | Login name |
| `password_hash` | String | `salt_hex:dk_hex` — see `app/auth_utils.py` |
| `sessions` | relationship | One-to-many → `Session`, cascade delete |

**`Session`** (`sessions` table):
| Column | Type | Notes |
|---|---|---|
| `session_id` | String, PK | UUID4 generated on login |
| `user_id` | Integer, FK → `users.id` | |
| `created_at` | DateTime | Default: `datetime.now(timezone.utc)` |
| `user` | relationship | Many-to-one → `User` |

#### 4. Pydantic Schemas (`app/schemas.py`)

**`RiskRuleSchema`** — `from_attributes=True`:
- `id: int`, `description: str`, `dangerous_verbs: Optional[str]`, `dangerous_resources: Optional[str]`, `category: str = "rbac"`, `key: Optional[str]`, `severity: str = "MEDIUM"`, `is_enabled: bool = True`, `remediation: Optional[str] = None`
- `RiskRuleCreate` (used by `POST /rules`) inherits all base fields
- `RiskRuleUpdate` (used by `PUT /rules/{id}`) — all fields optional including `is_enabled` and `remediation`, used with `exclude_none=True`

**`FindingSchema`** — `from_attributes=True`:
- `id: int`, `scan_id: int`, `subject: str`, `role: str`, `risk_description: str`, `severity: str = "MEDIUM"`, `remediation: Optional[str] = None`

**`ScanHistorySchema`** — `from_attributes=True`:
- `id: int`, `scan_date: datetime`, `target_name: str`, `findings: List[FindingSchema] = []`

**`BasScriptSchema`** — `from_attributes=True`:
- `id: int`, `name: str`, `description: Optional[str]`, `script_content: str`, `is_default: bool`, `is_enabled: bool`
- `BasScriptCreate` (used by `POST /scripts`) and `BasScriptUpdate` (used by `PUT /scripts/{id}`, all fields optional)

**`BASSimulateRequest`** (request body for `POST /bas/simulate/{ns}/{pod}`):
- `script_id: Optional[int] = None` — if set, runs the custom `BasScript`; otherwise runs built-in token theft

**`LoginRequest`** (request body for `POST /auth/login`):
- `username: str`, `password: str`

#### 5. Core Analysis Modules (CSPM)

**Scanner return type convention**: All scanner functions that return per-finding data use **3-tuples** `(description, severity, remediation)`. Call sites in `main.py` unpack with `for d, s, r in ...`.

**5a. RBAC Scanner** (`app/scanners/rbac.py` — 3 functions):
- `evaluate_rbac_rule(role_verbs, role_resources, db_rules) -> list[tuple]` — Returns `(description, severity, remediation)` tuples for matched rules. Supports wildcard (`*`) matching.
- `analyze_rbac_bindings(bindings, roles, cluster_roles, db_rbac_rules) -> list[dict]` — Iterates all RoleBindings/ClusterRoleBindings, resolves roleRef, runs `evaluate_rbac_rule`. Returns dicts with keys `{"subject", "role", "risk_description", "severity", "remediation"}`. Deduplicates findings.
- `get_sa_rbac_dangers(sa_name, namespace, bindings, roles, cluster_roles, db_rules) -> list[tuple]` — Returns `[(description, severity, remediation), ...]`. Used by Context Correlation in scan endpoints.

**5b. Workload Scanner** (`app/scanners/workload.py` — 2 functions):
- `_path_matches(data, path_parts) -> bool` — Recursive dict/list traversal helper. Supports wildcard matching on lists.
- `analyze_pod_workload(pod_data, db_workload_rules) -> list[tuple]` — Returns `[(description, severity, remediation), ...]`.

**5c. Network Scanner** (`app/scanners/network.py` — 1 function):
- `analyze_services(services, db_network_rules) -> list[dict]` — Checks each Service for NodePort/LoadBalancer type and exposed DB ports (5432, 3306, 27017, 6379). Returns dicts with `"remediation"` key.
- **Critical invariant**: All rule descriptor variables (`nodeport_desc`, `lb_desc`, `db_desc`) are initialized to `None`. No fallback hardcoded strings exist. If no enabled rule matches a pattern, no finding is emitted. The `db_desc is not None` guard must precede the DB-port check.

#### 6. Context Correlation ("The Killer Feature")
The system correlates Workload vulnerabilities with RBAC permissions. If a Pod is vulnerable (e.g., Privileged) AND its `ServiceAccount` has dangerous RBAC rights (e.g., `cluster-admin`), it generates a **"CRITICAL CHAIN"** finding. This logic lives directly inside the pod loop in both `scan_offline` and `scan_live` in `app/main.py` — not in a separate scanner module.

CRITICAL CHAIN remediation is assembled from both sources:
```python
workload_rem = next((r for _, _, r in workload_dangers if r), None)
rbac_rem = next((r for _, _, r in sa_rbac_dangers if r), None)
chain_rem = None
if workload_rem or rbac_rem:
    parts = []
    if workload_rem: parts.append(f"### Workload Fix\n{workload_rem}")
    if rbac_rem: parts.append(f"### RBAC Fix\n{rbac_rem}")
    chain_rem = "\n\n".join(parts)
```

Both scan endpoints filter rules with `is_enabled == True` before passing to scanners.

#### 7. BAS Module (Breach & Attack Simulation — `app/bas.py`)

Instead of guessing, the BAS module uses `kubernetes.stream` to actively `exec` into a running Pod. BAS execution results are saved into the `ScanHistory` and `Finding` database tables just like static scans, making them visible in the unified frontend dashboard.

**Result format** (`_result()` helper): `{"pod", "namespace", "attack", "success": bool, "details", "severity", "mitre"}`

**Available simulations** (signature: `fn(pod_name, namespace, core_v1=None) -> dict`):
| Function | MITRE | Severity | What it does |
|---|---|---|---|
| `simulate_token_theft` | T1528 | CRITICAL | Reads SA token via `cat /var/run/secrets/.../token` |
| `simulate_cloud_metadata_theft` | T1552.005 | CRITICAL | Curls 169.254.169.254 (AWS) or metadata.google.internal (GCP) |
| `simulate_container_socket_escape` | T1610 | CRITICAL | Checks for mounted docker/containerd/crio sockets |
| `simulate_host_filesystem_access` | T1611 | HIGH | Probes hostPath mounts and /etc/shadow |
| `simulate_privilege_recon` | T1548 | HIGH | Checks root user (uid=0) and CAP_SYS_ADMIN via /proc/self/status |
| `simulate_env_secret_leak` | T1552.007 | MEDIUM | Harvests env vars matching PASSWORD/SECRET/TOKEN/APIKEY/AWS_ patterns |
| `simulate_api_server_secrets_enum` | T1552.007 | CRITICAL | Uses in-pod SA token to curl the K8s API for Secrets |
| `simulate_custom_script` | — | varies | Executes arbitrary shell content (from `BasScript.script_content`) inside the pod |

**Aggregated runner**: `run_all_simulations(pod_name, namespace) -> dict` — runs all 7 built-in simulations, returns `{"pod", "namespace", "compromised": bool, "exploited_count", "results": [...]}`.

The `/bas/simulate` endpoint runs `simulate_custom_script` using a script resolved from the DB (default: the "Token Theft" built-in script; or the script specified by `script_id`). `run_all_simulations` is available but not yet wired to an endpoint.

#### 7b. Proactive Admission Control (Validating Webhook)

The endpoint `POST /admission/validate` acts as a Kubernetes **ValidatingAdmissionWebhook**. The K8s API server POSTs an `AdmissionReview` JSON object to this URL before persisting any resource creation/update. **This endpoint is intentionally unprotected** (no `get_current_user` dependency) — the K8s API server cannot provide a session cookie.

**Flow:**
1. Extract `uid`, `object` (the resource being created), `kind`, `name`, `namespace` from `request.payload`.
2. Normalize to a scannable pod spec: workload kinds (`Deployment`, `DaemonSet`, `StatefulSet`, `ReplicaSet`, `Job`) use `spec.template`; `CronJob` uses `spec.jobTemplate.spec.template`; `Pod` uses the object directly.
3. Run `analyze_pod_workload(target_to_scan, workload_rules)` with enabled workload rules from DB.
4. **Blocked**: if any dangers found → create `ScanHistory(target_name="Admission Blocked: {kind} {ns}/{name}")` + one `Finding` per danger → return `allowed: false`.
5. **Allowed**: no dangers → return `allowed: true`.

All blocked admissions are visible in History & Reports with `target_name` starting with `"Admission Blocked:"`.

#### 7c. Authentication System (`app/auth_utils.py` + `app/main.py`)

**Password hashing** (`app/auth_utils.py`):
- `hash_password(password: str) -> str` — generates 32-byte random salt, runs `pbkdf2_hmac('sha256', password, salt, 100_000)`, returns `"{salt_hex}:{dk_hex}"`.
- `verify_password(password: str, stored_hash: str) -> bool` — splits on `:`, recomputes PBKDF2, compares with `hmac.compare_digest` (timing-safe).
- No third-party packages — stdlib `hashlib`, `os`, `hmac` only.

**Session cookie**: HTTP-Only, `SameSite=Lax`, name `kra_session`, value = UUID4. Set `secure=True` when TLS is terminated by the app itself.

**Default admin** — seeded in lifespan on first startup if `users` table is empty:
- `username`: `admin`, `password`: `KubeRisk2026!`
- Print message: `[kube-risk-analyzer] Default admin user created (username: admin)`

**`get_current_user` dependency**:
```python
def get_current_user(request: Request, db: Session = Depends(get_db)) -> models.User:
    session_id = request.cookies.get("kra_session")
    # raises 401 if missing or not in sessions table
```
Applied to **all** endpoints except `GET /`, `GET /health`, `POST /admission/validate`.

#### 8. Endpoints Reference (`app/main.py`)

🔓 = unprotected (no auth required) | 🔐 = requires valid `kra_session` cookie

| Method | Path | Auth | Response | Notes |
|---|---|---|---|---|
| `GET` | `/` | 🔓 | HTML (Jinja2) | Renders `templates/index.html` — login page loads from here |
| `GET` | `/health` | 🔓 | `{"status": "ok"}` | Liveness check, no DB dependency |
| `POST` | `/auth/login` | 🔓 | `{"status", "username"}` | Verifies credentials, creates `Session`, sets `kra_session` HTTP-Only cookie |
| `POST` | `/auth/logout` | 🔓 | `{"status": "logged_out"}` | Deletes `Session` record, clears cookie |
| `GET` | `/cluster/pods` | 🔐 | `{"pods": [...], "source": "live"\|"unavailable"}` | Live pod list `{name, namespace, phase, node, sa}` |
| `GET` | `/dumps` | 🔐 | `list[str]` | Sorted YAML files in `dumps/` + root `cluster_dump.yaml` if present |
| `POST` | `/dump/live?namespace=&pod_name=` | 🔐 | `{"filename", "items_count"}` | Connects to live K8s, saves YAML dump. Returns 503 on K8s error |
| `GET` | `/rules` | 🔐 | `list[RiskRuleSchema]` | All rules from DB |
| `POST` | `/rules` | 🔐 | `RiskRuleSchema` (201) | Create rule |
| `PUT` | `/rules/{rule_id}` | 🔐 | `RiskRuleSchema` | Update rule (partial, `exclude_none`). Used for toggle: `{"is_enabled": false}` |
| `DELETE` | `/rules/{rule_id}` | 🔐 | 204 | Delete rule |
| `GET` | `/scans` | 🔐 | `list[ScanHistorySchema]` | Ordered by `id.desc()`. Includes nested `findings` array |
| `GET` | `/scans/{scan_id}` | 🔐 | `list[FindingSchema]` | All findings for a scan, sorted by severity |
| `DELETE` | `/scans/{scan_id}` | 🔐 | 204 | Delete scan + cascade findings |
| `GET` | `/scans/{scan_id}/export/json` | 🔐 | JSON file download | `{scan_id, target, date, findings:[...]}` sorted by severity |
| `GET` | `/scans/{scan_id}/export/csv` | 🔐 | CSV file download | Columns: Severity, Subject, Context, Risk Description |
| `GET` | `/scans/{scan_id}/export/markdown` | 🔐 | Markdown file download | Header with scan metadata + pipe table |
| `GET` | `/scans/{scan_id}/export/sarif` | 🔐 | SARIF 2.1.0 JSON download | Valid SARIF: `runs`, `tool.driver.rules`, `results`, `locations` |
| `GET` | `/scans/{scan_id}/export/remediated-yaml` | 🔐 | YAML file download | Only for offline YAML scans (400 otherwise) |
| `POST` | `/scan/offline?filename=` | 🔐 | `{"scan_id", "findings_count", "status"}` | Reads `dumps/{filename}`. Runs all 3 scanners + correlation |
| `POST` | `/scan/live?namespace=&pod_name=` | 🔐 | `{"scan_id", "status", "findings_count"}` | Live K8s scan with optional scope filters |
| `GET` | `/scripts` | 🔐 | `list[BasScriptSchema]` | All BAS scripts |
| `POST` | `/scripts` | 🔐 | `BasScriptSchema` (201) | Create script |
| `PUT` | `/scripts/{script_id}` | 🔐 | `BasScriptSchema` | Update script |
| `DELETE` | `/scripts/{script_id}` | 🔐 | 204 | Delete script |
| `POST` | `/bas/simulate/{namespace}/{pod_name}` | 🔐 | `{**bas_result, "scan_id"}` | Runs custom script by `script_id` or default "Token Theft". Persists to ScanHistory + Finding |
| `GET` | `/db/backup/download` | 🔐 | `.db` file download | WAL-safe hot backup via `sqlite3.Connection.backup()` |
| `POST` | `/db/backup/server` | 🔐 | `{"status": "success", "filename": str}` | Saves backup to `backups/` on server |
| `POST` | `/admission/validate` | 🔓 | `AdmissionReview` JSON | Validating Admission Webhook — called by K8s API server |

**Key helpers in `app/main.py`:**
- `_pod_display_status(status: dict) -> str` — reads `containerStatuses[*].state.waiting.reason` before falling back to `status.phase`
- `_write_dump(items, prefix) -> str` — serializes K8s objects to `apiVersion/kind: List` YAML in `dumps/`
- `_get_scan_or_404(scan_id, db)` — common scan lookup used by export endpoints
- `get_current_user(request, db)` — auth dependency; raises 401 if `kra_session` cookie missing or invalid

**Key imports added to `app/main.py`:**
- `uuid` — for `session_id` generation
- `FastAPIResponse` aliased from `fastapi.responses.Response` — for cookie operations in auth endpoints
- `from .auth_utils import hash_password, verify_password`

#### 9. Rules Engine (`app/rules.py` + `rules.json`)

- `sync_rules_to_db(db, file_path="rules.json")` — Called once on startup via FastAPI lifespan. **Only runs if `risk_rules` table is empty**. Maps `remediation=rule.get("remediation")` when creating `RiskRule` objects.
- `rules.json` contains **20 rules**: 10 RBAC (DANGER-001 through 010), 7 Workload (DANGER-011 through 017), 3 Network (DANGER-018 through 020). Every rule has a `"remediation"` field with Russian-language Markdown+YAML instructions.

#### 10. K8s Client (`app/k8s_client.py`)

- `get_live_k8s_data() -> dict` — Loads kube config (local or in-cluster), fetches all namespaces' pods/services/roles/rolebindings + cluster roles/bindings via `sanitize_for_serialization()`. Returns dict with keys: `pods`, `services`, `roles`, `cluster_roles`, `role_bindings`, `cluster_role_bindings`. Raises on connection failure (caller handles).

**Important**: `sanitize_for_serialization` sets `kind=None` on individual list items (K8s API quirk). Never use `b.get('kind') == 'ClusterRoleBinding'` to detect cluster-scope bindings — use `not b.get('metadata', {}).get('namespace')` instead.

#### 11. Database Configuration (`app/database.py`)

- SQLite URL: `sqlite:///./kube_risk.db`
- `check_same_thread=False` for FastAPI thread safety
- WAL mode + foreign keys enabled via `@event.listens_for(Pool, "connect")`
- `get_db()` — generator-based FastAPI dependency, yields `SessionLocal()`
- No `run_migrations()` function — Alembic is the sole migration mechanism

#### 11a. Alembic Migrations

- Config: `alembic.ini` (`sqlalchemy.url = sqlite:///./kube_risk.db`)
- `alembic/env.py`: imports `app.database.Base` and `app.models` so `target_metadata = Base.metadata`
- **Two migration files**:
  1. `2528ca9dd5f1` — initial schema: `risk_rules`, `scan_history`, `findings`, `bas_scripts`
  2. `c93e831e5815` — auth tables: `users`, `sessions`
- Run: `alembic upgrade head` (must be run before first server start on a fresh environment)
- When adding a new migration: `alembic revision --autogenerate -m "description"` then verify the upgrade body is non-empty before applying.

#### 12. Tech Stack & Frontend Design
- **Backend**: Python 3.10+, FastAPI, SQLAlchemy 2.0, Pydantic V2, K8s Python Client (`kubernetes`), PyYAML, Alembic. Additional stdlib: `csv`, `io`, `json`, `os`, `datetime`, `sqlite3`, `tempfile`, `uuid`, `hashlib`, `hmac`.
- `app/static/` is served at `/static` via FastAPI `StaticFiles` mount. **All** frontend assets are vendored here — no CDN requests at runtime.
- **Database**: SQLite with WAL mode. **Six tables**: `risk_rules`, `scan_history`, `findings`, `bas_scripts`, `users`, `sessions`.
- **Frontend**: Zero-build SPA using Alpine.js + Tailwind CSS + DaisyUI. All vendored locally.
- **Hash Routing**: Client-side navigation uses `window.location.hash`. Valid tab values: `dashboard`, `control`, `history`, `tests`, `rules`. Individual scan reports deep-linkable via `#history/{scan_id}`. The `hashchange` listener and `$watch('activeTab')` keep hash and state in sync.
- **Auth gate in `init()`**: On startup, `init()` probes `GET /scans`. If the response is `401`, sets `isLoggedIn = false` and stops (shows login screen). If `200`, sets `isLoggedIn = true` and proceeds with full `fetchData()`.
- **Design Language**: Serious, technical "Cyberpunk" aesthetic. DaisyUI `data-theme` for dark/light theme switching with `localStorage` key `kra-theme`. Sharp corners (`rounded-sm`), monospaced fonts for technical data, collapsible sidebar. All colors use DaisyUI semantic classes — **never** hardcode Tailwind dark-mode colors (e.g. `bg-gray-950`, `text-cyan-400`) in modals or cards. Use `bg-base-100`, `border-base-300`, `text-primary`, etc.
- **Attack Path Graph theming**: `renderAttackGraph()` reads `data-theme` from `<html>` at call time and builds a `P` palette object for dark/light. Edge `font.background` is set to `P.canvasBg` so labels are readable over arrow lines. The `#attackGraphNetwork` container's `backgroundColor` is set inline to `P.canvasBg` before vis-network initialises.

**Alpine.js SPA state** (key properties in `appData()`):

Auth state:
- `isLoggedIn: false` — gates the entire app; set from `init()` session probe
- `authUsername: ''`, `authPassword: ''` — login form inputs (empty by default, no placeholders)
- `loginLoading: false`, `loginError: ''` — login button spinner and error display

Tab & global state:
- `activeTab: 'dashboard'`, `loading`, `offlineScanLoading`, `liveScanLoading`, `sidebarExpanded`, `theme`

Data lists:
- `scans`, `rules`, `scripts`

Cluster:
- `clusterPods: []`, `clusterPodsSource: 'loading'|'live'|'unavailable'`

Dump management:
- `dumpFiles`, `selectedDumpFile`, `dumpNamespace`, `dumpPodName`, `dumpLoading`

Scan scope:
- `liveScanNamespace`, `liveScanPodName`

Dashboard filters/sort:
- `podViewAllScans` (localStorage `kra-pod-all-scans`)
- `dashPodSearch`, `dashPodNsFilter`, `dashPodSevFilter`, `dashPodSortCol`, `dashPodSortDir`
- `dashTargetSearch`, `dashTargetSortCol`, `dashTargetSortDir`

History filters/sort:
- `historySortCol`, `historySortDir`, `historySearch`, `historyModuleFilter`

Findings detail:
- `selectedScanFindings`, `viewingScan`, `findingFilter`, `findingSearch`, `findingSortDir`

BAS form:
- `basNamespace`, `basPodName`, `selectedSimType`, `basScriptId`, `basResult`

Built-in Tests tab:
- `builtinsSearch`, `builtinsSortCol`, `builtinsSortDir`

Detection Rules (KB) filters:
- `kbSearch`, `kbCategoryFilter`, `kbSeverityFilter`, `kbSortCol`, `kbSortDir`

Modals:
- `backupNotif: ''` — auto-dismisses after 4s
- `remediationModalOpen`, `currentRemediationText`, `currentRemediationSubject`
- `graphModalOpen`, `graphNetworkInstance` — destroyed on close to free canvas memory
- `severityChartInstance` — destroyed and re-created on each dashboard visit
- `ruleModalOpen`, `ruleModalMode`, `ruleModalError`, `ruleForm: { id, description, category, severity, dangerous_verbs, dangerous_resources, key, remediation }`
- `scriptModalOpen`, `scriptModalMode`, `scriptModalError`, `scriptForm`

Computed getters:
- `filteredFindings`, `filteredRules`, `filteredScans`, `filteredDashPods`, `filteredDashTargets`
- `dashPods` (includes `lastScanId`), `dashTargets`
- `basNamespaces`, `basPodsForNs`, `liveScanPodsForNs`, `dumpPodsForNs`
- `basDefenseRate`, `builtinScripts`, `filteredBuiltins`

Helper methods:
- `scanModule(targetName)` → `'BAS'|'LIVE'|'CSPM'`
- `scanMaxSev(findings)`, `scanBadgeCls(findings)`, `getSeverityPct(scan, severity)`, `sevCount(sev)`

Action methods:
- `init()`, `login()`, `logout()`
- `fetchData()`, `fetchScripts()`, `fetchDumps()`
- `generateDump()`, `runOfflineScan()`, `runLiveScan()`, `runBas()`
- `goToScan(scanId)`, `fetchScanDetails(scanId)`, `deleteScan(scanId)`, `exportScan(format)`
- `saveRule()`, `deleteRule(ruleId)`, `toggleRule(rule)`
- `saveScript()`, `deleteScript(scriptId)`, `openAddBuiltinScript()`, `toggleBuiltin(script)`
- `downloadBackup()`, `serverBackup()`
- `openRemediation(finding)`, `renderAttackGraph(finding)`, `renderSeverityChart()`
- `builtinsSortBy(col)`, `toggleTheme()`

**Frontend tabs (hash routes):**
1. **`#dashboard`** — 4 stat boxes + Security Posture Timeline (last 5 scans) + Latest Scan Severity doughnut (Chart.js)
2. **`#control`** — Offline Scan + Live Scan + BAS form + Custom BAS Scripts management
3. **`#history`** — Scan history table; click View → findings detail with export buttons (JSON/CSV/Markdown/SARIF). Deep-linkable via `#history/{scan_id}`
4. **`#tests`** — Built-in Tests: sortable/filterable table of default BAS scripts with enable/disable toggles
5. **`#rules`** — Detection Rules (formerly `#kb`): sortable/filterable table; inline edit/delete; toggle switch; remediation textarea in modal

**Sidebar layout (bottom to top):**
- Logout button (calls `logout()`, styled `text-error`)
- Theme toggle (Dark/Light Mode)
- Database section: Download Backup + Server Backup + `backupNotif` toast
- Navigation links: Dashboard / Control Panel / History & Reports / Built-in Tests / Detection Rules

**Severity color convention** (consistent across all tables):
- Row highlight: `bg-error/10 border-l-4 border-error` (CRITICAL), `bg-warning/5 border-l-4 border-warning` (HIGH), `border-l-4 border-info/40` (MEDIUM)
- Text severity labels: `text-error`, `text-warning`, `text-info`, `text-base-content/50`
- Scan History Module badge: `badge-error` (has MEDIUM+ findings), `badge-success` (clean/only LOW)

#### 13. CI/CD Pipeline (`.github/workflows/deploy.yml`)

Three-stage GitHub Actions pipeline triggered on `push` to `dev`. Each stage gates the next via `needs:`.

**Stage 1 — `security-and-lint`** (runs first, no dependencies):
- TruffleHog secret scan (`trufflesecurity/trufflehog@main`, `--only-verified`, scans push delta via `base`/`head`). Requires `fetch-depth: 0`.
- Ruff linter: `ruff check app/`
- Bandit SAST: `bandit -r app/ -ll` (Medium+ severity)
- pip-audit SCA: `pip-audit -r requirements.txt`

**Stage 2 — `build-and-transfer`** (`needs: security-and-lint`):
- `docker build -t kube-risk-analyzer:latest .`
- `docker save -o kube-risk-analyzer.tar kube-risk-analyzer:latest`
- SCP `kube-risk-analyzer.tar` + `k8s-deploy.yaml` → `/home/ubuntu/` on VPS via `appleboy/scp-action@master`
- Secrets used: `VPS_HOST`, `VPS_USER`, `VPS_SSH_KEY`

**Stage 3 — `deploy-to-vps`** (`needs: build-and-transfer`):
- SSH via `appleboy/ssh-action@master`
- Deletes old k3s image, imports new tar, `kubectl apply`, `kubectl rollout restart`, waits with `kubectl rollout status --timeout=120s`

#### 14. Project Structure
- `app/main.py`: FastAPI application, **30 endpoints** (28 original + `/auth/login` + `/auth/logout`). Key helpers: `_pod_display_status`, `_write_dump`, `_get_scan_or_404`, `get_current_user`.
- `app/auth_utils.py`: Password hashing/verification using stdlib `hashlib.pbkdf2_hmac` (sha256, 100k iterations, 32-byte salt). No third-party dependencies.
- `app/database.py` & `app/models.py` & `app/schemas.py`: SQLAlchemy setup, ORM classes (**6 models**), Pydantic validation.
- `app/scanners/`: `rbac.py` (3 functions), `workload.py` (2 functions), `network.py` (1 function), `remediator.py` (2 functions: `remediate_pod_spec`, `remediate_item`).
- `app/bas.py`: Active simulation logic — 8 individual attack functions + 1 aggregated runner.
- `app/k8s_client.py`: Live cluster data fetcher.
- `app/rules.py`: Rule synchronization from `rules.json` to DB on first startup (only if table is empty).
- `rules.json`: 20 threat signatures across rbac/workload/network categories. Each rule has a `"remediation"` field.
- `alembic/versions/2528ca9dd5f1_*.py`: Initial schema (4 tables).
- `alembic/versions/c93e831e5815_add_auth_tables.py`: Auth tables (`users`, `sessions`).
- `dumps/`: Generated YAML dumps. `.gitkeep` keeps directory in git; `.gitignore` inside excludes `*.yaml`.
- `backups/`: Server-side DB backups. `.gitkeep` keeps directory in git; `.gitignore` inside excludes `*.db`.
- `templates/index.html`: The entire frontend SPA (~1850 lines).
- `app/static/css/daisyui.min.css`: DaisyUI 4.12.10 (vendored).
- `app/static/js/tailwindcss.js`: Tailwind CSS (vendored).
- `app/static/js/alpine.min.js`: Alpine.js 3.14.0 (vendored).
- `app/static/js/chart.js`: Chart.js 4.4.3 (vendored).
- `app/static/js/vis-network.min.js`: vis-network 9.1.9 (vendored).
- `Dockerfile`: Base `python:3.10-slim`, WORKDIR `/workspace`. Copies `app/`, `templates/`, `alembic/`, `alembic.ini`, `rules.json`. Creates empty `dumps/` and `backups/` dirs. Exposes `8000`. Run `alembic upgrade head` before first start on a fresh volume.
- `k8s-deploy.yaml`: Kubernetes manifests for cluster deployment.
- `.github/workflows/deploy.yml`: Three-stage DevSecOps CI/CD pipeline (secret scan → build/transfer → deploy).

**Instructions for the AI:**
- Adhere strictly to FastAPI dependency injection (`Depends(get_db)`).
- **Always add `_: models.User = Depends(get_current_user)` to any new endpoint**, unless it must be publicly accessible (like `/health` or the admission webhook).
- When adding endpoints, include them in the Endpoints Reference table (section 8) with the correct 🔓/🔐 marker.
- When modifying Alpine.js state, update the state listing in section 12.
- When adding new columns to models, create a new Alembic migration — never call `create_all()`.
- Scanner functions must return 3-tuples `(description, severity, remediation)` — do not regress to 2-tuples.
- Never hardcode dark-mode hex colors in HTML/CSS — use DaisyUI semantic classes (`bg-base-100`, `border-base-300`, `text-primary`, etc.).
- All frontend assets must remain vendored in `app/static/` — never add CDN links to `index.html`.
- Hash routes are `#dashboard`, `#control`, `#history`, `#tests`, `#rules` — do not use the old `#kb` or `#builtins` values.
