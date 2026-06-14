### AI SYSTEM CONTEXT: kube-risk-analyzer

**Target AI:** Please read this conceptual overview carefully before modifying or writing any code. This document explains the *"Why"*, *"How"*, and *"Where"* of the project to save your context tokens.

#### 1. Project Identity & Goal
**`kube-risk-analyzer`** is an advanced, hybrid Kubernetes security tool combining **CSPM** (Cloud Security Posture Management - static analysis) and **BAS** (Breach & Attack Simulation - active exploitation). 
Objective: Reduce False Positives in security alerts by proving misconfigurations are exploitable (Attack Path Mapping), targeting Container Breakouts, Privilege Escalation, and Network Exposure.

#### 2. Architectural Paradigms (Strict Rules)
- **Data Source Agnosticism**: Scanner engines (`app/scanners/`) accept plain Python dictionaries representing K8s objects. The exact same scanner code processes both offline YAML dumps and live K8s API responses.
- **Database over Hardcode**: Security rules are in `rules.json` and synced to the `RiskRule` SQLite table **only on first startup** (when the `risk_rules` table is empty). Rules are never overwritten on restart — edit `rules.json` and clear the table to re-seed.
- **Air-Gapped Ready (Vendoring)**: The frontend is designed to work completely offline in isolated corporate networks. Do not introduce dependencies that require external internet at runtime.
- **SQLite WAL Mode**: To support concurrent async reads/writes, WAL (Write-Ahead Logging) mode is explicitly enabled in `database.py` via SQLAlchemy pool events. Also enables `PRAGMA foreign_keys=ON`.
- **Alembic Migrations**: Schema changes are managed exclusively via Alembic (`alembic upgrade head`). `models.Base.metadata.create_all()` is NOT called anywhere. There is a single initial migration (`2528ca9dd5f1`) that creates all 4 tables from scratch.

#### 3. Database Schema (SQLAlchemy ORM — `app/models.py`)

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
| `target_name` | String | `"cluster_dump.yaml"` / `"Live Cluster"` / `"Live Namespace: {ns}"` / `"Live Pod: {ns}/{pod}"` / `"BAS Simulation: {ns}/{pod} [{script}]"` |
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
- `id: int`, `name: str`, `description: Optional[str]`, `script_content: str`
- `BasScriptCreate` (used by `POST /scripts`) and `BasScriptUpdate` (used by `PUT /scripts/{id}`, all fields optional)

**`BASSimulateRequest`** (request body for `POST /bas/simulate/{ns}/{pod}`):
- `script_id: Optional[int] = None` — if set, runs the custom `BasScript`; otherwise runs built-in token theft

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

The `/bas/simulate` endpoint currently runs only `simulate_token_theft` (default) or `simulate_custom_script` (when `script_id` provided). `run_all_simulations` is available but not yet wired to an endpoint.

#### 8. Endpoints Reference (`app/main.py`)

| Method | Path | Response | Notes |
|---|---|---|---|
| `GET` | `/` | HTML (Jinja2) | Renders `templates/index.html` |
| `GET` | `/health` | `{"status": "ok"}` | Liveness check, no DB dependency |
| `GET` | `/cluster/pods` | `{"pods": [...], "source": "live"\|"unavailable"}` | Returns live pod list `{name, namespace, phase, node, sa}`. `phase` derived from `containerStatuses` (shows CrashLoopBackOff etc.). Graceful fallback on K8s error |
| `GET` | `/dumps` | `list[str]` | Sorted list of YAML files in `dumps/` folder (newest first) + `cluster_dump.yaml` at root if present |
| `POST` | `/dump/live?namespace=&pod_name=` | `{"filename", "items_count"}` | Connects to live K8s, serializes resources to YAML List, saves to `dumps/{prefix}_{timestamp}.yaml`. Prefix: `cluster`, `ns_{ns}`, `pod_{ns}_{name}`. Returns 503 on K8s error |
| `GET` | `/rules` | `list[RiskRuleSchema]` | All rules from DB |
| `POST` | `/rules` | `RiskRuleSchema` (201) | Create rule |
| `PUT` | `/rules/{rule_id}` | `RiskRuleSchema` | Update rule (partial, `exclude_none`). Used for toggle: `{"is_enabled": false}` |
| `DELETE` | `/rules/{rule_id}` | 204 | Delete rule |
| `GET` | `/scans` | `list[ScanHistorySchema]` | Ordered by `id.desc()`. Includes nested `findings` array |
| `GET` | `/scans/{scan_id}` | `list[FindingSchema]` | All findings for a scan, sorted by severity |
| `DELETE` | `/scans/{scan_id}` | 204 | Delete scan + cascade findings |
| `GET` | `/scans/{scan_id}/export/json` | JSON file download | `{scan_id, target, date, findings:[...]}` sorted by severity |
| `GET` | `/scans/{scan_id}/export/csv` | CSV file download | Columns: Severity, Subject, Context, Risk Description |
| `GET` | `/scans/{scan_id}/export/markdown` | Markdown file download | Header with scan metadata + pipe table, `\|` escaped |
| `GET` | `/scans/{scan_id}/export/sarif` | SARIF 2.1.0 JSON download | Valid SARIF: `runs`, `tool.driver.rules`, `results`, `locations`. Severity → SARIF level mapping |
| `POST` | `/scan/offline?filename=` | `{"scan_id", "findings_count", "status"}` | Reads `dumps/{filename}` (or root `cluster_dump.yaml` as fallback). Runs all 3 scanners + correlation. Returns 404 if file not found |
| `POST` | `/scan/live?namespace=&pod_name=` | `{"scan_id", "status", "findings_count"}` | Live K8s scan. Both params optional. **Pod scope**: RBAC for pod's SA + workload only. **Namespace scope**: namespace bindings + ClusterRoleBindings whose subjects are in namespace. **Full** (no params): entire cluster |
| `GET` | `/scripts` | `list[BasScriptSchema]` | All custom BAS scripts |
| `POST` | `/scripts` | `BasScriptSchema` (201) | Create script |
| `PUT` | `/scripts/{script_id}` | `BasScriptSchema` | Update script |
| `DELETE` | `/scripts/{script_id}` | 204 | Delete script |
| `POST` | `/bas/simulate/{namespace}/{pod_name}` | `{**bas_result, "scan_id"}` | Runs token theft (default) or custom script if `script_id` in body. Persists to ScanHistory + Finding |
| `GET` | `/db/backup/download` | `.db` file download | WAL-safe hot backup via `sqlite3.Connection.backup()`. Temp file cleaned up via `BackgroundTasks` after response sent |
| `POST` | `/db/backup/server` | `{"status": "success", "filename": str}` | Saves backup to `backups/` directory on the server. Filename: `kube_risk_backup_{YYYYMMDD_HHMMSS}.db` |
| `GET` | `/scans/{scan_id}/export/remediated-yaml` | YAML file download | Only for offline YAML scans (400 otherwise). Reads source dump, runs each item through `remediate_item`, returns hardened YAML stream. Filename: `remediated_{original_filename}` |

**Key helpers in `app/main.py`:**
- `_pod_display_status(status: dict) -> str` — reads `containerStatuses[*].state.waiting.reason` before falling back to `status.phase`; returns real statuses like `CrashLoopBackOff`
- `_write_dump(items, prefix) -> str` — serializes K8s objects to `apiVersion/kind: List` YAML in `dumps/`
- `_get_scan_or_404(scan_id, db)` — common scan lookup used by export endpoints

**Key constants/imports added to `app/main.py`:**
- `BACKUPS_DIR = "backups"`, `DB_PATH = "kube_risk.db"` — used by backup endpoints
- `sqlite3`, `tempfile`, `BackgroundTasks`, `FileResponse` — for hot-backup implementation

#### 9. Rules Engine (`app/rules.py` + `rules.json`)

- `sync_rules_to_db(db, file_path="rules.json")` — Called once on startup via FastAPI lifespan. **Only runs if `risk_rules` table is empty** (`db.query(RiskRule).count() == 0`). Maps `remediation=rule.get("remediation")` when creating `RiskRule` objects.
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
- **Single migration file**: `alembic/versions/2528ca9dd5f1_initial_schema_with_remediations_and_.py` — creates all 4 tables from scratch. **IMPORTANT**: This migration was generated against an **empty database**. If you need to add another migration, always run `alembic revision --autogenerate` and verify the generated upgrade body is non-empty.
- Run: `alembic upgrade head` (must be run before first server start on a fresh environment)

#### 12. Tech Stack & Frontend Design
- **Backend**: Python 3.10+, FastAPI, SQLAlchemy 2.0, Pydantic V2, K8s Python Client (`kubernetes`), PyYAML, Alembic. Additional stdlib: `csv`, `io`, `json`, `os`, `datetime`, `sqlite3`, `tempfile`.
- **Database**: SQLite with WAL mode. Four tables: `risk_rules`, `scan_history`, `findings`, `bas_scripts`.
- **Frontend**: Zero-build SPA using Alpine.js + Tailwind CSS + DaisyUI (CDN in dev; vendored in `app/static/` for air-gapped use).
- **Hash Routing**: Client-side navigation uses `window.location.hash` as the single source of truth. On `init()`, the active tab is read from the hash (default: `dashboard`). A `hashchange` listener updates `activeTab` on browser Back/Forward. A `$watch('activeTab', ...)` syncs the hash on any programmatic tab change (e.g., after a scan finishes). Sidebar `<a>` tags use `href="#tab"` instead of `@click` handlers. Valid tab values: `dashboard`, `control`, `history`, `kb`. Individual scan reports are deep-linkable via `#history/{scan_id}` (e.g., `#history/42`): opening a scan sets `window.location.hash = 'history/{id}'` via `$watch('viewingScan')`; the Back button returns to `#history`; a direct link loads the report after `fetchData()` completes. The `hashchange` handler guards against re-fetching an already-open scan (`scanId !== this.viewingScan`). `$watch('activeTab')` accounts for an existing `viewingScan` when switching to the history tab (e.g., via `goToScan()`).
- **Design Language**: Serious, technical "Cyberpunk" aesthetic. DaisyUI `data-theme` for dark/light theme switching with `localStorage` key `kra-theme`. Sharp corners (`rounded-sm`), monospaced fonts for technical data, collapsible sidebar (`w-72`/`w-20`, `transition-all duration-300`). All colors use DaisyUI semantic classes — no hardcoded Tailwind dark classes. Sidebar uses DaisyUI drawer pattern with `lg:drawer-open`. Active menu item: `bg-primary/15 font-semibold border-l-4 border-primary`.

**Alpine.js SPA state** (key properties in `appData()`):
- `scans`, `rules`, `scripts` — data lists fetched from API
- `clusterPods: []`, `clusterPodsSource: 'loading'|'live'|'unavailable'` — live pod data from `/cluster/pods` (each pod: `{name, namespace, phase, node, sa}`)
- `dumpFiles`, `selectedDumpFile`, `dumpNamespace`, `dumpPodName`, `dumpLoading` — dump management (Control Panel)
- `liveScanNamespace`, `liveScanPodName` — scope filters for live scan (Control Panel)
- `offlineScanLoading`, `liveScanLoading` — separate loading flags for Offline Scan and Live Scan buttons (prevent cross-button spinner bleed); shared `loading` still used for BAS/rule/script modals
- `podViewAllScans` — toggle: OFF=last scan only, ON=per-pod most recent scan. Persisted in `localStorage` key `kra-pod-all-scans`
- `dashPodSearch`, `dashPodNsFilter`, `dashPodSevFilter`, `dashPodSortCol`, `dashPodSortDir` — Pods & Workloads table sort/filter
- `dashTargetSearch`, `dashTargetSortCol`, `dashTargetSortDir` — Scan Targets table sort/filter
- `historySortCol`, `historySortDir`, `historySearch`, `historyModuleFilter` — Scan History sort/filter
- `basNamespace`, `basPodName`, `basScriptId`, `basResult` — BAS form state
- `kbSearch`, `kbCategoryFilter`, `kbSeverityFilter`, `kbSortCol`, `kbSortDir` — Detection Rules table filters/sort
- `selectedScanFindings`, `viewingScan`, `findingFilter`, `findingSearch`, `findingSortDir` — scan detail view
- `backupNotif: ''` — inline toast for backup status (auto-dismisses after 4s)
- `remediationModalOpen: false`, `currentRemediationText: ''`, `currentRemediationSubject: ''` — "Fix It" remediation modal state
- `ruleForm: { id, description, category, severity, dangerous_verbs, dangerous_resources, key, remediation }` — includes `remediation` field
- Computed getters: `filteredFindings`, `filteredRules`, `dashPods` (includes `lastScanId`), `dashTargets`, `filteredDashPods`, `filteredDashTargets`, `filteredScans`, `basNamespaces`, `basPodsForNs`, `liveScanPodsForNs`, `dumpPodsForNs`
- Helper methods: `scanModule(targetName)` → `'BAS'|'LIVE'|'CSPM'`, `scanMaxSev(findings)`, `scanBadgeCls(findings)`
- Action methods: `init()`, `fetchData()`, `fetchScripts()`, `fetchDumps()`, `generateDump()`, `runOfflineScan()`, `runLiveScan()`, `runBas()`, `goToScan(scanId)`, `fetchScanDetails(scanId)`, `deleteScan(scanId)`, `exportScan(format)`, `saveRule()`, `deleteRule(ruleId)`, `saveScript()`, `deleteScript(scriptId)`, `toggleRule(rule)`, `downloadBackup()`, `serverBackup()`, `openRemediation(finding)`

**Frontend tabs:**
1. **Dashboard** — stat boxes + "Pods & Workloads" table (live status, finding counts, per-pod toggle, sort/filter, `→` navigation to last scan) + "Scan Targets" table (sort/filter, `→` navigation)
2. **Control Panel** — Offline Scan (file selector + generate dump); Live Scan (namespace/pod scope dropdowns); BAS form; Custom BAS Scripts management
3. **History & Reports** — scan history table (sort by all columns, filter by text/module); click View → findings detail with keyword search + severity filter + export buttons (JSON/CSV/Markdown/SARIF). Findings table uses percentage-based column widths (`w-[10%]`/`w-[23%]`/`w-[22%]`/`w-[40%]`/`w-[5%]`) and `break-all whitespace-normal` on subject/role cells to handle long K8s resource names. Each finding row has a "Fix" button (shown only when `finding.remediation` exists) that opens the remediation modal.
4. **Detection Rules** (formerly "Knowledge Base") — sortable/filterable table (by #, category, severity; search by description); inline edit/delete per row; toggle switch in "Enabled" column (`opacity-40` on disabled rows); `✓ Remediation` badge shown when rule has remediation text; `remediation` textarea in edit modal.

**Sidebar Database section**: "Download Backup" button (`GET /db/backup/download`) and "Server Backup" button (`POST /db/backup/server`) with inline `backupNotif` toast.

**Severity color convention** (consistent across all tables):
- Row highlight: `bg-error/10 border-l-4 border-error` (CRITICAL), `bg-warning/5 border-l-4 border-warning` (HIGH), `border-l-4 border-info/40` (MEDIUM)
- Text severity labels: plain colored text (`text-error`, `text-warning`, `text-info`, `text-base-content/50`) — no badge backgrounds
- Category badges in Detection Rules still use `badge-secondary/accent/info`
- Scan History Module badge: `badge-error` (has MEDIUM+ findings), `badge-success` (clean/only LOW)

#### 13. Project Structure
- `app/main.py`: FastAPI application, 27 endpoints, Jinja2 frontend rendering. Key helpers: `_pod_display_status`, `_write_dump`, `_get_scan_or_404`.
- `app/database.py` & `app/models.py` & `app/schemas.py`: SQLAlchemy setup, ORM classes (4 models), Pydantic validation.
- `app/scanners/`: `rbac.py` (3 functions), `workload.py` (2 functions), `network.py` (1 function), `remediator.py` (2 functions: `remediate_pod_spec`, `remediate_item`).
- `app/bas.py`: Active simulation logic — 8 individual attack functions + 1 aggregated runner.
- `app/k8s_client.py`: Live cluster data fetcher.
- `app/rules.py`: Rule synchronization from `rules.json` to DB on first startup (only if table is empty).
- `rules.json`: 20 threat signatures across rbac/workload/network categories. Each rule has a `"remediation"` field.
- `alembic/`: Migration environment. Single version file `2528ca9dd5f1` creates all tables.
- `dumps/`: Generated YAML dumps from live cluster. Files named `{prefix}_{YYYYMMDD_HHMMSS}.yaml`. `.gitignore` excludes yaml files, `.gitkeep` tracks the folder.
- `backups/`: Server-side database backups. `.gitignore` excludes all files here.
- `templates/index.html`: The entire frontend SPA (single file, ~1650 lines).
- `app/static/`: Vendored CSS/JS assets for offline mode (Tailwind, DaisyUI, Alpine, ChartJS).

**Instructions for the AI:**
Adhere strictly to FastAPI dependency injection (`Depends(get_db)`). Ensure frontend changes utilize Alpine.js directives cleanly without breaking the SPA reactivity or the cyberpunk UI style. When adding endpoints, include them in the Endpoints Reference table above. When modifying Alpine.js state, update the state listing in section 12. When adding new columns to models, create a new Alembic migration — never call `create_all()`. Scanner functions must return 3-tuples `(description, severity, remediation)` — do not regress to 2-tuples.
