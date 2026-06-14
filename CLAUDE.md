### AI SYSTEM CONTEXT: kube-risk-analyzer

**Target AI:** Please read this conceptual overview carefully before modifying or writing any code. This document explains the *"Why"*, *"How"*, and *"Where"* of the project to save your context tokens.

#### 1. Project Identity & Goal
**`kube-risk-analyzer`** is an advanced, hybrid Kubernetes security tool combining **CSPM** (Cloud Security Posture Management - static analysis) and **BAS** (Breach & Attack Simulation - active exploitation). 
Objective: Reduce False Positives in security alerts by proving misconfigurations are exploitable (Attack Path Mapping), targeting Container Breakouts, Privilege Escalation, and Network Exposure.

#### 2. Architectural Paradigms (Strict Rules)
- **Data Source Agnosticism**: Scanner engines (`app/scanners/`) accept plain Python dictionaries representing K8s objects. The exact same scanner code processes both offline YAML dumps and live K8s API responses.
- **Database over Hardcode**: Security rules are in `rules.json` and synced to the `RiskRule` SQLite table on application startup (via FastAPI lifespan). 
- **Air-Gapped Ready (Vendoring)**: The frontend is designed to work completely offline in isolated corporate networks. Do not introduce dependencies that require external internet at runtime.
- **SQLite WAL Mode**: To support concurrent async reads/writes, WAL (Write-Ahead Logging) mode is explicitly enabled in `database.py` via SQLAlchemy pool events. Also enables `PRAGMA foreign_keys=ON`.

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
- `id: int`, `description: str`, `dangerous_verbs: Optional[str]`, `dangerous_resources: Optional[str]`, `category: str = "rbac"`, `key: Optional[str]`, `severity: str = "MEDIUM"`
- `RiskRuleCreate` (used by `POST /rules`) inherits all base fields
- `RiskRuleUpdate` (used by `PUT /rules/{id}`) — all fields optional, used with `exclude_none=True`

**`FindingSchema`** — `from_attributes=True`:
- `id: int`, `scan_id: int`, `subject: str`, `role: str`, `risk_description: str`, `severity: str = "MEDIUM"`

**`ScanHistorySchema`** — `from_attributes=True`:
- `id: int`, `scan_date: datetime`, `target_name: str`, `findings: List[FindingSchema] = []`

**`BasScriptSchema`** — `from_attributes=True`:
- `id: int`, `name: str`, `description: Optional[str]`, `script_content: str`
- `BasScriptCreate` (used by `POST /scripts`) and `BasScriptUpdate` (used by `PUT /scripts/{id}`, all fields optional)

**`BASSimulateRequest`** (request body for `POST /bas/simulate/{ns}/{pod}`):
- `script_id: Optional[int] = None` — if set, runs the custom `BasScript`; otherwise runs built-in token theft

#### 5. Core Analysis Modules (CSPM)

**5a. RBAC Scanner** (`app/scanners/rbac.py` — 3 functions):
- `evaluate_rbac_rule(role_verbs, role_resources, db_rules) -> list[str]` — Matches a single Role's verbs/resources against DB rules. Supports wildcard (`*`) matching.
- `analyze_rbac_bindings(bindings, roles, cluster_roles, db_rbac_rules) -> list[dict]` — Iterates all RoleBindings/ClusterRoleBindings, resolves roleRef, runs `evaluate_rbac_rule`. Returns `{"subject", "role", "risk_description", "severity"}` dicts. Deduplicates findings.
- `get_sa_rbac_dangers(sa_name, namespace, bindings, roles, cluster_roles, db_rules) -> list[tuple]` — Cross-references a specific ServiceAccount's bindings. Returns `[(description, severity), ...]`. Used by Context Correlation in scan endpoints.

**5b. Workload Scanner** (`app/scanners/workload.py` — 2 functions):
- `_path_matches(data, path_parts) -> bool` — Recursive dict/list traversal helper. Supports wildcard matching on lists.
- `analyze_pod_workload(pod_data, db_workload_rules) -> list[tuple]` — For each workload rule, splits `rule.key` by `.` and calls `_path_matches`. Returns `[(description, severity), ...]`.

**5c. Network Scanner** (`app/scanners/network.py` — 1 function):
- `analyze_services(services, db_network_rules) -> list[dict]` — Checks each Service for NodePort/LoadBalancer type and exposed DB ports (5432, 3306, 27017, 6379). Returns `{"subject", "role", "risk_description", "severity"}` dicts.

#### 6. Context Correlation ("The Killer Feature")
The system correlates Workload vulnerabilities with RBAC permissions. If a Pod is vulnerable (e.g., Privileged) AND its `ServiceAccount` has dangerous RBAC rights (e.g., `cluster-admin`), it generates a **"CRITICAL CHAIN"** finding. This logic lives directly inside the pod loop in both `scan_offline` and `scan_live` in `app/main.py` — not in a separate scanner module. Pattern: `if workload_dangers and sa_rbac_dangers: → add CRITICAL CHAIN finding`.

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
| `PUT` | `/rules/{rule_id}` | `RiskRuleSchema` | Update rule (partial, `exclude_none`) |
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

**Key helpers in `app/main.py`:**
- `_pod_display_status(status: dict) -> str` — reads `containerStatuses[*].state.waiting.reason` before falling back to `status.phase`; returns real statuses like `CrashLoopBackOff`
- `_write_dump(items, prefix) -> str` — serializes K8s objects to `apiVersion/kind: List` YAML in `dumps/`
- `_get_scan_or_404(scan_id, db)` — common scan lookup used by export endpoints

#### 9. Rules Engine (`app/rules.py` + `rules.json`)

- `sync_rules_to_db(db, file_path="rules.json")` — Called once on startup via FastAPI lifespan. Deletes all existing rules, reads `rules.json`, converts list fields to comma-separated strings, inserts into `RiskRule` table.
- `rules.json` contains 13 rules: 7 RBAC (DANGER-001 through 007), 3 Workload (DANGER-008 through 010), 3 Network (DANGER-011 through 013).

#### 10. K8s Client (`app/k8s_client.py`)

- `get_live_k8s_data() -> dict` — Loads kube config (local or in-cluster), fetches all namespaces' pods/services/roles/rolebindings + cluster roles/bindings via `sanitize_for_serialization()`. Returns dict with keys: `pods`, `services`, `roles`, `cluster_roles`, `role_bindings`, `cluster_role_bindings`. Raises on connection failure (caller handles).

**Important**: `sanitize_for_serialization` sets `kind=None` on individual list items (K8s API quirk). Never use `b.get('kind') == 'ClusterRoleBinding'` to detect cluster-scope bindings — use `not b.get('metadata', {}).get('namespace')` instead.

#### 11. Database Configuration (`app/database.py`)

- SQLite URL: `sqlite:///./kube_risk.db`
- `check_same_thread=False` for FastAPI thread safety
- WAL mode + foreign keys enabled via `@event.listens_for(Pool, "connect")`
- `get_db()` — generator-based FastAPI dependency, yields `SessionLocal()`

#### 12. Tech Stack & Frontend Design
- **Backend**: Python 3.10+, FastAPI, SQLAlchemy 2.0, Pydantic V2, K8s Python Client (`kubernetes`), PyYAML. Additional stdlib: `csv`, `io`, `json`, `os`, `datetime`.
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
- Computed getters: `filteredFindings`, `filteredRules`, `dashPods` (includes `lastScanId`), `dashTargets`, `filteredDashPods`, `filteredDashTargets`, `filteredScans`, `basNamespaces`, `basPodsForNs`, `liveScanPodsForNs`, `dumpPodsForNs`
- Helper methods: `scanModule(targetName)` → `'BAS'|'LIVE'|'CSPM'`, `scanMaxSev(findings)`, `scanBadgeCls(findings)`
- Action methods: `init()`, `fetchData()`, `fetchScripts()`, `fetchDumps()`, `generateDump()`, `runOfflineScan()`, `runLiveScan()`, `runBas()`, `goToScan(scanId)`, `fetchScanDetails(scanId)`, `deleteScan(scanId)`, `exportScan(format)`, `saveRule()`, `deleteRule(ruleId)`, `saveScript()`, `deleteScript(scriptId)`

**Frontend tabs:**
1. **Dashboard** — stat boxes + "Pods & Workloads" table (live status, finding counts, per-pod toggle, sort/filter, `→` navigation to last scan) + "Scan Targets" table (sort/filter, `→` navigation)
2. **Control Panel** — Offline Scan (file selector + generate dump); Live Scan (namespace/pod scope dropdowns); BAS form; Custom BAS Scripts management
3. **History & Reports** — scan history table (sort by all columns, filter by text/module); click View → findings detail with keyword search + severity filter + export buttons (JSON/CSV/Markdown/SARIF)
4. **Detection Rules** (formerly "Knowledge Base") — sortable/filterable table (by #, category, severity; search by description); inline edit/delete per row

**Severity color convention** (consistent across all tables):
- Row highlight: `bg-error/10 border-l-4 border-error` (CRITICAL), `bg-warning/5 border-l-4 border-warning` (HIGH), `border-l-4 border-info/40` (MEDIUM)
- Text severity labels: plain colored text (`text-error`, `text-warning`, `text-info`, `text-base-content/50`) — no badge backgrounds
- Category badges in Detection Rules still use `badge-secondary/accent/info`
- Scan History Module badge: `badge-error` (has MEDIUM+ findings), `badge-success` (clean/only LOW)

#### 13. Project Structure
- `app/main.py`: FastAPI application, 24 endpoints, Jinja2 frontend rendering. Key helpers: `_pod_display_status`, `_write_dump`, `_get_scan_or_404`.
- `app/database.py` & `app/models.py` & `app/schemas.py`: SQLAlchemy setup, ORM classes (4 models), Pydantic validation.
- `app/scanners/`: `rbac.py` (3 functions), `workload.py` (2 functions), `network.py` (1 function).
- `app/bas.py`: Active simulation logic — 8 individual attack functions + 1 aggregated runner.
- `app/k8s_client.py`: Live cluster data fetcher.
- `app/rules.py`: Rule synchronization from `rules.json` to DB on startup.
- `rules.json`: 13 threat signatures across rbac/workload/network categories.
- `dumps/`: Generated YAML dumps from live cluster. Files named `{prefix}_{YYYYMMDD_HHMMSS}.yaml`. `.gitignore` excludes yaml files, `.gitkeep` tracks the folder.
- `templates/index.html`: The entire frontend SPA (single file, ~1590 lines).
- `app/static/`: Vendored CSS/JS assets for offline mode (Tailwind, DaisyUI, Alpine, ChartJS).

**Instructions for the AI:**
Adhere strictly to FastAPI dependency injection (`Depends(get_db)`). Ensure frontend changes utilize Alpine.js directives cleanly without breaking the SPA reactivity or the cyberpunk UI style. When adding endpoints, include them in the Endpoints Reference table above. When modifying Alpine.js state, update the state listing in section 12.
