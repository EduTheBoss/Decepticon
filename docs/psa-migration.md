# PSA → Decepticon Migration

This document catalogs the migration of twelve features from
[Armur-Ai/Pentest-Swarm-AI](https://github.com/Armur-Ai/Pentest-Swarm-AI) (Go, "PSA")
into Decepticon's Python + LangGraph architecture. The goal of the port was not a
line-for-line rewrite — PSA's Go packages were redesigned to fit Decepticon's
async agent middleware, Pydantic schemas, and sandbox model. Where PSA shipped a
feature, Decepticon ships the semantic equivalent, adapted to its idioms and
extended where the autonomous kill chain demanded it.

> **Scoring note.** Per maintainer request, Decepticon standardizes on
> **CVSS v4.0** (not v3.1) for all severity calculations. The scoring engine
> implements the full FIRST specification, including the macroVector lookup
> table, equivalence classes, and severity distance interpolation. See the
> [CVSS v4.0 specification document](https://www.first.org/cvss/v4.0/specification-document)
> for the normative reference.

> **MITRE ATT&CK.** Scope rules, YAML playbooks, and ASM snapshots all carry
> ATT&CK technique IDs as first-class metadata. Scope enforcement records the
> blocked technique, playbooks declare the chain of techniques they execute,
> and ASM diffs are tagged with the discovery technique (T1590/T1595) that
> surfaced the change. This keeps every autonomous action traceable back to
> the ATT&CK matrix.

## File mapping

| PSA (Go) | Decepticon (Python) | Notes |
|---|---|---|
| `internal/scoring/cvss3.go` | `decepticon/scoring/cvss4.py` | Upgraded v3.1 → v4.0; full macroVector LUT |
| `internal/scope/validator.go` | `decepticon/scope/validator.py` + `decepticon/scope/middleware.py` | Hard-fail validator + LangGraph middleware |
| `internal/cleanup/registry.go` | `decepticon/cleanup/registry.py` + `decepticon/cleanup/emergency.py` | Registry, campaign state machine, SIGINT handler |
| `internal/mcp/server.go` | `decepticon/mcp/server.py` + `decepticon/mcp/tools.py` | stdio MCP, 7 tools exposed |
| `internal/integrations/*.go` | `decepticon/integrations/{jira,slack,siem,sarif,webhook,github_action}.py` | Jira, Slack, SIEM (CEF/STIX/syslog), SARIF, HMAC webhook, GitHub Action |
| `internal/playbooks/{loader,runner}.go` + `playbooks/*.yaml` | `decepticon/playbooks/{loader,runner,schema}.py` + `playbooks/*.yaml` | 4 playbooks shipped |
| `internal/asm/*.go` | `decepticon/asm/{snapshot,differ,watcher,trigger}.py` | CLI `decepticon-asm` |
| `internal/bugbounty/*.go` | `decepticon/bugbounty/{importer,hackerone,bugcrowd,intigriti,dedup,formatter,schemas}.py` | 3 platforms + dedup + program-compliant formatter |
| `internal/plugins/*.go` | `decepticon/plugins/{types,loader}.py` + `decepticon/plugins/examples/` | ABC + loader + example |
| `internal/ctf/*.go` | `decepticon/ctf/{platforms,solver}.py` | HTB, THM, VulnHub + solver harness |
| `internal/memory/pattern.go` | `decepticon/pattern_memory/{store,embeddings}.py` | SQLite fallback + pgvector |
| `cmd/psa-doctor`, `cmd/psa-explain` | `decepticon/cli.py` (`decepticon-doctor`, `decepticon-explain`) | click-based CLI |

---

## 1. CVSS 4.0 Scoring

**What was migrated.** PSA's CVSS v3.1 calculator was replaced with a full
CVSS v4.0 implementation: vector parser, metric model, macroVector derivation,
and score computation using the FIRST lookup table.

**Why.** CVSS v3.1 mis-ranks supply-chain and chained-exploit findings that
Decepticon produces routinely. v4.0's Environmental and Threat metrics (MAV,
MAC, MAT, E) capture kill-chain context that v3.1 throws away.

**Usage.**
```python
from decepticon.scoring.cvss4 import score_from_vector, severity_from_score

s = score_from_vector("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")
print(s.base_score, severity_from_score(s.base_score))
```

**MITRE ATT&CK.** Severity is emitted alongside the triggering technique ID
so Jira/SARIF reports link score → technique.

---

## 2. Hard Scope Validator + Middleware

**What was migrated.** PSA's `scope.Validator` (CIDR/domain/URL matching with
allow/deny precedence) became `ScopeValidator`, and the LangGraph
`ScopeMiddleware` intercepts every tool call before it reaches the sandbox.

**Why.** Decepticon runs autonomous agents against real assets; an
out-of-scope command must fail *before* execution, not be caught in review.

**Usage.**
```python
from decepticon.scope.validator import ScopeValidator, ScopeRule, ScopeAction, ScopeKind

v = ScopeValidator(rules=[
    ScopeRule(kind=ScopeKind.CIDR, pattern="10.10.0.0/16", action=ScopeAction.ALLOW),
    ScopeRule(kind=ScopeKind.DOMAIN, pattern="*.prod.example.com", action=ScopeAction.DENY),
])
result = v.check("nmap -sV 10.10.0.5")
assert result.allowed
```

**Config / env vars.** `DECEPTICON_SCOPE_FILE` — YAML path loaded at agent boot.

**MITRE ATT&CK.** Deny events record `mitre_technique` (e.g., `T1046`) on the
audit log so purple-team dashboards can correlate blocked attempts.

---

## 3. Cleanup Registry + Emergency Stop + Campaign State Machine

**What was migrated.** PSA's `cleanup.Registry` (reverse-order teardown),
campaign state transitions, and Ctrl-C handler were ported. The Python
version uses `contextlib.AsyncExitStack` semantics for registered actions.

**Why.** Red-team engagements leave artifacts (implants, users, firewall
rules). The registry guarantees rollback even on hard abort.

**Usage.**
```python
from decepticon.cleanup.registry import CleanupRegistry, CleanupAction
from decepticon.cleanup.emergency import emergency_stop, install_sigint_handler

reg = CleanupRegistry()
reg.register(CleanupAction(name="remove-implant", command="sliver implants rm alpha"))
install_sigint_handler(reg, sandbox)
# ... run engagement ...
await emergency_stop(reg, sandbox)
```

**Config / env vars.** `DECEPTICON_CLEANUP_ON_ABORT=1` (default) — auto-run
registered actions on SIGINT.

---

## 4. MCP Server Surface

**What was migrated.** PSA's JSON-RPC MCP server became a Python stdio MCP
server exposing 7 Decepticon tools: `scope_check`, `cvss4_score`,
`playbook_list`, `playbook_run`, `asm_snapshot`, `asm_diff`, `findings_query`.

**Why.** MCP lets Claude Desktop, Cursor, and other MCP hosts drive Decepticon
without spinning up the full CLI.

**Usage.**
```bash
decepticon-mcp            # stdio server; register in claude_desktop_config.json
```

**Config / env vars.** `DECEPTICON_MCP_ALLOW_EXEC=0` disables the exec-capable
tools for read-only hosts.

---

## 5. Enterprise Integrations (Jira / Slack / SIEM / SARIF / Webhook / GitHub Action)

**What was migrated.** Each PSA integration became its own module:
`jira.py` (REST v3, auto-create issues), `slack.py` (block kit), `siem.py`
(CEF, STIX 2.1, RFC-5424 syslog), `sarif.py` (SARIF 2.1.0 for GitHub Code
Scanning), `webhook.py` (HMAC-SHA256 signing), `github_action.py` (composite
action YAML for CI).

**Why.** Findings must land where SecOps already lives. Out-of-the-box
integrations remove the "now what?" gap after a scan completes.

**Usage.**
```python
from decepticon.integrations.jira import JiraClient, JiraFinding
from decepticon.integrations.sarif import to_sarif

jira = JiraClient(base_url="https://acme.atlassian.net", email="bot@acme", token="...")
await jira.create_issue(JiraFinding(title="SQLi in /login", severity="HIGH", cvss=8.8))

sarif_doc = to_sarif(findings)  # dict; write to GitHub Actions output
```

**Config / env vars.**
- `JIRA_BASE_URL`, `JIRA_EMAIL`, `JIRA_TOKEN`, `JIRA_PROJECT`
- `SLACK_WEBHOOK_URL`
- `SIEM_SYSLOG_HOST`, `SIEM_FORMAT` (`cef`|`stix`|`syslog`)
- `DECEPTICON_WEBHOOK_SECRET` (HMAC key)

---

## 6. YAML Playbooks

**What was migrated.** PSA's playbook DSL was ported to Pydantic schemas;
loader validates on read, runner dispatches step-by-step against the agent
graph. Four playbooks ship in `playbooks/`:
`owasp-top10.yaml`, `api-security.yaml`, `active-directory.yaml`,
`webapp-authbypass.yaml`.

**Why.** Repeatable engagements need a declarative spec the orchestrator can
consume without re-prompting the LLM for structure.

**Usage.**
```python
from decepticon.playbooks.loader import list_playbooks
from decepticon.playbooks.runner import PlaybookRunner

for pb in list_playbooks("playbooks/"):
    print(pb.name, pb.mitre)

runner = PlaybookRunner(graph=agent_graph)
await runner.run("playbooks/owasp-top10.yaml", target="https://juice.local")
```

**MITRE ATT&CK.** Each playbook step declares `mitre:` (list of technique
IDs); results roll up into a per-engagement ATT&CK heat-map.

---

## 7. ASM Mode (Attack Surface Monitoring)

**What was migrated.** PSA's ASM scanner became four modules: `snapshot.py`
(capture), `differ.py` (compare two snapshots), `watcher.py` (polling loop
with cron-like scheduling), `trigger.py` (auto-fires a playbook when new
assets appear).

**Why.** Continuous red-teaming beats point-in-time scans. Auto-trigger on
new asset closes the "new prod box goes online at 2am" gap.

**Usage.**
```bash
decepticon-asm --target example.com --interval 3600 \
  --on-new-asset playbooks/webapp-authbypass.yaml
```

```python
from decepticon.asm.snapshot import capture_snapshot
from decepticon.asm.differ import diff

a = await capture_snapshot("example.com")
b = await capture_snapshot("example.com")
delta = diff(a, b)
```

**Config / env vars.** `DECEPTICON_ASM_INTERVAL` (seconds),
`DECEPTICON_ASM_SNAPSHOT_DIR`.

**MITRE ATT&CK.** New-asset events are tagged `T1590.*` / `T1595.*`.

---

## 8. Bug Bounty Scope Importer

**What was migrated.** Importers for HackerOne, Bugcrowd, and Intigriti scope
APIs; dedup across programs; a formatter that outputs
program-compliant finding reports (Markdown, including the platform's
required sections and severity mapping to each program's rubric).

**Why.** Hunters run Decepticon against dozens of programs; manual scope
copy/paste is the #1 way to go out-of-scope.

**Usage.**
```python
from decepticon.bugbounty.importer import import_program
from decepticon.bugbounty.formatter import format_finding

rules = await import_program("hackerone", handle="example", token="...")
report = format_finding(finding, platform="hackerone")
```

**Config / env vars.** `H1_TOKEN`, `BUGCROWD_TOKEN`, `INTIGRITI_TOKEN`.

---

## 9. Plugin System

**What was migrated.** PSA's Go-plugin interface became a Python ABC
(`decepticon.plugins.types.Plugin`) plus a loader that imports plugins from
an entry-point group or a directory. An example plugin is shipped under
`decepticon/plugins/examples/`.

**Why.** Users ship custom recon/exploit modules without forking the core.

**Usage.**
```python
from decepticon.plugins.loader import PluginLoader

loader = PluginLoader()
loader.load_directory("./my_plugins")
for p in loader.plugins:
    p.register(agent_graph)
```

**Config / env vars.** `DECEPTICON_PLUGIN_DIR`.

---

## 10. CTF Adapters

**What was migrated.** Adapters for HackTheBox, TryHackMe, and VulnHub —
each exposes `list_machines()`, `spawn(machine_id)`, `submit_flag(id, flag)`.
A solver harness drives the orchestrator against a selected machine.

**Why.** CTFs are the cleanest regression test for the autonomous loop —
known solutions, scored outcomes.

**Usage.**
```python
from decepticon.ctf.platforms import HackTheBoxAdapter
from decepticon.ctf.solver import solve

htb = HackTheBoxAdapter(token="...")
machine = (await htb.list_machines())[0]
await solve(htb, machine, graph=agent_graph)
```

**Config / env vars.** `HTB_TOKEN`, `THM_TOKEN`.

---

## 11. Pattern Memory

**What was migrated.** PSA's exploit-pattern vector store was ported to a
`PatternStore` with a SQLite backend (default, cosine-sim in pure Python)
and an optional pgvector backend when `PATTERN_DB_URL` points at Postgres.

**Why.** Agents reuse successful technique chains across engagements. Local
SQLite keeps the default install zero-dep; pgvector scales past ~100k
patterns.

**Usage.**
```python
from decepticon.pattern_memory.store import PatternStore

store = PatternStore.open()  # SQLite at ~/.decepticon/patterns.db
await store.add("sqli-login-boolean", embedding=vec, metadata={"cve": "..."})
hits = await store.query(vec, k=5)
```

**Config / env vars.** `PATTERN_DB_URL` (e.g. `postgresql://…/decepticon`),
`PATTERN_EMBED_MODEL`.

---

## 12. Diagnostic CLI (`decepticon-doctor`, `decepticon-explain`)

**What was migrated.** PSA's `psa-doctor` (environment check) and
`psa-explain` (explain a CVSS vector / scope rule / playbook step) were
rewritten with `click`, wired into `pyproject.toml` as console scripts.

**Why.** First-run failures and "why did this get blocked?" questions
dominate support; both commands resolve them without spelunking logs.

**Usage.**
```bash
decepticon-doctor                         # sandbox, docker, API key, scope file
decepticon-explain cvss "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
decepticon-explain playbook playbooks/owasp-top10.yaml
```

---

## Non-goals

- PSA's Go-specific concurrency primitives (channels, errgroups) are *not*
  mirrored 1:1; Python equivalents use `asyncio.TaskGroup` and `anyio`.
- PSA's bundled exploit modules are out of scope for this migration — they
  belong to the plugin system (§9) and will land as separate packages.
- CVSS v3.1 scoring is intentionally *not* preserved; legacy vectors must be
  re-scored under v4.0 before ingestion.
