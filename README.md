# recon-mcp

`recon-mcp` is a local Python MCP server for authorized, low-risk, human-led bug bounty recon. It provides lightweight helpers for scope checks, headers, robots.txt, sitemap.xml, JavaScript URL collection, endpoint extraction, URL deduplication, evidence notes, manual test planning, and campaign-based recon organization.

This project complements a separate Go DirFuzz MCP server. It does not implement directory fuzzing in Python. For scope, it can use local JSON snapshots written by H1-Scope-Watcher as the source of truth.

## Safety Model

This server is designed for authorized, low-risk security testing only. Every network-facing Python tool checks configured scope before making requests and before following redirect targets. HTTP behavior is read-only, uses timeouts and small request delays, and avoids custom attack payloads.

Recon MCP blocks literal local, loopback, private, link-local, multicast, reserved, and unspecified IP targets. It also resolves hostnames before requests and before following redirects, then blocks any hostname that resolves to those unsafe IP ranges. This helps reduce DNS rebinding and accidental internal-network request risks while preserving a fail-closed recon model.

Sitemap XML parsing uses `defusedxml` so unsafe XML constructs are rejected safely instead of being parsed by the standard library XML parser.

It does not exploit vulnerabilities, bypass authentication, brute-force accounts, create accounts, perform login testing, send destructive requests, run high-volume scans, or scan outside configured scope. DNS resolved-IP checks and hardened XML parsing are defensive controls for authorized recon, not bypass or exploitation features.

Directory fuzzing belongs in the separate Go DirFuzz MCP server, with tools such as `dirfuzz_scan`, `dirfuzz_scan_status`, `dirfuzz_cancel`, `dirfuzz_analyze`, `dirfuzz_list_scope`, and `dirfuzz_build_scan`.

## Campaign Workflow

Campaigns organize scoped recon artifacts, finding candidates, evidence, memory, and reports under `output/campaigns/<campaign_id>/`. Creating a campaign checks configured scope first and fails closed when the target is not authorized.

Each campaign stores:

```text
output/campaigns/<campaign_id>/
  campaign.json
  scope.json
  audit.jsonl
  recon/
  findings/
  evidence/
  memory/
  reports/
```

Campaign-aware tools save JSON artifacts into the matching `recon/` subfolder and append audit events to `audit.jsonl`. Network-facing campaign tools still rely on the existing scope-enforced fetch and JavaScript helpers.

Recommended campaign flow:

1. `create_campaign`
2. `fetch_headers_for_campaign`
3. `fetch_robots_for_campaign`
4. `fetch_sitemap_for_campaign`
5. `collect_js_urls_for_campaign`
6. `extract_endpoints_for_campaign`
7. `scan_sensitive_artifacts_for_campaign` and `extract_api_contracts_for_campaign`
8. `get_evidence_graph_summary` and a bounded `query_evidence_graph` when useful
9. Optionally run passive subdomain discovery; DNS resolution remains off by default
10. `score_endpoints`
11. `create_finding_candidate`
12. `promote_finding` only after manual validation
13. `create_campaign_evidence_note`
14. `generate_campaign_summary` and `verify_campaign_artifacts`
15. `generate_report_candidate_markdown`

`generate_campaign_summary` writes `reports/summary.md`, and `generate_manual_test_plan_for_campaign` writes `reports/manual_test_plan.md`. Reports are local Markdown files only; nothing is auto-submitted anywhere.

## Campaign Cleanup

Campaign cleanup is archive-first. `archive_campaign` moves a campaign from `output/campaigns/` to `output/archived_campaigns/` and marks its metadata as archived. This preserves evidence, findings, reports, and audit logs while keeping active campaign lists tidy.

Active campaigns are not directly deleted by MCP for safety. Permanent deletion, when used, only works on archived campaigns and requires the exact campaign ID as confirmation through `delete_archived_campaign`.

## Finding Pipeline

Possible issues are not vulnerabilities. Every new candidate starts in the hallucination bin at `findings/hallucinations/` with `manual_validation_required: true`.

Allowed status flow:

- `hallucination` to `needs_manual_validation`
- `needs_manual_validation` to `validated`
- `validated` to `report_candidate`
- any status to `rejected`

Report candidates require all gates to be true: scope confirmed, evidence saved, reproduced manually, impact proven, safe non-destructive testing, and report ready. The pipeline blocks direct jumps from hallucination to validated or report candidate.

Negative-result memory is stored in `memory/negative_results.jsonl`. These records document useful checks that did not produce findings; they are included in summaries and manual plans, but they are not treated as vulnerabilities.

The hallucination bin is intentional. It keeps AI-assisted or speculative leads separate until a human validates scope, evidence, reproducibility, impact, and safety.

## Source Map Recon

Source maps can reveal original frontend source files, routes, API paths, GraphQL usage, environment names, feature flags, client configuration, and source file names. These are recon leads, not vulnerabilities by themselves.

Recon MCP handles source maps inside a campaign with a safe, explicit workflow:

- Fetch JavaScript through the existing scope-checked HTTP helpers.
- Detect `sourceMappingURL` references without downloading by default.
- Resolve and scope-check every source map URL.
- Skip out-of-scope source map URLs instead of fetching them.
- Download only bounded, in-scope source map JSON.
- Extract embedded `sourcesContent` locally inside the campaign folder.
- Analyze extracted files for endpoint candidates and manual-review signals.
- Redact likely sensitive values in previews.

Recon MCP does not use unsafe remote external modes such as `sourcemapper -jsurl https://target/app.js` or `sourcemapper -url https://target/app.js.map`. External sourcemapper, if used later, must be local-file-only: it should accept only `.map` files already stored inside the campaign and write only inside the campaign extracted folder. No cookies, Authorization headers, tokens, custom auth headers, or remote URLs are passed to external tools. No reports are auto-submitted.

Source map workflow:

1. `create_campaign`
2. `collect_js_urls_for_campaign`
3. `detect_sourcemap_references_for_campaign`
4. `download_sourcemap_for_campaign`
5. `extract_sourcemap_sources_for_campaign`
6. `analyze_sourcemap_sources_for_campaign`
7. `generate_manual_test_plan_for_campaign`
8. `create_finding_candidate` only if manual validation suggests a real issue
9. `promote_finding` only after impact is proven
10. `generate_campaign_summary`

## Deterministic local analysis

The architecture keeps one safety path instead of parallel subsystems: `scope.py` owns authorization, `http_fetch.py` owns streamed target requests and redirect/DNS checks, `safeio.py` owns campaign path and artifact boundaries, `audit.py` owns append-only operation history, and the existing campaign/finding/report workflow remains the only promotion path. Feature modules contribute redacted structured artifacts and evidence-graph observations through those shared layers.

`scan_sensitive_artifacts_for_campaign` analyzes only approved campaign-local text. It returns minimal prefix/suffix redactions and SHA-256 fingerprints; complete candidates and surrounding source lines are never returned, persisted, logged, or placed in reports. Private-key candidates expose only their type/header, location, and fingerprint. Placeholder values are downgraded, and public client identifiers such as Stripe publishable keys, Sentry DSNs, Firebase configuration, and Google browser API keys are separate client-configuration signals. The tool never tests a credential.

`extract_api_contracts_for_campaign` recognizes deterministic `fetch`, Axios, Angular `HttpClient`, `XMLHttpRequest`, WebSocket, JSON body, and named GraphQL operation patterns. Every contract declares endpoint uncertainty as `static`, `partially_dynamic`, `fully_dynamic`, or `unknown`. Its previews redact authentication-like values. Contract priority is only a manual-review order, never a vulnerability conclusion.

## Evidence, passive discovery, and comparison

The campaign evidence graph records normalized, redacted nodes, edges, provenance, confidence, scope decisions, and observation history. Graph summaries and neighborhood queries are bounded; the entire graph is not returned by default. `import_dirfuzz_evidence_for_campaign` adapts analysis already saved by the existing DirFuzz handoff. The stable version 1.0 schema is documented in [Security Design](docs/security-design.md).

Passive discovery queries fixed public provider APIs, so it does make external requests and reveals the authorized root domain to those providers. It does not contact discovered subdomains. Exact apex authorization permits recording children only as out-of-scope leads; wildcard authorization is required before children become testable. Optional DNS resolution is explicit, bounded, and never followed by HTTP probing.

`compare_campaign_recon` compares normalized artifacts rather than timestamps or generated filenames. It produces structured JSON and Markdown for added, removed, or changed recon observations, using only detector IDs and fingerprints for secret candidates. Differences remain recon leads.

## Traffic import and artifact integrity

HAR and Burp XML imports accept only campaign-local files (prefer `imports/`) and never replay requests. They retain host, path, method, status, content type, parameter names, body-field names, authentication presence, cookie names, and scope decisions. Authorization values, cookies, sensitive query values, session data, and bodies are not stored. Burp XML uses hardened XML parsing.

New structured artifacts carry provenance and have sibling integrity metadata whose SHA-256 is calculated from final saved bytes. `verify_campaign_artifacts` is read-only and reports verified, missing, modified, malformed, and unsupported legacy artifacts.

Nuclei is intentionally not executed here. A future separate Nuclei MCP must use exact reviewed template IDs, pinned signed HTTP-only templates, strict one-target plans and limits, explicit approval, and structured result import. Tags are never the main safety boundary. `nuclei_integration_info` returns the non-executing contract.

## Installation

Use Python 3.11 or newer.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
```

## Configure Scope

Create a local `config/scope.json` from `config/scope.example.json`, then edit it for your authorized target scope. The local `config/scope.json` file is ignored so personal snapshot paths and active program scope do not get pushed.

```json
{
  "scope_source": "manual",
  "h1_snapshot_dir": "",
  "include_only_bounty_eligible": false,
  "include_only_submission_eligible": true,
  "allowed_assets": [
    {"value": "api.example.com", "match": "exact"},
    {"value": "*.example.com", "match": "wildcard"}
  ],
  "allowed_domains": [],
  "user_agent": "ReconMCP/0.1",
  "request_delay_ms": 500,
  "max_requests_per_tool_call": 20,
  "fetch_headers_method": "HEAD",
  "blocked_domains": [
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "::1"
  ]
}
```

Set `scope_source` to `h1_snapshots` to load local H1-Scope-Watcher JSON files for scope checks. Scope config is cached briefly, and new snapshots are picked up without restarting the MCP server. Set `scope_source` to `manual` to use `allowed_domains` instead.

Exact assets authorize only the normalized host. Wildcard assets authorize child and deeply nested subdomains but exclude the apex. Legacy plain `allowed_domains` entries now migrate as exact assets; only an explicit `*.example.com` legacy entry is a wildcard. This safer behavior intentionally replaces the former implicit-subdomain authorization. H1 wildcard entries remain normalized into host rules. IDNs are normalized, while malformed assets and unsafe IPs fail closed.

Request hygiene settings:

- `user_agent` sets the User-Agent used by read-only HTTP helpers. The default is `ReconMCP/0.1`.
- `request_delay_ms` adds a small delay before network requests. The default is `500`.
- `max_requests_per_tool_call` caps collection helpers that can discover many request targets. The default is `20`.
- `check_scope_batch` accepts up to 200 hosts or URLs per call.
- `fetch_headers_method` defaults to `HEAD`. If `HEAD` is blocked or fails before useful headers are available, `fetch_headers` falls back to a safe `GET` that requests only the first byte and still checks scope before every redirect hop.
- `max_html_bytes`, `max_javascript_bytes`, `max_sourcemap_bytes`, `max_sitemap_bytes`, and `max_robots_bytes` stop streamed reads as soon as a limit is exceeded.
- `max_saved_artifact_bytes`, `max_extracted_source_files`, `max_total_extracted_source_bytes`, `max_analysis_signals`, and `max_endpoint_candidates` bound local artifacts and analysis output. Invalid or unreasonable integer values reject the configuration.

## H1-Scope-Watcher Snapshots

This project does not call any bug bounty platform API directly. H1-Scope-Watcher should fetch program scope and write plain JSON snapshots to disk.

When running H1-Scope-Watcher in Docker on Windows, use a bind mount so snapshots are visible on the host:

```yaml
volumes:
  - ./config.yaml:/app/config.yaml:ro
  - ./snapshots:/app/snapshots
```

That creates local JSON files such as:

```text
D:/Tools/H1-Scope-Watcher/snapshots/program_handle.json
```

Point `h1_snapshot_dir` at that folder. Do not point Recon MCP at H1-Scope-Watcher `config.yaml`, `.env`, or any file containing API tokens.

## Use Recon MCP from a CLI or MCP Client

Recon MCP is a local **stdio** server. Normally, your CLI or desktop client starts
`server.py` for you and communicates with it over standard input/output. Use
absolute paths so the client starts the intended Python environment even when the
virtual environment is not activated in that client's shell.

Before connecting a client, complete the installation steps above and create your
authorized `config/scope.json`.

### Codex CLI

Add Recon MCP to Codex on Windows PowerShell:

```powershell
codex mcp add recon -- D:/Tools/recon-mcp/.venv/Scripts/python.exe D:/Tools/recon-mcp/server.py
```

On macOS or Linux, replace both paths with absolute paths on your machine:

```bash
codex mcp add recon -- /absolute/path/recon-mcp/.venv/bin/python /absolute/path/recon-mcp/server.py
```

Check that Codex saved the server correctly:

```powershell
codex mcp list
codex mcp get recon
```

Start an interactive Codex session in the repository, then use `/mcp` to inspect
the connected server:

```powershell
codex -C D:/Tools/recon-mcp
```

A safe first prompt is:

```text
Use the recon health and list_loaded_scope tools. Do not make network requests.
```

You can also run a one-shot Codex command:

```powershell
codex -C D:/Tools/recon-mcp "Use the recon health tool and summarize the server status."
```

To replace or remove this registration:

```powershell
codex mcp remove recon
codex mcp add recon -- D:/Tools/recon-mcp/.venv/Scripts/python.exe D:/Tools/recon-mcp/server.py
```

Run `codex mcp --help` for the commands supported by your installed Codex version.
See the [official Codex MCP documentation](https://developers.openai.com/codex/mcp/)
for current CLI, IDE extension, and desktop-app instructions.

### Codex `config.toml`

As an alternative to `codex mcp add`, add the server directly to
`~/.codex/config.toml` (on Windows, usually
`%USERPROFILE%\.codex\config.toml`) or to a trusted project's
`.codex/config.toml`:

```toml
[mcp_servers.recon]
command = "D:/Tools/recon-mcp/.venv/Scripts/python.exe"
args = ["D:/Tools/recon-mcp/server.py"]
```

Codex CLI, the Codex IDE extension, and the ChatGPT desktop app share this MCP
configuration. In the graphical clients, you can instead add an MCP server in
Settings, choose **STDIO**, and enter the same command and argument.

### Other stdio MCP clients

Clients that use JSON configuration commonly accept a structure like this. The
configuration filename and settings screen vary by client, so check that client's
documentation.

```json
{
  "mcpServers": {
    "recon": {
      "command": "D:/Tools/recon-mcp/.venv/Scripts/python.exe",
      "args": ["D:/Tools/recon-mcp/server.py"]
    }
  }
}
```

If a CLI accepts a server command after `--`, the equivalent command portion is:

```text
D:/Tools/recon-mcp/.venv/Scripts/python.exe D:/Tools/recon-mcp/server.py
```

Select local stdio transport, not HTTP or SSE. This repository does not expose a
remote MCP URL.

### Manual launch and troubleshooting

You can launch the server directly as a diagnostic:

```powershell
D:/Tools/recon-mcp/.venv/Scripts/python.exe D:/Tools/recon-mcp/server.py
```

A blank terminal that appears to wait is expected: the process is waiting for MCP
JSON-RPC messages on stdin. Press `Ctrl+C` to stop it. It is not a standalone chat
CLI.

If the client cannot connect:

- Confirm the Python and `server.py` paths are absolute and exist.
- Run `codex mcp get recon` or inspect the equivalent client configuration.
- Launch the command manually and check for import or configuration errors.
- Confirm `config/scope.json` is valid; invalid or unsafe scope fails closed.
- Do not put API tokens or bug-bounty platform credentials in MCP arguments.

### Run alongside DirFuzz MCP

You can run this alongside your Go DirFuzz MCP server:

```toml
[mcp_servers.recon]
command = "D:/Tools/recon-mcp/.venv/Scripts/python.exe"
args = ["D:/Tools/recon-mcp/server.py"]

[mcp_servers.dirfuzz]
command = "D:/Tools/DirFuzz-Mcp-Monitor/dirfuzz-mcp.exe"
args = []
env = {
  DIRFUZZ_WORDLIST_DIR = "D:/Tools/DirFuzz-Mcp-Monitor/wordlists",
  DIRFUZZ_SCOPE_DIR = "D:/Tools/H1-Scope-Watcher/snapshots",
  DIRFUZZ_OUTPUT_DIR = "D:/Tools/DirFuzz-Mcp-Monitor/output"
}
```

The key idea: Python Recon MCP `h1_snapshot_dir` and Go DirFuzz MCP `DIRFUZZ_SCOPE_DIR` should point to the same H1-Scope-Watcher snapshots folder.

## Available Python MCP Tools

- `health()`
- `check_scope(domain: str)`
- `resolve_scope_target(host_or_url: str, format: str | None = None)`
- `check_scope_batch(hosts_or_urls: list[str], format: str | None = None)`
- `get_scope_map()`
- `recommend_bugmap_parent(host_or_url: str, available_bugmap_targets: list[dict])`
- `explain_scope_decision(host_or_url: str)`
- `list_loaded_scope()`
- `fetch_headers(url: str)`
- `fetch_robots(url: str)`
- `fetch_sitemap(url: str)`
- `collect_js_urls(url: str)`
- `extract_endpoints_from_js(file_or_url: str)`
- `dedupe_urls(urls: list[str])`
- `create_evidence_note(finding: dict)`
- `generate_manual_test_plan(target_summary: dict)`
- `dirfuzz_integration_info()`
- `create_campaign(program: str, target: str, notes: str | None = None)`
- `list_campaigns(limit: int = 50)`
- `get_campaign(campaign_id: str)`
- `archive_campaign(campaign_id: str, reason: str | None = None)`
- `list_archived_campaigns(limit: int = 50)`
- `get_archived_campaign(campaign_id: str)`
- `delete_archived_campaign(campaign_id: str, confirm_campaign_id: str)`
- `fetch_headers_for_campaign(campaign_id: str, url: str)`
- `fetch_robots_for_campaign(campaign_id: str, url: str)`
- `fetch_sitemap_for_campaign(campaign_id: str, url: str)`
- `collect_js_urls_for_campaign(campaign_id: str, url: str)`
- `extract_endpoints_for_campaign(campaign_id: str, file_or_url: str, source_type: str | None = None)`
- `save_dirfuzz_analysis_for_campaign(campaign_id: str, analysis: dict)`
- `create_finding_candidate(campaign_id: str, finding: dict)`
- `get_finding(campaign_id: str, finding_id: str)`
- `list_findings(campaign_id: str, status: str | None = None)`
- `promote_finding(campaign_id: str, finding_id: str, target_status: str, reason: str, gate_updates: dict | None = None)`
- `demote_finding(campaign_id: str, finding_id: str, target_status: str, reason: str)`
- `reject_finding(campaign_id: str, finding_id: str, reason: str)`
- `create_campaign_evidence_note(campaign_id: str, finding: dict)`
- `score_endpoint(endpoint: dict | str)`
- `score_endpoints(endpoints: list[dict | str])`
- `record_negative_result(campaign_id: str, target: str, check_type: str, result: str, repeat_after: str | None = None, metadata: dict | None = None)`
- `list_negative_results(campaign_id: str, check_type: str | None = None)`
- `generate_manual_test_plan_for_campaign(campaign_id: str)`
- `generate_campaign_summary(campaign_id: str)`
- `generate_report_candidate_markdown(campaign_id: str, finding_id: str)`
- `detect_sourcemap_references_for_campaign(campaign_id: str, js_url: str)`
- `download_sourcemap_for_campaign(campaign_id: str, sourcemap_url: str)`
- `extract_sourcemap_sources_for_campaign(campaign_id: str, map_path: str)`
- `analyze_sourcemap_sources_for_campaign(campaign_id: str, extracted_dir: str | None = None)`
- `sourcemap_workflow_for_campaign(campaign_id: str, js_url: str)`
- `external_sourcemapper_info()`
- `scan_sensitive_artifacts_for_campaign(campaign_id: str, extracted_dir: str | None = None)`
- `extract_api_contracts_for_campaign(campaign_id: str, extracted_dir: str | None = None)`
- `get_evidence_graph_summary(campaign_id: str)`
- `query_evidence_graph(campaign_id: str, node_uuid: str, depth: int = 1, limit: int = 100)`
- `import_dirfuzz_evidence_for_campaign(campaign_id: str, analysis_path: str | None = None)`
- `discover_subdomains_passive_for_campaign(campaign_id: str, root_domain: str, providers: list[str] | None = None, max_results: int = 500, resolve_dns: bool = False)`
- `compare_campaign_recon(campaign_id: str, baseline_campaign_id: str)`
- `import_har_for_campaign(campaign_id: str, har_path: str)`
- `import_burp_xml_for_campaign(campaign_id: str, xml_path: str)`
- `verify_campaign_artifacts(campaign_id: str)`
- `nuclei_integration_info()`

## Legacy Example Workflow

1. Run H1-Scope-Watcher in Docker with snapshots written to a host-accessible folder.
2. Point Python Recon MCP `h1_snapshot_dir` at that snapshots folder.
3. Point Go DirFuzz MCP `DIRFUZZ_SCOPE_DIR` at that same snapshots folder.
4. Check scope with Python Recon MCP.
5. Fetch headers, robots.txt, and sitemap.xml.
6. Collect JavaScript URLs from in-scope pages.
7. Extract possible endpoints from JavaScript.
8. Use Go DirFuzz MCP for directory fuzzing after scope is confirmed.
9. Analyze DirFuzz results with `dirfuzz_analyze`.
10. Generate a manual test plan.
11. Create evidence notes for manually validated findings.

For campaign mode, prefer the campaign workflow above. Candidate findings are not vulnerabilities, everything starts in hallucinations until validated manually, reports are not auto-submitted, and DirFuzz remains separate in the Go DirFuzz MCP server.

## Project Layout

```text
recon-mcp/
├── pyproject.toml
├── README.md
├── server.py
├── config/
│   └── scope.example.json
├── recon/
│   ├── __init__.py
│   ├── h1_scope.py
│   ├── scope.py
│   ├── http_fetch.py
│   ├── js_analysis.py
│   ├── urls.py
│   ├── notes.py
│   ├── planner.py
│   ├── campaigns.py
│   ├── audit.py
│   ├── workflow.py
│   ├── findings.py
│   ├── endpoint_scoring.py
│   ├── memory.py
│   ├── sourcemaps.py
│   └── reports.py
├── output/
│   ├── logs/
│   ├── evidence/
│   ├── campaigns/
│   └── reports/
└── tests/
    ├── test_scope.py
    ├── test_h1_scope.py
    ├── test_urls.py
    └── test_js_analysis.py
```

## Development

Run tests:

```powershell
pytest
```

Run the server:

```powershell
python .\server.py
```

## Disclaimer

Use this only for authorized bug bounty and security testing workflows. The server is intentionally scoped and conservative, and it is not an autonomous hacking agent.
