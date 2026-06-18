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
7. `score_endpoints`
8. `create_finding_candidate`
9. `promote_finding` only after manual validation
10. `create_campaign_evidence_note`
11. `generate_campaign_summary`
12. `generate_report_candidate_markdown`

`generate_campaign_summary` writes `reports/summary.md`, and `generate_manual_test_plan_for_campaign` writes `reports/manual_test_plan.md`. Reports are local Markdown files only; nothing is auto-submitted anywhere.

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
  "allowed_domains": [
    "example.com"
  ],
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

Exact domains and subdomains are allowed. For example, `api.example.com` matches `example.com`. H1 wildcard entries like `*.example.com` are normalized into host rules. Localhost, loopback, private IPs, link-local IPs, and blocked domains are rejected. If H1 snapshots are missing or invalid, scope checks fail closed.

Request hygiene settings:

- `user_agent` sets the User-Agent used by read-only HTTP helpers. The default is `ReconMCP/0.1`.
- `request_delay_ms` adds a small delay before network requests. The default is `500`.
- `max_requests_per_tool_call` caps collection helpers that can discover many request targets. The default is `20`.
- `check_scope_batch` accepts up to 200 hosts or URLs per call.
- `fetch_headers_method` defaults to `HEAD`. If `HEAD` is blocked or fails before useful headers are available, `fetch_headers` falls back to a safe `GET` that requests only the first byte and still checks scope before every redirect hop.

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

## Run the MCP Server

```powershell
python .\server.py
```

The server runs over stdio:

```python
if __name__ == "__main__":
    mcp.run(transport="stdio")
```

## Codex MCP Config Example

Replace paths with your real local paths.

```toml
[mcp_servers.recon]
command = "python"
args = ["D:/Tools/recon-mcp/server.py"]
```

You can run this alongside your Go DirFuzz MCP server:

```toml
[mcp_servers.recon]
command = "python"
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
