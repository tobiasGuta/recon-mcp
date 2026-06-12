# recon-mcp

`recon-mcp` is a local Python MCP server for safe, human-led bug bounty recon. It provides lightweight helpers for scope checks, headers, robots.txt, sitemap.xml, JavaScript URL collection, endpoint extraction, URL deduplication, evidence notes, and manual test planning.

This project complements a separate Go DirFuzz MCP server. It does not implement directory fuzzing in Python. For scope, it can use local JSON snapshots written by H1-Scope-Watcher as the source of truth.

## Safety Model

This server is designed for authorized security testing only. Every network-facing Python tool checks configured scope before making requests. HTTP behavior is read-only, uses timeouts, and avoids custom attack payloads.

It does not exploit vulnerabilities, bypass authentication, brute-force accounts, create accounts, perform login testing, send destructive requests, run high-volume scans, or scan outside configured scope.

Directory fuzzing belongs in the separate Go DirFuzz MCP server, with tools such as `dirfuzz_scan`, `dirfuzz_scan_status`, `dirfuzz_cancel`, `dirfuzz_analyze`, `dirfuzz_list_scope`, and `dirfuzz_build_scan`.

## Installation

Use Python 3.11 or newer.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
```

## Configure Scope

Edit `config/scope.json`:

```json
{
  "scope_source": "h1_snapshots",
  "h1_snapshot_dir": "D:/Tools/H1-Scope-Watcher/snapshots",
  "include_only_bounty_eligible": false,
  "include_only_submission_eligible": true,
  "allowed_domains": [],
  "blocked_domains": [
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "::1"
  ]
}
```

Set `scope_source` to `h1_snapshots` to load local H1-Scope-Watcher JSON files on every scope check. New snapshots are picked up without restarting the MCP server. Set `scope_source` to `manual` to use `allowed_domains` instead.

Exact domains and subdomains are allowed. For example, `api.example.com` matches `example.com`. H1 wildcard entries like `*.example.com` are normalized into host rules. Localhost, loopback, private IPs, link-local IPs, and blocked domains are rejected. If H1 snapshots are missing or invalid, scope checks fail closed.

## H1-Scope-Watcher Snapshots

This project does not call the HackerOne API. H1-Scope-Watcher should fetch program scope and write plain JSON snapshots to disk.

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

## Example Workflow

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

## Project Layout

```text
recon-mcp/
├── pyproject.toml
├── README.md
├── server.py
├── config/
│   └── scope.json
├── recon/
│   ├── __init__.py
│   ├── h1_scope.py
│   ├── scope.py
│   ├── http_fetch.py
│   ├── js_analysis.py
│   ├── urls.py
│   ├── notes.py
│   └── planner.py
├── output/
│   ├── logs/
│   ├── evidence/
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
