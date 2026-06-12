"""MCP entrypoint for the Recon MCP server."""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from recon import __version__
from recon.http_fetch import fetch_headers as fetch_headers_logic
from recon.http_fetch import fetch_robots as fetch_robots_logic
from recon.http_fetch import fetch_sitemap as fetch_sitemap_logic
from recon.js_analysis import collect_js_urls as collect_js_urls_logic
from recon.js_analysis import extract_endpoints_from_js as extract_endpoints_from_js_logic
from recon.notes import create_evidence_note as create_evidence_note_logic
from recon.planner import generate_manual_test_plan as generate_manual_test_plan_logic
from recon.scope import check_scope as check_scope_logic
from recon.scope import list_loaded_scope as list_loaded_scope_logic
from recon.urls import dedupe_urls as dedupe_urls_logic


mcp = FastMCP("recon-mcp")

AVAILABLE_TOOLS = [
    "health",
    "check_scope",
    "list_loaded_scope",
    "fetch_headers",
    "fetch_robots",
    "fetch_sitemap",
    "collect_js_urls",
    "extract_endpoints_from_js",
    "dedupe_urls",
    "create_evidence_note",
    "generate_manual_test_plan",
    "dirfuzz_integration_info",
]


@mcp.tool()
def health() -> dict:
    """Return health for safe recon helpers for authorized testing only."""
    return {
        "ok": True,
        "project": "recon-mcp",
        "version": __version__,
        "available_tools": AVAILABLE_TOOLS,
        "safety_note": "This server provides scoped, low-risk recon helpers only.",
        "dirfuzz_note": "Directory fuzzing is delegated to the separate Go DirFuzz MCP server.",
    }


@mcp.tool()
def check_scope(domain: str) -> dict:
    """Safely check whether a domain or URL is authorized by configured recon scope."""
    return check_scope_logic(domain)


@mcp.tool()
def list_loaded_scope() -> dict:
    """Return a safe, non-secret summary of loaded authorized recon scope."""
    return list_loaded_scope_logic()


@mcp.tool()
def fetch_headers(url: str) -> dict:
    """Safely fetch HTTP response headers from an authorized in-scope URL only."""
    return fetch_headers_logic(url)


@mcp.tool()
def fetch_robots(url: str) -> dict:
    """Safely fetch robots.txt from an authorized in-scope URL origin only."""
    return fetch_robots_logic(url)


@mcp.tool()
def fetch_sitemap(url: str) -> dict:
    """Safely fetch sitemap.xml from an authorized in-scope URL origin only."""
    return fetch_sitemap_logic(url)


@mcp.tool()
def collect_js_urls(url: str) -> dict:
    """Safely collect same-origin or authorized in-scope JavaScript URLs from HTML."""
    return collect_js_urls_logic(url)


@mcp.tool()
def extract_endpoints_from_js(file_or_url: str) -> dict:
    """Safely extract endpoint candidates from authorized JS URLs or local project JS files."""
    return extract_endpoints_from_js_logic(file_or_url)


@mcp.tool()
def dedupe_urls(urls: list[str]) -> dict:
    """Normalize and deduplicate URLs for authorized recon notes."""
    return dedupe_urls_logic(urls)


@mcp.tool()
def create_evidence_note(finding: dict) -> dict:
    """Create a local Markdown evidence note for authorized manual testing only."""
    return create_evidence_note_logic(finding)


@mcp.tool()
def generate_manual_test_plan(target_summary: dict) -> dict:
    """Generate a safe authorized-testing checklist from recon output."""
    return generate_manual_test_plan_logic(target_summary)


@mcp.tool()
def dirfuzz_integration_info() -> dict:
    """Explain that directory fuzzing is delegated to the separate Go DirFuzz MCP server."""
    return {
        "ok": True,
        "message": "Directory fuzzing is handled by the separate Go DirFuzz MCP server.",
        "recommended_tools": [
            "dirfuzz_scan",
            "dirfuzz_scan_status",
            "dirfuzz_cancel",
            "dirfuzz_analyze",
            "dirfuzz_list_scope",
            "dirfuzz_build_scan",
        ],
        "recommended_workflow": [
            "Run H1-Scope-Watcher in Docker with snapshots written to a host-accessible folder.",
            "Point Python Recon MCP h1_snapshot_dir at that snapshots folder for scope checks.",
            "Point Go DirFuzz MCP DIRFUZZ_SCOPE_DIR at the same snapshots folder.",
            "Use Python Recon MCP to collect headers, robots.txt, sitemap.xml, JS URLs, and possible endpoints.",
            "Use Go DirFuzz MCP only after scope is confirmed from the same H1 snapshots.",
            "Analyze DirFuzz JSONL output with dirfuzz_analyze.",
            "Use Python Recon MCP to create evidence notes and manual test plans.",
            "Use Codex Desktop with both MCP servers enabled for a coordinated workflow.",
        ],
    }


if __name__ == "__main__":
    mcp.run(transport="stdio")
