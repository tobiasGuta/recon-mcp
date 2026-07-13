"""MCP entrypoint for the Recon MCP server."""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from recon import __version__
from recon.campaigns import archive_campaign as archive_campaign_logic
from recon.campaigns import create_campaign as create_campaign_logic
from recon.campaigns import delete_archived_campaign as delete_archived_campaign_logic
from recon.campaigns import get_archived_campaign as get_archived_campaign_logic
from recon.campaigns import get_campaign as get_campaign_logic
from recon.campaigns import list_archived_campaigns as list_archived_campaigns_logic
from recon.campaigns import list_campaigns as list_campaigns_logic
from recon.endpoint_scoring import score_endpoint as score_endpoint_logic
from recon.endpoint_scoring import score_endpoints as score_endpoints_logic
from recon.contracts import extract_api_contracts_for_campaign as extract_api_contracts_for_campaign_logic
from recon.differential import compare_campaign_recon as compare_campaign_recon_logic
from recon.evidence_graph import get_evidence_graph_summary as get_evidence_graph_summary_logic
from recon.evidence_graph import import_dirfuzz_evidence_for_campaign as import_dirfuzz_evidence_for_campaign_logic
from recon.evidence_graph import query_evidence_graph as query_evidence_graph_logic
from recon.findings import create_finding_candidate as create_finding_candidate_logic
from recon.findings import demote_finding as demote_finding_logic
from recon.findings import get_finding as get_finding_logic
from recon.findings import list_findings as list_findings_logic
from recon.findings import promote_finding as promote_finding_logic
from recon.findings import reject_finding as reject_finding_logic
from recon.http_fetch import fetch_headers as fetch_headers_logic
from recon.http_fetch import fetch_robots as fetch_robots_logic
from recon.http_fetch import fetch_sitemap as fetch_sitemap_logic
from recon.imports import import_burp_xml_for_campaign as import_burp_xml_for_campaign_logic
from recon.imports import import_har_for_campaign as import_har_for_campaign_logic
from recon.integrity import verify_campaign_artifacts as verify_campaign_artifacts_logic
from recon.js_analysis import collect_js_urls as collect_js_urls_logic
from recon.js_analysis import extract_endpoints_from_js as extract_endpoints_from_js_logic
from recon.memory import list_negative_results as list_negative_results_logic
from recon.memory import record_negative_result as record_negative_result_logic
from recon.notes import create_campaign_evidence_note as create_campaign_evidence_note_logic
from recon.notes import create_evidence_note as create_evidence_note_logic
from recon.planner import generate_manual_test_plan as generate_manual_test_plan_logic
from recon.passive import discover_subdomains_passive_for_campaign as discover_subdomains_passive_for_campaign_logic
from recon.reports import generate_report_candidate_markdown as generate_report_candidate_markdown_logic
from recon.scope import check_scope as check_scope_logic
from recon.scope import check_scope_batch as check_scope_batch_logic
from recon.scope import explain_scope_decision as explain_scope_decision_logic
from recon.scope import get_scope_map as get_scope_map_logic
from recon.scope import list_loaded_scope as list_loaded_scope_logic
from recon.scope import DEFAULT_LIMITS, ScopeError, load_scope
from recon.sensitive import scan_sensitive_artifacts_for_campaign as scan_sensitive_artifacts_for_campaign_logic
from recon.scope import recommend_bugmap_parent as recommend_bugmap_parent_logic
from recon.scope import resolve_scope_target as resolve_scope_target_logic
from recon.sourcemaps import analyze_sourcemap_sources_for_campaign as analyze_sourcemap_sources_for_campaign_logic
from recon.sourcemaps import detect_sourcemap_references_for_campaign as detect_sourcemap_references_for_campaign_logic
from recon.sourcemaps import download_sourcemap_for_campaign as download_sourcemap_for_campaign_logic
from recon.sourcemaps import external_sourcemapper_info as external_sourcemapper_info_logic
from recon.sourcemaps import extract_sourcemap_sources_for_campaign as extract_sourcemap_sources_for_campaign_logic
from recon.sourcemaps import sourcemap_workflow_for_campaign as sourcemap_workflow_for_campaign_logic
from recon.urls import dedupe_urls as dedupe_urls_logic
from recon.workflow import collect_js_urls_for_campaign as collect_js_urls_for_campaign_logic
from recon.workflow import extract_endpoints_for_campaign as extract_endpoints_for_campaign_logic
from recon.workflow import fetch_headers_for_campaign as fetch_headers_for_campaign_logic
from recon.workflow import fetch_robots_for_campaign as fetch_robots_for_campaign_logic
from recon.workflow import fetch_sitemap_for_campaign as fetch_sitemap_for_campaign_logic
from recon.workflow import generate_campaign_summary as generate_campaign_summary_logic
from recon.workflow import generate_manual_test_plan_for_campaign as generate_manual_test_plan_for_campaign_logic
from recon.workflow import save_dirfuzz_analysis_for_campaign as save_dirfuzz_analysis_for_campaign_logic


mcp = FastMCP("recon-mcp")

AVAILABLE_TOOLS = [
    "health",
    "check_scope",
    "resolve_scope_target",
    "check_scope_batch",
    "get_scope_map",
    "recommend_bugmap_parent",
    "explain_scope_decision",
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
    "create_campaign",
    "list_campaigns",
    "get_campaign",
    "fetch_headers_for_campaign",
    "fetch_robots_for_campaign",
    "fetch_sitemap_for_campaign",
    "collect_js_urls_for_campaign",
    "extract_endpoints_for_campaign",
    "save_dirfuzz_analysis_for_campaign",
    "create_finding_candidate",
    "get_finding",
    "list_findings",
    "promote_finding",
    "demote_finding",
    "reject_finding",
    "create_campaign_evidence_note",
    "score_endpoint",
    "score_endpoints",
    "record_negative_result",
    "list_negative_results",
    "generate_manual_test_plan_for_campaign",
    "generate_campaign_summary",
    "generate_report_candidate_markdown",
    "detect_sourcemap_references_for_campaign",
    "download_sourcemap_for_campaign",
    "extract_sourcemap_sources_for_campaign",
    "analyze_sourcemap_sources_for_campaign",
    "sourcemap_workflow_for_campaign",
    "external_sourcemapper_info",
    "archive_campaign",
    "list_archived_campaigns",
    "get_archived_campaign",
    "delete_archived_campaign",
    "scan_sensitive_artifacts_for_campaign",
    "extract_api_contracts_for_campaign",
    "get_evidence_graph_summary",
    "query_evidence_graph",
    "import_dirfuzz_evidence_for_campaign",
    "discover_subdomains_passive_for_campaign",
    "compare_campaign_recon",
    "import_har_for_campaign",
    "import_burp_xml_for_campaign",
    "verify_campaign_artifacts",
    "nuclei_integration_info",
]


@mcp.tool()
def health() -> dict:
    """Return health for safe recon helpers for authorized testing only."""
    try:
        config = load_scope()
        config_error = None
    except ScopeError as exc:
        config = DEFAULT_LIMITS
        config_error = str(exc)
    return {
        "ok": config_error is None,
        "project": "recon-mcp",
        "version": __version__,
        "available_tools": AVAILABLE_TOOLS,
        "safety_note": "This server provides scoped, low-risk recon helpers only.",
        "dirfuzz_note": "Directory fuzzing is delegated to the separate Go DirFuzz MCP server.",
        "nuclei_note": "Nuclei execution is intentionally outside this MCP trust boundary.",
        "processing_limits": {name: int(config.get(name, default)) for name, default in DEFAULT_LIMITS.items()},
        "scope_compatibility": "Legacy allowed_domains entries are exact; use *.example.com or allowed_assets match=wildcard explicitly.",
        "configuration_error": config_error,
    }


@mcp.tool()
def check_scope(domain: str) -> dict:
    """Safely check whether a domain or URL is authorized by configured recon scope."""
    return check_scope_logic(domain)


@mcp.tool()
def resolve_scope_target(host_or_url: str, format: str | None = None) -> dict:
    """Resolve the best configured scope target for a host or URL."""
    return resolve_scope_target_logic(host_or_url, format=format)


@mcp.tool()
def check_scope_batch(hosts_or_urls: list[str], format: str | None = None) -> dict:
    """Return one structured scope decision per host or URL."""
    return check_scope_batch_logic(hosts_or_urls, format=format)


@mcp.tool()
def get_scope_map() -> dict:
    """Return normalized machine-readable scope entries."""
    return get_scope_map_logic()


@mcp.tool()
def recommend_bugmap_parent(host_or_url: str, available_bugmap_targets: list[dict]) -> dict:
    """Recommend the best BugMap parent from current scope and provided targets."""
    return recommend_bugmap_parent_logic(host_or_url, available_bugmap_targets)


@mcp.tool()
def explain_scope_decision(host_or_url: str) -> dict:
    """Explain a scope decision in human-readable and structured form."""
    return explain_scope_decision_logic(host_or_url)


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
def extract_endpoints_from_js(file_or_url: str, source_type: str | None = None) -> dict:
    """Safely extract endpoint candidates from authorized JS URLs or local project JS files."""
    return extract_endpoints_from_js_logic(file_or_url, source_type=source_type)


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


@mcp.tool()
def create_campaign(program: str, target: str, notes: str | None = None) -> dict:
    """Create an in-scope campaign for authorized, human-led testing only."""
    return create_campaign_logic(program, target, notes=notes)


@mcp.tool()
def list_campaigns(limit: int = 50) -> dict:
    """List local campaigns for authorized, human-led testing workflows only."""
    return list_campaigns_logic(limit=limit)


@mcp.tool()
def get_campaign(campaign_id: str) -> dict:
    """Get campaign metadata for authorized, human-led testing only."""
    return get_campaign_logic(campaign_id)


@mcp.tool()
def archive_campaign(campaign_id: str, reason: str | None = None) -> dict:
    """Archive a campaign instead of deleting evidence for authorized, human-led testing only."""
    return archive_campaign_logic(campaign_id, reason=reason)


@mcp.tool()
def list_archived_campaigns(limit: int = 50) -> dict:
    """List archived campaigns for authorized, human-led testing workflows only."""
    return list_archived_campaigns_logic(limit=limit)


@mcp.tool()
def get_archived_campaign(campaign_id: str) -> dict:
    """Get archived campaign metadata for authorized, human-led testing only."""
    return get_archived_campaign_logic(campaign_id)


@mcp.tool()
def delete_archived_campaign(campaign_id: str, confirm_campaign_id: str) -> dict:
    """Permanently delete only an archived campaign when exact confirmation matches."""
    return delete_archived_campaign_logic(campaign_id, confirm_campaign_id)


@mcp.tool()
def fetch_headers_for_campaign(campaign_id: str, url: str) -> dict:
    """Fetch headers for an in-scope campaign URL for authorized, human-led testing only."""
    return fetch_headers_for_campaign_logic(campaign_id, url)


@mcp.tool()
def fetch_robots_for_campaign(campaign_id: str, url: str) -> dict:
    """Fetch robots.txt for an in-scope campaign URL for authorized, human-led testing only."""
    return fetch_robots_for_campaign_logic(campaign_id, url)


@mcp.tool()
def fetch_sitemap_for_campaign(campaign_id: str, url: str) -> dict:
    """Fetch sitemap.xml for an in-scope campaign URL for authorized, human-led testing only."""
    return fetch_sitemap_for_campaign_logic(campaign_id, url)


@mcp.tool()
def collect_js_urls_for_campaign(campaign_id: str, url: str) -> dict:
    """Collect in-scope JS URLs for a campaign for authorized, human-led testing only."""
    return collect_js_urls_for_campaign_logic(campaign_id, url)


@mcp.tool()
def extract_endpoints_for_campaign(campaign_id: str, file_or_url: str, source_type: str | None = None) -> dict:
    """Extract and score endpoint candidates for authorized, human-led testing only."""
    return extract_endpoints_for_campaign_logic(campaign_id, file_or_url, source_type=source_type)


@mcp.tool()
def save_dirfuzz_analysis_for_campaign(campaign_id: str, analysis: dict) -> dict:
    """Save Go DirFuzz analysis for an authorized, human-led campaign only."""
    return save_dirfuzz_analysis_for_campaign_logic(campaign_id, analysis)


@mcp.tool()
def create_finding_candidate(campaign_id: str, finding: dict) -> dict:
    """Create a candidate in the hallucination bin for authorized, human-led testing only."""
    return create_finding_candidate_logic(campaign_id, finding)


@mcp.tool()
def get_finding(campaign_id: str, finding_id: str) -> dict:
    """Get a finding candidate for authorized, human-led testing only."""
    return get_finding_logic(campaign_id, finding_id)


@mcp.tool()
def list_findings(campaign_id: str, status: str | None = None) -> dict:
    """List finding candidates for authorized, human-led testing only."""
    return list_findings_logic(campaign_id, status=status)


@mcp.tool()
def promote_finding(campaign_id: str, finding_id: str, target_status: str, reason: str, gate_updates: dict | None = None) -> dict:
    """Promote a finding after human validation for authorized, human-led testing only."""
    return promote_finding_logic(campaign_id, finding_id, target_status, reason, gate_updates=gate_updates)


@mcp.tool()
def demote_finding(campaign_id: str, finding_id: str, target_status: str, reason: str) -> dict:
    """Demote a finding for safer authorized, human-led review only."""
    return demote_finding_logic(campaign_id, finding_id, target_status, reason)


@mcp.tool()
def reject_finding(campaign_id: str, finding_id: str, reason: str) -> dict:
    """Reject a candidate finding during authorized, human-led testing only."""
    return reject_finding_logic(campaign_id, finding_id, reason)


@mcp.tool()
def create_campaign_evidence_note(campaign_id: str, finding: dict) -> dict:
    """Create campaign evidence notes for authorized, human-led testing only."""
    return create_campaign_evidence_note_logic(campaign_id, finding)


@mcp.tool()
def score_endpoint(endpoint: dict | str) -> dict:
    """Score an endpoint for manual review in authorized, human-led testing only."""
    return score_endpoint_logic(endpoint)


@mcp.tool()
def score_endpoints(endpoints: list[dict | str]) -> dict:
    """Score endpoints for manual review in authorized, human-led testing only."""
    return score_endpoints_logic(endpoints)


@mcp.tool()
def record_negative_result(
    campaign_id: str,
    target: str,
    check_type: str,
    result: str,
    repeat_after: str | None = None,
    metadata: dict | None = None,
) -> dict:
    """Record non-finding campaign memory for authorized, human-led testing only."""
    return record_negative_result_logic(campaign_id, target, check_type, result, repeat_after=repeat_after, metadata=metadata)


@mcp.tool()
def list_negative_results(campaign_id: str, check_type: str | None = None) -> dict:
    """List non-finding campaign memory for authorized, human-led testing only."""
    return list_negative_results_logic(campaign_id, check_type=check_type)


@mcp.tool()
def generate_manual_test_plan_for_campaign(campaign_id: str) -> dict:
    """Generate a safe manual test plan for authorized, human-led testing only."""
    return generate_manual_test_plan_for_campaign_logic(campaign_id)


@mcp.tool()
def generate_campaign_summary(campaign_id: str) -> dict:
    """Generate a campaign summary for authorized, human-led testing only."""
    return generate_campaign_summary_logic(campaign_id)


@mcp.tool()
def generate_report_candidate_markdown(campaign_id: str, finding_id: str) -> dict:
    """Generate local report Markdown for authorized, human-led testing only; no submission occurs."""
    return generate_report_candidate_markdown_logic(campaign_id, finding_id)


@mcp.tool()
def detect_sourcemap_references_for_campaign(campaign_id: str, js_url: str) -> dict:
    """Detect in-scope source map references for authorized, human-led testing only."""
    return detect_sourcemap_references_for_campaign_logic(campaign_id, js_url)


@mcp.tool()
def download_sourcemap_for_campaign(campaign_id: str, sourcemap_url: str) -> dict:
    """Download an in-scope source map for authorized, human-led testing only."""
    return download_sourcemap_for_campaign_logic(campaign_id, sourcemap_url)


@mcp.tool()
def extract_sourcemap_sources_for_campaign(campaign_id: str, map_path: str) -> dict:
    """Extract local source map sources for authorized, human-led testing only."""
    return extract_sourcemap_sources_for_campaign_logic(campaign_id, map_path)


@mcp.tool()
def analyze_sourcemap_sources_for_campaign(campaign_id: str, extracted_dir: str | None = None) -> dict:
    """Analyze extracted source map files for manual-review leads only."""
    return analyze_sourcemap_sources_for_campaign_logic(campaign_id, extracted_dir=extracted_dir)


@mcp.tool()
def sourcemap_workflow_for_campaign(campaign_id: str, js_url: str) -> dict:
    """Run safe source map recon for an in-scope campaign JS URL only."""
    return sourcemap_workflow_for_campaign_logic(campaign_id, js_url)


@mcp.tool()
def external_sourcemapper_info() -> dict:
    """Explain safe local-only external sourcemapper usage; does not execute it."""
    return external_sourcemapper_info_logic()


@mcp.tool()
def scan_sensitive_artifacts_for_campaign(campaign_id: str, extracted_dir: str | None = None) -> dict:
    """Locally scan approved campaign sources for redacted manual-review candidates only."""
    return scan_sensitive_artifacts_for_campaign_logic(campaign_id, extracted_dir=extracted_dir)


@mcp.tool()
def extract_api_contracts_for_campaign(campaign_id: str, extracted_dir: str | None = None) -> dict:
    """Deterministically extract uncertain API contract leads from campaign-local sources."""
    return extract_api_contracts_for_campaign_logic(campaign_id, extracted_dir=extracted_dir)


@mcp.tool()
def get_evidence_graph_summary(campaign_id: str) -> dict:
    """Return bounded counts for a campaign evidence graph."""
    return get_evidence_graph_summary_logic(campaign_id)


@mcp.tool()
def query_evidence_graph(campaign_id: str, node_uuid: str, depth: int = 1, limit: int = 100) -> dict:
    """Return a bounded graph neighborhood around one node."""
    return query_evidence_graph_logic(campaign_id, node_uuid, depth=depth, limit=limit)


@mcp.tool()
def import_dirfuzz_evidence_for_campaign(campaign_id: str, analysis_path: str | None = None) -> dict:
    """Import already saved DirFuzz observations into the shared evidence graph."""
    return import_dirfuzz_evidence_for_campaign_logic(campaign_id, analysis_path=analysis_path)


@mcp.tool()
def discover_subdomains_passive_for_campaign(campaign_id: str, root_domain: str, providers: list[str] | None = None, max_results: int = 500, resolve_dns: bool = False) -> dict:
    """Query fixed passive providers without sending HTTP requests to discovered hosts."""
    return discover_subdomains_passive_for_campaign_logic(campaign_id, root_domain, providers=providers, max_results=max_results, resolve_dns=resolve_dns)


@mcp.tool()
def compare_campaign_recon(campaign_id: str, baseline_campaign_id: str) -> dict:
    """Compare normalized redacted campaign artifacts as recon differences only."""
    return compare_campaign_recon_logic(campaign_id, baseline_campaign_id)


@mcp.tool()
def import_har_for_campaign(campaign_id: str, har_path: str) -> dict:
    """Safely summarize a campaign-local HAR without replaying requests or retaining bodies."""
    return import_har_for_campaign_logic(campaign_id, har_path)


@mcp.tool()
def import_burp_xml_for_campaign(campaign_id: str, xml_path: str) -> dict:
    """Safely summarize campaign-local Burp XML without replaying requests."""
    return import_burp_xml_for_campaign_logic(campaign_id, xml_path)


@mcp.tool()
def verify_campaign_artifacts(campaign_id: str) -> dict:
    """Read-only verification of campaign artifact integrity metadata."""
    return verify_campaign_artifacts_logic(campaign_id)


@mcp.tool()
def nuclei_integration_info() -> dict:
    """Describe the non-executing trust boundary for a future separate Nuclei MCP."""
    return {
        "ok": True,
        "executed": False,
        "message": "Recon MCP does not execute Nuclei. A future separate MCP must build a one-target plan for explicit human approval.",
        "required_controls": [
            "exact reviewed template-ID allowlist", "pinned local signed templates", "HTTP-only templates",
            "no code, JavaScript, headless, file, TCP, workflow, fuzzing, DAST, OAST, remote templates, or AI-generated templates",
            "no local-file access", "private-network restrictions", "strict rate/concurrency/process limits",
            "JSONL result import into an existing Recon MCP campaign",
        ],
        "safety_boundary": "Template tags are metadata, never the primary safety boundary.",
    }


if __name__ == "__main__":
    mcp.run(transport="stdio")
