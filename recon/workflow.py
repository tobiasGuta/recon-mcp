"""Campaign-aware wrappers around safe recon helpers."""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlsplit

from recon.audit import write_audit_event
from recon.campaigns import file_timestamp, get_campaign, get_campaign_paths, slugify
from recon.endpoint_scoring import score_endpoints
from recon.http_fetch import fetch_headers, fetch_robots, fetch_sitemap
from recon.js_analysis import collect_js_urls, extract_endpoints_from_js
from recon.memory import list_negative_results
from recon.planner import generate_manual_test_plan
from recon.reports import generate_campaign_markdown_summary
from recon.scope import resolve_scope_target


def _error(message: str) -> dict:
    return {"ok": False, "error": message}


def _safe_label(value: str) -> str:
    parsed = urlsplit(value)
    host = parsed.hostname or value
    path = parsed.path.strip("/").replace("/", "-")
    return slugify(f"{host}-{path}" if path else host, fallback="target", max_length=90)


def _save_json(campaign_id: str, recon_subdir: str, label: str, payload: dict) -> dict:
    paths = get_campaign_paths(campaign_id)
    if not paths.get("ok"):
        return _error(paths.get("error", "Could not load campaign paths."))
    directory = Path(paths["paths"]["recon"][recon_subdir])
    filename = f"{file_timestamp()}-{_safe_label(label)}.json"
    path = (directory / filename).resolve()
    if path.parent != directory.resolve() or path.name != filename:
        return _error("Unsafe output filename.")
    try:
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except OSError as exc:
        return _error(f"Could not write recon artifact: {exc}")
    return {"ok": True, "path": str(path)}


def _wrapper_response(campaign_id: str, tool: str, target: str, result: dict, subdir: str, label: str, scope_decision: dict | None = None) -> dict:
    artifact = {"tool": tool, "target": target, "result": result}
    save = _save_json(campaign_id, subdir, label, artifact)
    warnings = list(result.get("warnings") or result.get("notes") or []) if isinstance(result, dict) else []
    audit = write_audit_event(
        campaign_id,
        tool,
        target=target,
        ok=bool(result.get("ok")) if isinstance(result, dict) else False,
        scope_decision=scope_decision,
        result_path=save.get("path") if save.get("ok") else None,
        warnings=warnings + ([save.get("error")] if not save.get("ok") else []),
    )
    if not audit.get("ok"):
        warnings.extend(audit.get("warnings", []))
    if not save.get("ok"):
        return {"ok": False, "result": result, "error": save.get("error"), "warnings": warnings}
    return {"ok": bool(result.get("ok", True)), "result": result, "path": save["path"], "warnings": warnings}


def fetch_headers_for_campaign(campaign_id: str, url: str) -> dict:
    """Fetch headers for an in-scope campaign URL and save the artifact."""
    scope_decision = resolve_scope_target(url)
    result = fetch_headers(url)
    return _wrapper_response(campaign_id, "fetch_headers_for_campaign", url, result, "headers", url, scope_decision)


def fetch_robots_for_campaign(campaign_id: str, url: str) -> dict:
    """Fetch robots.txt for an in-scope campaign URL and save the artifact."""
    scope_decision = resolve_scope_target(url)
    result = fetch_robots(url)
    return _wrapper_response(campaign_id, "fetch_robots_for_campaign", url, result, "robots", url, scope_decision)


def fetch_sitemap_for_campaign(campaign_id: str, url: str) -> dict:
    """Fetch sitemap.xml for an in-scope campaign URL and save the artifact."""
    scope_decision = resolve_scope_target(url)
    result = fetch_sitemap(url)
    return _wrapper_response(campaign_id, "fetch_sitemap_for_campaign", url, result, "sitemap", url, scope_decision)


def collect_js_urls_for_campaign(campaign_id: str, url: str) -> dict:
    """Collect in-scope JavaScript URLs for a campaign and save the artifact."""
    scope_decision = resolve_scope_target(url)
    result = collect_js_urls(url)
    return _wrapper_response(campaign_id, "collect_js_urls_for_campaign", url, result, "js_urls", url, scope_decision)


def extract_endpoints_for_campaign(campaign_id: str, file_or_url: str, source_type: str | None = None) -> dict:
    """Extract endpoint candidates and score them for manual review."""
    scope_decision = resolve_scope_target(file_or_url) if file_or_url.lower().startswith(("http://", "https://")) else None
    result = extract_endpoints_from_js(file_or_url, source_type=source_type)
    scored = score_endpoints(result.get("endpoints", [])) if result.get("ok") else {"ok": True, "endpoints": []}
    artifact = {
        "tool": "extract_endpoints_for_campaign",
        "target": file_or_url,
        "source_type": source_type,
        "result": result,
        "scored_endpoints": scored.get("endpoints", []),
    }
    save = _save_json(campaign_id, "endpoints", file_or_url, artifact)
    warnings = list(result.get("notes") or [])
    audit = write_audit_event(
        campaign_id,
        "extract_endpoints_for_campaign",
        target=file_or_url,
        ok=bool(result.get("ok")),
        scope_decision=scope_decision,
        result_path=save.get("path") if save.get("ok") else None,
        warnings=warnings + ([save.get("error")] if not save.get("ok") else []),
        metadata={"scored_count": scored.get("count", 0)},
    )
    if not audit.get("ok"):
        warnings.extend(audit.get("warnings", []))
    if not save.get("ok"):
        return {"ok": False, "result": result, "scored_endpoints": scored.get("endpoints", []), "error": save.get("error"), "warnings": warnings}
    return {"ok": bool(result.get("ok")), "result": result, "scored_endpoints": scored.get("endpoints", []), "path": save["path"], "warnings": warnings}


def save_dirfuzz_analysis_for_campaign(campaign_id: str, analysis: dict) -> dict:
    """Save analysis produced by the separate Go DirFuzz MCP server."""
    if not isinstance(analysis, dict):
        return _error("analysis must be a dictionary.")
    save = _save_json(campaign_id, "dirfuzz", str(analysis.get("target") or "dirfuzz-analysis"), {"tool": "save_dirfuzz_analysis_for_campaign", "result": analysis})
    write_audit_event(campaign_id, "save_dirfuzz_analysis_for_campaign", target=str(analysis.get("target") or ""), ok=save.get("ok", False), result_path=save.get("path"))
    if not save.get("ok"):
        return save
    return {"ok": True, "path": save["path"], "result": analysis}


def _load_artifacts(campaign_id: str) -> dict:
    paths = get_campaign_paths(campaign_id)
    if not paths.get("ok"):
        return {}
    recon_paths = paths["paths"]["recon"]
    artifacts: dict[str, list[dict]] = {}
    for name, directory in recon_paths.items():
        artifacts[name] = []
        for path in sorted(Path(directory).glob("*.json")):
            try:
                artifacts[name].append(json.loads(path.read_text(encoding="utf-8")))
            except (OSError, json.JSONDecodeError):
                continue
    return artifacts


def _campaign_summary_input(campaign_id: str) -> dict:
    campaign = get_campaign(campaign_id).get("campaign", {})
    artifacts = _load_artifacts(campaign_id)
    endpoints = []
    js_urls = []
    interesting_headers = {}
    for item in artifacts.get("endpoints", []):
        endpoints.extend(item.get("scored_endpoints", []))
    for item in artifacts.get("js_urls", []):
        js_urls.extend(item.get("result", {}).get("js_urls", []))
    for item in artifacts.get("headers", []):
        interesting_headers.update(item.get("result", {}).get("interesting_headers", {}))
    endpoints.sort(key=lambda item: (-item.get("score", 0), item.get("value", "")))
    return {
        "campaign": campaign,
        "endpoints": endpoints,
        "js_urls": js_urls,
        "interesting_headers": interesting_headers,
        "negative_results": list_negative_results(campaign_id).get("results", []),
    }


def generate_manual_test_plan_for_campaign(campaign_id: str) -> dict:
    """Generate and save a campaign manual test plan for authorized testing only."""
    paths = get_campaign_paths(campaign_id)
    if not paths.get("ok"):
        return _error(paths.get("error", "Could not load campaign paths."))
    summary = _campaign_summary_input(campaign_id)
    plan = generate_manual_test_plan(summary)
    top_endpoints = summary["endpoints"][:20]
    negatives = summary["negative_results"]
    content = "# Manual Test Plan\n\n"
    content += "## Priority Items\n" + "\n".join(f"- {item}" for item in plan.get("priority_items", [])) + "\n\n"
    content += "## Top Endpoint Candidates\n" + ("\n".join(f"- {item['score']} {item['priority']}: {item['value']}" for item in top_endpoints) or "- None.") + "\n\n"
    content += "## Negative Results\n" + ("\n".join(f"- {item.get('check_type')}: {item.get('result')}" for item in negatives) or "- None recorded.") + "\n\n"
    content += "## Checklist\n" + "\n".join(f"- {item}" for item in plan.get("checklist", [])) + "\n\n"
    content += "## DirFuzz Handoff\n" + "\n".join(f"- {item}" for item in plan.get("dirfuzz_handoff", [])) + "\n"
    path = Path(paths["paths"]["manual_test_plan_md"])
    try:
        path.write_text(content, encoding="utf-8")
    except OSError as exc:
        return _error(f"Could not write manual test plan: {exc}")
    audit = write_audit_event(campaign_id, "generate_manual_test_plan_for_campaign", ok=True, result_path=str(path))
    warnings = audit.get("warnings", []) if not audit.get("ok") else []
    return {"ok": True, "path": str(path), "plan": plan, "warnings": warnings}


def generate_campaign_summary(campaign_id: str) -> dict:
    """Generate and save a campaign summary for authorized testing only."""
    return generate_campaign_markdown_summary(campaign_id)
