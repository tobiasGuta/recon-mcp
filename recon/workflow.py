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
from recon.sourcemaps import analyze_sourcemap_sources_for_campaign
from recon.sourcemaps import detect_sourcemap_references_for_campaign
from recon.sourcemaps import download_sourcemap_for_campaign
from recon.sourcemaps import extract_sourcemap_sources_for_campaign
from recon.sourcemaps import sourcemap_workflow_for_campaign
from recon.safeio import SafeIOError, limit, read_bytes_bounded, write_artifact_bytes, write_flat_json_artifact
from recon.redaction import redact_structure


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
        saved = write_flat_json_artifact(campaign_id, str(payload.get("tool") or "campaign_recon"), path, payload, limits_applied={"max_saved_artifact_bytes": limit("max_saved_artifact_bytes")})
    except (OSError, SafeIOError) as exc:
        return _error(f"Could not write recon artifact: {exc}")
    return {"ok": True, **saved}


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
    analysis = redact_structure(analysis)
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
            if path.name.endswith(".metadata.json") or path.is_symlink():
                continue
            try:
                payload = json.loads(read_bytes_bounded(path, limit("max_saved_artifact_bytes")))
                artifacts[name].append(payload.get("payload", payload) if isinstance(payload, dict) else {})
            except (OSError, json.JSONDecodeError):
                continue
    return artifacts


def _load_sourcemap_analysis(campaign_id: str) -> dict:
    paths = get_campaign_paths(campaign_id)
    if not paths.get("ok"):
        return {"detections": [], "downloads": [], "extractions": [], "analyses": []}
    sourcemap_root = Path(paths["paths"]["recon"]["sourcemaps"])
    analysis_dir = sourcemap_root / "analysis"
    result = {"detections": [], "downloads": [], "extractions": [], "analyses": []}
    if not analysis_dir.exists():
        return result
    for path in sorted(analysis_dir.glob("*.json")):
        try:
            payload = json.loads(read_bytes_bounded(path, limit("max_saved_artifact_bytes")))
        except (OSError, json.JSONDecodeError, SafeIOError):
            continue
        name = path.name
        if "sourcemap-detect" in name:
            result["detections"].append(payload)
        elif "download" in name:
            result["downloads"].append(payload)
        elif "extract" in name:
            result["extractions"].append(payload)
        elif "source-analysis" in name:
            result["analyses"].append(payload)
    return result


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
    sourcemaps = _load_sourcemap_analysis(campaign_id)
    sourcemap_endpoints = []
    sourcemap_signals = []
    sourcemap_warnings = []
    for analysis in sourcemaps["analyses"]:
        sourcemap_endpoints.extend(analysis.get("scored_endpoints", []))
        sourcemap_signals.extend(analysis.get("signals", []))
        sourcemap_warnings.extend(analysis.get("warnings", []))
    endpoints.extend(sourcemap_endpoints)
    endpoints.sort(key=lambda item: (-item.get("score", 0), item.get("value", "")))
    sensitive = artifacts.get("sensitive", [])[-1] if artifacts.get("sensitive") else {}
    contracts = artifacts.get("contracts", [])[-1] if artifacts.get("contracts") else {}
    return {
        "campaign": campaign,
        "endpoints": endpoints,
        "js_urls": js_urls,
        "interesting_headers": interesting_headers,
        "negative_results": list_negative_results(campaign_id).get("results", []),
        "sensitive_candidates": sensitive.get("matches", []),
        "client_configuration_signals": sensitive.get("client_configuration_signals", []),
        "api_contracts": contracts.get("contracts", []),
        "sourcemaps": {
            "detected": sum(len(item.get("references", [])) for item in sourcemaps["detections"]),
            "downloaded": len(sourcemaps["downloads"]),
            "extracted": len(sourcemaps["extractions"]),
            "files_analyzed": sum(item.get("files_analyzed", 0) for item in sourcemaps["analyses"]),
            "top_endpoints": sourcemap_endpoints[:20],
            "signals": sourcemap_signals[:50],
            "signals_count": len(sourcemap_signals),
            "warnings": sorted(set(sourcemap_warnings)),
        },
    }


def generate_manual_test_plan_for_campaign(campaign_id: str) -> dict:
    """Generate and save a campaign manual test plan for authorized testing only."""
    paths = get_campaign_paths(campaign_id)
    if not paths.get("ok"):
        return _error(paths.get("error", "Could not load campaign paths."))
    summary = _campaign_summary_input(campaign_id)
    plan = generate_manual_test_plan(summary)
    top_endpoints = summary["endpoints"][:20]
    sourcemaps = summary["sourcemaps"]
    negatives = summary["negative_results"]
    content = "# Manual Test Plan\n\n"
    content += "## Priority Items\n" + "\n".join(f"- {item}" for item in plan.get("priority_items", [])) + "\n\n"
    content += "## Top Endpoint Candidates\n" + ("\n".join(f"- {item['score']} {item['priority']}: {item['value']}" for item in top_endpoints) or "- None.") + "\n\n"
    content += "## Source Map Endpoint Candidates\n" + (
        "\n".join(f"- {item['score']} {item['priority']}: {item['value']}" for item in sourcemaps["top_endpoints"])
        or "- None."
    ) + "\n\n"
    content += "## Source Map Signals\n" + (
        "\n".join(f"- {item.get('type')} in {Path(item.get('file', '')).name}:{item.get('line')}: {item.get('preview')}" for item in sourcemaps["signals"][:20])
        or "- None."
    ) + "\n\n"
    content += "## Source Map Safety Notes\n"
    content += "- Exposed source maps are recon leads, not vulnerabilities by themselves.\n"
    content += "- Validate scope, exposure, exploitability, and impact manually before creating findings.\n\n"
    content += "## Redacted Sensitive-Artifact Leads\n" + (
        "\n".join(f"- {item.get('detector_id')} {item.get('redacted_value')} in {item.get('file')}:{item.get('line')} (manual validation required)" for item in summary["sensitive_candidates"][:20])
        or "- None."
    ) + "\n\n"
    content += "- Never test whether a discovered credential is active.\n\n"
    content += "## API Contract Leads\n" + (
        "\n".join(f"- {item.get('method')} {item.get('endpoint')} [{item.get('endpoint_uncertainty')}, {item.get('confidence')}]" for item in summary["api_contracts"][:20])
        or "- None."
    ) + "\n\n"
    content += "## Negative Results\n" + ("\n".join(f"- {item.get('check_type')}: {item.get('result')}" for item in negatives) or "- None recorded.") + "\n\n"
    content += "## Checklist\n" + "\n".join(f"- {item}" for item in plan.get("checklist", [])) + "\n\n"
    content += "## DirFuzz Handoff\n" + "\n".join(f"- {item}" for item in plan.get("dirfuzz_handoff", [])) + "\n"
    path = Path(paths["paths"]["manual_test_plan_md"])
    try:
        saved = write_artifact_bytes(campaign_id, "generate_manual_test_plan_for_campaign", path, content.encode("utf-8"), maximum=limit("max_saved_artifact_bytes"), limits_applied={"max_saved_artifact_bytes": limit("max_saved_artifact_bytes")})
    except (OSError, SafeIOError) as exc:
        return _error(f"Could not write manual test plan: {exc}")
    audit = write_audit_event(campaign_id, "generate_manual_test_plan_for_campaign", ok=True, result_path=str(path))
    warnings = audit.get("warnings", []) if not audit.get("ok") else []
    return {"ok": True, "path": str(path), "metadata_path": saved["metadata_path"], "artifact_uuid": saved["artifact_uuid"], "plan": plan, "warnings": warnings}


def generate_campaign_summary(campaign_id: str) -> dict:
    """Generate and save a campaign summary for authorized testing only."""
    return generate_campaign_markdown_summary(campaign_id)
