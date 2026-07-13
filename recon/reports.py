"""Markdown report generation for campaign workflows."""

from __future__ import annotations

import json
from pathlib import Path

from recon.audit import write_audit_event
from recon.campaigns import get_campaign, get_campaign_paths
from recon.endpoint_scoring import score_endpoints
from recon.findings import REPORT_CANDIDATE, get_finding, list_findings
from recon.memory import list_negative_results
from recon.safeio import SafeIOError, limit, read_bytes_bounded, write_artifact_bytes
from recon.redaction import redact_structure


def _md(value: object) -> str:
    value = redact_structure(value)
    if isinstance(value, list):
        return "\n".join(f"- {item}" for item in value) if value else "None."
    if isinstance(value, dict):
        return "\n".join(f"- **{key}:** {item}" for key, item in value.items()) if value else "None."
    return str(value) if value not in {None, ""} else "None."


def _load_json_files(directory: Path) -> list[dict]:
    items = []
    for path in sorted(directory.glob("*.json")):
        if path.name.endswith(".metadata.json") or path.is_symlink():
            continue
        try:
            payload = json.loads(read_bytes_bounded(path, limit("max_saved_artifact_bytes")))
        except (OSError, json.JSONDecodeError, SafeIOError):
            continue
        if isinstance(payload, dict) and isinstance(payload.get("payload"), dict):
            payload = payload["payload"]
        items.append({"path": str(path), "payload": payload})
    return items


def _all_scored_endpoints(paths: dict) -> list[dict]:
    endpoint_dir = Path(paths["recon"]["endpoints"])
    endpoints = []
    for item in _load_json_files(endpoint_dir):
        payload = item["payload"]
        if isinstance(payload.get("scored_endpoints"), list):
            endpoints.extend(payload["scored_endpoints"])
        elif isinstance(payload.get("result"), dict):
            endpoints.extend(score_endpoints(payload["result"].get("endpoints", [])).get("endpoints", []))
    endpoints.sort(key=lambda item: (-item.get("score", 0), item.get("value", "")))
    return endpoints


def _sourcemap_summary(paths: dict) -> dict:
    analysis_dir = Path(paths["recon"]["sourcemaps"]) / "analysis"
    result = {
        "detected_maps": 0,
        "downloaded_maps": 0,
        "extracted_dirs": [],
        "top_endpoints": [],
        "signals": [],
        "warnings": [],
    }
    if not analysis_dir.exists():
        return result
    endpoints = []
    for item in _load_json_files(analysis_dir):
        path = Path(item["path"])
        payload = item["payload"]
        if "sourcemap-detect" in path.name:
            result["detected_maps"] += len(payload.get("references", []))
        elif "download" in path.name and payload.get("ok"):
            result["downloaded_maps"] += 1
        elif "extract" in path.name and payload.get("extracted_dir"):
            result["extracted_dirs"].append(payload["extracted_dir"])
        elif "source-analysis" in path.name:
            endpoints.extend(payload.get("scored_endpoints", []))
            result["signals"].extend(payload.get("signals", []))
            result["warnings"].extend(payload.get("warnings", []))
    endpoints.sort(key=lambda endpoint: (-endpoint.get("score", 0), endpoint.get("value", "")))
    result["top_endpoints"] = endpoints[:20]
    result["signals"] = result["signals"][:50]
    result["warnings"] = sorted(set(result["warnings"]))
    return result


def _audit_tools(paths: dict) -> list[str]:
    audit_path = Path(paths["audit_jsonl"])
    tools = []
    if not audit_path.exists():
        return tools
    try:
        audit_text = read_bytes_bounded(audit_path, 20 * 1024 * 1024).decode("utf-8", errors="replace")
    except SafeIOError:
        return tools
    for line in audit_text.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event.get("tool"):
            tools.append(event["tool"])
    return sorted(set(tools))


def generate_campaign_markdown_summary(campaign_id: str) -> dict:
    """Generate a campaign summary for authorized, human-led testing only."""
    campaign = get_campaign(campaign_id)
    if not campaign.get("ok"):
        return {"ok": False, "error": campaign.get("error")}
    paths_result = get_campaign_paths(campaign_id)
    if not paths_result.get("ok"):
        return {"ok": False, "error": paths_result.get("error")}
    paths = paths_result["paths"]
    metadata = campaign["campaign"]
    findings = list_findings(campaign_id).get("findings", [])
    negatives = list_negative_results(campaign_id).get("results", [])
    endpoints = _all_scored_endpoints(paths)[:20]
    sourcemaps = _sourcemap_summary(paths)
    sensitive_items = _load_json_files(Path(paths["recon"]["sensitive"]))
    sensitive = sensitive_items[-1]["payload"] if sensitive_items else {}
    contract_items = _load_json_files(Path(paths["recon"]["contracts"]))
    contracts = contract_items[-1]["payload"] if contract_items else {}
    graph_path = Path(paths["recon"]["graph"]) / "evidence-graph.json"
    graph = {}
    if graph_path.exists() and not graph_path.is_symlink():
        try:
            graph = json.loads(read_bytes_bounded(graph_path, 20 * 1024 * 1024))
        except (OSError, json.JSONDecodeError, SafeIOError):
            graph = {}
    artifact_counts = {
        name: len([item for item in (Path(directory).rglob("*.json") if name == "sourcemaps" else Path(directory).glob("*.json")) if not item.name.endswith(".metadata.json")])
        for name, directory in paths["recon"].items()
    }
    by_status: dict[str, int] = {}
    for finding in findings:
        by_status[finding.get("status", "unknown")] = by_status.get(finding.get("status", "unknown"), 0) + 1

    content = f"""# Campaign Summary

## Campaign Metadata
- **Campaign ID:** {metadata.get("campaign_id")}
- **Program:** {metadata.get("program")}
- **Target:** {metadata.get("target")}
- **Normalized Host:** {metadata.get("normalized_host")}
- **Created:** {metadata.get("created_at")}
- **Updated:** {metadata.get("updated_at")}
- **Safety Model:** {metadata.get("safety_model")}

## Scope Decision
{_md(metadata.get("scope_decision"))}

## Tools Run
{_md(_audit_tools(paths))}

## Recon Artifacts Created
{_md(artifact_counts)}

## Top Endpoint Candidates by Score
{_md([f"{item['score']} {item['priority']}: {item['value']}" for item in endpoints])}

## Source Map Recon
- **Detected maps:** {sourcemaps["detected_maps"]}
- **Downloaded maps:** {sourcemaps["downloaded_maps"]}
- **Extracted source directories:** {len(sourcemaps["extracted_dirs"])}

### Top Source Map Endpoint Candidates
{_md([f"{item['score']} {item['priority']}: {item['value']}" for item in sourcemaps["top_endpoints"]])}

### Manual-Review Source Map Signals
{_md([f"{item.get('type')} in {Path(item.get('file', '')).name}:{item.get('line')} - {item.get('preview')}" for item in sourcemaps["signals"][:20]])}

### Source Map Safety Warnings
{_md(sourcemaps["warnings"] + ["Exposed source maps are recon leads, not vulnerabilities by themselves.", "Validate impact manually before creating or promoting findings."])}

## Sensitive Artifact Leads (Redacted)
- **Candidate count:** {sensitive.get("count", 0)}
- **Client configuration signal count:** {len(sensitive.get("client_configuration_signals", []))}
{_md([f"{item.get('detector_id')} {item.get('redacted_value')} in {item.get('file')}:{item.get('line')}" for item in sensitive.get("matches", [])[:20]])}

All values above are redacted fingerprints and require manual validation. No credential was tested.

## Deterministic API Contracts
- **Contract count:** {contracts.get("count", 0)}
{_md([f"{item.get('method')} {item.get('endpoint')} ({item.get('endpoint_uncertainty')}, {item.get('confidence')})" for item in contracts.get("contracts", [])[:20]])}

Contracts are reconstruction leads, not complete schemas or vulnerability claims.

## Evidence Graph
- **Nodes:** {len(graph.get("nodes", []))}
- **Edges:** {len(graph.get("edges", []))}

## Findings by Status
{_md(by_status)}

## Negative Results
{_md([f"{item.get('check_type')}: {item.get('result')} ({item.get('target')})" for item in negatives])}

## Manual Validation Tasks
- Promote candidates only after manual validation.
- Review high-scoring endpoints for authorization boundaries using authorized accounts only.
- Treat negative results as useful notes, not vulnerabilities.

## Safety Warnings
- Candidate findings are not vulnerabilities.
- Everything starts in hallucinations until validated manually.
- Reports are not auto-submitted.

## DirFuzz Handoff Reminder
Directory fuzzing remains delegated to the separate Go DirFuzz MCP server.
"""
    path = Path(paths["summary_md"])
    try:
        saved = write_artifact_bytes(campaign_id, "generate_campaign_summary", path, content.encode("utf-8"), maximum=limit("max_saved_artifact_bytes"), limits_applied={"max_saved_artifact_bytes": limit("max_saved_artifact_bytes")})
    except (OSError, SafeIOError) as exc:
        return {"ok": False, "error": f"Could not write summary: {exc}"}
    audit = write_audit_event(campaign_id, "generate_campaign_summary", ok=True, result_path=str(path))
    return {"ok": True, "path": str(path), "metadata_path": saved["metadata_path"], "artifact_uuid": saved["artifact_uuid"], "summary": content, "warnings": audit.get("warnings", []) if not audit.get("ok") else []}


def generate_report_candidate_markdown(campaign_id: str, finding_id: str) -> dict:
    """Generate a local report-candidate Markdown file; it is not submitted anywhere."""
    result = get_finding(campaign_id, finding_id)
    if not result.get("ok"):
        return {"ok": False, "error": result.get("error")}
    finding = result["finding"]
    if finding.get("status") != REPORT_CANDIDATE:
        return {"ok": False, "error": "Finding must be a report_candidate before report Markdown is generated."}
    paths = get_campaign_paths(campaign_id)
    if not paths.get("ok"):
        return {"ok": False, "error": paths.get("error")}

    content = f"""# {finding.get("title")}

## Status
Report candidate / needs final human review

## Target
{_md(finding.get("target"))}

## Scope Confirmation
{_md(finding.get("promotion_gates", {}).get("scope_confirmed"))}

## Summary
{_md(finding.get("summary"))}

## Steps to Reproduce
{_md(finding.get("steps_to_reproduce"))}

## Evidence
{_md(finding.get("evidence"))}

## Impact
{_md(finding.get("impact") or finding.get("impact_hypothesis"))}

## Safety Notes
This was validated using authorized, non-destructive testing only.

## Remaining Human Review
Confirm wording, scope, evidence, impact, and program policy before any submission.
"""
    path = Path(paths["paths"]["reports"]) / f"{finding_id}-report-candidate.md"
    try:
        saved = write_artifact_bytes(campaign_id, "generate_report_candidate_markdown", path, content.encode("utf-8"), maximum=limit("max_saved_artifact_bytes"), limits_applied={"max_saved_artifact_bytes": limit("max_saved_artifact_bytes")})
    except (OSError, SafeIOError) as exc:
        return {"ok": False, "error": f"Could not write report candidate: {exc}"}
    audit = write_audit_event(campaign_id, "generate_report_candidate_markdown", target=str(finding.get("target") or ""), ok=True, result_path=str(path))
    return {"ok": True, "path": str(path), "metadata_path": saved["metadata_path"], "artifact_uuid": saved["artifact_uuid"], "markdown": content, "warnings": audit.get("warnings", []) if not audit.get("ok") else []}
