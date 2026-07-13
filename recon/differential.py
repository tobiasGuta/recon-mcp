"""Normalized, redacted differential recon between campaigns."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from recon.audit import write_audit_event
from recon.campaigns import file_timestamp, get_campaign_paths
from recon.safeio import SafeIOError, artifact_envelope, limit, read_bytes_bounded, write_artifact_bytes, write_json_artifact
from recon.redaction import redact_endpoint

MAX_DIFF_ITEMS = 5000


def _payload(path: Path) -> dict:
    try:
        value = json.loads(read_bytes_bounded(path, 20 * 1024 * 1024))
    except (SafeIOError, json.JSONDecodeError):
        return {}
    return value.get("payload", value) if isinstance(value, dict) else {}


def _collect(campaign_id: str) -> dict[str, dict[str, dict]]:
    paths = get_campaign_paths(campaign_id)
    if not paths.get("ok"):
        raise SafeIOError(str(paths.get("error")))
    root = Path(paths["paths"]["root"]) / "recon"
    categories: dict[str, dict[str, dict]] = {name: {} for name in ("hosts", "javascript", "endpoints", "api_contracts", "source_maps", "secret_candidates", "headers", "robots", "sitemap", "passive_subdomains", "client_configuration", "negative_results")}
    campaign_path = Path(paths["paths"]["campaign_json"])
    if campaign_path.exists() and not campaign_path.is_symlink():
        campaign = _payload(campaign_path)
        host = str(campaign.get("normalized_host") or "")
        if host:
            categories["hosts"][host] = {"host": host}
    for path in root.rglob("*.json"):
        if path.is_symlink() or path.name.endswith(".metadata.json") or path.name.startswith("cache-"):
            continue
        data = _payload(path)
        source = str(path.relative_to(root))
        for item in data.get("matches", []) if isinstance(data.get("matches"), list) else []:
            key = f"{item.get('detector_id')}:{item.get('fingerprint_sha256')}"
            categories["secret_candidates"][key] = {"detector_id": item.get("detector_id"), "fingerprint_sha256": item.get("fingerprint_sha256"), "file": item.get("file")}
        for item in data.get("client_configuration_signals", []) if isinstance(data.get("client_configuration_signals"), list) else []:
            key = f"{item.get('signal_id')}:{item.get('file')}:{item.get('line')}"
            categories["client_configuration"][key] = item
        for item in data.get("contracts", []) if isinstance(data.get("contracts"), list) else []:
            key = f"{item.get('method')}:{item.get('endpoint_expression')}:{item.get('graphql_operation_name')}:{item.get('source_file')}"
            safe = {k: v for k, v in item.items() if "value" not in k.lower() or "redacted" in k.lower()}
            categories["api_contracts"][key] = safe
            if item.get("endpoint"):
                categories["endpoints"][f"{item.get('method')}:{item.get('endpoint')}"] = {"method": item.get("method"), "endpoint": item.get("endpoint")}
        for item in data.get("results", []) if isinstance(data.get("results"), list) else []:
            if item.get("host") and "scope_classification" in item:
                categories["passive_subdomains"][str(item["host"]).lower().rstrip(".")] = {"host": item["host"], "scope_classification": item.get("scope_classification")}
        result = data.get("result") if isinstance(data.get("result"), dict) else data
        for url in result.get("js_urls", []) if isinstance(result.get("js_urls"), list) else []:
            if isinstance(url, dict):
                value = redact_endpoint(url.get("url") or url.get("value") or "")
                digest = url.get("sha256") or url.get("hash")
            else:
                value = redact_endpoint(url)
                digest = None
            if value:
                categories["javascript"][value] = {"url": value, "sha256": digest}
        for endpoint in result.get("endpoints", []) if isinstance(result.get("endpoints"), list) else []:
            value = endpoint.get("value") if isinstance(endpoint, dict) else endpoint
            value = redact_endpoint(value)
            categories["endpoints"][str(value)] = {"endpoint": value}
        for key, value in (result.get("interesting_headers") or {}).items() if isinstance(result.get("interesting_headers"), dict) else []:
            categories["headers"][str(key).lower()] = {"name": key, "value_sha256": hashlib.sha256(str(value).encode()).hexdigest()}
        for entry in result.get("disallow", []) if isinstance(result.get("disallow"), list) else []:
            categories["robots"][str(entry)] = {"entry": entry}
        for entry in result.get("discovered_urls", []) if isinstance(result.get("discovered_urls"), list) else []:
            categories["sitemap"][str(entry)] = {"entry": entry}
        if data.get("map_path"):
            key = redact_endpoint(data.get("sourcemap_url") or Path(str(data["map_path"])).name)
            categories["source_maps"][key] = {"identifier": key, "size_bytes": data.get("size_bytes")}
    extracted = root / "sourcemaps" / "extracted"
    if extracted.exists() and not extracted.is_symlink():
        for path in [item for item in sorted(extracted.rglob("*")) if item.is_file() and not item.is_symlink()][:1000]:
            if path.name == "sources-index.json" or path.suffix.lower() not in {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".vue", ".svelte"}:
                continue
            try:
                data = read_bytes_bounded(path, limit("max_javascript_bytes"))
            except SafeIOError:
                continue
            key = path.relative_to(extracted).as_posix()
            categories["javascript"][key] = {"path": key, "sha256": hashlib.sha256(data).hexdigest(), "size_bytes": len(data)}
    memory_path = Path(paths["paths"]["negative_results_jsonl"])
    if memory_path.exists() and not memory_path.is_symlink():
        try:
            for line in read_bytes_bounded(memory_path, 10 * 1024 * 1024).decode().splitlines():
                item = json.loads(line)
                key = f"{item.get('target')}:{item.get('check_type')}"
                categories["negative_results"][key] = {"target": item.get("target"), "check_type": item.get("check_type"), "result": item.get("result")}
        except (SafeIOError, json.JSONDecodeError):
            pass
    return categories


def compare_campaign_recon(campaign_id: str, baseline_campaign_id: str) -> dict:
    try:
        current = _collect(campaign_id)
        baseline = _collect(baseline_campaign_id)
    except SafeIOError as exc:
        write_audit_event(campaign_id, "compare_campaign_recon", target=baseline_campaign_id, ok=False, warnings=[str(exc)])
        return {"ok": False, "error": str(exc)}
    changes: dict[str, dict] = {}
    truncated = False
    for category in current:
        current_keys, baseline_keys = set(current[category]), set(baseline[category])
        added_keys = sorted(current_keys - baseline_keys)
        removed_keys = sorted(baseline_keys - current_keys)
        common = current_keys & baseline_keys
        changed_keys = sorted(key for key in common if current[category][key] != baseline[category][key])
        if len(added_keys) + len(removed_keys) + len(changed_keys) > MAX_DIFF_ITEMS:
            truncated = True
        changes[category] = {"added": [{"normalized_identifier": key, "item": current[category][key], "reason": "Normalized identifier is absent from baseline."} for key in added_keys[:MAX_DIFF_ITEMS]], "removed": [{"normalized_identifier": key, "item": baseline[category][key], "reason": "Normalized identifier is absent from current campaign."} for key in removed_keys[:MAX_DIFF_ITEMS]], "changed": [{"normalized_identifier": key, "before": baseline[category][key], "after": current[category][key], "reason": "Normalized identifier is shared but redacted structured metadata differs."} for key in changed_keys[:MAX_DIFF_ITEMS]]}
    payload = {"ok": True, "campaign_id": campaign_id, "baseline_campaign_id": baseline_campaign_id, "changes": changes, "truncated": truncated, "manual_validation_required": True, "safety_note": "Differences are recon changes, not vulnerabilities."}
    paths = get_campaign_paths(campaign_id)
    directory = Path(paths["paths"]["recon"]["diffs"])
    envelope = artifact_envelope(campaign_id, "compare_campaign_recon", payload, truncation_status={"truncated": truncated}, limits_applied={"max_items_per_category": MAX_DIFF_ITEMS})
    try:
        saved = write_json_artifact(directory / f"{file_timestamp()}-vs-{baseline_campaign_id}.json", envelope)
        summary_path = directory / f"{file_timestamp()}-vs-{baseline_campaign_id}.md"
        lines = ["# Differential Recon Summary", "", f"Current: `{campaign_id}`", f"Baseline: `{baseline_campaign_id}`", "", "Recon differences are not validated vulnerabilities.", ""]
        for category, value in changes.items():
            lines.extend([f"## {category.replace('_', ' ').title()}", "", f"- Added: {len(value['added'])}", f"- Removed: {len(value['removed'])}", f"- Changed: {len(value['changed'])}", ""])
        summary_saved = write_artifact_bytes(campaign_id, "compare_campaign_recon", summary_path, "\n".join(lines).encode("utf-8"), maximum=limit("max_saved_artifact_bytes"), limits_applied={"max_saved_artifact_bytes": limit("max_saved_artifact_bytes")})
    except (SafeIOError, OSError) as exc:
        write_audit_event(campaign_id, "compare_campaign_recon", target=baseline_campaign_id, ok=False, warnings=[str(exc)])
        return {"ok": False, "error": f"Could not save differential recon: {exc}"}
    write_audit_event(campaign_id, "compare_campaign_recon", target=baseline_campaign_id, ok=True, result_path=saved["path"], metadata={"truncated": truncated})
    return {**payload, **saved, "summary_path": str(summary_path), "summary_metadata_path": summary_saved["metadata_path"]}
