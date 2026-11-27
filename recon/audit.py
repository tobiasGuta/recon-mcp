"""Append-only JSONL audit logging for campaign workflows."""

from __future__ import annotations

import json
import re
from pathlib import Path

from recon.campaign_jsonl import MAX_RECORD, append_campaign_record
from recon.campaign_lock import campaign_operation
from recon.campaigns import get_campaign_paths, iso_now
from recon.redaction import MAX_STRUCTURE_DEPTH, redact_embedded_urls

SENSITIVE_KEY = re.compile(r"(?i)(secret|token|password|passwd|authorization|cookie|session|csrf|xsrf|api[_-]?key|request[_-]?body|response[_-]?body)")


def _safe_string(value: object) -> str:
    return redact_embedded_urls(value)[:2000]


def _sanitize(value: object, key: str = "", depth: int = 0) -> object:
    if depth > MAX_STRUCTURE_DEPTH:
        return "<structure-redacted>"
    if SENSITIVE_KEY.search(key) and "fingerprint" not in key.lower() and "redacted" not in key.lower() and not key.lower().endswith("_present"):
        return "<redacted>"
    if isinstance(value, dict):
        return {_safe_string(item_key): _sanitize(item_value, str(item_key), depth + 1) for item_key, item_value in value.items()}
    if isinstance(value, list):
        return [_sanitize(item, depth=depth + 1) for item in value[:1000]]
    if isinstance(value, tuple):
        return [_sanitize(item, depth=depth + 1) for item in value[:1000]]
    if isinstance(value, str):
        return _safe_string(value)
    if isinstance(value, (int, float, bool, type(None))):
        return value
    return _safe_string(value)


@campaign_operation
def write_audit_event(
    campaign_id: str,
    tool: str,
    target: str | None = None,
    ok: bool = True,
    scope_decision: dict | None = None,
    result_path: str | None = None,
    warnings: list[str] | None = None,
    metadata: dict | None = None,
) -> dict:
    """Append an audit event; return a warning instead of raising on failure."""
    paths = get_campaign_paths(campaign_id)
    if not paths.get("ok"):
        return {"ok": False, "warnings": [f"Audit not written: {paths.get('error')}"]}

    event = {
        "timestamp": iso_now(),
        "campaign_id": campaign_id,
        "tool": _safe_string(tool or ""),
        "target": _sanitize(target),
        "ok": bool(ok),
        "scope_ok": bool(scope_decision.get("in_scope")) if isinstance(scope_decision, dict) else None,
        "scope_decision": _sanitize(scope_decision or {}),
        "result_path": _safe_string(result_path) if result_path is not None else None,
        "warnings": _sanitize(warnings or []),
        "metadata": _sanitize(metadata or {}),
    }
    encoded = (json.dumps(event, sort_keys=True) + "\n").encode("utf-8")
    if len(encoded) > MAX_RECORD:
        event["metadata"] = {"redacted": "Audit metadata exceeded the per-event limit."}
        event["warnings"] = ["Audit event content was truncated at the per-event limit."]
        encoded = (json.dumps(event, sort_keys=True) + "\n").encode("utf-8")
        if len(encoded) > MAX_RECORD:
            return {"ok": False, "warnings": ["Audit event exceeded its size limit."]}
    audit_path = Path(paths["paths"]["audit_jsonl"])
    try:
        append_campaign_record(audit_path, event)
    except (OSError, ValueError):
        return {"ok": False, "warnings": ["Audit not written: could not append to the campaign log."], "event": event}
    return {"ok": True, "event": event, "path": str(audit_path)}
