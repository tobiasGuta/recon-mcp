"""Append-only JSONL audit logging for campaign workflows."""

from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from recon.campaigns import get_campaign_paths, iso_now

SENSITIVE_KEY = re.compile(r"(?i)(secret|token|password|passwd|authorization|cookie|session|csrf|xsrf|api[_-]?key|request[_-]?body|response[_-]?body)")
SENSITIVE_TEXT = re.compile(r"(?i)(bearer\s+|(?:token|secret|password|authorization)\s*[:=]\s*)[A-Za-z0-9._~+/=-]{8,}")


def _safe_string(value: object) -> str:
    text = SENSITIVE_TEXT.sub(lambda match: match.group(1) + "<redacted>", str(value))
    try:
        parts = urlsplit(text)
        if parts.scheme and parts.netloc and parts.query:
            query = [(key, "<redacted>" if SENSITIVE_KEY.search(key) else val) for key, val in parse_qsl(parts.query, keep_blank_values=True)]
            text = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))
    except ValueError:
        pass
    return text[:2000]


def _sanitize(value: object, key: str = "") -> object:
    if SENSITIVE_KEY.search(key) and "fingerprint" not in key.lower() and "redacted" not in key.lower() and not key.lower().endswith("_present"):
        return "<redacted>"
    if isinstance(value, dict):
        return {str(item_key): _sanitize(item_value, str(item_key)) for item_key, item_value in value.items()}
    if isinstance(value, list):
        return [_sanitize(item) for item in value[:1000]]
    if isinstance(value, tuple):
        return [_sanitize(item) for item in value[:1000]]
    if isinstance(value, str):
        return _safe_string(value)
    if isinstance(value, (int, float, bool, type(None))):
        return value
    return _safe_string(value)


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
        "tool": str(tool or ""),
        "target": _sanitize(target),
        "ok": bool(ok),
        "scope_ok": bool(scope_decision.get("in_scope")) if isinstance(scope_decision, dict) else None,
        "scope_decision": _sanitize(scope_decision or {}),
        "result_path": result_path,
        "warnings": _sanitize(warnings or []),
        "metadata": _sanitize(metadata or {}),
    }
    encoded = json.dumps(event, sort_keys=True).encode("utf-8")
    if len(encoded) > 1024 * 1024:
        event["metadata"] = {"redacted": "Audit metadata exceeded the per-event limit."}
        event["warnings"] = ["Audit event content was truncated at the per-event limit."]
    audit_path = Path(paths["paths"]["audit_jsonl"])
    try:
        audit_path.parent.mkdir(parents=True, exist_ok=True)
        with audit_path.open("a", encoding="utf-8") as audit_file:
            audit_file.write(json.dumps(event, sort_keys=True) + "\n")
    except OSError as exc:
        return {"ok": False, "warnings": [f"Audit not written: {exc}"], "event": event}
    return {"ok": True, "event": event, "path": str(audit_path)}
