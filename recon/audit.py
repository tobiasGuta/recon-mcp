"""Append-only JSONL audit logging for campaign workflows."""

from __future__ import annotations

import json
from pathlib import Path

from recon.campaigns import get_campaign_paths, iso_now


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
        "target": target,
        "ok": bool(ok),
        "scope_ok": bool(scope_decision.get("in_scope")) if isinstance(scope_decision, dict) else None,
        "scope_decision": scope_decision or {},
        "result_path": result_path,
        "warnings": warnings or [],
        "metadata": metadata or {},
    }
    audit_path = Path(paths["paths"]["audit_jsonl"])
    try:
        audit_path.parent.mkdir(parents=True, exist_ok=True)
        with audit_path.open("a", encoding="utf-8") as audit_file:
            audit_file.write(json.dumps(event, sort_keys=True) + "\n")
    except OSError as exc:
        return {"ok": False, "warnings": [f"Audit not written: {exc}"], "event": event}
    return {"ok": True, "event": event, "path": str(audit_path)}
