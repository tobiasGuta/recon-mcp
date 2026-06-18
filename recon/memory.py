"""Campaign memory for useful negative recon results."""

from __future__ import annotations

import json
from pathlib import Path

from recon.audit import write_audit_event
from recon.campaigns import get_campaign_paths, iso_now


def record_negative_result(
    campaign_id: str,
    target: str,
    check_type: str,
    result: str,
    repeat_after: str | None = None,
    metadata: dict | None = None,
) -> dict:
    """Record a non-finding note so humans avoid repeating low-value checks."""
    paths = get_campaign_paths(campaign_id)
    if not paths.get("ok"):
        return {"ok": False, "error": paths.get("error")}
    record = {
        "timestamp": iso_now(),
        "campaign_id": campaign_id,
        "target": target,
        "check_type": check_type,
        "result": result,
        "repeat_after": repeat_after,
        "metadata": metadata or {},
    }
    path = Path(paths["paths"]["negative_results_jsonl"])
    try:
        with path.open("a", encoding="utf-8") as memory_file:
            memory_file.write(json.dumps(record, sort_keys=True) + "\n")
    except OSError as exc:
        return {"ok": False, "error": f"Could not write negative result: {exc}"}
    audit = write_audit_event(campaign_id, "record_negative_result", target=target, ok=True, result_path=str(path))
    warnings = audit.get("warnings", []) if not audit.get("ok") else []
    return {"ok": True, "record": record, "path": str(path), "warnings": warnings}


def list_negative_results(campaign_id: str, check_type: str | None = None) -> dict:
    """List campaign negative-result memory entries."""
    paths = get_campaign_paths(campaign_id)
    if not paths.get("ok"):
        return {"ok": False, "error": paths.get("error")}
    path = Path(paths["paths"]["negative_results_jsonl"])
    records = []
    if path.exists():
        try:
            for line in path.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                record = json.loads(line)
                if check_type is None or record.get("check_type") == check_type:
                    records.append(record)
        except (OSError, json.JSONDecodeError) as exc:
            return {"ok": False, "error": f"Could not read negative results: {exc}"}
    return {"ok": True, "results": records, "count": len(records)}
