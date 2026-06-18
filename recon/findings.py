"""Finding candidate pipeline with an explicit hallucination bin."""

from __future__ import annotations

import json
from pathlib import Path

from recon.audit import write_audit_event
from recon.campaigns import file_timestamp, get_campaign_paths, iso_now, slugify


HALLUCINATION = "hallucination"
NEEDS_MANUAL_VALIDATION = "needs_manual_validation"
VALIDATED = "validated"
REJECTED = "rejected"
REPORT_CANDIDATE = "report_candidate"

ALLOWED_STATUSES = {
    HALLUCINATION,
    NEEDS_MANUAL_VALIDATION,
    VALIDATED,
    REJECTED,
    REPORT_CANDIDATE,
}
STATUS_DIRS = {
    HALLUCINATION: "hallucinations",
    NEEDS_MANUAL_VALIDATION: "needs_manual_validation",
    VALIDATED: "validated",
    REJECTED: "rejected",
    REPORT_CANDIDATE: "report_candidates",
}
PROMOTIONS = {
    HALLUCINATION: NEEDS_MANUAL_VALIDATION,
    NEEDS_MANUAL_VALIDATION: VALIDATED,
    VALIDATED: REPORT_CANDIDATE,
}
DEMOTIONS = {
    REPORT_CANDIDATE: VALIDATED,
    VALIDATED: NEEDS_MANUAL_VALIDATION,
    NEEDS_MANUAL_VALIDATION: HALLUCINATION,
}
REPORT_GATES = [
    "scope_confirmed",
    "evidence_saved",
    "reproduced_manually",
    "impact_proven",
    "safe_non_destructive",
    "report_ready",
]
DEFAULT_GATES = {
    "scope_confirmed": False,
    "evidence_saved": False,
    "reproduced_manually": False,
    "impact_proven": False,
    "safe_non_destructive": True,
    "report_ready": False,
}


def _error(message: str) -> dict:
    return {"ok": False, "error": message}


def _paths(campaign_id: str) -> dict:
    paths = get_campaign_paths(campaign_id)
    if not paths.get("ok"):
        return {"error": paths.get("error", "Could not load campaign paths.")}
    return paths["paths"]["findings"]


def _safe_finding_id(finding_id: str) -> bool:
    return bool(finding_id) and slugify(finding_id, fallback="") == finding_id and ".." not in finding_id


def _finding_file(campaign_id: str, status: str, finding_id: str) -> Path | None:
    paths = _paths(campaign_id)
    if "error" in paths or status not in STATUS_DIRS or not _safe_finding_id(finding_id):
        return None
    return Path(paths[STATUS_DIRS[status]]) / f"{finding_id}.json"


def _find_existing_file(campaign_id: str, finding_id: str) -> tuple[Path | None, str | None, str | None]:
    if not _safe_finding_id(finding_id):
        return None, None, "Unsafe finding_id."
    paths = _paths(campaign_id)
    if "error" in paths:
        return None, None, paths.get("error", "Could not load campaign paths.")
    for status, dirname in STATUS_DIRS.items():
        path = Path(paths[dirname]) / f"{finding_id}.json"
        if path.exists():
            return path, status, None
    return None, None, "Finding not found."


def _read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, finding: dict) -> str | None:
    try:
        path.write_text(json.dumps(finding, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except OSError as exc:
        return f"Could not write finding: {exc}"
    return None


def _new_finding_id(title: str) -> str:
    return f"{file_timestamp().lower()}-{slugify(title, fallback='finding', max_length=70)}"


def _history_entry(action: str, from_status: str | None, to_status: str, reason: str, gate_updates: dict | None = None) -> dict:
    return {
        "timestamp": iso_now(),
        "action": action,
        "from_status": from_status,
        "to_status": to_status,
        "reason": reason,
        "gate_updates": gate_updates or {},
    }


def create_finding_candidate(campaign_id: str, finding: dict) -> dict:
    """Create a possible issue in the hallucination bin for manual validation."""
    if not isinstance(finding, dict):
        return _error("finding must be a dictionary.")
    paths = get_campaign_paths(campaign_id)
    if not paths.get("ok"):
        return _error(paths.get("error", "Could not load campaign paths."))

    title = str(finding.get("title") or finding.get("summary") or "Recon finding")
    finding_id = slugify(str(finding.get("finding_id") or ""), fallback="", max_length=120) or _new_finding_id(title)
    if not _safe_finding_id(finding_id):
        return _error("Unsafe finding_id.")
    path = _finding_file(campaign_id, HALLUCINATION, finding_id)
    if path is None:
        return _error("Could not resolve finding path.")
    if path.exists():
        return _error("Finding already exists.")

    now = iso_now()
    candidate = {
        "finding_id": finding_id,
        "campaign_id": campaign_id,
        "title": title,
        "status": HALLUCINATION,
        "confidence": finding.get("confidence") if finding.get("confidence") in {"low", "medium", "high"} else "low",
        "target": finding.get("target"),
        "category": finding.get("category"),
        "summary": finding.get("summary") or "",
        "evidence": finding.get("evidence") or {},
        "manual_validation_required": True,
        "impact_hypothesis": finding.get("impact_hypothesis") or finding.get("impact") or "",
        "impact_proven": False,
        "safe_test_only": True,
        "promotion_gates": {**DEFAULT_GATES, **(finding.get("promotion_gates") or {})},
        "created_at": now,
        "updated_at": now,
        "history": [_history_entry("create", None, HALLUCINATION, "Candidate starts in hallucinations.")],
    }
    error = _write_json(path, candidate)
    if error:
        return _error(error)
    audit = write_audit_event(campaign_id, "create_finding_candidate", target=str(candidate.get("target") or ""), ok=True, result_path=str(path))
    return {"ok": True, "finding": candidate, "path": str(path), "warnings": audit.get("warnings", []) if not audit.get("ok") else []}


def get_finding(campaign_id: str, finding_id: str) -> dict:
    """Load one finding candidate from any status folder."""
    path, _, error = _find_existing_file(campaign_id, finding_id)
    if error:
        return _error(error)
    assert path is not None
    try:
        finding = _read_json(path)
    except (OSError, json.JSONDecodeError) as exc:
        return _error(f"Could not read finding: {exc}")
    return {"ok": True, "finding": finding, "path": str(path)}


def list_findings(campaign_id: str, status: str | None = None) -> dict:
    """List findings, optionally filtered by status."""
    if status is not None and status not in ALLOWED_STATUSES:
        return _error("Invalid finding status.")
    paths = _paths(campaign_id)
    if "error" in paths:
        return _error(paths.get("error", "Could not load campaign paths."))

    statuses = [status] if status else list(STATUS_DIRS)
    findings = []
    for item_status in statuses:
        directory = Path(paths[STATUS_DIRS[item_status]])
        for path in sorted(directory.glob("*.json")):
            try:
                finding = _read_json(path)
            except (OSError, json.JSONDecodeError):
                continue
            findings.append(finding)
    findings.sort(key=lambda item: item.get("updated_at") or item.get("created_at") or "", reverse=True)
    return {"ok": True, "findings": findings, "count": len(findings)}


def _transition(
    campaign_id: str,
    finding_id: str,
    target_status: str,
    reason: str,
    *,
    action: str,
    gate_updates: dict | None = None,
) -> dict:
    if target_status not in ALLOWED_STATUSES:
        return _error("Invalid target_status.")
    if not reason:
        return _error("A reason is required for every state change.")
    path, current_status, error = _find_existing_file(campaign_id, finding_id)
    if error:
        return _error(error)
    assert path is not None and current_status is not None

    if action == "promote" and target_status != REJECTED and PROMOTIONS.get(current_status) != target_status:
        return _error(f"Invalid promotion from {current_status} to {target_status}.")
    if action == "demote" and DEMOTIONS.get(current_status) != target_status:
        return _error(f"Invalid demotion from {current_status} to {target_status}.")

    try:
        finding = _read_json(path)
    except (OSError, json.JSONDecodeError) as exc:
        return _error(f"Could not read finding: {exc}")

    gates = {**DEFAULT_GATES, **(finding.get("promotion_gates") or {})}
    if gate_updates:
        gates.update({key: bool(value) for key, value in gate_updates.items() if key in DEFAULT_GATES})
    if target_status == REPORT_CANDIDATE and not all(gates.get(gate) is True for gate in REPORT_GATES):
        return _error("Report candidate status requires all promotion gates to be true.")

    finding["promotion_gates"] = gates
    finding["status"] = target_status
    finding["updated_at"] = iso_now()
    finding.setdefault("history", []).append(_history_entry(action, current_status, target_status, reason, gate_updates))
    destination = _finding_file(campaign_id, target_status, finding_id)
    if destination is None:
        return _error("Could not resolve destination finding path.")
    error = _write_json(destination, finding)
    if error:
        return _error(error)
    if destination != path:
        try:
            path.unlink()
        except OSError as exc:
            return _error(f"Finding moved but old file could not be removed: {exc}")
    audit = write_audit_event(
        campaign_id,
        f"{action}_finding",
        target=str(finding.get("target") or ""),
        ok=True,
        result_path=str(destination),
        metadata={"finding_id": finding_id, "from_status": current_status, "to_status": target_status},
    )
    return {"ok": True, "finding": finding, "path": str(destination), "warnings": audit.get("warnings", []) if not audit.get("ok") else []}


def promote_finding(campaign_id: str, finding_id: str, target_status: str, reason: str, gate_updates: dict | None = None) -> dict:
    """Promote a finding one allowed step after human validation."""
    return _transition(campaign_id, finding_id, target_status, reason, action="promote", gate_updates=gate_updates)


def demote_finding(campaign_id: str, finding_id: str, target_status: str, reason: str) -> dict:
    """Demote a finding one allowed step for safer manual review."""
    return _transition(campaign_id, finding_id, target_status, reason, action="demote")


def reject_finding(campaign_id: str, finding_id: str, reason: str) -> dict:
    """Reject a candidate from any status with a required reason."""
    return _transition(campaign_id, finding_id, REJECTED, reason, action="reject")


def update_finding_gates(campaign_id: str, finding_id: str, gate_updates: dict, reason: str) -> dict:
    """Update promotion gates without changing the current finding status."""
    path, current_status, error = _find_existing_file(campaign_id, finding_id)
    if error:
        return _error(error)
    assert path is not None and current_status is not None
    try:
        finding = _read_json(path)
    except (OSError, json.JSONDecodeError) as exc:
        return _error(f"Could not read finding: {exc}")
    gates = {**DEFAULT_GATES, **(finding.get("promotion_gates") or {})}
    gates.update({key: bool(value) for key, value in gate_updates.items() if key in DEFAULT_GATES})
    finding["promotion_gates"] = gates
    finding["updated_at"] = iso_now()
    finding.setdefault("history", []).append(_history_entry("gate_update", current_status, current_status, reason, gate_updates))
    error = _write_json(path, finding)
    if error:
        return _error(error)
    write_audit_event(
        campaign_id,
        "update_finding_gates",
        target=str(finding.get("target") or ""),
        ok=True,
        result_path=str(path),
        metadata={"finding_id": finding_id, "gate_updates": gate_updates},
    )
    return {"ok": True, "finding": finding, "path": str(path)}
