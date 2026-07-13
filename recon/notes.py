"""Evidence note creation for human review."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

from recon.audit import write_audit_event
from recon.campaigns import get_campaign_paths
from recon.findings import update_finding_gates
from recon.redaction import redact_structure
from recon.safeio import SafeIOError, atomic_write_bytes, limit, write_artifact_bytes


PROJECT_ROOT = Path(__file__).resolve().parent.parent
EVIDENCE_DIR = PROJECT_ROOT / "output" / "evidence"


def _slug(value: str) -> str:
    """Create a filesystem-safe slug."""
    slug = re.sub(r"[^A-Za-z0-9_-]+", "-", value.strip().lower()).strip("-")
    return slug[:80] or "finding"


def _list_or_text(value: object) -> str:
    """Render lists and plain values as Markdown."""
    value = redact_structure(value)
    if isinstance(value, list):
        return "\n".join(f"- {item}" for item in value) if value else "None provided."
    if isinstance(value, dict):
        return "\n".join(f"- **{key}:** {item}" for key, item in value.items()) if value else "None provided."
    return str(value) if value else "None provided."


def create_evidence_note(finding: dict) -> dict:
    """Write a Markdown evidence note for a manually reviewed finding."""
    finding = redact_structure(finding)
    if EVIDENCE_DIR.is_symlink():
        return {"ok": False, "error": "EVIDENCE_DIR must not be a symlink."}

    try:
        EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        return {"ok": False, "error": f"Could not create evidence directory: {exc}"}

    title = str(finding.get("title") or finding.get("summary") or "Recon finding")
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    base_filename = f"{timestamp}-{_slug(title)}"
    filename = f"{base_filename}.md"
    evidence_root = EVIDENCE_DIR.resolve()
    for suffix in range(1000):
        candidate_name = filename if suffix == 0 else f"{base_filename}-{suffix}.md"
        path = (EVIDENCE_DIR / candidate_name).resolve()
        if path.parent != evidence_root or path.name != candidate_name:
            return {"ok": False, "error": "Unsafe evidence note filename."}
        if not path.exists():
            filename = candidate_name
            break
    else:
        return {"ok": False, "error": "Could not find a unique evidence note filename."}

    impact = finding.get("impact") or "Manual impact analysis needed."
    content = f"""# {title}

## Target
{_list_or_text(finding.get("target"))}

## Summary
{_list_or_text(finding.get("summary"))}

## Evidence
{_list_or_text(finding.get("evidence"))}

## Steps to Reproduce
{_list_or_text(finding.get("steps_to_reproduce"))}

## Impact
{_list_or_text(impact)}

## Manual Validation Needed
{_list_or_text(finding.get("manual_validation_needed") or "Manual validation required before reporting.")}

## Notes
{_list_or_text(finding.get("notes"))}
"""

    try:
        atomic_write_bytes(path, content.encode("utf-8"), maximum=limit("max_saved_artifact_bytes"))
    except (OSError, SafeIOError) as exc:
        return {"ok": False, "error": f"Could not write evidence note: {exc}"}

    return {"ok": True, "path": str(path), "title": title}


def create_campaign_evidence_note(campaign_id: str, finding: dict) -> dict:
    """Write a campaign evidence note for authorized manual validation only."""
    if not isinstance(finding, dict):
        return {"ok": False, "error": "finding must be a dictionary."}
    finding = redact_structure(finding)
    paths = get_campaign_paths(campaign_id)
    if not paths.get("ok"):
        return {"ok": False, "error": paths.get("error", "Could not load campaign paths.")}

    evidence_dir = Path(paths["paths"]["evidence"])
    if evidence_dir.is_symlink():
        return {"ok": False, "error": "Campaign evidence directory must not be a symlink."}
    title = str(finding.get("title") or finding.get("summary") or "Recon finding")
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    filename = f"{timestamp}-{_slug(title)}.md"
    evidence_root = evidence_dir.resolve()
    path = (evidence_dir / filename).resolve()
    if path.parent != evidence_root or path.name != filename:
        return {"ok": False, "error": "Unsafe evidence note filename."}

    scope_confirmation = finding.get("scope_confirmation") or finding.get("promotion_gates", {}).get("scope_confirmed")
    request_response = finding.get("request_response") or finding.get("request_response_metadata")
    content = f"""# {title}

## Target
{_list_or_text(finding.get("target"))}

## Summary
{_list_or_text(finding.get("summary"))}

## Scope Confirmation
{_list_or_text(scope_confirmation)}

## Request / Response Metadata
{_list_or_text(request_response)}

## Evidence
{_list_or_text(finding.get("evidence"))}

## Steps to Reproduce
{_list_or_text(finding.get("steps_to_reproduce"))}

## Impact
{_list_or_text(finding.get("impact") or finding.get("impact_hypothesis"))}

## Manual Validation Checklist
{_list_or_text(finding.get("manual_validation_checklist") or finding.get("manual_validation_needed"))}

## Status / Gates
{_list_or_text({"status": finding.get("status"), **(finding.get("promotion_gates") or {})})}

## Notes
{_list_or_text(finding.get("notes"))}
"""
    try:
        saved = write_artifact_bytes(campaign_id, "create_campaign_evidence_note", path, content.encode("utf-8"), maximum=limit("max_saved_artifact_bytes"), limits_applied={"max_saved_artifact_bytes": limit("max_saved_artifact_bytes")})
    except (OSError, SafeIOError) as exc:
        return {"ok": False, "error": f"Could not write campaign evidence note: {exc}"}

    gate_result = None
    finding_id = finding.get("finding_id")
    if finding_id:
        gate_result = update_finding_gates(
            campaign_id,
            str(finding_id),
            {"evidence_saved": True},
            "Campaign evidence note was created.",
        )

    audit = write_audit_event(
        campaign_id,
        "create_campaign_evidence_note",
        target=str(finding.get("target") or ""),
        ok=True,
        result_path=str(path),
        metadata={"finding_id": finding_id},
    )
    warnings = []
    if gate_result and not gate_result.get("ok"):
        warnings.append(f"Finding gate was not updated: {gate_result.get('error')}")
    if not audit.get("ok"):
        warnings.extend(audit.get("warnings", []))
    return {"ok": True, "path": str(path), "metadata_path": saved["metadata_path"], "artifact_uuid": saved["artifact_uuid"], "title": title, "gate_update": gate_result, "warnings": warnings}
