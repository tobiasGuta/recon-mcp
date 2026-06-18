"""Evidence note creation for human review."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
EVIDENCE_DIR = PROJECT_ROOT / "output" / "evidence"


def _slug(value: str) -> str:
    """Create a filesystem-safe slug."""
    slug = re.sub(r"[^A-Za-z0-9_-]+", "-", value.strip().lower()).strip("-")
    return slug[:80] or "finding"


def _list_or_text(value: object) -> str:
    """Render lists and plain values as Markdown."""
    if isinstance(value, list):
        return "\n".join(f"- {item}" for item in value) if value else "None provided."
    if isinstance(value, dict):
        return "\n".join(f"- **{key}:** {item}" for key, item in value.items()) if value else "None provided."
    return str(value) if value else "None provided."


def create_evidence_note(finding: dict) -> dict:
    """Write a Markdown evidence note for a manually reviewed finding."""
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
        path.write_text(content, encoding="utf-8")
    except OSError as exc:
        return {"ok": False, "error": f"Could not write evidence note: {exc}"}

    return {"ok": True, "path": str(path), "title": title}
