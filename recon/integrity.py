"""Read-only campaign artifact integrity verification."""

from __future__ import annotations

import json
from pathlib import Path

from recon.audit import write_audit_event
from recon.safeio import SafeIOError, campaign_root, read_bytes_bounded, sha256_bytes

MAX_VERIFY_FILES = 10000
MAX_VERIFY_BYTES = 100 * 1024 * 1024


def verify_campaign_artifacts(campaign_id: str) -> dict:
    """Verify integrity sidecars without rewriting evidence."""
    try:
        root = campaign_root(campaign_id)
    except SafeIOError as exc:
        return {"ok": False, "error": str(exc)}
    verified: list[dict] = []
    missing: list[dict] = []
    modified: list[dict] = []
    malformed: list[dict] = []
    sidecar_targets: set[Path] = set()
    sidecars = [path for path in root.rglob("*.metadata.json") if path.is_file() and not path.is_symlink()][:MAX_VERIFY_FILES]
    for sidecar in sidecars:
        try:
            metadata = json.loads(read_bytes_bounded(sidecar, 1024 * 1024))
            if metadata.get("schema") != "recon-mcp-artifact-integrity-v1" or not metadata.get("artifact_path") or not metadata.get("artifact_sha256"):
                raise ValueError("Unsupported or missing integrity metadata fields.")
            artifact = sidecar.parent / str(metadata["artifact_path"])
            if artifact.parent.resolve() != sidecar.parent.resolve() or artifact.is_symlink():
                raise ValueError("Unsafe artifact_path in integrity metadata.")
            sidecar_targets.add(artifact.resolve())
            if not artifact.exists():
                missing.append({"metadata_path": str(sidecar.relative_to(root)), "artifact_path": str(metadata["artifact_path"])})
                continue
            digest = sha256_bytes(read_bytes_bounded(artifact, MAX_VERIFY_BYTES))
            item = {"artifact_uuid": metadata.get("artifact_uuid"), "path": str(artifact.relative_to(root)), "expected_sha256": metadata["artifact_sha256"], "observed_sha256": digest}
            (verified if digest == metadata["artifact_sha256"] else modified).append(item)
        except (SafeIOError, OSError, json.JSONDecodeError, ValueError) as exc:
            malformed.append({"metadata_path": str(sidecar.relative_to(root)), "error": str(exc)})
    legacy: list[str] = []
    for path in root.rglob("*.json"):
        if path.is_symlink() or path.name.endswith(".metadata.json") or path.resolve() in sidecar_targets:
            continue
        legacy.append(str(path.relative_to(root)))
        if len(legacy) >= MAX_VERIFY_FILES:
            break
    result = {"ok": not missing and not modified and not malformed, "campaign_id": campaign_id, "verified_artifacts": verified, "missing_artifacts": missing, "modified_artifacts": modified, "malformed_metadata": malformed, "unsupported_legacy_artifacts": legacy, "counts": {"verified": len(verified), "missing": len(missing), "modified": len(modified), "malformed": len(malformed), "legacy": len(legacy)}, "rewritten": False}
    write_audit_event(campaign_id, "verify_campaign_artifacts", ok=result["ok"], warnings=["Artifact integrity problems were detected."] if not result["ok"] else [], metadata=result["counts"])
    return result
