"""Fail-closed campaign-local file and artifact helpers."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import uuid
from pathlib import Path
from typing import Any

from recon import __version__
from recon.campaigns import get_campaign_paths, iso_now
from recon.scope import DEFAULT_LIMITS, load_scope


class SafeIOError(ValueError):
    """Raised for unsafe paths, symlinks, malformed data, or size violations."""


def limit(name: str) -> int:
    return int(load_scope().get(name, DEFAULT_LIMITS[name]))


def campaign_root(campaign_id: str) -> Path:
    result = get_campaign_paths(campaign_id)
    if not result.get("ok"):
        raise SafeIOError(str(result.get("error") or "Campaign is unavailable."))
    root = Path(result["paths"]["root"])
    if root.is_symlink():
        raise SafeIOError("Campaign root must not be a symlink.")
    return root.resolve()


def safe_campaign_path(
    campaign_id: str,
    value: str | Path,
    *,
    allowed_root: str | Path | None = None,
    must_exist: bool = True,
    require_file: bool = False,
    require_dir: bool = False,
) -> Path:
    root = campaign_root(campaign_id)
    raw_boundary = Path(allowed_root) if allowed_root else root
    if raw_boundary.is_symlink():
        raise SafeIOError("Approved path boundary must not be a symlink.")
    boundary = raw_boundary.resolve()
    if not boundary.is_relative_to(root):
        raise SafeIOError("Approved path boundary is unsafe.")
    candidate = Path(value)
    if not candidate.is_absolute():
        candidate = boundary / candidate
    try:
        lexical = candidate.absolute()
        relative_parts = lexical.relative_to(boundary).parts
    except ValueError as exc:
        raise SafeIOError("Local path escapes the approved campaign directory.") from exc
    current = boundary
    for part in relative_parts:
        current = current / part
        if current.exists() and current.is_symlink():
            raise SafeIOError("Symlinks are not accepted for campaign-local paths.")
    try:
        resolved = candidate.resolve(strict=must_exist)
    except OSError as exc:
        raise SafeIOError(f"Could not resolve local path: {exc}") from exc
    if not resolved.is_relative_to(boundary):
        raise SafeIOError("Local path escapes the approved campaign directory.")
    if must_exist and not resolved.exists():
        raise SafeIOError("Local path does not exist.")
    if require_file and not resolved.is_file():
        raise SafeIOError("Local path must be a regular file.")
    if require_dir and not resolved.is_dir():
        raise SafeIOError("Local path must be a directory.")
    return resolved


def read_bytes_bounded(path: Path, maximum: int) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise SafeIOError("Input must be a regular non-symlink file.")
    size = path.stat().st_size
    if size > maximum:
        raise SafeIOError(f"Input exceeds configured maximum of {maximum} bytes (observed {size}).")
    with path.open("rb") as handle:
        data = handle.read(maximum + 1)
    if len(data) > maximum:
        raise SafeIOError(f"Input exceeded configured maximum of {maximum} bytes while reading.")
    return data


def read_text_bounded(path: Path, maximum: int) -> str:
    return read_bytes_bounded(path, maximum).decode("utf-8", errors="replace")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def scope_snapshot_sha256(campaign_id: str) -> str | None:
    root = campaign_root(campaign_id)
    path = root / "scope.json"
    try:
        return sha256_bytes(read_bytes_bounded(path, limit("max_saved_artifact_bytes")))
    except SafeIOError:
        return None


def atomic_write_bytes(path: Path, data: bytes, *, maximum: int | None = None) -> None:
    maximum = maximum if maximum is not None else limit("max_saved_artifact_bytes")
    if len(data) > maximum:
        raise SafeIOError(f"Artifact exceeds configured maximum of {maximum} bytes.")
    path.parent.mkdir(parents=True, exist_ok=True)
    current = path.parent
    while current != current.parent:
        if current.is_symlink():
            raise SafeIOError("Artifact path must not contain a symlink.")
        current = current.parent
    if path.exists() and path.is_symlink():
        raise SafeIOError("Artifact path must not contain a symlink.")
    temp_path: Path | None = None
    try:
        fd, name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
        temp_path = Path(name)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        temp_path.replace(path)
    finally:
        if temp_path and temp_path.exists():
            temp_path.unlink(missing_ok=True)


def artifact_envelope(
    campaign_id: str,
    tool: str,
    payload: Any,
    *,
    parent_artifact_ids: list[str] | None = None,
    input_artifact_ids: list[str] | None = None,
    truncation_status: dict | None = None,
    limits_applied: dict | None = None,
) -> dict:
    return {
        "artifact_uuid": str(uuid.uuid4()),
        "campaign_id": campaign_id,
        "tool": tool,
        "tool_version": __version__,
        "project_version": __version__,
        "created_at": iso_now(),
        "scope_snapshot_sha256": scope_snapshot_sha256(campaign_id),
        "parent_artifact_ids": parent_artifact_ids or [],
        "input_artifact_ids": input_artifact_ids or [],
        "truncation_status": truncation_status or {"truncated": False},
        "configuration_limits_applied": limits_applied or {},
        "payload": payload,
    }


def write_json_artifact(path: Path, envelope: dict) -> dict:
    final = json.dumps(envelope, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    atomic_write_bytes(path, final)
    digest = sha256_bytes(final)
    return _write_integrity_metadata(path, envelope, digest)


def _write_integrity_metadata(path: Path, envelope: dict, digest: str) -> dict:
    metadata_path = path.with_name(path.name + ".metadata.json")
    metadata = {
        "schema": "recon-mcp-artifact-integrity-v1",
        "artifact_uuid": envelope["artifact_uuid"],
        "artifact_path": path.name,
        "artifact_sha256": digest,
        "tool": envelope.get("tool"),
        "tool_version": envelope.get("tool_version"),
        "project_version": envelope.get("project_version"),
        "created_at": envelope.get("created_at"),
        "scope_snapshot_sha256": envelope.get("scope_snapshot_sha256"),
        "parent_artifact_ids": envelope.get("parent_artifact_ids", []),
        "input_artifact_ids": envelope.get("input_artifact_ids", []),
        "truncation_status": envelope.get("truncation_status", {}),
        "configuration_limits_applied": envelope.get("configuration_limits_applied", {}),
    }
    atomic_write_bytes(metadata_path, json.dumps(metadata, indent=2, sort_keys=True).encode("utf-8") + b"\n")
    return {"path": str(path), "metadata_path": str(metadata_path), "artifact_uuid": envelope["artifact_uuid"], "sha256": digest}


def write_flat_json_artifact(campaign_id: str, tool: str, path: Path, payload: dict, *, truncation_status: dict | None = None, limits_applied: dict | None = None) -> dict:
    """Write provenance alongside an established top-level JSON payload shape."""
    envelope = artifact_envelope(campaign_id, tool, payload, truncation_status=truncation_status, limits_applied=limits_applied)
    flattened = {**payload, **{key: value for key, value in envelope.items() if key != "payload"}}
    return write_json_artifact(path, flattened)


def write_artifact_bytes(campaign_id: str, tool: str, path: Path, data: bytes, *, maximum: int | None = None, truncation_status: dict | None = None, limits_applied: dict | None = None) -> dict:
    """Atomically write arbitrary final artifact bytes and a provenance sidecar."""
    envelope = artifact_envelope(campaign_id, tool, None, truncation_status=truncation_status, limits_applied=limits_applied)
    atomic_write_bytes(path, data, maximum=maximum)
    return _write_integrity_metadata(path, envelope, sha256_bytes(data))
