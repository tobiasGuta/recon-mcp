"""Campaign storage for authorized, human-led recon workflows."""

from __future__ import annotations

import json
import os
import re
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from recon.campaign_lock import CampaignLockError, campaign_operation, check_campaign_directory, open_directory
from recon.authorization import AuthorizationError, normalize_host, require_url
from recon.policy_io import PolicyFileError, read_policy_json
from recon.redaction import redact_structure


PROJECT_ROOT = Path(__file__).resolve().parent.parent
CAMPAIGNS_DIR = PROJECT_ROOT / "output" / "campaigns"
ARCHIVED_CAMPAIGNS_DIR = PROJECT_ROOT / "output" / "archived_campaigns"
SAFETY_MODEL = "authorized_low_risk_human_led"
CAMPAIGN_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]{0,159}$")
RECON_SUBDIRS = [
    "headers", "robots", "sitemap", "js_urls", "endpoints", "dirfuzz", "sourcemaps",
    "sensitive", "contracts", "graph", "passive", "diffs", "imports",
]
FINDING_SUBDIRS = [
    "hallucinations",
    "needs_manual_validation",
    "validated",
    "rejected",
    "report_candidates",
]


def utc_now() -> datetime:
    """Return a timezone-aware UTC timestamp."""
    return datetime.now(timezone.utc)


def iso_now() -> str:
    """Return the current UTC time in ISO format."""
    return utc_now().isoformat()


def file_timestamp() -> str:
    """Return a compact UTC timestamp for filenames."""
    return utc_now().strftime("%Y%m%dT%H%M%S%fZ")


def slugify(value: str, *, fallback: str = "item", max_length: int = 80) -> str:
    """Create a filesystem-safe lowercase slug."""
    slug = re.sub(r"[^A-Za-z0-9_-]+", "-", str(value or "").strip().lower()).strip("-_")
    return (slug[:max_length].strip("-_") or fallback)[:max_length]


def is_safe_campaign_id(campaign_id: str) -> bool:
    """Return True when the campaign ID cannot escape the campaigns directory."""
    return bool(CAMPAIGN_ID_PATTERN.fullmatch(str(campaign_id or "")))


def _safe_error(message: str) -> dict:
    return {"ok": False, "error": message}


def _campaign_root(campaign_id: str) -> Path:
    return CAMPAIGNS_DIR / campaign_id


def _archived_campaign_root(campaign_id: str) -> Path:
    return ARCHIVED_CAMPAIGNS_DIR / campaign_id


def _resolve_campaign_root(campaign_id: str, *, must_exist: bool = True) -> tuple[Path | None, str | None]:
    if not is_safe_campaign_id(campaign_id):
        return None, "Unsafe campaign_id."
    base = CAMPAIGNS_DIR.resolve()
    root = _campaign_root(campaign_id)
    if CAMPAIGNS_DIR.is_symlink() or root.is_symlink():
        return None, "Campaign storage path must not be a symlink."
    if must_exist and not root.exists():
        return None, "Campaign does not exist."
    try:
        if must_exist or root.exists():
            check_campaign_directory(root)
        resolved = root.resolve()
    except CampaignLockError as exc:
        return None, str(exc)
    except OSError as exc:
        return None, f"Could not resolve campaign path: {exc}"
    if resolved != base / campaign_id or not resolved.is_relative_to(base):
        return None, "Campaign path escapes campaign storage."
    return resolved, None


def _resolve_archived_campaign_root(campaign_id: str, *, must_exist: bool = True) -> tuple[Path | None, str | None]:
    if not is_safe_campaign_id(campaign_id):
        return None, "Unsafe campaign_id."
    base = ARCHIVED_CAMPAIGNS_DIR.resolve()
    root = _archived_campaign_root(campaign_id)
    if ARCHIVED_CAMPAIGNS_DIR.is_symlink() or root.is_symlink():
        return None, "Campaign storage path must not be a symlink."
    if must_exist and not root.exists():
        return None, "Archived campaign does not exist."
    try:
        if must_exist or root.exists():
            check_campaign_directory(root)
        resolved = root.resolve()
    except CampaignLockError as exc:
        return None, str(exc)
    except OSError as exc:
        return None, f"Could not resolve archived campaign path: {exc}"
    if resolved != base / campaign_id or not resolved.is_relative_to(base):
        return None, "Archived campaign path escapes archive storage."
    return resolved, None


def _reject_symlink(path: Path, label: str) -> str | None:
    if path.is_symlink():
        return f"{label} must not be a symlink."
    return None


def _guard_core_dirs(root: Path) -> str | None:
    checks = {
        "Campaign root": root,
        "Recon directory": root / "recon",
        "Evidence directory": root / "evidence",
        "Findings directory": root / "findings",
        "Reports directory": root / "reports",
        "Memory directory": root / "memory",
        "Imports directory": root / "imports",
        **{f"Recon {name} directory": root / "recon" / name for name in RECON_SUBDIRS},
    }
    for label, path in checks.items():
        error = _reject_symlink(path, label)
        if error:
            return error
    return None


def _campaign_paths(root: Path) -> dict:
    return {
        "root": str(root),
        "campaign_json": str(root / "campaign.json"),
        "scope_json": str(root / "scope.json"),
        "audit_jsonl": str(root / "audit.jsonl"),
        "recon": {name: str(root / "recon" / name) for name in RECON_SUBDIRS},
        "findings": {name: str(root / "findings" / name) for name in FINDING_SUBDIRS},
        "evidence": str(root / "evidence"),
        "imports": str(root / "imports"),
        "memory": str(root / "memory"),
        "negative_results_jsonl": str(root / "memory" / "negative_results.jsonl"),
        "reports": str(root / "reports"),
        "summary_md": str(root / "reports" / "summary.md"),
        "manual_test_plan_md": str(root / "reports" / "manual_test_plan.md"),
    }


def _create_layout(root: Path) -> str | None:
    error = _guard_core_dirs(root)
    if error:
        return error
    try:
        root.parent.mkdir(mode=0o700, exist_ok=True)
        root.mkdir(mode=0o700)
        (root / "recon").mkdir(mode=0o700)
        for name in RECON_SUBDIRS:
            (root / "recon" / name).mkdir(mode=0o700)
        for name in ("maps", "extracted", "analysis"):
            (root / "recon" / "sourcemaps" / name).mkdir(mode=0o700)
        (root / "findings").mkdir(mode=0o700)
        for name in FINDING_SUBDIRS:
            (root / "findings" / name).mkdir(mode=0o700)
        (root / "evidence").mkdir(mode=0o700)
        (root / "imports").mkdir(mode=0o700)
        (root / "memory").mkdir(mode=0o700)
        (root / "reports").mkdir(mode=0o700)
    except OSError as exc:
        return f"Could not create campaign layout: {exc}"
    return _guard_core_dirs(root)


def _unique_campaign_id(program: str, normalized_host: str) -> str:
    base = f"{slugify(program, fallback='program')}-{slugify(normalized_host, fallback='target')}-{file_timestamp().lower()}"
    base = base[:150].strip("-_") or "campaign"
    for suffix in range(1000):
        campaign_id = base if suffix == 0 else f"{base}-{suffix}"
        if not _campaign_root(campaign_id).exists():
            return campaign_id
    return f"{base}-{utc_now().strftime('%f')}"


def _write_json(path: Path, payload: dict) -> str | None:
    temp_path: Path | None = None
    try:
        encoded = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
        if len(encoded) > 2 * 1024 * 1024:
            return f"Could not write {path.name}: content exceeds 2097152 bytes."
        fd, name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
        temp_path = Path(name)
        with os.fdopen(fd, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        with open_directory(path.parent) as dirfd:
            os.replace(temp_path.name, path.name, src_dir_fd=dirfd, dst_dir_fd=dirfd)
            os.fsync(dirfd)
    except OSError as exc:
        return f"Could not write {path.name}: {exc}"
    finally:
        if temp_path and temp_path.exists():
            temp_path.unlink(missing_ok=True)
    return None


def _read_json(path: Path, maximum: int = 2 * 1024 * 1024) -> dict:
    try:
        value, _ = read_policy_json(path, maximum)
    except PolicyFileError as exc:
        raise OSError(str(exc)) from exc
    if not isinstance(value, dict):
        raise OSError("Expected a JSON object.")
    return value


def _authorize_campaign_anchor(target: str) -> tuple[str, dict]:
    url = target
    if "://" not in url:
        try:
            hostname = normalize_host(url)
            url = f"https://[{hostname}]/" if ":" in hostname else f"https://{hostname}/"
        except ValueError:
            pass
    normalized, scope_decision = require_url(url)
    if normalized.query is not None or normalized.url != normalized.redacted:
        raise AuthorizationError("Use an authorized campaign anchor without a query or sensitive values.",
                                 code="invalid_campaign_anchor")
    return normalized.url, scope_decision


@campaign_operation
def create_campaign(program: str, target: str, notes: str | None = None) -> dict:
    """Create a scoped campaign for authorized, human-led recon only."""
    try:
        anchor, scope_decision = _authorize_campaign_anchor(target)
    except AuthorizationError as exc:
        return {"ok": False, "error": str(exc), "scope_decision": exc.decision}

    normalized_host = scope_decision["normalized_url"]["hostname"]
    campaign_id = _unique_campaign_id(program, normalized_host)
    if not is_safe_campaign_id(campaign_id):
        return _safe_error("Generated unsafe campaign_id.")

    root, error = _resolve_campaign_root(campaign_id, must_exist=False)
    if error:
        return _safe_error(error)
    assert root is not None

    error = _create_layout(root)
    if error:
        return _safe_error(error)

    now = iso_now()
    metadata = {
        "campaign_id": campaign_id,
        "program": str(program or ""),
        "target": anchor,
        "normalized_host": normalized_host,
        "created_at": now,
        "updated_at": now,
        "scope_decision": scope_decision,
        "scope_binding": {"anchor": anchor, "bound_at": now, "decision": scope_decision},
        "safety_model": SAFETY_MODEL,
        "notes": [redact_structure(notes)] if notes else [],
    }
    for path, payload in ((root / "scope.json", scope_decision), (root / "campaign.json", metadata)):
        error = _write_json(path, payload)
        if error:
            return _safe_error(error)

    # Local import avoids an audit/campaign module cycle during initialization.
    from recon.audit import write_audit_event

    write_audit_event(campaign_id, "create_campaign", target=anchor, ok=True, scope_decision=scope_decision, result_path=str(root / "campaign.json"), metadata={"program": str(program or "")})

    return {"ok": True, "campaign_id": campaign_id, "path": str(root), "scope_decision": scope_decision}


@campaign_operation
def reauthorize_campaign(campaign_id: str, target: str, confirm_fingerprint: str) -> dict:
    """Bind an existing campaign to a manually reviewed policy from the local CLI."""
    current = get_campaign(campaign_id)
    if not current.get("ok"):
        return current
    try:
        anchor, scope_decision = _authorize_campaign_anchor(target)
    except AuthorizationError as exc:
        return {"ok": False, "error": str(exc), "scope_decision": exc.decision}
    if confirm_fingerprint != scope_decision["policy_fingerprint"]:
        return _safe_error("Confirmation must match the current full policy fingerprint.")
    metadata = current["campaign"]
    if metadata.get("status") == "archived":
        return _safe_error("Campaign archival is pending or complete.")
    if metadata.get("normalized_host") != scope_decision["normalized_url"]["hostname"]:
        return _safe_error("Anchor must use the campaign's original normalized hostname.")
    now = iso_now()
    previous = metadata.get("scope_binding")
    previous_decision = previous.get("decision") if isinstance(previous, dict) else None
    previous_fingerprint = previous_decision.get("policy_fingerprint") if isinstance(previous_decision, dict) else None
    metadata["scope_binding"] = {"anchor": anchor, "bound_at": now, "decision": scope_decision}
    metadata["updated_at"] = now

    from recon.audit import write_audit_event

    audit = write_audit_event(campaign_id, "reauthorize_campaign", target=anchor, scope_decision=scope_decision,
                              metadata={"previous_policy_fingerprint": previous_fingerprint})
    if not audit.get("ok"):
        return _safe_error("Could not append the campaign policy review to its audit log.")
    error = _write_json(_campaign_root(campaign_id) / "campaign.json", metadata)
    if error:
        write_audit_event(campaign_id, "reauthorize_campaign_write_failed", target=anchor, ok=False,
                          scope_decision=scope_decision)
        return _safe_error(error)
    return {"ok": True, "campaign_id": campaign_id, "scope_decision": scope_decision}


@campaign_operation
def list_campaigns(limit: int = 50) -> dict:
    """List stored campaigns without following unsafe campaign IDs."""
    try:
        CAMPAIGNS_DIR.mkdir(mode=0o700, exist_ok=True)
    except OSError as exc:
        return _safe_error(f"Could not create campaign storage: {exc}")

    campaigns = []
    for path in CAMPAIGNS_DIR.iterdir():
        if not path.is_dir() or not is_safe_campaign_id(path.name) or path.is_symlink():
            continue
        metadata_path = path / "campaign.json"
        if not metadata_path.exists():
            continue
        try:
            check_campaign_directory(path)
            metadata = _read_json(metadata_path)
        except (OSError, json.JSONDecodeError):
            continue
        campaigns.append(metadata)

    campaigns.sort(key=lambda item: item.get("updated_at") or item.get("created_at") or "", reverse=True)
    safe_limit = max(1, min(int(limit or 50), 500))
    return {"ok": True, "campaigns": campaigns[:safe_limit], "count": min(len(campaigns), safe_limit)}


@campaign_operation
def get_campaign(campaign_id: str) -> dict:
    """Load campaign metadata for authorized, human-led recon only."""
    root, error = _resolve_campaign_root(campaign_id)
    if error:
        return _safe_error(error)
    assert root is not None
    error = _guard_core_dirs(root)
    if error:
        return _safe_error(error)
    try:
        metadata = _read_json(root / "campaign.json")
    except FileNotFoundError:
        return _safe_error("Campaign metadata not found.")
    except (OSError, json.JSONDecodeError) as exc:
        return _safe_error(f"Could not load campaign metadata: {exc}")
    return {"ok": True, "campaign": metadata, "path": str(root)}


def get_campaign_paths(campaign_id: str) -> dict:
    """Resolve paths without retaining the lock across the caller's work.

    Production callers hold campaign_storage_lock for the operation using these
    paths. Standalone callers receive a snapshot that can become stale.
    """
    root, error = _resolve_campaign_root(campaign_id)
    if error:
        return _safe_error(error)
    assert root is not None
    error = _guard_core_dirs(root)
    if error:
        return _safe_error(error)
    return {"ok": True, "campaign_id": campaign_id, "paths": _campaign_paths(root)}


@campaign_operation
def archive_campaign(campaign_id: str, reason: str | None = None) -> dict:
    """Move a campaign into archived_campaigns instead of deleting it."""
    if ARCHIVED_CAMPAIGNS_DIR.parent.absolute() != CAMPAIGNS_DIR.parent.absolute():
        return _safe_error("Active and archived campaigns must share a storage root.")
    source_root, error = _resolve_campaign_root(campaign_id)
    if error:
        return _safe_error(error)
    assert source_root is not None
    if source_root.is_symlink():
        return _safe_error("Campaign root must not be a symlink.")
    error = _guard_core_dirs(source_root)
    if error:
        return _safe_error(error)

    try:
        ARCHIVED_CAMPAIGNS_DIR.mkdir(mode=0o700, exist_ok=True)
    except OSError as exc:
        return _safe_error(f"Could not create archived campaign storage: {exc}")

    archive_root, error = _resolve_archived_campaign_root(campaign_id, must_exist=False)
    if error:
        return _safe_error(error)
    assert archive_root is not None
    if archive_root.exists():
        return _safe_error("Archived campaign destination already exists; refusing to overwrite.")
    if ARCHIVED_CAMPAIGNS_DIR.exists() and ARCHIVED_CAMPAIGNS_DIR.is_symlink():
        return _safe_error("Archived campaign storage must not be a symlink.")

    metadata_path = source_root / "campaign.json"
    try:
        metadata = _read_json(metadata_path)
    except FileNotFoundError:
        return _safe_error("Campaign metadata not found.")
    except (OSError, json.JSONDecodeError) as exc:
        return _safe_error(f"Could not load campaign metadata: {exc}")

    now = iso_now()
    archive_reason = reason or "Archived by user request."
    original = dict(metadata)
    metadata["archived_at"] = now
    metadata["archive_reason"] = archive_reason
    metadata["updated_at"] = now
    metadata["status"] = "archived"
    error = _write_json(metadata_path, metadata)
    if error:
        return _safe_error(error)

    try:
        # rename fails on cross-mount moves instead of starting a partial copy.
        source_root.rename(archive_root)
    except OSError:
        restore_error = _write_json(metadata_path, original)
        if restore_error:
            return _safe_error("Could not archive campaign or restore metadata. Retry archival after checking storage.")
        return _safe_error("Could not archive campaign. Check destination permissions and storage mount.")

    try:
        with open_directory(source_root.parent) as source, open_directory(archive_root.parent) as destination:
            os.fsync(source)
            os.fsync(destination)
    except OSError:
        return _safe_error("Campaign moved, but archive durability could not be verified.")
    return {"ok": True, "campaign_id": campaign_id, "archived_path": str(archive_root), "reason": archive_reason}


@campaign_operation
def list_archived_campaigns(limit: int = 50) -> dict:
    """List archived campaigns."""
    if ARCHIVED_CAMPAIGNS_DIR.parent.absolute() != CAMPAIGNS_DIR.parent.absolute():
        return _safe_error("Active and archived campaigns must share a storage root.")
    try:
        ARCHIVED_CAMPAIGNS_DIR.mkdir(mode=0o700, exist_ok=True)
    except OSError as exc:
        return _safe_error(f"Could not create archived campaign storage: {exc}")
    if ARCHIVED_CAMPAIGNS_DIR.is_symlink():
        return _safe_error("Archived campaign storage must not be a symlink.")

    campaigns = []
    for path in ARCHIVED_CAMPAIGNS_DIR.iterdir():
        if not path.is_dir() or not is_safe_campaign_id(path.name) or path.is_symlink():
            continue
        metadata_path = path / "campaign.json"
        if not metadata_path.exists():
            continue
        try:
            check_campaign_directory(path)
            metadata = _read_json(metadata_path)
        except (OSError, json.JSONDecodeError):
            continue
        campaigns.append(metadata)

    campaigns.sort(key=lambda item: item.get("archived_at") or item.get("updated_at") or "", reverse=True)
    safe_limit = max(1, min(int(limit or 50), 500))
    return {"ok": True, "campaigns": campaigns[:safe_limit], "count": min(len(campaigns), safe_limit)}


@campaign_operation
def get_archived_campaign(campaign_id: str) -> dict:
    """Read archived campaign metadata."""
    if ARCHIVED_CAMPAIGNS_DIR.parent.absolute() != CAMPAIGNS_DIR.parent.absolute():
        return _safe_error("Active and archived campaigns must share a storage root.")
    root, error = _resolve_archived_campaign_root(campaign_id)
    if error:
        return _safe_error(error)
    assert root is not None
    if root.is_symlink():
        return _safe_error("Archived campaign root must not be a symlink.")
    error = _guard_core_dirs(root)
    if error:
        return _safe_error(error)
    try:
        metadata = _read_json(root / "campaign.json")
    except FileNotFoundError:
        return _safe_error("Archived campaign metadata not found.")
    except (OSError, json.JSONDecodeError) as exc:
        return _safe_error(f"Could not load archived campaign metadata: {exc}")
    return {"ok": True, "campaign": metadata, "path": str(root)}


@campaign_operation
def delete_archived_campaign(campaign_id: str, confirm_campaign_id: str) -> dict:
    """Permanently delete an archived campaign only when confirmation matches."""
    if ARCHIVED_CAMPAIGNS_DIR.parent.absolute() != CAMPAIGNS_DIR.parent.absolute():
        return _safe_error("Active and archived campaigns must share a storage root.")
    if confirm_campaign_id != campaign_id:
        return _safe_error("Confirmation campaign_id does not match; archived campaign was not deleted.")
    root, error = _resolve_archived_campaign_root(campaign_id)
    if error:
        return _safe_error(error)
    assert root is not None
    if root.is_symlink():
        return _safe_error("Archived campaign root must not be a symlink.")
    error = _guard_core_dirs(root)
    if error:
        return _safe_error(error)

    try:
        shutil.rmtree(root)
    except OSError as exc:
        return _safe_error(f"Could not delete archived campaign: {exc}")
    return {
        "ok": True,
        "campaign_id": campaign_id,
        "deleted": True,
        "warning": "Archived campaign was permanently deleted from local disk.",
    }
