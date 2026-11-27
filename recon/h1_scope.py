"""Local H1-Scope-Watcher snapshot parsing helpers."""

from __future__ import annotations

import ipaddress
import os
import re
import time
from pathlib import Path
from urllib.parse import urlparse

import idna

from recon.policy_io import PolicyFileError, read_policy_json, reject_path_links
from recon.redaction import redact_url


class H1ScopeError(ValueError):
    """Raised when H1 snapshot scope cannot be loaded safely."""


class H1ProgramSelectionError(H1ScopeError):
    code = "h1_program_selection_required"


def _normalise_host(value: str) -> str:
    """Normalize a URL-like value to a lowercase hostname."""
    raw = (value or "").strip()
    if not raw:
        return ""

    wildcard = raw.startswith("*.")
    candidate = raw[2:] if wildcard else raw
    try:
        parsed = urlparse(candidate if "://" in candidate else f"//{candidate}", scheme="https")
        host = (parsed.hostname or candidate).strip().rstrip(".").lower()
    except ValueError:
        return ""
    try:
        host = idna.encode(host, uts46=True, std3_rules=True).decode("ascii")
    except (UnicodeError, idna.IDNAError):
        pass
    return f"*.{host}" if wildcard and host else host


def _is_private_or_loopback_host(host: str) -> bool:
    """Return True when a host is an unsafe local/private IP."""
    normalized = host[2:] if host.startswith("*.") else host
    try:
        ip = ipaddress.ip_address(normalized)
    except ValueError:
        return normalized == "localhost" or normalized.endswith(".localhost")

    return bool(
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def _snapshot_paths(directory: Path, program: str | None) -> list[Path]:
    if program is not None:
        if not isinstance(program, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", program):
            raise H1ScopeError("h1_snapshot_program must be a program handle without path separators or an extension.")
        return [directory / (program + ".json")]

    paths = []
    for index, path in enumerate(directory.iterdir()):
        if index >= 512:
            raise H1ScopeError("H1 snapshot directory exceeds 512 entries.")
        if path.suffix.lower() == ".json":
            paths.append(path)
            if len(paths) > 64:
                raise H1ScopeError("H1 snapshot directory exceeds 64 JSON files.")
    return sorted(paths)


def load_h1_snapshots(snapshot_dir: str, *, max_age: int | None = None,
                      program: str | None = None, require_single_program: bool = False) -> list[dict]:
    """Read a bounded, stable view of the local snapshot directory."""
    if not snapshot_dir:
        raise H1ScopeError("H1 snapshot directory does not exist.")
    path = Path(snapshot_dir).expanduser().absolute()
    if os.name == "nt" and path.anchor.startswith("\\\\"):
        raise H1ScopeError("Snapshots must be on a local drive.")
    entries: list[dict] = []
    observed = {}
    remaining = 20 * 1024 * 1024
    try:
        if os.name == "nt":
            reject_path_links(path)
        if not path.is_dir() or path.is_symlink():
            raise H1ScopeError("H1 snapshot directory does not exist or is a symlink.")
        files = _snapshot_paths(path, program)
        if require_single_program and len(files) > 1:
            raise H1ProgramSelectionError("Multiple H1 snapshots found. Select one with h1_snapshot_program.")
        for json_file in files:
            raw_data, info = read_policy_json(json_file, min(remaining, 10 * 1024 * 1024))
            remaining -= info.st_size
            observed[json_file.name] = (info.st_dev, info.st_ino, info.st_mtime_ns, info.st_ctime_ns, info.st_size)
            if max_age is not None and not 0 <= time.time() - info.st_mtime <= max_age:
                raise H1ScopeError("H1 snapshot timestamp is stale or in the future.")
            if not isinstance(raw_data, list) or any(not isinstance(item, dict) for item in raw_data):
                raise H1ScopeError("H1 snapshot must contain a list of scope-entry objects.")
            if len(entries) + len(raw_data) > 5000:
                raise H1ScopeError("H1 snapshots exceed 5000 scope entries.")
            entries.extend(
                {**item, "_source_file": str(json_file), "_program_handle": json_file.stem}
                for item in raw_data
            )
        current = {}
        for json_file in _snapshot_paths(path, program):
            if json_file.name not in observed:
                raise H1ScopeError("H1 snapshot directory changed while loading.")
            info = json_file.lstat()
            current[json_file.name] = (info.st_dev, info.st_ino, info.st_mtime_ns, info.st_ctime_ns, info.st_size)
        if current != observed:
            raise H1ScopeError("H1 snapshot directory changed while loading.")
    except (OSError, PolicyFileError) as exc:
        detail = str(exc) if isinstance(exc, PolicyFileError) else "Could not safely read H1 snapshots."
        raise H1ScopeError(detail) from exc
    if not entries:
        raise H1ScopeError("H1 snapshots contained no usable scope entries.")
    return sorted(entries, key=lambda entry: entry["_source_file"])


def normalise_h1_asset_identifier(asset_identifier: str) -> list[str]:
    """Normalize an H1 asset identifier into one or more host rules."""
    host = _normalise_host(asset_identifier)
    if not host or _is_private_or_loopback_host(host):
        return []
    return [host]


def _is_blocked(host: str, blocked_domains: list[str]) -> bool:
    """Return True when a host matches configured blocked domains."""
    normalized = host[2:] if host.startswith("*.") else host
    blocked = [_normalise_host(item) for item in blocked_domains]
    return any(normalized == item or normalized.endswith(f".{item}") for item in blocked if item)


def extract_allowed_hosts_from_h1_entries(
    entries: list[dict],
    include_only_bounty_eligible: bool,
    include_only_submission_eligible: bool,
    blocked_domains: list[str] | None = None,
) -> dict:
    """Extract allowed host metadata from H1 structured scope entries."""
    allowed_hosts = []
    warnings = []
    blocked_domains = blocked_domains or []

    for entry in entries:
        if include_only_submission_eligible and entry.get("eligible_for_submission") is not True:
            continue
        if include_only_bounty_eligible and entry.get("eligible_for_bounty") is not True:
            continue

        asset_identifier = str(entry.get("asset_identifier") or "")
        hosts = normalise_h1_asset_identifier(asset_identifier)
        if not hosts and asset_identifier:
            warnings.append("Skipped a malformed or unsafe asset identifier.")

        for host_rule in hosts:
            if _is_blocked(host_rule, blocked_domains):
                warnings.append("Skipped a blocked asset identifier.")
                continue

            is_wildcard = host_rule.startswith("*.")
            host = host_rule[2:] if is_wildcard else host_rule
            allowed_hosts.append(
                {
                    "host": host,
                    "rule": host_rule,
                    "allow_subdomains": True,
                    "wildcard": is_wildcard,
                    "source_file": entry.get("_source_file"),
                    "program_handle": entry.get("_program_handle"),
                    "asset_type": entry.get("asset_type"),
                    "original_asset_identifier": redact_url(asset_identifier, redact_all_query_values=True),
                    "eligible_for_bounty": entry.get("eligible_for_bounty"),
                    "eligible_for_submission": entry.get("eligible_for_submission"),
                    "max_severity": entry.get("max_severity"),
                    "instruction": entry.get("instruction"),
                }
            )

    return {
        "ok": True,
        "allowed_hosts": allowed_hosts,
        "allowed_count": len(allowed_hosts),
        "warnings": warnings,
    }
