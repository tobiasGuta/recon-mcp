"""Local H1-Scope-Watcher snapshot parsing helpers."""

from __future__ import annotations

import ipaddress
import json
from pathlib import Path
from urllib.parse import urlparse


class H1ScopeError(ValueError):
    """Raised when H1 snapshot scope cannot be loaded safely."""


def _normalise_host(value: str) -> str:
    """Normalize a URL-like value to a lowercase hostname."""
    raw = (value or "").strip()
    if not raw:
        return ""

    wildcard = raw.startswith("*.")
    candidate = raw[2:] if wildcard else raw
    parsed = urlparse(candidate if "://" in candidate else f"//{candidate}", scheme="https")
    host = (parsed.hostname or candidate).strip().rstrip(".").lower()
    return f"*.{host}" if wildcard and host else host


def _is_private_or_loopback_host(host: str) -> bool:
    """Return True when a host is an unsafe local/private IP."""
    normalized = host[2:] if host.startswith("*.") else host
    try:
        ip = ipaddress.ip_address(normalized)
    except ValueError:
        return normalized in {"localhost"}

    return bool(
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def load_h1_snapshots(snapshot_dir: str) -> list[dict]:
    """Load local JSON snapshot files created by H1-Scope-Watcher."""
    try:
        path = Path(snapshot_dir).expanduser()
        if not path.exists() or not path.is_dir():
            raise H1ScopeError(f"H1 snapshot directory does not exist: {snapshot_dir}")

        json_files = sorted(path.glob("*.json"))
    except OSError as exc:
        raise H1ScopeError(f"H1 snapshot directory is not readable: {snapshot_dir}: {exc}") from exc

    if not json_files:
        raise H1ScopeError(f"No H1 snapshot JSON files found in: {snapshot_dir}")

    entries: list[dict] = []
    for json_file in json_files:
        try:
            raw_data = json.loads(json_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise H1ScopeError(f"Could not load H1 snapshot {json_file}: {exc}") from exc

        if not isinstance(raw_data, list):
            raise H1ScopeError(f"H1 snapshot must contain a list of scope entries: {json_file}")

        for item in raw_data:
            if not isinstance(item, dict):
                continue
            entry = dict(item)
            entry["_source_file"] = str(json_file)
            entry["_program_handle"] = json_file.stem
            entries.append(entry)

    if not entries:
        raise H1ScopeError(f"H1 snapshots contained no usable scope entries: {snapshot_dir}")

    return entries


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
            warnings.append(f"Skipped malformed or unsafe asset identifier: {asset_identifier}")

        for host_rule in hosts:
            if _is_blocked(host_rule, blocked_domains):
                warnings.append(f"Skipped blocked asset identifier: {asset_identifier}")
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
                    "original_asset_identifier": entry.get("asset_identifier"),
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
