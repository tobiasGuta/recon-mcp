"""Scope loading and enforcement for safe recon tools."""

from __future__ import annotations

import ipaddress
import json
from pathlib import Path
from urllib.parse import urlparse

from recon.h1_scope import H1ScopeError, extract_allowed_hosts_from_h1_entries, load_h1_snapshots


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SCOPE_PATH = PROJECT_ROOT / "config" / "scope.json"
DEFAULT_USER_AGENT = "ReconMCP/0.1"
DEFAULT_REQUEST_DELAY_MS = 500
DEFAULT_MAX_REQUESTS_PER_TOOL_CALL = 20
DEFAULT_FETCH_HEADERS_METHOD = "HEAD"


class ScopeError(ValueError):
    """Raised when a target is not allowed by the configured scope."""


def load_scope() -> dict:
    """Load the configured scope file as a JSON-compatible dictionary."""
    try:
        with DEFAULT_SCOPE_PATH.open("r", encoding="utf-8") as scope_file:
            data = json.load(scope_file)
    except FileNotFoundError:
        return {
            "scope_source": "manual",
            "allowed_domains": [],
            "blocked_domains": [],
            "user_agent": DEFAULT_USER_AGENT,
            "request_delay_ms": DEFAULT_REQUEST_DELAY_MS,
            "max_requests_per_tool_call": DEFAULT_MAX_REQUESTS_PER_TOOL_CALL,
            "fetch_headers_method": DEFAULT_FETCH_HEADERS_METHOD,
        }
    except json.JSONDecodeError as exc:
        raise ScopeError(f"Invalid scope config: {exc}") from exc

    return {
        "scope_source": data.get("scope_source", "manual"),
        "h1_snapshot_dir": data.get("h1_snapshot_dir", ""),
        "include_only_bounty_eligible": bool(data.get("include_only_bounty_eligible", False)),
        "include_only_submission_eligible": bool(data.get("include_only_submission_eligible", False)),
        "allowed_domains": data.get("allowed_domains", []),
        "blocked_domains": data.get("blocked_domains", []),
        "user_agent": str(data.get("user_agent") or DEFAULT_USER_AGENT),
        "request_delay_ms": int(data.get("request_delay_ms", DEFAULT_REQUEST_DELAY_MS)),
        "max_requests_per_tool_call": int(data.get("max_requests_per_tool_call", DEFAULT_MAX_REQUESTS_PER_TOOL_CALL)),
        "fetch_headers_method": str(data.get("fetch_headers_method") or DEFAULT_FETCH_HEADERS_METHOD).upper(),
    }


def normalize_domain(value: str) -> str:
    """Normalize a domain or URL to a lowercase hostname."""
    raw = (value or "").strip()
    if not raw:
        return ""

    parsed = urlparse(raw if "://" in raw else f"//{raw}", scheme="https")
    host = parsed.hostname or raw
    return host.strip().rstrip(".").lower()


def is_private_or_loopback_host(host: str) -> bool:
    """Return True when a host is a private, loopback, or link-local IP."""
    normalized = normalize_domain(host)
    if normalized == "localhost" or normalized.endswith(".localhost"):
        return True

    try:
        ip = ipaddress.ip_address(normalized)
    except ValueError:
        return False

    return bool(
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def is_blocked_domain(domain: str) -> bool:
    """Return True when a domain is blocked by config or IP safety rules."""
    normalized = normalize_domain(domain)
    scope = load_scope()
    blocked_domains = [normalize_domain(item) for item in scope.get("blocked_domains", [])]

    if is_private_or_loopback_host(normalized):
        return True

    return any(normalized == blocked or normalized.endswith(f".{blocked}") for blocked in blocked_domains)


def _matches_allowed_domain(domain: str, allowed_domain: str) -> bool:
    """Return True for exact or subdomain matches."""
    return domain == allowed_domain or domain.endswith(f".{allowed_domain}")


def _matches_allowed_host_rule(domain: str, host_rule: dict) -> bool:
    """Return True when a domain matches an allowed host rule."""
    host = normalize_domain(str(host_rule.get("host") or ""))
    if not host:
        return False
    if host_rule.get("wildcard"):
        return domain != host and domain.endswith(f".{host}")
    return _matches_allowed_domain(domain, host)


def _check_manual_scope(domain: str, normalized: str, scope: dict) -> dict:
    """Check a target against manually configured allowed domains."""
    allowed_domains = [normalize_domain(item) for item in scope.get("allowed_domains", [])]
    allowed_domains = [item for item in allowed_domains if item]
    if not allowed_domains:
        return {
            "ok": False,
            "input": domain,
            "domain": normalized,
            "target": normalized,
            "in_scope": False,
            "scope_source": "manual",
            "reason": "Manual scope has no allowed domains configured; failing closed.",
        }

    matched = next((item for item in allowed_domains if _matches_allowed_domain(normalized, item)), None)

    if matched:
        return {
            "ok": True,
            "input": domain,
            "domain": normalized,
            "target": normalized,
            "in_scope": True,
            "matched_scope": matched,
            "scope_source": "manual",
            "reason": "Target matches configured allowed scope.",
        }

    return {
        "ok": True,
        "input": domain,
        "domain": normalized,
        "target": normalized,
        "in_scope": False,
        "scope_source": "manual",
        "reason": "Target does not match configured allowed scope.",
    }


def _load_h1_allowed_scope(scope: dict) -> dict:
    """Load and parse H1 snapshot scope from local files."""
    entries = load_h1_snapshots(str(scope.get("h1_snapshot_dir") or ""))
    extracted = extract_allowed_hosts_from_h1_entries(
        entries,
        include_only_bounty_eligible=bool(scope.get("include_only_bounty_eligible", False)),
        include_only_submission_eligible=bool(scope.get("include_only_submission_eligible", False)),
        blocked_domains=scope.get("blocked_domains", []),
    )
    return {"entries": entries, **extracted}


def _check_h1_scope(domain: str, normalized: str, scope: dict) -> dict:
    """Check a target against H1-Scope-Watcher snapshot scope."""
    try:
        loaded = _load_h1_allowed_scope(scope)
    except H1ScopeError as exc:
        return {
            "ok": False,
            "input": domain,
            "domain": normalized,
            "target": normalized,
            "in_scope": False,
            "scope_source": "h1_snapshots",
            "reason": str(exc),
        }

    allowed_hosts = loaded.get("allowed_hosts", [])
    if not allowed_hosts:
        return {
            "ok": False,
            "input": domain,
            "domain": normalized,
            "target": normalized,
            "in_scope": False,
            "scope_source": "h1_snapshots",
            "reason": "H1 snapshot scope produced no allowed hosts; failing closed.",
        }

    for item in allowed_hosts:
        host = item.get("host", "")
        if _matches_allowed_host_rule(normalized, item):
            return {
                "ok": True,
                "input": domain,
                "domain": normalized,
                "target": normalized,
                "in_scope": True,
                "matched_scope": host,
                "scope_source": "h1_snapshots",
                "program_handle": item.get("program_handle"),
                "asset_type": item.get("asset_type"),
                "eligible_for_bounty": item.get("eligible_for_bounty"),
                "eligible_for_submission": item.get("eligible_for_submission"),
                "max_severity": item.get("max_severity"),
                "reason": "Target matches local H1 snapshot scope.",
            }

    return {
        "ok": True,
        "input": domain,
        "domain": normalized,
        "target": normalized,
        "in_scope": False,
        "scope_source": "h1_snapshots",
        "reason": "No matching H1 scope entry found.",
    }


def check_scope(domain: str) -> dict:
    """Check whether a domain or URL is inside the configured scope."""
    normalized = normalize_domain(domain)
    scope = load_scope()
    scope_source = scope.get("scope_source", "manual")

    if not normalized:
        return {
            "ok": False,
            "input": domain,
            "domain": normalized,
            "target": normalized,
            "in_scope": False,
            "scope_source": scope_source,
            "reason": "No domain or host was provided.",
        }

    if is_blocked_domain(normalized):
        return {
            "ok": True,
            "input": domain,
            "domain": normalized,
            "target": normalized,
            "in_scope": False,
            "scope_source": scope_source,
            "reason": "Target is blocked by safety rules or blocked_domains.",
        }

    if scope_source == "h1_snapshots":
        return _check_h1_scope(domain, normalized, scope)
    if scope_source == "manual":
        return _check_manual_scope(domain, normalized, scope)

    return {
        "ok": False,
        "input": domain,
        "domain": normalized,
        "target": normalized,
        "in_scope": False,
        "scope_source": scope_source,
        "reason": f"Unsupported scope_source: {scope_source}",
    }


def list_loaded_scope() -> dict:
    """Return a safe summary of currently loaded scope."""
    try:
        scope = load_scope()
    except ScopeError as exc:
        return {
            "ok": False,
            "scope_source": "unknown",
            "warnings": [str(exc)],
        }

    scope_source = scope.get("scope_source", "manual")
    if scope_source == "manual":
        allowed_domains = [normalize_domain(item) for item in scope.get("allowed_domains", []) if normalize_domain(item)]
        if not allowed_domains:
            return {
                "ok": False,
                "scope_source": "manual",
                "snapshot_directory": None,
                "json_files_loaded": 0,
                "scope_entries_parsed": 0,
                "allowed_hosts_count": 0,
                "program_handles": [],
                "allowed_hosts": [],
                "warnings": ["Manual scope has no allowed domains configured; failing closed."],
            }
        return {
            "ok": True,
            "scope_source": "manual",
            "snapshot_directory": None,
            "json_files_loaded": 0,
            "scope_entries_parsed": 0,
            "allowed_hosts_count": len(allowed_domains),
            "program_handles": [],
            "allowed_hosts": sorted(set(allowed_domains)),
            "warnings": [],
        }

    if scope_source != "h1_snapshots":
        return {
            "ok": False,
            "scope_source": scope_source,
            "snapshot_directory": scope.get("h1_snapshot_dir"),
            "warnings": [f"Unsupported scope_source: {scope_source}"],
        }

    try:
        loaded = _load_h1_allowed_scope(scope)
    except H1ScopeError as exc:
        return {
            "ok": False,
            "scope_source": "h1_snapshots",
            "snapshot_directory": scope.get("h1_snapshot_dir"),
            "json_files_loaded": 0,
            "scope_entries_parsed": 0,
            "allowed_hosts_count": 0,
            "program_handles": [],
            "allowed_hosts": [],
            "warnings": [str(exc)],
        }

    entries = loaded.get("entries", [])
    allowed_hosts = loaded.get("allowed_hosts", [])
    source_files = {entry.get("_source_file") for entry in entries if entry.get("_source_file")}
    program_handles = {entry.get("_program_handle") for entry in entries if entry.get("_program_handle")}

    return {
        "ok": True,
        "scope_source": "h1_snapshots",
        "snapshot_directory": scope.get("h1_snapshot_dir"),
        "json_files_loaded": len(source_files),
        "scope_entries_parsed": len(entries),
        "allowed_hosts_count": len(allowed_hosts),
        "program_handles": sorted(program_handles),
        "allowed_hosts": sorted({item.get("host") for item in allowed_hosts if item.get("host")}),
        "warnings": loaded.get("warnings", []),
    }


def assert_in_scope(url_or_domain: str) -> None:
    """Raise ScopeError if a URL or domain is outside the configured scope."""
    result = check_scope(url_or_domain)
    if not result.get("in_scope"):
        raise ScopeError(result.get("reason", "Target is out of scope."))
