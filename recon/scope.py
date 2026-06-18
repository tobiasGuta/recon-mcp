"""Scope loading and enforcement for safe recon tools."""

from __future__ import annotations

import ipaddress
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from recon.h1_scope import H1ScopeError, extract_allowed_hosts_from_h1_entries, load_h1_snapshots


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SCOPE_PATH = PROJECT_ROOT / "config" / "scope.json"
DEFAULT_USER_AGENT = "ReconMCP/0.1"
DEFAULT_REQUEST_DELAY_MS = 500
DEFAULT_MAX_REQUESTS_PER_TOOL_CALL = 20
DEFAULT_FETCH_HEADERS_METHOD = "HEAD"
MAX_BATCH_SIZE = 200
SCOPE_CACHE_TTL_SECONDS = 30.0
SUPPORTED_HOST_ASSET_TYPES = {"", "url", "domain", "wildcard", "api"}
_scope_cache: dict | None = None
_scope_cache_time = 0.0


class ScopeError(ValueError):
    """Raised when a target is not allowed by the configured scope."""


def load_scope() -> dict:
    """Load the configured scope file as a JSON-compatible dictionary."""
    global _scope_cache, _scope_cache_time

    now = time.monotonic()
    if _scope_cache is not None and now - _scope_cache_time < SCOPE_CACHE_TTL_SECONDS:
        return _scope_cache

    try:
        with DEFAULT_SCOPE_PATH.open("r", encoding="utf-8") as scope_file:
            data = json.load(scope_file)
    except FileNotFoundError:
        result = {
            "scope_source": "manual",
            "allowed_domains": [],
            "blocked_domains": [],
            "user_agent": DEFAULT_USER_AGENT,
            "request_delay_ms": DEFAULT_REQUEST_DELAY_MS,
            "max_requests_per_tool_call": DEFAULT_MAX_REQUESTS_PER_TOOL_CALL,
            "fetch_headers_method": DEFAULT_FETCH_HEADERS_METHOD,
        }
        _scope_cache = result
        _scope_cache_time = now
        return result
    except json.JSONDecodeError as exc:
        raise ScopeError(f"Invalid scope config: {exc}") from exc

    result = {
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
    _scope_cache = result
    _scope_cache_time = now
    return result


def _invalidate_scope_cache() -> None:
    """Clear cached scope config; intended for tests and config reload workflows."""
    global _scope_cache, _scope_cache_time
    _scope_cache = None
    _scope_cache_time = 0.0


def normalize_domain(value: str) -> str:
    """Normalize a domain or URL to a lowercase hostname."""
    raw = (value or "").strip()
    if not raw:
        return ""

    lowered = raw.lower()
    if lowered.startswith("host:"):
        raw = raw.split(":", 1)[1].strip()
    elif lowered.startswith(":authority:"):
        raw = raw.split(":authority:", 1)[-1].strip()

    parsed = urlparse(raw if "://" in raw else f"//{raw}", scheme="https")
    host = parsed.hostname or raw
    host = host.strip().strip("[]").rstrip(".").lower()
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError:
        return host


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


def is_blocked_domain(domain: str, scope: dict | None = None) -> bool:
    """Return True when a domain is blocked by config or IP safety rules."""
    normalized = normalize_domain(domain)
    scope = scope or load_scope()
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


def _iso_from_timestamp(timestamp: float) -> str:
    """Return a stable UTC ISO timestamp from a filesystem timestamp."""
    return datetime.fromtimestamp(timestamp, timezone.utc).isoformat()


def _scope_metadata(scope: dict, loaded: dict | None = None) -> dict:
    """Build response metadata for the current scope snapshot/config."""
    loaded = loaded or {}
    entries = loaded.get("entries", [])
    source_files = sorted({entry.get("_source_file") for entry in entries if entry.get("_source_file")})
    generated_at = None
    for source_file in source_files:
        try:
            modified_at = Path(source_file).stat().st_mtime
        except OSError:
            continue
        generated_at = max(generated_at or modified_at, modified_at)

    return {
        "snapshot_directory": scope.get("h1_snapshot_dir") if scope.get("scope_source") == "h1_snapshots" else None,
        "source_files": source_files,
        "source_file": source_files[0] if len(source_files) == 1 else None,
        "loaded_at": datetime.now(timezone.utc).isoformat(),
        "generated_at": _iso_from_timestamp(generated_at) if generated_at else None,
        "total_assets_loaded": len(entries),
        "warnings": loaded.get("warnings", []),
    }


def _with_metadata(result: dict, scope: dict, loaded: dict | None = None) -> dict:
    """Attach snapshot metadata both top-level and under scope_metadata."""
    metadata = _scope_metadata(scope, loaded)
    result["scope_metadata"] = metadata
    result.setdefault("snapshot_directory", metadata["snapshot_directory"])
    result.setdefault("source_file", metadata["source_file"])
    result.setdefault("loaded_at", metadata["loaded_at"])
    result.setdefault("generated_at", metadata["generated_at"])
    result.setdefault("total_assets_loaded", metadata["total_assets_loaded"])
    result.setdefault("warnings", metadata["warnings"])
    return result


def _asset_type_supported(asset_type: object) -> bool:
    """Return True when a scope entry describes a host-like asset."""
    normalized = str(asset_type or "").strip().lower()
    return normalized in SUPPORTED_HOST_ASSET_TYPES


def _host_rule_match_type(normalized: str, item: dict) -> str | None:
    """Return the match type for a normalized host against one host rule."""
    host = item.get("host", "")
    if item.get("wildcard"):
        if normalized != host and normalized.endswith(f".{host}"):
            return "wildcard"
        return None
    if normalized == host:
        return "exact"
    if normalized.endswith(f".{host}"):
        return "parent_domain"
    return None


def _rank_match(match_type: str, item: dict) -> tuple[int, int]:
    """Rank scope matches so exact assets win before wildcard and fallback parents."""
    match_rank = {"exact": 0, "wildcard": 1, "parent_domain": 2}.get(match_type, 9)
    host_depth = len(str(item.get("host") or "").split("."))
    return (match_rank, -host_depth)


def _reason_code_for_decision(decision: dict) -> str:
    """Return a stable reason code for a scope decision."""
    if not decision.get("in_scope"):
        return decision.get("reason_code") or "no_matching_asset"
    if not decision.get("submission_eligible"):
        return "in_scope_not_submission_eligible"
    if not decision.get("bounty_eligible"):
        return "in_scope_not_bounty_eligible"
    if decision.get("match_type") == "wildcard":
        return "wildcard_scope_match"
    return "in_scope_bounty_eligible"


def _interop_payload(decision: dict) -> dict:
    """Return stable keys for other local MCP servers."""
    scope_ok = bool(decision.get("in_scope") and decision.get("submission_eligible"))
    can_scan = bool(scope_ok and decision.get("bounty_eligible"))
    risk_warning = "; ".join(decision.get("warnings") or []) or None
    if decision.get("in_scope") and not decision.get("bounty_eligible"):
        risk_warning = risk_warning or "In scope, but not bounty eligible."
    if not decision.get("in_scope"):
        risk_warning = risk_warning or decision.get("reason")

    return {
        "normalized_host": decision.get("normalized_host"),
        "scope_ok": scope_ok,
        "can_test": scope_ok,
        "can_scan": can_scan,
        "can_store_evidence": scope_ok,
        "recommended_bugmap_target_label": decision.get("suggested_target_label"),
        "risk_warning": risk_warning,
    }


def _decision_from_host_rule(input_value: str, normalized: str, item: dict, match_type: str, scope: dict, loaded: dict) -> dict:
    """Create a rich scope decision from a matched host rule."""
    exact_asset = item.get("original_asset_identifier") if match_type == "exact" else None
    wildcard_asset = item.get("original_asset_identifier") if match_type == "wildcard" else None
    source_file = item.get("source_file")
    warnings = list(loaded.get("warnings", []))
    if match_type == "wildcard":
        warnings.append("Host matched a wildcard scope asset; confirm exact target ownership before linking evidence.")
    if not _asset_type_supported(item.get("asset_type")):
        warnings.append(f"Matched asset type may not be host-testable: {item.get('asset_type')}")

    supported = _asset_type_supported(item.get("asset_type"))
    submission_eligible = item.get("eligible_for_submission") is True
    bounty_eligible = item.get("eligible_for_bounty") is True
    in_scope = supported and submission_eligible
    reason = "Exact in-scope host match from scope snapshot."
    confidence = "high"
    parent_strategy = "exact_host"
    if match_type == "wildcard":
        reason = "Wildcard in-scope host match from scope snapshot."
        confidence = "medium"
        parent_strategy = "wildcard_host"
    elif match_type == "parent_domain":
        reason = "Host is a subdomain of an in-scope host asset."
        confidence = "medium"
        parent_strategy = "program_fallback"
    if not supported:
        reason = "Matching asset uses an unsupported asset type for host testing."
        confidence = "low"
    elif not submission_eligible:
        reason = "Matching asset is in scope but not submission eligible."
        confidence = "low"
    elif not bounty_eligible:
        reason = "Matching asset is in scope for submission but not bounty eligible."

    decision = {
        "ok": True,
        "input": input_value,
        "normalized_host": normalized,
        "domain": normalized,
        "target": normalized,
        "in_scope": in_scope,
        "bounty_eligible": bounty_eligible,
        "submission_eligible": submission_eligible,
        "eligible_for_bounty": bounty_eligible,
        "eligible_for_submission": submission_eligible,
        "program_handle": item.get("program_handle"),
        "max_severity": item.get("max_severity"),
        "severity_allowed": item.get("max_severity") if in_scope else None,
        "match_type": match_type,
        "exact_matched_asset": exact_asset,
        "wildcard_matched_asset": wildcard_asset,
        "matched_scope": item.get("host"),
        "asset_type": item.get("asset_type"),
        "asset_identifier": item.get("original_asset_identifier"),
        "suggested_target_label": normalized if match_type in {"exact", "wildcard"} else item.get("host"),
        "suggested_parent_strategy": parent_strategy,
        "confidence": confidence,
        "scope_source": scope.get("scope_source", "h1_snapshots"),
        "source_file": source_file,
        "reason": reason,
        "warnings": warnings,
    }
    decision["reason_code"] = _reason_code_for_decision(decision)
    return _with_metadata(decision, scope, loaded)


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


def _resolve_manual_scope(input_value: str, normalized: str, scope: dict, response_format: str | None = None) -> dict:
    """Resolve a host against manually configured scope."""
    result = _check_manual_scope(input_value, normalized, scope)
    result["normalized_host"] = normalized
    result["bounty_eligible"] = bool(result.get("in_scope"))
    result["submission_eligible"] = bool(result.get("in_scope"))
    result["max_severity"] = None
    result["severity_allowed"] = None
    result["program_handle"] = None
    result["match_type"] = "manual_domain" if result.get("in_scope") else "none"
    result["exact_matched_asset"] = result.get("matched_scope") if result.get("in_scope") else None
    result["wildcard_matched_asset"] = None
    result["suggested_target_label"] = result.get("matched_scope") or normalized
    result["suggested_parent_strategy"] = "manual_scope" if result.get("in_scope") else "none"
    result["confidence"] = "medium" if result.get("in_scope") else "low"
    result["reason_code"] = "in_scope_bounty_eligible" if result.get("in_scope") else "no_matching_asset"
    result["warnings"] = result.get("warnings", [])
    result = _with_metadata(result, scope, {"entries": [], "warnings": []})
    if response_format == "mcp_interop":
        result["mcp_interop"] = _interop_payload(result)
    return result


def _resolve_h1_scope(input_value: str, normalized: str, scope: dict, response_format: str | None = None) -> dict:
    """Resolve a host against loaded H1 snapshot scope."""
    try:
        loaded = _load_h1_allowed_scope(scope)
    except H1ScopeError as exc:
        result = {
            "ok": False,
            "input": input_value,
            "normalized_host": normalized,
            "domain": normalized,
            "target": normalized,
            "in_scope": False,
            "bounty_eligible": False,
            "submission_eligible": False,
            "eligible_for_bounty": False,
            "eligible_for_submission": False,
            "program_handle": None,
            "max_severity": None,
            "severity_allowed": None,
            "match_type": "none",
            "exact_matched_asset": None,
            "wildcard_matched_asset": None,
            "suggested_target_label": normalized,
            "suggested_parent_strategy": "none",
            "confidence": "low",
            "scope_source": "h1_snapshots",
            "reason_code": "scope_load_failed",
            "reason": str(exc),
            "warnings": [str(exc)],
        }
        result = _with_metadata(result, scope, {"entries": [], "warnings": [str(exc)]})
        if response_format == "mcp_interop":
            result["mcp_interop"] = _interop_payload(result)
        return result

    allowed_hosts = loaded.get("allowed_hosts", [])
    if not allowed_hosts:
        result = {
            "ok": False,
            "input": input_value,
            "normalized_host": normalized,
            "domain": normalized,
            "target": normalized,
            "in_scope": False,
            "bounty_eligible": False,
            "submission_eligible": False,
            "eligible_for_bounty": False,
            "eligible_for_submission": False,
            "program_handle": None,
            "max_severity": None,
            "severity_allowed": None,
            "match_type": "none",
            "exact_matched_asset": None,
            "wildcard_matched_asset": None,
            "suggested_target_label": normalized,
            "suggested_parent_strategy": "none",
            "confidence": "low",
            "scope_source": "h1_snapshots",
            "reason_code": "empty_scope",
            "reason": "H1 snapshot scope produced no allowed hosts; failing closed.",
            "warnings": loaded.get("warnings", []),
        }
        result = _with_metadata(result, scope, loaded)
        if response_format == "mcp_interop":
            result["mcp_interop"] = _interop_payload(result)
        return result

    matches = []
    for item in allowed_hosts:
        match_type = _host_rule_match_type(normalized, item)
        if match_type:
            matches.append((match_type, item))

    if matches:
        match_type, item = sorted(matches, key=lambda pair: _rank_match(pair[0], pair[1]))[0]
        result = _decision_from_host_rule(input_value, normalized, item, match_type, scope, loaded)
        if response_format == "mcp_interop":
            result["mcp_interop"] = _interop_payload(result)
        return result

    result = {
        "ok": True,
        "input": input_value,
        "normalized_host": normalized,
        "domain": normalized,
        "target": normalized,
        "in_scope": False,
        "bounty_eligible": False,
        "submission_eligible": False,
        "eligible_for_bounty": False,
        "eligible_for_submission": False,
        "program_handle": None,
        "max_severity": None,
        "severity_allowed": None,
        "match_type": "none",
        "exact_matched_asset": None,
        "wildcard_matched_asset": None,
        "suggested_target_label": normalized,
        "suggested_parent_strategy": "none",
        "confidence": "low",
        "scope_source": "h1_snapshots",
        "reason_code": "no_matching_asset",
        "reason": "No matching H1 scope entry found.",
        "warnings": loaded.get("warnings", []),
    }
    result = _with_metadata(result, scope, loaded)
    if response_format == "mcp_interop":
        result["mcp_interop"] = _interop_payload(result)
    return result


def resolve_scope_target(host_or_url: str, format: str | None = None) -> dict:
    """Resolve the best configured scope target for a host or URL."""
    normalized = normalize_domain(host_or_url)
    scope = load_scope()
    scope_source = scope.get("scope_source", "manual")

    if not normalized:
        result = {
            "ok": False,
            "input": host_or_url,
            "normalized_host": normalized,
            "domain": normalized,
            "target": normalized,
            "in_scope": False,
            "bounty_eligible": False,
            "submission_eligible": False,
            "eligible_for_bounty": False,
            "eligible_for_submission": False,
            "program_handle": None,
            "max_severity": None,
            "severity_allowed": None,
            "match_type": "none",
            "exact_matched_asset": None,
            "wildcard_matched_asset": None,
            "suggested_target_label": None,
            "suggested_parent_strategy": "none",
            "confidence": "low",
            "scope_source": scope_source,
            "reason_code": "missing_host",
            "reason": "No domain or host was provided.",
            "warnings": [],
        }
        result = _with_metadata(result, scope, {"entries": [], "warnings": []})
        if format == "mcp_interop":
            result["mcp_interop"] = _interop_payload(result)
        return result

    if is_blocked_domain(normalized, scope):
        result = {
            "ok": True,
            "input": host_or_url,
            "normalized_host": normalized,
            "domain": normalized,
            "target": normalized,
            "in_scope": False,
            "bounty_eligible": False,
            "submission_eligible": False,
            "eligible_for_bounty": False,
            "eligible_for_submission": False,
            "program_handle": None,
            "max_severity": None,
            "severity_allowed": None,
            "match_type": "none",
            "exact_matched_asset": None,
            "wildcard_matched_asset": None,
            "suggested_target_label": normalized,
            "suggested_parent_strategy": "none",
            "confidence": "high",
            "scope_source": scope_source,
            "reason_code": "blocked_target",
            "reason": "Target is blocked by safety rules or blocked_domains.",
            "warnings": ["Target is blocked by safety rules or blocked_domains."],
        }
        result = _with_metadata(result, scope, {"entries": [], "warnings": result["warnings"]})
        if format == "mcp_interop":
            result["mcp_interop"] = _interop_payload(result)
        return result

    if scope_source == "h1_snapshots":
        return _resolve_h1_scope(host_or_url, normalized, scope, format)
    if scope_source == "manual":
        return _resolve_manual_scope(host_or_url, normalized, scope, format)

    result = {
        "ok": False,
        "input": host_or_url,
        "normalized_host": normalized,
        "domain": normalized,
        "target": normalized,
        "in_scope": False,
        "bounty_eligible": False,
        "submission_eligible": False,
        "eligible_for_bounty": False,
        "eligible_for_submission": False,
        "program_handle": None,
        "max_severity": None,
        "severity_allowed": None,
        "match_type": "none",
        "exact_matched_asset": None,
        "wildcard_matched_asset": None,
        "suggested_target_label": normalized,
        "suggested_parent_strategy": "none",
        "confidence": "low",
        "scope_source": scope_source,
        "reason_code": "unsupported_scope_source",
        "reason": f"Unsupported scope_source: {scope_source}",
        "warnings": [f"Unsupported scope_source: {scope_source}"],
    }
    result = _with_metadata(result, scope, {"entries": [], "warnings": result["warnings"]})
    if format == "mcp_interop":
        result["mcp_interop"] = _interop_payload(result)
    return result


def check_scope_batch(hosts_or_urls: list[str], format: str | None = None) -> dict:
    """Return one rich resolver-shaped scope decision for each host or URL."""
    if len(hosts_or_urls) > MAX_BATCH_SIZE:
        return {
            "ok": False,
            "count": len(hosts_or_urls),
            "max_batch_size": MAX_BATCH_SIZE,
            "error": f"Batch size {len(hosts_or_urls)} exceeds maximum {MAX_BATCH_SIZE}.",
        }

    return {
        "ok": True,
        "count": len(hosts_or_urls),
        "results": [resolve_scope_target(item, format=format) for item in hosts_or_urls],
    }


def _scope_map_entry_from_allowed_host(item: dict) -> dict:
    """Normalize an allowed host rule for machine consumption."""
    host = item.get("host")
    rule = item.get("rule") or host
    return {
        "asset_identifier": item.get("original_asset_identifier"),
        "normalized_host": host,
        "asset_type": item.get("asset_type"),
        "eligible_for_bounty": item.get("eligible_for_bounty") is True,
        "eligible_for_submission": item.get("eligible_for_submission") is True,
        "program_handle": item.get("program_handle"),
        "max_severity": item.get("max_severity"),
        "scope_status": "in_scope" if item.get("eligible_for_submission") is True else "not_submission_eligible",
        "source_file": item.get("source_file"),
        "match_patterns": [rule],
        "wildcard": item.get("wildcard") is True,
        "supported": _asset_type_supported(item.get("asset_type")),
    }


def get_scope_map() -> dict:
    """Return normalized machine-readable scope entries."""
    scope = load_scope()
    scope_source = scope.get("scope_source", "manual")
    if scope_source == "manual":
        entries = [
            {
                "asset_identifier": item,
                "normalized_host": normalize_domain(item),
                "asset_type": "manual",
                "eligible_for_bounty": True,
                "eligible_for_submission": True,
                "program_handle": None,
                "max_severity": None,
                "scope_status": "in_scope",
                "source_file": None,
                "match_patterns": [normalize_domain(item)],
                "wildcard": False,
                "supported": True,
            }
            for item in scope.get("allowed_domains", [])
            if normalize_domain(item)
        ]
        result = {"ok": True, "scope_source": "manual", "entries": entries, "count": len(entries), "warnings": []}
        return _with_metadata(result, scope, {"entries": [], "warnings": []})

    if scope_source != "h1_snapshots":
        result = {
            "ok": False,
            "scope_source": scope_source,
            "entries": [],
            "count": 0,
            "warnings": [f"Unsupported scope_source: {scope_source}"],
        }
        return _with_metadata(result, scope, {"entries": [], "warnings": result["warnings"]})

    try:
        loaded = _load_h1_allowed_scope(scope)
    except H1ScopeError as exc:
        result = {"ok": False, "scope_source": "h1_snapshots", "entries": [], "count": 0, "warnings": [str(exc)]}
        return _with_metadata(result, scope, {"entries": [], "warnings": [str(exc)]})

    entries = [_scope_map_entry_from_allowed_host(item) for item in loaded.get("allowed_hosts", [])]
    result = {
        "ok": True,
        "scope_source": "h1_snapshots",
        "entries": entries,
        "count": len(entries),
        "warnings": loaded.get("warnings", []),
    }
    return _with_metadata(result, scope, loaded)


def recommend_bugmap_parent(host_or_url: str, available_bugmap_targets: list[dict]) -> dict:
    """Recommend the best BugMap parent from current scope and provided targets."""
    decision = resolve_scope_target(host_or_url)
    normalized = decision.get("normalized_host") or ""
    target_rows = [
        {"id": item.get("id"), "label": str(item.get("label") or ""), "normalized_label": normalize_domain(str(item.get("label") or ""))}
        for item in available_bugmap_targets
        if isinstance(item, dict)
    ]

    def candidate_reason(row: dict) -> tuple[int, str] | None:
        label = row["normalized_label"]
        if label and label == normalized:
            return (0, "exact target label")
        suggested = normalize_domain(str(decision.get("suggested_target_label") or ""))
        if label and suggested and label == suggested:
            return (1, "resolved scope target label")
        matched_scope = normalize_domain(str(decision.get("matched_scope") or ""))
        if label and matched_scope and label == matched_scope:
            return (2, "matched scope label")
        program = str(decision.get("program_handle") or "").lower()
        if row["label"].strip().lower() == program and program:
            return (3, "program-level fallback")
        if label and normalized.endswith(f".{label}"):
            return (4, "parent domain fallback")
        return None

    candidates = []
    for row in target_rows:
        reason = candidate_reason(row)
        if reason:
            rank, text = reason
            candidates.append({"rank": rank, "id": row["id"], "label": row["label"], "reason": text})

    candidates.sort(key=lambda item: item["rank"])
    selected = candidates[0] if candidates else None
    alternatives = [{"id": item["id"], "label": item["label"], "reason": item["reason"]} for item in candidates[1:]]
    warnings = list(decision.get("warnings") or [])
    if not selected:
        warnings.append("No available BugMap target matched the resolved scope decision.")

    return {
        "ok": selected is not None,
        "input": host_or_url,
        "normalized_host": normalized,
        "recommended_parent_id": selected.get("id") if selected else None,
        "recommended_parent_label": selected.get("label") if selected else None,
        "alternatives": alternatives,
        "match_type": decision.get("match_type"),
        "reason": selected.get("reason") if selected else "No matching BugMap target was available.",
        "warnings": warnings,
        "scope_decision": decision,
    }


def explain_scope_decision(host_or_url: str) -> dict:
    """Return a human-readable scope explanation plus the structured decision."""
    decision = resolve_scope_target(host_or_url)
    host = decision.get("normalized_host") or host_or_url
    if decision.get("in_scope"):
        source = Path(str(decision.get("source_file") or "")).name or "configured scope"
        eligibility = "bounty-eligible" if decision.get("bounty_eligible") else "submission-eligible but not bounty-eligible"
        explanation = (
            f"{host} is in scope because it has a {decision.get('match_type')} match "
            f"against a {eligibility} asset in {source}. Max severity: {decision.get('max_severity') or 'unspecified'}."
        )
    else:
        explanation = f"{host} is not in scope: {decision.get('reason')}"
    return {"ok": decision.get("ok", True), "explanation": explanation, **decision}


def check_scope(domain: str) -> dict:
    """Check whether a domain or URL is inside scope using the rich resolver response shape."""
    return resolve_scope_target(domain)


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
            result = {
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
            return _with_metadata(result, scope, {"entries": [], "warnings": result["warnings"]})
        result = {
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
        return _with_metadata(result, scope, {"entries": [], "warnings": []})

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

    result = {
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
    return _with_metadata(result, scope, loaded)


def assert_in_scope(url_or_domain: str) -> None:
    """Raise ScopeError if a URL or domain is outside the configured scope."""
    result = check_scope(url_or_domain)
    if not result.get("in_scope"):
        raise ScopeError(result.get("reason", "Target is out of scope."))
