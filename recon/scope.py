"""Scope loading and enforcement for safe recon tools."""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import idna
from recon.redaction import redact_embedded_urls, redact_text, redact_url
from recon.policy_io import PolicyFileError, read_policy_json

from recon.h1_scope import H1ScopeError, extract_allowed_hosts_from_h1_entries, load_h1_snapshots


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SCOPE_PATH = PROJECT_ROOT / "config" / "scope.json"
DEFAULT_USER_AGENT = "ReconMCP/0.2"
DEFAULT_REQUEST_DELAY_MS = 500
DEFAULT_MAX_REQUESTS_PER_TOOL_CALL = 20
DEFAULT_FETCH_HEADERS_METHOD = "HEAD"
DEFAULT_LIMITS = {
    "max_html_bytes": 2 * 1024 * 1024,
    "max_javascript_bytes": 5 * 1024 * 1024,
    "max_sourcemap_bytes": 5 * 1024 * 1024,
    "max_sitemap_bytes": 1024 * 1024,
    "max_robots_bytes": 512 * 1024,
    "max_saved_artifact_bytes": 10 * 1024 * 1024,
    "max_extracted_source_files": 500,
    "max_total_extracted_source_bytes": 20 * 1024 * 1024,
    "max_analysis_signals": 1000,
    "max_endpoint_candidates": 1000,
}
LIMIT_BOUNDS = {
    **{name: (1024, 100 * 1024 * 1024) for name in DEFAULT_LIMITS if name.endswith("_bytes")},
    "max_extracted_source_files": (1, 10000),
    "max_analysis_signals": (1, 10000),
    "max_endpoint_candidates": (1, 10000),
}
MAX_BATCH_SIZE = 200
SUPPORTED_HOST_ASSET_TYPES = {"", "url", "domain", "wildcard", "api"}


class ScopeError(ValueError):
    """Raised when a target is not allowed by the configured scope."""


def load_scope(path: Path | None = None) -> dict:
    """Read settings on demand so replacement, deletion, and corruption revoke access."""
    try:
        data, _ = read_policy_json(path if path is not None else DEFAULT_SCOPE_PATH)
    except FileNotFoundError as exc:
        if path is not None:
            raise ScopeError("Selected scope configuration does not exist.") from exc
        data = {}
    except (OSError, PolicyFileError) as exc:
        detail = str(exc) if isinstance(exc, PolicyFileError) else "Could not safely open scope configuration."
        raise ScopeError(f"Invalid scope config: {detail}") from exc

    if not isinstance(data, dict):
        raise ScopeError("Invalid scope config: top-level value must be an object.")
    scope_keys = {
        "scope_source", "h1_snapshot_dir", "h1_snapshot_program", "h1_snapshot_max_age_seconds", "burp_scope_file",
        "include_only_bounty_eligible", "include_only_submission_eligible", "allowed_domains",
        "allowed_assets", "blocked_domains", "url_include", "url_exclude", "user_agent",
        "request_delay_ms", "max_requests_per_tool_call", "fetch_headers_method",
        *DEFAULT_LIMITS,
    }
    if data.keys() - scope_keys:
        raise ScopeError("Invalid scope config: unrecognized setting.")
    for name in ("include_only_bounty_eligible", "include_only_submission_eligible"):
        if name in data and type(data[name]) is not bool:
            raise ScopeError(f"Invalid scope config: {name} must be a boolean.")
    for name in ("scope_source", "h1_snapshot_dir", "h1_snapshot_program", "burp_scope_file"):
        if name in data and not isinstance(data[name], str):
            raise ScopeError(f"Invalid scope config: {name} must be a string.")
    user_agent = data.get("user_agent") or DEFAULT_USER_AGENT
    if not isinstance(user_agent, str) or len(user_agent) > 256 or not user_agent.isascii() or not user_agent.isprintable():
        raise ScopeError("Invalid scope config: user_agent must be printable ASCII.")
    try:
        request_delay_ms = int(data.get("request_delay_ms", DEFAULT_REQUEST_DELAY_MS))
        max_requests_per_tool_call = int(data.get("max_requests_per_tool_call", DEFAULT_MAX_REQUESTS_PER_TOOL_CALL))
    except (TypeError, ValueError) as exc:
        raise ScopeError("Invalid scope config: request limits must be integers.") from exc
    if not 0 <= request_delay_ms <= 60000:
        raise ScopeError("Invalid scope config: request_delay_ms must be between 0 and 60000.")
    if not 1 <= max_requests_per_tool_call <= 1000:
        raise ScopeError("Invalid scope config: max_requests_per_tool_call must be between 1 and 1000.")
    fetch_headers_method = str(data.get("fetch_headers_method") or DEFAULT_FETCH_HEADERS_METHOD).upper()
    if fetch_headers_method not in {"HEAD", "GET"}:
        raise ScopeError("Invalid scope config: fetch_headers_method must be HEAD or GET.")
    result = {
        "scope_source": data.get("scope_source", "manual"),
        "h1_snapshot_dir": data.get("h1_snapshot_dir", ""),
        "include_only_bounty_eligible": bool(data.get("include_only_bounty_eligible", False)),
        "include_only_submission_eligible": bool(data.get("include_only_submission_eligible", False)),
        "allowed_domains": data.get("allowed_domains", []),
        "allowed_assets": data.get("allowed_assets", []),
        "blocked_domains": data.get("blocked_domains", []),
        "user_agent": user_agent,
        "request_delay_ms": request_delay_ms,
        "max_requests_per_tool_call": max_requests_per_tool_call,
        "fetch_headers_method": fetch_headers_method,
    }
    for name, default in DEFAULT_LIMITS.items():
        raw = data.get(name, default)
        if isinstance(raw, bool):
            raise ScopeError(f"Invalid scope config: {name} must be an integer.")
        try:
            value = int(raw)
        except (TypeError, ValueError) as exc:
            raise ScopeError(f"Invalid scope config: {name} must be an integer.") from exc
        minimum, maximum = LIMIT_BOUNDS[name]
        if value < minimum or value > maximum:
            raise ScopeError(f"Invalid scope config: {name} must be between {minimum} and {maximum}.")
        result[name] = value
    for name in ("burp_scope_file", "h1_snapshot_program", "h1_snapshot_max_age_seconds", "url_include", "url_exclude"):
        if name in data:
            result[name] = data[name]
    return result


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

    literal = raw.strip().strip("[]").rstrip(".")
    try:
        return str(ipaddress.ip_address(literal)).lower()
    except ValueError:
        pass

    try:
        parsed = urlparse(raw if "://" in raw else f"//{raw}", scheme="https")
        host = parsed.hostname or raw
    except ValueError:
        return ""
    host = host.strip().strip("[]").rstrip(".").lower()
    try:
        return idna.encode(host, uts46=True, std3_rules=True).decode("ascii")
    except (UnicodeError, idna.IDNAError):
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

    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
        elif ip.sixtofour is not None or ip.teredo is not None:
            return True
    return not ip.is_global or ip.is_multicast or ip.is_reserved


def is_valid_host_asset(host: str) -> bool:
    """Return True for normalized DNS names or IP literals only."""
    normalized = normalize_domain(host)
    try:
        ipaddress.ip_address(normalized)
        return True
    except ValueError:
        pass
    if len(normalized) > 253 or "." not in normalized:
        return False
    return all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in normalized.split("."))


def is_blocked_domain(domain: str, scope: dict | None = None) -> bool:
    """Return True when a domain is blocked by config or IP safety rules."""
    normalized = normalize_domain(domain)
    scope = scope or load_scope()
    blocked_domains = [normalize_domain(item) for item in scope.get("blocked_domains", [])]

    if is_private_or_loopback_host(normalized):
        return True

    return any(normalized == blocked or normalized.endswith(f".{blocked}") for blocked in blocked_domains)


def _matches_allowed_domain(domain: str, allowed_domain: str) -> bool:
    """Return True only for an exact legacy manual-domain match."""
    return domain == allowed_domain


def _manual_assets(scope: dict) -> tuple[list[dict], list[str]]:
    """Normalize manual assets; legacy plain domains are exact unless prefixed by *."""
    assets: list[dict] = []
    warnings: list[str] = []
    raw_assets = scope.get("allowed_assets", [])
    if raw_assets is None:
        raw_assets = []
    if not isinstance(raw_assets, list):
        return [], ["allowed_assets must be a list; manual scope failed closed."]
    for item in raw_assets:
        if not isinstance(item, dict):
            warnings.append("Ignored malformed allowed_assets entry.")
            continue
        original = str(item.get("value") or "").strip()
        match = str(item.get("match") or "exact").strip().lower()
        if original.startswith("*."):
            original_host = original[2:]
            match = "wildcard"
        else:
            original_host = original
        host = normalize_domain(original_host)
        if not host or not is_valid_host_asset(host) or match not in {"exact", "wildcard"} or is_private_or_loopback_host(host):
            warnings.append("Ignored an unsupported or malformed manual asset.")
            continue
        try:
            ipaddress.ip_address(host)
            if match == "wildcard":
                warnings.append("Ignored a wildcard IP asset.")
                continue
        except ValueError:
            pass
        assets.append({"host": host, "match": match, "original_asset": redact_url(original, redact_all_query_values=True)})
    legacy = scope.get("allowed_domains", [])
    if not isinstance(legacy, list):
        return assets, warnings + ["allowed_domains must be a list; malformed entries were ignored."]
    for raw in legacy:
        original = str(raw or "").strip()
        wildcard = original.startswith("*.")
        host = normalize_domain(original[2:] if wildcard else original)
        if not host or not is_valid_host_asset(host) or is_private_or_loopback_host(host):
            continue
        assets.append({"host": host, "match": "wildcard" if wildcard else "exact", "original_asset": redact_url(original, redact_all_query_values=True)})
    return assets, warnings


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
    if decision.get("bounty_eligible") is None:
        return "in_scope_eligibility_unknown"
    if decision["bounty_eligible"] is False:
        return "in_scope_not_bounty_eligible"
    if decision.get("match_type") == "wildcard":
        return "wildcard_scope_match"
    return "in_scope_bounty_eligible"


def _interop_payload(decision: dict) -> dict:
    """Return stable keys for other local MCP servers."""
    submission = decision.get("submission_eligible")
    bounty = decision.get("bounty_eligible")
    scope_ok = bool(decision.get("in_scope") and submission is True)
    risk_warning = "; ".join(decision.get("warnings") or []) or None
    if not risk_warning:
        if not decision.get("in_scope"):
            risk_warning = decision.get("reason")
        elif bounty is False:
            risk_warning = "Bounty eligibility is explicitly denied by the source."
        elif bounty is None or submission is None:
            risk_warning = "Eligibility is unknown."

    return {
        "normalized_host": decision.get("normalized_host"),
        "scope_ok": scope_ok,
        "authorized_url": decision.get("authorized") is True,
        "submission_eligible": submission,
        "bounty_eligible": bounty,
        "can_test": False,
        "can_scan": False,
        "can_store_evidence": scope_ok,
        "recommended_bugmap_target_label": decision.get("suggested_target_label"),
        "risk_warning": risk_warning,
    }


def _reported_eligibility(value: object) -> bool | None:
    return value if isinstance(value, bool) else None


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
    submission_eligible = _reported_eligibility(item.get("eligible_for_submission"))
    bounty_eligible = _reported_eligibility(item.get("eligible_for_bounty"))
    in_scope = supported and submission_eligible is True
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
    elif submission_eligible is not True:
        reason = "Submission eligibility is unknown or denied for the matching asset."
        confidence = "low"
    elif bounty_eligible is not True:
        reason = "Bounty eligibility is unknown or denied for the matching asset."

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
    assets, warnings = _manual_assets(scope)
    if not assets:
        return {
            "ok": False,
            "input": domain,
            "domain": normalized,
            "target": normalized,
            "in_scope": False,
            "scope_source": "manual",
            "reason": "Manual scope has no allowed domains configured; failing closed.",
            "reason_code": "no_configured_assets",
            "warnings": warnings,
        }

    matched = next((item for item in assets if item["match"] == "exact" and normalized == item["host"]), None)
    if matched is None:
        matched = next(
            (item for item in assets if item["match"] == "wildcard" and normalized != item["host"] and normalized.endswith(f".{item['host']}")),
            None,
        )

    if matched:
        return {
            "ok": True,
            "input": domain,
            "domain": normalized,
            "target": normalized,
            "in_scope": True,
            "matched_scope": matched["host"],
            "matched_asset": matched["original_asset"],
            "match_type": matched["match"],
            "scope_source": "manual",
            "reason": f"Target matches configured {matched['match']} scope asset.",
            "reason_code": f"{matched['match']}_scope_match",
            "warnings": warnings,
        }

    return {
        "ok": True,
        "input": domain,
        "domain": normalized,
        "target": normalized,
        "in_scope": False,
        "scope_source": "manual",
        "reason": "Target does not match configured allowed scope.",
        "reason_code": "no_matching_asset",
        "warnings": warnings,
    }


def _load_h1_allowed_scope(scope: dict) -> dict:
    """Load and parse H1 snapshot scope from local files."""
    entries = load_h1_snapshots(str(scope.get("h1_snapshot_dir") or ""), program=scope.get("h1_snapshot_program"))
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
    result["bounty_eligible"] = None
    result["submission_eligible"] = None
    result["max_severity"] = None
    result["severity_allowed"] = None
    result["program_handle"] = None
    result["match_type"] = result.get("match_type") if result.get("in_scope") else "none"
    result["exact_matched_asset"] = result.get("matched_asset") if result.get("match_type") == "exact" else None
    result["wildcard_matched_asset"] = result.get("matched_asset") if result.get("match_type") == "wildcard" else None
    result["suggested_target_label"] = result.get("matched_scope") or normalized
    result["suggested_parent_strategy"] = "manual_scope" if result.get("in_scope") else "none"
    result["confidence"] = "medium" if result.get("in_scope") else "low"
    result.setdefault("reason_code", "no_matching_asset")
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


def _resolve_host_inventory(host_or_url: str, format: str | None = None) -> dict:
    """Resolve a host for legacy scope and evidence metadata."""
    normalized = normalize_domain(host_or_url)
    safe_input = normalized or "<invalid-host>"
    scope = load_scope()
    scope_source = scope.get("scope_source", "manual")

    if not normalized:
        result = {
            "ok": False,
            "input": safe_input,
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
            "input": safe_input,
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

    if not is_valid_host_asset(normalized) or redact_text(normalized) != normalized:
        result = {
            "ok": False, "input": None, "normalized_host": None, "domain": None,
            "target": None, "in_scope": False, "bounty_eligible": False,
            "submission_eligible": False, "eligible_for_bounty": False,
            "eligible_for_submission": False, "program_handle": None, "max_severity": None,
            "severity_allowed": None, "match_type": "unsupported", "exact_matched_asset": None,
            "wildcard_matched_asset": None, "suggested_target_label": None,
            "suggested_parent_strategy": "none", "confidence": "low", "scope_source": scope_source,
            "reason_code": "unsupported_asset", "reason": "Input is not a supported hostname or IP asset.", "warnings": [],
        }
        return _with_metadata(result, scope, {"entries": [], "warnings": []})

    if scope_source == "h1_snapshots":
        return _resolve_h1_scope(safe_input, normalized, scope, format)
    if scope_source == "manual":
        return _resolve_manual_scope(safe_input, normalized, scope, format)

    if scope_source == "burp_advanced":
        from recon.authorization import AuthorizationError, load_policy, policy_failure

        try:
            policy = load_policy()
        except AuthorizationError as exc:
            return policy_failure(exc)
        includes = [rule.rule_id for rule in policy.include if rule.matches_host(normalized)]
        excludes = [rule.rule_id for rule in policy.exclude if rule.matches_host(normalized)]
        return {
            "ok": True, "in_scope": False, "input": safe_input, "normalized_host": normalized,
            "domain": normalized, "target": normalized, "evaluation_kind": "host_match",
            "scope_source": scope_source, "policy_fingerprint": policy.fingerprint,
            "host_rule_match": bool(includes), "matching_host_inclusion_rule_ids": includes,
            "matching_host_exclusion_rule_ids": excludes, "bounty_eligible": None,
            "reason_code": "url_required", "reason": "Evaluate a complete URL for Burp policy authorization.",
        }


    raise ScopeError("Unsupported scope source. Select manual, h1_snapshots, or burp_advanced.")


def resolve_scope_target(host_or_url: str, format: str | None = None) -> dict:
    """Preserve host metadata and delegate complete URLs to the enforcement engine."""
    from recon.authorization import MAX_URL_LENGTH, AuthorizationError, check_url_scope, load_policy, policy_failure

    if len(host_or_url) > MAX_URL_LENGTH or any(symbol in host_or_url for symbol in ("/", "?", "#", "@", "\\")):
        url_decision = check_url_scope(host_or_url)
        components = url_decision.get("normalized_url") or {}
        host = components.get("hostname")
        rule = url_decision["matched_inclusion_rule"] if url_decision["authorized"] else None
        result = {
            **url_decision, "input": url_decision["target"], "evaluation_kind": "url",
            "normalized_host": host, "domain": host, "match_type": rule["host_match"] if rule else "none",
            "matched_scope": rule["host"] if rule and rule["host_match"] != "regex" else host if rule else None,
            "suggested_target_label": host if rule else None,
            "submission_eligible": True if url_decision["authorized"] and url_decision["policy_source"] == "h1_snapshots" else None,
            "bounty_eligible": None,
        }
    else:
        try:
            inventory = _resolve_host_inventory(host_or_url)
            if inventory.get("ok") and inventory.get("evaluation_kind") != "host_match":
                try:
                    load_policy()
                except AuthorizationError as exc:
                    if exc.code != "h1_program_selection_required":
                        inventory = {**policy_failure(exc), "ok": False}
        except (TypeError, ValueError, OSError) as exc:
            inventory = policy_failure(exc)
        result = {"evaluation_kind": "host_inventory", **inventory, "network_execution_permitted": False}
    if not result.get("in_scope") and result.get("match_type") in {None, "none", "unsupported"}:
        for key in ("bounty_eligible", "submission_eligible", "eligible_for_bounty", "eligible_for_submission"):
            result[key] = None
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

    if any(len(item) > 4096 for item in hosts_or_urls) or sum(len(item.encode("utf-8", errors="replace")) for item in hosts_or_urls) > 256 * 1024:
        return {"ok": False, "error": "Scope inventory batch exceeds its per-item or aggregate size limit."}

    return {
        "ok": True,
        "count": len(hosts_or_urls),
        "results": [resolve_scope_target(item, format=format) for item in hosts_or_urls],
    }


def _scope_map_entry_from_allowed_host(item: dict) -> dict:
    """Normalize an allowed host rule for machine consumption."""
    host = item.get("host")
    rule = item.get("rule") or host
    submission = _reported_eligibility(item.get("eligible_for_submission"))
    return {
        "asset_identifier": item.get("original_asset_identifier"),
        "normalized_host": host,
        "asset_type": item.get("asset_type"),
        "eligible_for_bounty": _reported_eligibility(item.get("eligible_for_bounty")),
        "eligible_for_submission": submission,
        "program_handle": item.get("program_handle"),
        "max_severity": item.get("max_severity"),
        "scope_status": {
            True: "in_scope", False: "not_submission_eligible", None: "submission_eligibility_unknown",
        }[submission],
        "source_file": item.get("source_file"),
        "match_patterns": [rule],
        "wildcard": item.get("wildcard") is True,
        "supported": _asset_type_supported(item.get("asset_type")),
    }


def get_scope_map() -> dict:
    """Return normalized machine-readable scope inventory entries."""
    from recon.authorization import load_policy, policy_failure

    try:
        policy = load_policy()
        scope = load_scope()
    except ScopeError as exc:
        failure = policy_failure(exc)
        return {**failure, "ok": False, "entries": [], "count": 0, "warnings": [failure["reason"]]}
    scope_source = policy.source
    if scope_source == "manual":
        assets, asset_warnings = _manual_assets(scope)
        entries = [
            {
                "asset_identifier": item["original_asset"],
                "normalized_host": item["host"],
                "asset_type": "manual",
                "eligible_for_bounty": None,
                "eligible_for_submission": None,
                "program_handle": None,
                "max_severity": None,
                "scope_status": "in_scope",
                "source_file": None,
                "match_patterns": [f"*.{item['host']}" if item["match"] == "wildcard" else item["host"]],
                "wildcard": item["match"] == "wildcard",
                "supported": True,
            }
            for item in assets
        ]
        result = {"ok": True, "scope_source": "manual", "entries": entries, "count": len(entries), "warnings": asset_warnings}
        return _with_metadata(result, scope, {"entries": [], "warnings": asset_warnings})

    if scope_source == "burp_advanced":
        from recon.authorization import get_scope_policy_summary
        return {**get_scope_policy_summary(), "evaluation_kind": "policy_summary", "entries": [], "count": 0}
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


def _safe_bugmap_value(value):
    if not isinstance(value, str):
        return value if isinstance(value, int) else None
    if any(mark in value for mark in ("@", "?", "#")):
        return redact_url(value, redact_all_query_values=True) if value.lower().startswith(("http://", "https://")) else "<redacted>"
    return redact_embedded_urls(value)


def recommend_bugmap_parent(host_or_url: str, available_bugmap_targets: list[dict]) -> dict:
    """Recommend the best BugMap parent from current scope and provided targets."""
    decision = resolve_scope_target(host_or_url)
    normalized = decision.get("normalized_host") or ""
    target_rows = [
        {"id": _safe_bugmap_value(item.get("id")), "label": _safe_bugmap_value(item.get("label")) or "", "normalized_label": normalize_domain(str(item.get("label") or ""))}
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
        "input": decision.get("input") or decision.get("target"),
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
    host = decision.get("normalized_host") or "The supplied target"
    if decision.get("in_scope"):
        source = Path(str(decision.get("source_file") or "")).name or "configured scope"
        if decision.get("bounty_eligible") is True:
            eligibility = "bounty-eligible"
        elif decision.get("bounty_eligible") is False:
            eligibility = "bounty-ineligible"
        else:
            eligibility = "eligibility-unconfirmed"
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
    from recon.authorization import load_policy, policy_failure

    try:
        load_policy()
        scope = load_scope()
    except ScopeError as exc:
        failure = policy_failure(exc)
        return {**failure, "ok": False, "warnings": [failure["reason"]]}

    scope_source = scope.get("scope_source", "manual")
    if scope_source == "manual":
        assets, asset_warnings = _manual_assets(scope)
        if not assets:
            result = {
                "ok": False,
                "scope_source": "manual",
                "snapshot_directory": None,
                "json_files_loaded": 0,
                "scope_entries_parsed": 0,
                "allowed_hosts_count": 0,
                "program_handles": [],
                "allowed_hosts": [],
                "warnings": ["Manual scope has no allowed assets configured; failing closed.", *asset_warnings],
            }
            return _with_metadata(result, scope, {"entries": [], "warnings": result["warnings"]})
        result = {
            "ok": True,
            "scope_source": "manual",
            "snapshot_directory": None,
            "json_files_loaded": 0,
            "scope_entries_parsed": 0,
            "allowed_hosts_count": len(assets),
            "program_handles": [],
            "allowed_hosts": sorted({f"*.{item['host']}" if item["match"] == "wildcard" else item["host"] for item in assets}),
            "warnings": asset_warnings,
        }
        return _with_metadata(result, scope, {"entries": [], "warnings": asset_warnings})

    if scope_source == "burp_advanced":
        from recon.authorization import get_scope_policy_summary
        return get_scope_policy_summary()

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


def assert_in_scope(url: str) -> None:
    """Require full URL authorization for callers of the legacy assertion."""
    from recon.authorization import require_url

    require_url(url)
