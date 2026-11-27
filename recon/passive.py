"""Bounded passive subdomain discovery through fixed public providers."""

from __future__ import annotations

import json
import re
import time
from pathlib import Path
from urllib.parse import quote

import httpx

from recon.audit import write_audit_event
from recon.authorization import AuthorizationError, evaluate, load_policy, normalize_host, parse_target, policy_failure
from recon.campaign_scope import campaign_network, current_grant, verify_current_binding
from recon.campaigns import file_timestamp, get_campaign_paths
from recon.evidence_graph import add_evidence_batch
from recon.http_fetch import checked_dns, safe_get_bytes
from recon.safeio import SafeIOError, artifact_envelope, atomic_write_bytes, read_bytes_bounded, write_json_artifact

PROVIDERS = {"certificate_transparency", "alienvault_otx"}
HOST_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])$")
MAX_PROVIDER_BYTES = 5 * 1024 * 1024
CACHE_SECONDS = 3600


def _provider_url(provider: str, root: str) -> str:
    if provider == "certificate_transparency":
        return f"https://crt.sh/?q=%25.{quote(root)}&output=json"
    return f"https://otx.alienvault.com/api/v1/indicators/domain/{quote(root)}/passive_dns"


def _query(provider: str, root: str) -> list[str]:
    data = None
    for attempt in range(2):
        try:
            content, _ = safe_get_bytes(_provider_url(provider, root), MAX_PROVIDER_BYTES,
                                        content_type=f"{provider} provider", follow_redirects=False, timeout=12.0)
            data = json.loads(content)
            break
        except AuthorizationError:
            raise
        except (httpx.HTTPError, ValueError):
            if attempt == 0:
                time.sleep(0.2)
    if data is None:
        raise ValueError("Provider query failed after 2 attempts.")
    if provider == "certificate_transparency":
        if not isinstance(data, list):
            raise ValueError("Unexpected provider response shape.")
        return [name for item in data if isinstance(item, dict) and isinstance(item.get("name_value"), str)
                for name in item["name_value"].splitlines()][:10000]
    entries = data.get("passive_dns") if isinstance(data, dict) else None
    if not isinstance(entries, list):
        raise ValueError("Unexpected provider response shape.")
    return [item.get("hostname") for item in entries[:10000] if isinstance(item, dict)]


def _current_root_policy(target, fingerprint):
    verify_current_binding()
    policy = load_policy()
    decision = evaluate(policy, target, expected_fingerprint=fingerprint)
    if not decision["authorized"]:
        raise AuthorizationError(decision["reason"], code=decision["reason_code"], decision=decision)
    return policy, decision


def _candidate_target(raw, root):
    if not isinstance(raw, str) or len(raw) > 255:
        raise ValueError("Unsupported candidate shape.")
    value = normalize_host(raw.removeprefix("*."))
    if not HOST_RE.fullmatch(value) or not value.endswith("." + root):
        raise ValueError("Candidate is not a child DNS name.")
    return parse_target(f"https://{value}/")


def _passive_denial(campaign_id, exc):
    decision = exc.decision or policy_failure(exc)
    write_audit_event(campaign_id, "discover_subdomains_passive_for_campaign", ok=False, scope_decision=decision)
    return {"ok": False, "error_code": exc.code, "error": decision["reason"], "scope_decision": decision}


@campaign_network("root_domain")
def discover_subdomains_passive_for_campaign(campaign_id: str, root_domain: str, providers: list[str] | None = None, max_results: int = 500, resolve_dns: bool = False) -> dict:
    try:
        root = normalize_host(root_domain)
        if not HOST_RE.fullmatch(root):
            raise ValueError("Expected a root DNS name.")
        root_target = parse_target(f"https://{root}/")
    except ValueError:
        return {"ok": False, "error": "Expected a bare root DNS hostname."}
    grant = current_grant()
    try:
        _, root_decision = _current_root_policy(root_target, grant.fingerprint)
    except AuthorizationError as exc:
        return _passive_denial(campaign_id, exc)
    selected = list(dict.fromkeys(providers or ["certificate_transparency", "alienvault_otx"]))
    if not selected or any(item not in PROVIDERS for item in selected):
        error = f"providers must be selected from {sorted(PROVIDERS)}."
        write_audit_event(campaign_id, "discover_subdomains_passive_for_campaign", target=root, ok=False, scope_decision=root_decision, warnings=[error])
        return {"ok": False, "error": error}
    maximum = max(1, min(int(max_results), 5000))
    paths = get_campaign_paths(campaign_id)
    if not paths.get("ok"):
        return {"ok": False, "error": paths.get("error")}
    directory = Path(paths["paths"]["recon"]["passive"])
    all_names: dict[str, set[str]] = {}
    targets = {}
    caches = {}
    candidate_rejections = {"rejected": 0, "unsupported": 0}
    failures: list[dict] = []
    for provider in selected:
        cache = directory / f"cache-{provider}-{root}.json"
        names = None
        try:
            if not cache.is_symlink() and time.time() - cache.stat().st_mtime < CACHE_SECONDS:
                cached = json.loads(read_bytes_bounded(cache, MAX_PROVIDER_BYTES))
                names = cached.get("names") if isinstance(cached, dict) else None
        except (OSError, ValueError):
            pass
        refresh = not isinstance(names, list)
        if refresh:
            try:
                names = _query(provider, root)
            except AuthorizationError as exc:
                if exc.code in {"policy_changed", "invalid_policy", "unsupported_policy"}:
                    return _passive_denial(campaign_id, exc)
                failures.append({"provider": provider, "error": "Provider request was denied.", "reason_code": exc.code})
                continue
            except (httpx.HTTPError, ValueError, OSError):
                failures.append({"provider": provider, "error": "Provider data was unavailable or invalid."})
                continue
        try:
            policy, root_decision = _current_root_policy(root_target, grant.fingerprint)
        except AuthorizationError as exc:
            return _passive_denial(campaign_id, exc)
        accepted_names = set()
        for raw in names[:10000]:
            try:
                target = _candidate_target(raw, root)
            except AuthorizationError:
                candidate_rejections["rejected"] += 1
                continue
            except ValueError:
                candidate_rejections["unsupported"] += 1
                continue
            targets[target.host] = target
            accepted_names.add(target.host)
            all_names.setdefault(target.host, set()).add(provider)
        if refresh:
            caches[cache] = {"provider": provider, "root": root, "queried_at": time.time(), "names": sorted(accepted_names)}
    try:
        policy, root_decision = _current_root_policy(root_target, grant.fingerprint)
    except AuthorizationError as exc:
        return _passive_denial(campaign_id, exc)
    truncated = len(all_names) > maximum
    results: list[dict] = []
    for host in sorted(all_names)[:maximum]:
        target = targets[host]
        decision = evaluate(policy, target, expected_fingerprint=grant.fingerprint)
        active = decision["authorized"]
        rule = decision.get("matched_inclusion_rule")
        classification = "rejected"
        if active:
            classification = {
                "exact": "exact_in_scope", "wildcard": "wildcard_in_scope", "regex": "regex_in_scope",
            }.get(rule["host_match"], "unsupported")
        item = {"host": host, "providers": sorted(all_names[host]), "queried_at": time.time(),
                "scope_classification": classification, "scope_decision": decision, "testable": active,
                "manual_validation_required": True}
        if resolve_dns and active:
            try:
                item["resolved_public_ips"] = sorted(checked_dns(target.url, dns_only=True)[2])[:8]
            except AuthorizationError as exc:
                if exc.code in {"policy_changed", "invalid_policy", "unsupported_policy", "invalid_campaign_binding"}:
                    return _passive_denial(campaign_id, exc)
                item["dns_error"] = exc.code
        results.append(item)
    try:
        _, root_decision = _current_root_policy(root_target, grant.fingerprint)
    except AuthorizationError as exc:
        return _passive_denial(campaign_id, exc)
    for cache, contents in caches.items():
        try:
            atomic_write_bytes(cache, json.dumps(contents).encode(), maximum=MAX_PROVIDER_BYTES)
        except (OSError, SafeIOError):
            failures.append({"provider": contents["provider"], "error": "Provider cache could not be written safely."})
    wildcard_authorized = any(item["scope_classification"] == "wildcard_in_scope" for item in results)
    payload = {"ok": bool(results or not failures), "campaign_id": campaign_id, "root_domain": root, "providers": selected, "results": results, "count": len(results), "truncated": truncated, "partial_failures": failures, "candidate_rejections": candidate_rejections, "resolve_dns": resolve_dns, "wildcard_authorized": wildcard_authorized, "privacy_note": "Provider queries are external passive-discovery requests; discovered hosts were not contacted by HTTP.", "manual_validation_required": True}
    try:
        _current_root_policy(root_target, grant.fingerprint)
    except AuthorizationError as exc:
        return _passive_denial(campaign_id, exc)
    envelope = artifact_envelope(campaign_id, "discover_subdomains_passive_for_campaign", payload, truncation_status={"truncated": truncated}, limits_applied={"max_results": maximum, "max_provider_bytes": MAX_PROVIDER_BYTES})
    try:
        saved = write_json_artifact(directory / f"{file_timestamp()}-passive-{root}.json", envelope)
    except (SafeIOError, OSError) as exc:
        write_audit_event(campaign_id, "discover_subdomains_passive_for_campaign", target=root, ok=False, scope_decision=root_decision, warnings=[str(exc)])
        return {"ok": False, "error": f"Could not save passive discovery: {exc}"}
    nodes = [{"id": "root", "node_type": "host", "normalized_value": root, "scope_decision": root_decision, "confidence": "high"}]
    edges = []
    for index, item in enumerate(results):
        node_id = f"sub-{index}"
        nodes.append({"id": node_id, "node_type": "subdomain_candidate", "normalized_value": item["host"], "scope_decision": item["scope_decision"], "confidence": "medium", "source_artifact_path": saved["path"], "metadata": {"providers": ",".join(item["providers"])}})
        edges.append({"source": node_id, "destination": "root", "edge_type": "child_of", "evidence_path": saved["path"], "confidence": "high"})
    add_evidence_batch(campaign_id, "discover_subdomains_passive_for_campaign", nodes, edges)
    write_audit_event(campaign_id, "discover_subdomains_passive_for_campaign", target=root, ok=payload["ok"], scope_decision=root_decision, result_path=saved["path"], warnings=[item["error"] for item in failures], metadata={"count": len(results), "truncated": truncated, "resolve_dns": resolve_dns})
    return {**payload, **saved}
