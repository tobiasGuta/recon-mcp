"""Bounded passive subdomain discovery through fixed public providers."""

from __future__ import annotations

import json
import re
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import quote

import httpx

from recon.audit import write_audit_event
from recon.campaigns import file_timestamp, get_campaign_paths
from recon.evidence_graph import add_evidence_batch
from recon.http_fetch import _read_bounded
from recon.safeio import SafeIOError, artifact_envelope, atomic_write_bytes, read_bytes_bounded, write_json_artifact
from recon.scope import get_scope_map, is_private_or_loopback_host, normalize_domain, resolve_scope_target

PROVIDERS = {"certificate_transparency", "alienvault_otx"}
HOST_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])$")
MAX_PROVIDER_BYTES = 5 * 1024 * 1024
CACHE_SECONDS = 3600


def _provider_url(provider: str, root: str) -> str:
    if provider == "certificate_transparency":
        return f"https://crt.sh/?q=%25.{quote(root)}&output=json"
    return f"https://otx.alienvault.com/api/v1/indicators/domain/{quote(root)}/passive_dns"


def _query(provider: str, root: str) -> list[str]:
    last_error: Exception | None = None
    data = None
    for attempt in range(2):
        try:
            with httpx.Client(timeout=12.0, follow_redirects=False, headers={"User-Agent": "ReconMCP/0.1 passive-discovery"}) as client:
                request = client.build_request("GET", _provider_url(provider, root))
                response = client.send(request, stream=True)
                try:
                    response.raise_for_status()
                    data = json.loads(_read_bounded(response, MAX_PROVIDER_BYTES, content_type=f"{provider} provider"))
                finally:
                    response.close()
            break
        except (httpx.HTTPError, ValueError, json.JSONDecodeError) as exc:
            last_error = exc
            if attempt == 0:
                time.sleep(0.2)
    if data is None:
        raise ValueError(f"Provider query failed after 2 attempts: {last_error}")
    if provider == "certificate_transparency":
        return [name for item in data if isinstance(item, dict) for name in str(item.get("name_value") or "").splitlines()]
    return [str(item.get("hostname") or "") for item in data.get("passive_dns", []) if isinstance(item, dict)] if isinstance(data, dict) else []


def _root_authorization(root: str) -> tuple[bool, bool, dict]:
    decision = resolve_scope_target(root)
    wildcard = decision.get("match_type") == "wildcard"
    scope_map = get_scope_map()
    for item in scope_map.get("entries", []):
        asset = str(item.get("asset_identifier") or item.get("host") or item.get("value") or "")
        host = normalize_domain(asset[2:] if asset.startswith("*.") else asset)
        is_wildcard = bool(item.get("wildcard") or asset.startswith("*.") or item.get("match_type") == "wildcard")
        if host == root and is_wildcard:
            wildcard = True
            return True, True, decision
    return bool(decision.get("in_scope")), wildcard, decision


def _resolve_public(host: str) -> list[str]:
    values: set[str] = set()
    for item in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM):
        ip = item[4][0]
        if not is_private_or_loopback_host(ip):
            values.add(ip)
    return sorted(values)[:8]


def discover_subdomains_passive_for_campaign(campaign_id: str, root_domain: str, providers: list[str] | None = None, max_results: int = 500, resolve_dns: bool = False) -> dict:
    root = normalize_domain(root_domain)
    authorized, wildcard_authorized, root_decision = _root_authorization(root)
    if not HOST_RE.fullmatch(root) or not authorized:
        result = {"ok": False, "error": "root_domain is malformed or does not correspond to an authorized scope asset.", "scope_decision": root_decision}
        write_audit_event(campaign_id, "discover_subdomains_passive_for_campaign", target=root_domain, ok=False, scope_decision=root_decision, warnings=[result["error"]])
        return result
    selected = providers or ["certificate_transparency", "alienvault_otx"]
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
    failures: list[dict] = []
    for provider in selected:
        cache = directory / f"cache-{provider}-{root}.json"
        names: list[str] | None = None
        if cache.exists() and not cache.is_symlink() and time.time() - cache.stat().st_mtime < CACHE_SECONDS:
            try:
                cached = json.loads(read_bytes_bounded(cache, MAX_PROVIDER_BYTES))
                names = cached.get("names", [])
            except (OSError, json.JSONDecodeError):
                names = None
        if names is None:
            try:
                names = _query(provider, root)
                atomic_write_bytes(cache, json.dumps({"provider": provider, "root": root, "queried_at": time.time(), "names": names[:10000]}).encode())
            except (httpx.HTTPError, ValueError, json.JSONDecodeError, OSError) as exc:
                failures.append({"provider": provider, "error": str(exc)[:300]})
                continue
        for raw in names:
            value = normalize_domain(str(raw).removeprefix("*."))
            if value != root and value.endswith(f".{root}") and HOST_RE.fullmatch(value):
                all_names.setdefault(value, set()).add(provider)
    truncated = len(all_names) > maximum
    results: list[dict] = []
    for host in sorted(all_names)[:maximum]:
        decision = resolve_scope_target(host)
        classification = "wildcard_in_scope" if wildcard_authorized and decision.get("in_scope") else "exact_in_scope" if decision.get("match_type") == "exact" else "out_of_scope"
        results.append({"host": host, "providers": sorted(all_names[host]), "queried_at": time.time(), "scope_classification": classification, "scope_decision": decision, "testable": classification in {"exact_in_scope", "wildcard_in_scope"}, "manual_validation_required": True})
    if resolve_dns and results:
        with ThreadPoolExecutor(max_workers=min(8, len(results))) as pool:
            futures = {pool.submit(_resolve_public, item["host"]): item for item in results}
            for future in as_completed(futures):
                item = futures[future]
                try:
                    item["resolved_public_ips"] = future.result()
                except OSError as exc:
                    item["dns_error"] = str(exc)[:200]
    payload = {"ok": bool(results or not failures), "campaign_id": campaign_id, "root_domain": root, "providers": selected, "results": results, "count": len(results), "truncated": truncated, "partial_failures": failures, "resolve_dns": resolve_dns, "wildcard_authorized": wildcard_authorized, "privacy_note": "Provider queries are external passive-discovery requests; discovered hosts were not contacted by HTTP.", "manual_validation_required": True}
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
