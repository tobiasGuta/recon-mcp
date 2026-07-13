"""Campaign-scoped, redacted recon evidence graph."""

from __future__ import annotations

import hashlib
import json
import uuid
from pathlib import Path
from typing import Any

from recon.audit import write_audit_event
from recon.campaigns import get_campaign_paths, iso_now
from recon.safeio import SafeIOError, read_bytes_bounded, safe_campaign_path, write_artifact_bytes
from recon.redaction import redact_endpoint, redact_structure, redact_text

SCHEMA_VERSION = "1.0"
NODE_TYPES = {"campaign", "scope_asset", "host", "url", "html_page", "javascript_bundle", "source_map", "extracted_source_file", "endpoint", "api_contract", "graphql_operation", "secret_candidate", "client_configuration", "header_observation", "robots_entry", "sitemap_entry", "subdomain_candidate", "dirfuzz_discovery", "finding_candidate", "negative_result", "evidence_note", "imported_request"}
EDGE_TYPES = {"discovered_from", "loaded_by", "references", "source_map_for", "extracted_from", "defines_endpoint", "calls_endpoint", "contains_candidate", "observed_on", "child_of", "resolved_to", "imported_from", "supports_finding", "contradicted_by", "duplicate_of", "changed_from"}
NAMESPACE = uuid.UUID("6d111e48-425d-4b42-a343-410ac93b8349")
MAX_GRAPH_BYTES = 20 * 1024 * 1024


def _paths(campaign_id: str) -> tuple[Path, Path]:
    paths = get_campaign_paths(campaign_id)
    if not paths.get("ok"):
        raise SafeIOError(str(paths.get("error")))
    directory = Path(paths["paths"]["recon"]["graph"])
    return directory / "evidence-graph.json", directory


def _empty(campaign_id: str) -> dict:
    return {"schema": "recon-mcp-evidence-graph", "schema_version": SCHEMA_VERSION, "campaign_id": campaign_id, "updated_at": iso_now(), "nodes": [], "edges": []}


def _load(campaign_id: str) -> dict:
    path, _ = _paths(campaign_id)
    if not path.exists():
        return _empty(campaign_id)
    try:
        graph = json.loads(read_bytes_bounded(path, MAX_GRAPH_BYTES))
    except (json.JSONDecodeError, SafeIOError) as exc:
        raise SafeIOError(f"Evidence graph is malformed: {exc}") from exc
    if graph.get("campaign_id") != campaign_id or not isinstance(graph.get("nodes"), list) or not isinstance(graph.get("edges"), list):
        raise SafeIOError("Evidence graph schema is invalid.")
    return graph


def _save(campaign_id: str, graph: dict) -> str:
    path, _ = _paths(campaign_id)
    graph["updated_at"] = iso_now()
    write_artifact_bytes(campaign_id, "evidence_graph", path, json.dumps(graph, indent=2, sort_keys=True).encode("utf-8") + b"\n", maximum=MAX_GRAPH_BYTES, limits_applied={"max_graph_bytes": MAX_GRAPH_BYTES})
    return str(path)


def _safe_metadata(metadata: dict | None) -> dict:
    metadata = redact_structure(metadata or {})
    result: dict[str, Any] = {}
    for key, value in (metadata or {}).items():
        lowered = str(key).lower()
        if any(term in lowered for term in ("secret", "token", "password", "authorization", "cookie", "body")) and "redacted" not in lowered and "fingerprint" not in lowered and not lowered.endswith("_present"):
            result[f"{key}_redacted"] = True
        elif isinstance(value, (str, int, float, bool, type(None))):
            result[str(key)] = value
    return result


def _fingerprint(node_type: str, normalized_value: str, source_artifact_path: str | None, metadata: dict) -> str:
    observation_discriminator = metadata.get("fingerprint_sha256") or ""
    data = f"{node_type}\0{normalized_value}\0{source_artifact_path or ''}\0{observation_discriminator}".encode()
    return hashlib.sha256(data).hexdigest()


def add_evidence_batch(campaign_id: str, tool: str, nodes: list[dict], edges: list[dict] | None = None) -> dict:
    """Upsert deterministic nodes and edges while retaining observation timestamps."""
    try:
        graph = _load(campaign_id)
    except SafeIOError as exc:
        write_audit_event(campaign_id, "add_evidence_batch", ok=False, warnings=[str(exc)])
        return {"ok": False, "error": str(exc)}
    by_id = {item["uuid"]: item for item in graph["nodes"] if isinstance(item, dict) and item.get("uuid")}
    aliases: dict[str, str] = {}
    added = updated = 0
    now = iso_now()
    for index, raw in enumerate(nodes[:5000]):
        node_type = str(raw.get("node_type") or "").lower()
        if node_type not in NODE_TYPES:
            continue
        normalized = str(raw.get("normalized_value") or "").strip()
        normalized = redact_endpoint(normalized) if normalized.lower().startswith(("http://", "https://", "/")) else redact_text(normalized)
        if not normalized:
            continue
        metadata = _safe_metadata(raw.get("metadata"))
        fingerprint = _fingerprint(node_type, normalized, raw.get("source_artifact_path"), metadata)
        node_id = str(uuid.uuid5(NAMESPACE, f"{campaign_id}:node:{fingerprint}"))
        aliases[str(raw.get("id") or index)] = node_id
        if node_id in by_id:
            observations = by_id[node_id].setdefault("observations", [])
            observations.append({"timestamp": now, "tool": tool, "source_artifact_path": raw.get("source_artifact_path")})
            updated += 1
            continue
        display = redact_text(raw.get("display_label") or normalized)[:200]
        node = {"uuid": node_id, "campaign_id": campaign_id, "node_type": node_type, "normalized_value": normalized, "display_label": display, "source_artifact_path": raw.get("source_artifact_path"), "created_by_tool": tool, "timestamp": now, "scope_decision": redact_structure(raw.get("scope_decision") or {}), "confidence": raw.get("confidence") or "unknown", "fingerprint_sha256": fingerprint, "manual_validation_required": bool(raw.get("manual_validation_required", True)), "metadata": metadata, "observations": [{"timestamp": now, "tool": tool, "source_artifact_path": raw.get("source_artifact_path")}]}
        graph["nodes"].append(node)
        by_id[node_id] = node
        added += 1
    edge_ids = {item.get("uuid") for item in graph["edges"] if isinstance(item, dict)}
    edge_added = 0
    for raw in (edges or [])[:10000]:
        edge_type = str(raw.get("edge_type") or "").lower()
        source = aliases.get(str(raw.get("source")), str(raw.get("source") or ""))
        destination = aliases.get(str(raw.get("destination")), str(raw.get("destination") or ""))
        if edge_type not in EDGE_TYPES or source not in by_id or destination not in by_id:
            continue
        fingerprint = hashlib.sha256(f"{source}\0{destination}\0{edge_type}\0{raw.get('evidence_path') or ''}".encode()).hexdigest()
        edge_id = str(uuid.uuid5(NAMESPACE, f"{campaign_id}:edge:{fingerprint}"))
        if edge_id in edge_ids:
            continue
        graph["edges"].append({"uuid": edge_id, "source_node": source, "destination_node": destination, "edge_type": edge_type, "discovery_tool": tool, "timestamp": now, "evidence_path": raw.get("evidence_path"), "confidence": raw.get("confidence") or "unknown"})
        edge_ids.add(edge_id)
        edge_added += 1
    try:
        path = _save(campaign_id, graph)
    except SafeIOError as exc:
        write_audit_event(campaign_id, "add_evidence_batch", ok=False, warnings=[str(exc)], metadata={"source_tool": tool})
        return {"ok": False, "error": str(exc)}
    write_audit_event(campaign_id, "add_evidence_batch", ok=True, result_path=path, metadata={"source_tool": tool, "nodes_added": added, "nodes_observed": updated, "edges_added": edge_added})
    return {"ok": True, "path": path, "nodes_added": added, "nodes_observed": updated, "edges_added": edge_added, "node_ids": aliases}


def get_evidence_graph_summary(campaign_id: str) -> dict:
    try:
        graph = _load(campaign_id)
    except SafeIOError as exc:
        write_audit_event(campaign_id, "get_evidence_graph_summary", ok=False, warnings=[str(exc)])
        return {"ok": False, "error": str(exc)}
    counts: dict[str, int] = {}
    for node in graph["nodes"]:
        counts[node["node_type"]] = counts.get(node["node_type"], 0) + 1
    edge_counts: dict[str, int] = {}
    for edge in graph["edges"]:
        edge_counts[edge["edge_type"]] = edge_counts.get(edge["edge_type"], 0) + 1
    write_audit_event(campaign_id, "get_evidence_graph_summary", ok=True, metadata={"node_count": len(graph["nodes"]), "edge_count": len(graph["edges"])})
    return {"ok": True, "campaign_id": campaign_id, "schema_version": graph["schema_version"], "node_count": len(graph["nodes"]), "edge_count": len(graph["edges"]), "nodes_by_type": counts, "edges_by_type": edge_counts}


def query_evidence_graph(campaign_id: str, node_uuid: str, depth: int = 1, limit: int = 100) -> dict:
    depth = max(0, min(int(depth), 3))
    maximum = max(1, min(int(limit), 500))
    try:
        graph = _load(campaign_id)
        uuid.UUID(node_uuid)
    except (SafeIOError, ValueError) as exc:
        write_audit_event(campaign_id, "query_evidence_graph", target=node_uuid, ok=False, warnings=[str(exc)])
        return {"ok": False, "error": str(exc)}
    by_id = {node["uuid"]: node for node in graph["nodes"]}
    if node_uuid not in by_id:
        write_audit_event(campaign_id, "query_evidence_graph", target=node_uuid, ok=False, warnings=["Graph node not found."])
        return {"ok": False, "error": "Graph node not found."}
    selected = {node_uuid}
    selected_edges: list[dict] = []
    frontier = {node_uuid}
    for _ in range(depth):
        next_frontier: set[str] = set()
        for edge in graph["edges"]:
            if edge["source_node"] in frontier or edge["destination_node"] in frontier:
                selected_edges.append(edge)
                next_frontier.update((edge["source_node"], edge["destination_node"]))
                if len(selected | next_frontier) >= maximum:
                    break
        selected |= next_frontier
        frontier = next_frontier
        if len(selected) >= maximum:
            break
    truncated = len(selected) >= maximum
    nodes = [by_id[item] for item in list(selected)[:maximum] if item in by_id]
    edges = [edge for edge in selected_edges if edge["source_node"] in selected and edge["destination_node"] in selected][: maximum * 2]
    write_audit_event(campaign_id, "query_evidence_graph", target=node_uuid, ok=True, metadata={"depth": depth, "limit": maximum, "truncated": truncated})
    return {"ok": True, "node_uuid": node_uuid, "nodes": nodes, "edges": edges, "truncated": truncated}


def import_dirfuzz_evidence_for_campaign(campaign_id: str, analysis_path: str | None = None) -> dict:
    paths = get_campaign_paths(campaign_id)
    if not paths.get("ok"):
        return {"ok": False, "error": paths.get("error")}
    root = Path(paths["paths"]["recon"]["dirfuzz"])
    try:
        candidates = [safe_campaign_path(campaign_id, analysis_path, allowed_root=root, require_file=True)] if analysis_path else [item for item in sorted(root.glob("*.json")) if item.is_file() and not item.is_symlink()]
    except SafeIOError as exc:
        write_audit_event(campaign_id, "import_dirfuzz_evidence_for_campaign", target=analysis_path, ok=False, warnings=[str(exc)])
        return {"ok": False, "error": str(exc)}
    nodes: list[dict] = []
    for path in candidates[:100]:
        try:
            payload = json.loads(read_bytes_bounded(path, 5 * 1024 * 1024))
        except (SafeIOError, json.JSONDecodeError):
            continue
        result = payload.get("result", payload) if isinstance(payload, dict) else {}
        observations = result.get("discoveries") or result.get("results") or result.get("interesting") or []
        for item in observations[:2000] if isinstance(observations, list) else []:
            value = str(item.get("url") or item.get("path") or "") if isinstance(item, dict) else str(item)
            value = redact_endpoint(value)
            if value:
                nodes.append({"node_type": "dirfuzz_discovery", "normalized_value": value, "source_artifact_path": str(path), "confidence": "medium", "manual_validation_required": True, "metadata": {"status_code": item.get("status_code") if isinstance(item, dict) else None}})
    result = add_evidence_batch(campaign_id, "import_dirfuzz_evidence_for_campaign", nodes)
    write_audit_event(campaign_id, "import_dirfuzz_evidence_for_campaign", ok=bool(result.get("ok")), metadata={"observations": len(nodes)})
    return result
