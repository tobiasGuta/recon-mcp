"""Deterministic API-contract extraction from campaign-local client sources."""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

from recon.audit import write_audit_event
from recon.campaigns import file_timestamp, get_campaign_paths
from recon.endpoint_scoring import score_endpoint
from recon.evidence_graph import add_evidence_batch
from recon.redaction import redact_endpoint, redact_text
from recon.safeio import SafeIOError, artifact_envelope, limit, read_text_bounded, safe_campaign_path, write_json_artifact

SUFFIXES = {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".vue", ".svelte"}
FETCH = re.compile(r"fetch\s*\(\s*([`'\"])(?P<url>.*?)(?<!\\)\1\s*(?:,\s*\{(?P<opts>.{0,3000})\})?\s*\)", re.S)
AXIOS_METHOD = re.compile(r"axios\s*\.\s*(?P<method>get|post|put|patch|delete|head|options)\s*\(\s*([`'\"])(?P<url>.*?)(?<!\\)\2(?P<rest>.{0,3000}?)\)", re.I | re.S)
AXIOS_CONFIG = re.compile(r"axios\s*\(\s*\{(?P<opts>.{0,4000}?)\}\s*\)", re.S)
ANGULAR = re.compile(r"\.(?P<method>get|post|put|patch|delete)\s*(?:<[^>]+>)?\s*\(\s*([`'\"])(?P<url>.*?)(?<!\\)\2(?P<rest>.{0,3000}?)\)", re.I | re.S)
XHR_OPEN = re.compile(r"\.open\s*\(\s*['\"](?P<method>[A-Z]+)['\"]\s*,\s*([`'\"])(?P<url>.*?)(?<!\\)\2", re.I | re.S)
WEBSOCKET = re.compile(r"new\s+WebSocket\s*\(\s*([`'\"])(?P<url>.*?)(?<!\\)\1", re.S)
GRAPHQL = re.compile(r"\b(?P<kind>query|mutation|subscription)\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)", re.I)
OPENAPI_REF = re.compile(r"([`'\"])(?P<url>(?:https?://[^`'\"]+|/[^`'\"]*?(?:openapi|swagger)[^`'\"]*?\.(?:json|ya?ml)))(?<!\\)\1", re.I)
REQUEST_WRAPPER = re.compile(r"\b(?P<client>api|client|request|http)\s*\(\s*([`'\"])(?P<url>.*?)(?<!\\)\2(?P<rest>.{0,2000}?)\)", re.I | re.S)
HEADER_NAME = re.compile(r"(?i)(?:^|[,;{])\s*['\"]?([A-Za-z][A-Za-z0-9-]{1,60})['\"]?\s*:")
OBJECT_KEY = re.compile(r"(?:^|[,;{])\s*(?:['\"]([^'\"]+)['\"]|([A-Za-z_$][\w$]*))\s*(?=[:},]|$)")
SECRET = re.compile(r"(?i)((?:['\"]?authorization['\"]?)\s*[:=]\s*['\"])[^'\"]+|((?:['\"]?(?:token|secret|password|cookie)['\"]?)\s*[:=]\s*['\"])[^'\"]+")


def _preview(value: str) -> str:
    value = " ".join(value.split())
    value = SECRET.sub(lambda match: (match.group(1) or match.group(2) or "") + "<redacted>", value)
    return redact_text(value)[:300]


def _location(text: str, offset: int) -> tuple[int, int]:
    line = text.count("\n", 0, offset) + 1
    last = text.rfind("\n", 0, offset)
    return line, offset - last


def _uncertainty(url: str) -> tuple[str, list[str]]:
    segments = re.findall(r"\$\{([^}]+)\}", url)
    if not segments:
        return "static", []
    static_chars = len(re.sub(r"\$\{[^}]+\}", "", url))
    return ("partially_dynamic" if static_chars else "fully_dynamic"), segments


def _body_fields(fragment: str) -> list[str]:
    stringify = re.search(r"JSON\.stringify\s*\(\s*\{(?P<body>.{0,2000}?)\}\s*\)", fragment, re.S)
    body = stringify.group("body") if stringify else ""
    if not body:
        literal = re.search(r"(?:data|body)\s*:\s*\{(?P<body>.{0,2000}?)\}", fragment, re.S)
        body = literal.group("body") if literal else ""
    if not body:
        direct = re.search(r"^\s*,?\s*\{(?P<body>.{0,2000}?)\}", fragment, re.S)
        body = direct.group("body") if direct else ""
    fields = {(match.group(1) or match.group(2)) for match in OBJECT_KEY.finditer(body)}
    return sorted(item for item in fields if item and item.lower() not in {"headers", "method"})[:100]


def _contract(text: str, path: Path, match: re.Match[str], client: str, method: str, url: str, fragment: str) -> dict:
    line, column = _location(text, match.start())
    uncertainty, dynamic = _uncertainty(url)
    parsed = urlsplit(url if not url.startswith("/") else f"https://placeholder.invalid{url}")
    query = sorted({name for name, _ in parse_qsl(parsed.query, keep_blank_values=True)})
    query.extend(name for name in re.findall(r"[?&]([A-Za-z_$][\w$]*)=\$\{", url) if name not in query)
    path_params = sorted(set(re.findall(r"(?::|\{)([A-Za-z_][\w-]*)(?:\}|(?=/|$))", parsed.path)))
    headers_match = re.search(r"headers\s*:\s*\{(?P<headers>.{0,1500}?)\}", fragment, re.S | re.I)
    headers = sorted({m.group(1) for m in HEADER_NAME.finditer(headers_match.group("headers") if headers_match else "")})
    auth = any(name.lower() in {"authorization", "proxy-authorization", "cookie", "x-api-key"} for name in headers)
    fields = _body_fields(fragment)
    content_type = next(("application/json" for item in headers if item.lower() == "content-type" and "json" in fragment.lower()), None)
    body_encoding = "json" if "JSON.stringify" in fragment or fields else ("form_data" if "FormData" in fragment else "urlencoded" if "URLSearchParams" in fragment else "unknown")
    confidence = "high" if uncertainty == "static" and method != "UNKNOWN" else "medium" if uncertainty == "partially_dynamic" else "low"
    url = redact_endpoint(url)
    static_endpoint = re.sub(r"\$\{[^}]+\}", "{dynamic}", url)
    score = score_endpoint({"value": static_endpoint, "method": method}).get("score", 0)
    return {
        "endpoint": static_endpoint, "endpoint_expression": url, "endpoint_uncertainty": uncertainty,
        "unresolved_dynamic_segments": dynamic, "method": method.upper(), "query_parameters": sorted(set(query)),
        "path_parameters": path_params, "body_fields": fields, "body_encoding": body_encoding,
        "content_type": content_type, "headers": headers, "authentication_header_present": auth,
        "authentication_value_redacted": auth, "client": client, "source_file": path.as_posix(),
        "line": line, "column": column, "confidence": confidence,
        "confidence_reason": "Static client call and method." if confidence == "high" else "Dynamic construction prevents full reconstruction.",
        "evidence_preview": _preview(match.group(0)), "priority_score": score,
        "manual_validation_required": True,
    }


def extract_contracts_from_text(text: str, source_file: str = "source.js") -> list[dict]:
    """Extract bounded, explicitly uncertain API contract candidates from source text."""
    path = Path(source_file)
    results: list[dict] = []
    for match in FETCH.finditer(text):
        opts = match.group("opts") or ""
        method_match = re.search(r"method\s*:\s*['\"]([A-Z]+)['\"]", opts, re.I)
        results.append(_contract(text, path, match, "fetch", method_match.group(1) if method_match else "GET", match.group("url"), opts))
    for match in AXIOS_METHOD.finditer(text):
        results.append(_contract(text, path, match, "axios", match.group("method"), match.group("url"), match.group("rest") or ""))
    for match in AXIOS_CONFIG.finditer(text):
        opts = match.group("opts") or ""
        url_match = re.search(r"url\s*:\s*([`'\"])(.*?)\1", opts, re.S | re.I)
        if not url_match:
            continue
        method_match = re.search(r"method\s*:\s*['\"]([A-Z]+)['\"]", opts, re.I)
        results.append(_contract(text, path, match, "axios", method_match.group(1) if method_match else "GET", url_match.group(2), opts))
    for match in ANGULAR.finditer(text):
        results.append(_contract(text, path, match, "angular_httpclient", match.group("method"), match.group("url"), match.group("rest") or ""))
    for match in XHR_OPEN.finditer(text):
        results.append(_contract(text, path, match, "xmlhttprequest", match.group("method"), match.group("url"), match.group(0)))
    for match in WEBSOCKET.finditer(text):
        results.append(_contract(text, path, match, "websocket", "GET", match.group("url"), match.group(0)))
    for match in REQUEST_WRAPPER.finditer(text):
        rest = match.group("rest") or ""
        method_match = re.search(r"method\s*:\s*['\"]([A-Z]+)['\"]", rest, re.I)
        results.append(_contract(text, path, match, f"request_wrapper:{match.group('client').lower()}", method_match.group(1) if method_match else "UNKNOWN", match.group("url"), rest))
    for match in OPENAPI_REF.finditer(text):
        results.append(_contract(text, path, match, "openapi_reference", "GET", match.group("url"), match.group(0)))
    for match in GRAPHQL.finditer(text):
        line, column = _location(text, match.start())
        results.append({"endpoint": None, "endpoint_expression": None, "endpoint_uncertainty": "unknown", "method": "POST", "query_parameters": [], "path_parameters": [], "body_fields": [], "body_encoding": "graphql", "content_type": "application/json", "headers": [], "authentication_header_present": False, "authentication_value_redacted": True, "client": "graphql", "graphql_operation_type": match.group("kind").lower(), "graphql_operation_name": match.group("name"), "source_file": path.as_posix(), "line": line, "column": column, "confidence": "high", "confidence_reason": "Named GraphQL operation parsed from source.", "evidence_preview": _preview(match.group(0)), "priority_score": 8 if match.group("kind").lower() == "mutation" else 4, "manual_validation_required": True})
    unique: dict[tuple, dict] = {}
    for item in results:
        key = (item.get("source_file"), item.get("line"), item.get("client"), item.get("endpoint_expression"), item.get("graphql_operation_name"))
        unique[key] = item
    return list(unique.values())


def extract_api_contracts_for_campaign(campaign_id: str, extracted_dir: str | None = None) -> dict:
    paths = get_campaign_paths(campaign_id)
    if not paths.get("ok"):
        return {"ok": False, "error": paths.get("error")}
    default_root = Path(paths["paths"]["recon"]["sourcemaps"]) / "extracted"
    try:
        root = safe_campaign_path(campaign_id, extracted_dir or default_root, allowed_root=default_root, require_dir=True)
    except SafeIOError as exc:
        write_audit_event(campaign_id, "extract_api_contracts_for_campaign", ok=False, warnings=[str(exc)])
        return {"ok": False, "error": str(exc)}
    max_files = limit("max_extracted_source_files")
    max_total = limit("max_total_extracted_source_bytes")
    max_results = limit("max_endpoint_candidates")
    contracts: list[dict] = []
    files = total = 0
    truncated = False
    warnings: list[str] = []
    for path in sorted(root.rglob("*")):
        if files >= max_files or len(contracts) >= max_results:
            truncated = True
            break
        if not path.is_file() or path.is_symlink() or path.suffix.lower() not in SUFFIXES:
            continue
        try:
            size = path.stat().st_size
            if size > limit("max_javascript_bytes") or total + size > max_total:
                truncated = True
                continue
            text = read_text_bounded(path, limit("max_javascript_bytes"))
        except (OSError, SafeIOError) as exc:
            warnings.append(f"Skipped {path.name}: {exc}")
            continue
        files += 1
        total += size
        for item in extract_contracts_from_text(text, path.relative_to(root).as_posix()):
            contracts.append(item)
            if len(contracts) >= max_results:
                truncated = True
                break
    contracts.sort(key=lambda item: (-int(item.get("priority_score", 0)), item.get("source_file", ""), item.get("line", 0)))
    payload = {"ok": True, "campaign_id": campaign_id, "contracts": contracts, "count": len(contracts), "files_analyzed": files, "bytes_analyzed": total, "truncated": truncated, "warnings": warnings, "manual_validation_required": True, "safety_note": "Contracts are deterministic recon leads, not validated request schemas or vulnerabilities."}
    envelope = artifact_envelope(campaign_id, "extract_api_contracts_for_campaign", payload, truncation_status={"truncated": truncated}, limits_applied={"max_files": max_files, "max_total_bytes": max_total, "max_results": max_results})
    try:
        saved = write_json_artifact(Path(paths["paths"]["recon"]["contracts"]) / f"{file_timestamp()}-api-contracts.json", envelope)
    except (OSError, SafeIOError) as exc:
        write_audit_event(campaign_id, "extract_api_contracts_for_campaign", ok=False, warnings=[str(exc)])
        return {"ok": False, "error": f"Could not save contract artifact: {exc}"}
    graph_nodes = []
    for item in contracts:
        node_type = "graphql_operation" if item.get("graphql_operation_name") else "api_contract"
        normalized = f"{item.get('method')}:{item.get('endpoint_expression') or ''}:{item.get('graphql_operation_name') or ''}:{item.get('source_file')}:{item.get('line')}"
        graph_nodes.append({"node_type": node_type, "normalized_value": normalized, "source_artifact_path": saved["path"], "confidence": item.get("confidence"), "metadata": {"endpoint": item.get("endpoint"), "method": item.get("method"), "source_file": item.get("source_file"), "line": item.get("line"), "uncertainty": item.get("endpoint_uncertainty")}})
    add_evidence_batch(campaign_id, "extract_api_contracts_for_campaign", graph_nodes)
    write_audit_event(campaign_id, "extract_api_contracts_for_campaign", ok=True, result_path=saved["path"], warnings=warnings, metadata={"count": len(contracts), "truncated": truncated, "artifact_uuid": saved["artifact_uuid"]})
    return {**payload, **saved}
