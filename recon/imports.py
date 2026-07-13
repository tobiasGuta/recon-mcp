"""Safe, non-replaying HAR and Burp XML campaign imports."""

from __future__ import annotations

import base64
import json
import re
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

from defusedxml import ElementTree as ET
from defusedxml.common import DefusedXmlException

from recon.audit import write_audit_event
from recon.campaigns import file_timestamp, get_campaign_paths
from recon.evidence_graph import add_evidence_batch
from recon.safeio import SafeIOError, artifact_envelope, limit, read_bytes_bounded, safe_campaign_path, write_json_artifact
from recon.scope import resolve_scope_target
from recon.redaction import redact_url

MAX_IMPORT_BYTES = 50 * 1024 * 1024
MAX_ENTRIES = 5000
MAX_PARAMETERS = 200
SENSITIVE_NAMES = re.compile(r"(?i)(token|secret|password|passwd|authorization|cookie|session|csrf|xsrf|api[_-]?key|signature)")


def _names_from_json(data: bytes, content_type: str) -> list[str]:
    if len(data) > 256 * 1024 or "json" not in content_type.lower():
        return []
    try:
        value = json.loads(data)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return []
    if isinstance(value, dict):
        return sorted(str(key)[:100] for key in value)[:MAX_PARAMETERS]
    return []


def _observation(url: str, method: str, status: int | None, content_type: str | None, *, query_names: list[str] | None = None, request_fields: list[str] | None = None, response_fields: list[str] | None = None, header_names: list[str] | None = None, cookie_names: list[str] | None = None, source: str) -> dict:
    parts = urlsplit(url)
    decision = resolve_scope_target(url)
    query = query_names or [name for name, _ in parse_qsl(parts.query, keep_blank_values=True)]
    sensitive_query = sorted({name for name in query if SENSITIVE_NAMES.search(name)})
    scope_summary = {key: decision.get(key) for key in ("ok", "normalized_host", "in_scope", "match_type", "matched_scope", "matched_asset", "reason_code", "reason", "submission_eligible", "bounty_eligible")}
    safe_url = redact_url(url, redact_all_query_values=True)
    safe_parts = urlsplit(safe_url)
    safe_url = safe_parts._replace(query="").geturl()[:500]
    return {"host": parts.hostname, "url": safe_url, "method": method.upper(), "path": parts.path, "status_code": status, "content_type": content_type, "query_parameter_names": sorted(set(query))[:MAX_PARAMETERS], "sensitive_query_values_redacted": sensitive_query, "request_body_field_names": sorted(set(request_fields or []))[:MAX_PARAMETERS], "response_body_field_names": sorted(set(response_fields or []))[:MAX_PARAMETERS], "authentication_mechanisms_present": sorted({name for name in header_names or [] if name.lower() in {"authorization", "proxy-authorization", "x-api-key"}}), "cookie_names": sorted(set(cookie_names or []))[:MAX_PARAMETERS], "scope_decision": scope_summary, "scope_classification": "in_scope" if decision.get("in_scope") else "excluded_out_of_scope", "active_target": False, "source_import": source, "manual_validation_required": True}


def _save(campaign_id: str, tool: str, source: Path, observations: list[dict], truncated: bool, warnings: list[str]) -> dict:
    paths = get_campaign_paths(campaign_id)
    payload = {"ok": True, "campaign_id": campaign_id, "source_file": source.name, "observations": observations, "count": len(observations), "truncated": truncated, "warnings": warnings, "replayed": False, "manual_validation_required": True, "safety_note": "Imported traffic was summarized and redacted; no request was replayed."}
    envelope = artifact_envelope(campaign_id, tool, payload, truncation_status={"truncated": truncated}, limits_applied={"max_input_bytes": MAX_IMPORT_BYTES, "max_entries": MAX_ENTRIES, "max_parameters": MAX_PARAMETERS})
    try:
        saved = write_json_artifact(Path(paths["paths"]["recon"]["imports"]) / f"{file_timestamp()}-{tool}.json", envelope)
    except (SafeIOError, OSError) as exc:
        write_audit_event(campaign_id, tool, target=source.name, ok=False, warnings=[str(exc)])
        return {"ok": False, "error": f"Could not save imported observations: {exc}"}
    nodes = [{"node_type": "imported_request", "normalized_value": f"{item['method']} {item['url']}", "source_artifact_path": saved["path"], "scope_decision": item["scope_decision"], "confidence": "high", "metadata": {"status_code": item["status_code"], "source": source.name}} for item in observations]
    add_evidence_batch(campaign_id, tool, nodes)
    write_audit_event(campaign_id, tool, target=source.name, ok=True, result_path=saved["path"], warnings=warnings, metadata={"count": len(observations), "truncated": truncated, "replayed": False})
    return {**payload, **saved}


def _input_path(campaign_id: str, value: str) -> Path:
    paths = get_campaign_paths(campaign_id)
    if not paths.get("ok"):
        raise SafeIOError(str(paths.get("error")))
    campaign = Path(paths["paths"]["root"])
    return safe_campaign_path(campaign_id, value, allowed_root=campaign, require_file=True)


def import_har_for_campaign(campaign_id: str, har_path: str) -> dict:
    try:
        path = _input_path(campaign_id, har_path)
        data = json.loads(read_bytes_bounded(path, MAX_IMPORT_BYTES))
    except (SafeIOError, OSError, json.JSONDecodeError) as exc:
        write_audit_event(campaign_id, "import_har_for_campaign", target=Path(har_path).name, ok=False, warnings=[str(exc)])
        return {"ok": False, "error": f"HAR import rejected: {exc}"}
    entries = data.get("log", {}).get("entries") if isinstance(data, dict) else None
    if not isinstance(entries, list):
        write_audit_event(campaign_id, "import_har_for_campaign", target=path.name, ok=False, warnings=["HAR log.entries must be a list."])
        return {"ok": False, "error": "HAR log.entries must be a list."}
    observations: list[dict] = []
    warnings: list[str] = []
    for entry in entries[:MAX_ENTRIES]:
        if not isinstance(entry, dict):
            continue
        request = entry.get("request") if isinstance(entry.get("request"), dict) else {}
        response = entry.get("response") if isinstance(entry.get("response"), dict) else {}
        url = str(request.get("url") or "")
        if not urlsplit(url).hostname:
            continue
        request_content = request.get("postData") if isinstance(request.get("postData"), dict) else {}
        response_content = response.get("content") if isinstance(response.get("content"), dict) else {}
        request_fields = [str(item.get("name")) for item in request_content.get("params", []) if isinstance(item, dict) and item.get("name")]
        if not request_fields and isinstance(request_content.get("text"), str) and len(request_content["text"]) <= 256 * 1024:
            request_fields = _names_from_json(request_content["text"].encode(), str(request_content.get("mimeType") or ""))
        response_fields: list[str] = []
        response_text = response_content.get("text")
        if isinstance(response_text, str) and len(response_text) <= 256 * 1024 and response_content.get("encoding") != "base64":
            response_fields = _names_from_json(response_text.encode(), str(response_content.get("mimeType") or ""))
        observations.append(_observation(url, str(request.get("method") or "GET"), response.get("status") if isinstance(response.get("status"), int) else None, str(response_content.get("mimeType") or ""), query_names=[str(item.get("name")) for item in request.get("queryString", []) if isinstance(item, dict) and item.get("name")], request_fields=request_fields, response_fields=response_fields, header_names=[str(item.get("name")) for item in request.get("headers", []) if isinstance(item, dict)], cookie_names=[str(item.get("name")) for item in request.get("cookies", []) if isinstance(item, dict) and item.get("name")], source=path.name))
    return _save(campaign_id, "import_har_for_campaign", path, observations, len(entries) > MAX_ENTRIES, warnings)


def _decode_burp(value: str, encoded: bool) -> bytes:
    if not encoded:
        return value.encode("utf-8", errors="replace")
    try:
        return base64.b64decode(value, validate=True)
    except ValueError:
        return b""


def import_burp_xml_for_campaign(campaign_id: str, xml_path: str) -> dict:
    try:
        path = _input_path(campaign_id, xml_path)
        raw = read_bytes_bounded(path, MAX_IMPORT_BYTES)
        root = ET.fromstring(raw)
    except (SafeIOError, OSError, ET.ParseError, DefusedXmlException) as exc:
        write_audit_event(campaign_id, "import_burp_xml_for_campaign", target=Path(xml_path).name, ok=False, warnings=[str(exc)])
        return {"ok": False, "error": f"Burp XML import rejected: {exc}"}
    observations: list[dict] = []
    items = list(root.findall(".//item"))
    for item in items[:MAX_ENTRIES]:
        url = item.findtext("url") or ""
        if not urlsplit(url).hostname:
            continue
        request_element = item.find("request")
        request_bytes = _decode_burp(request_element.text or "", request_element is not None and request_element.get("base64") == "true") if request_element is not None else b""
        header_blob = request_bytes[: min(len(request_bytes), 64 * 1024)].split(b"\r\n\r\n", 1)[0].decode("latin-1", errors="replace")
        header_names = [line.split(":", 1)[0] for line in header_blob.splitlines()[1:] if ":" in line]
        cookie_names: list[str] = []
        for line in header_blob.splitlines():
            if line.lower().startswith("cookie:"):
                cookie_names.extend(part.split("=", 1)[0].strip() for part in line.split(":", 1)[1].split(";") if "=" in part)
        observations.append(_observation(url, item.findtext("method") or "GET", int(item.findtext("status") or 0) or None, item.findtext("mimetype"), header_names=header_names, cookie_names=cookie_names, source=path.name))
    return _save(campaign_id, "import_burp_xml_for_campaign", path, observations, len(items) > MAX_ENTRIES, [])
