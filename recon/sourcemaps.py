"""Safe campaign-aware source map recon helpers."""

from __future__ import annotations

import json
import re
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit

import httpx

from recon import http_fetch
from recon.audit import write_audit_event
from recon.campaigns import file_timestamp, get_campaign_paths, slugify
from recon.endpoint_scoring import score_endpoints
from recon.js_analysis import extract_endpoints_from_js, parse_sourcemap_references
from recon.memory import record_negative_result
from recon.safeio import SafeIOError, atomic_write_bytes, limit, read_text_bounded, write_artifact_bytes, write_flat_json_artifact
from recon.scope import ScopeError, resolve_scope_target


MAX_SOURCEMAP_BYTES = 5 * 1024 * 1024
MAX_EXTRACTED_SOURCE_BYTES = 2 * 1024 * 1024
SAFE_TEXT_SUFFIXES = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".json", ".vue", ".svelte", ".html", ".txt"}
MANUAL_SIGNAL_TERMS = [
    "graphql",
    "openapi",
    "swagger",
    "admin",
    "internal",
    "debug",
    "staging",
    "dev",
    "featureFlag",
    "firebase",
    "sentry",
    "datadog",
    "apiKey",
    "token",
    "secret",
    "client_secret",
    "authorization",
    "bearer",
    "oauth",
    "redirect_uri",
    "reset-password",
    "password-reset",
]
SENSITIVE_VALUE_PATTERN = re.compile(
    r"""(?i)(api[_-]?key|token|secret|client_secret|authorization|bearer)\s*[:=]\s*["']?[^"',\s]{8,}"""
)


def _error(message: str) -> dict:
    return {"ok": False, "error": message}


def _safe_label(value: str) -> str:
    parsed = urlsplit(value)
    host = parsed.hostname or ""
    path = parsed.path.strip("/").replace("/", "-")
    label = f"{host}-{path}" if host else value
    return slugify(label, fallback="sourcemap", max_length=90)


def _reject_symlink(path: Path, label: str) -> str | None:
    if path.exists() and path.is_symlink():
        return f"{label} must not be a symlink."
    return None


def _sourcemap_dirs(campaign_id: str) -> dict:
    paths = get_campaign_paths(campaign_id)
    if not paths.get("ok"):
        return {"ok": False, "error": paths.get("error", "Could not load campaign paths.")}
    sourcemaps_root = Path(paths["paths"]["recon"]["sourcemaps"])
    root = Path(paths["paths"]["root"])
    recon_root = root / "recon"
    for label, path in (("Recon directory", recon_root), ("Source maps directory", sourcemaps_root)):
        error = _reject_symlink(path, label)
        if error:
            return {"ok": False, "error": error}
    try:
        sourcemaps_root.mkdir(parents=True, exist_ok=True)
        maps_dir = sourcemaps_root / "maps"
        extracted_dir = sourcemaps_root / "extracted"
        analysis_dir = sourcemaps_root / "analysis"
        for label, path in (
            ("Source map maps directory", maps_dir),
            ("Source map extracted directory", extracted_dir),
            ("Source map analysis directory", analysis_dir),
        ):
            error = _reject_symlink(path, label)
            if error:
                return {"ok": False, "error": error}
            path.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        return {"ok": False, "error": f"Could not create source map directories: {exc}"}
    return {
        "ok": True,
        "root": sourcemaps_root.resolve(),
        "maps": maps_dir.resolve(),
        "extracted": extracted_dir.resolve(),
        "analysis": analysis_dir.resolve(),
    }


def _write_json(path: Path, payload: dict) -> dict:
    try:
        campaign_id = str(payload.get("campaign_id") or "")
        if campaign_id:
            saved = write_flat_json_artifact(campaign_id, str(payload.get("tool") or "sourcemap_analysis"), path, payload, limits_applied={"max_saved_artifact_bytes": limit("max_saved_artifact_bytes")})
        else:
            atomic_write_bytes(path, (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8"), maximum=limit("max_saved_artifact_bytes"))
            saved = {"path": str(path)}
    except (OSError, SafeIOError) as exc:
        return _error(f"Could not write JSON artifact: {exc}")
    return {"ok": True, **saved}


def _analysis_path(dirs: dict, label: str) -> Path:
    return dirs["analysis"] / f"{file_timestamp()}-{slugify(label, fallback='sourcemap', max_length=90)}.json"


def detect_sourcemap_references(js_text: str, js_url: str | None = None) -> dict:
    """Detect sourceMappingURL references without downloading anything."""
    references = parse_sourcemap_references(js_text or "", js_url=js_url)
    warnings = ["Source map references require manual review; no vulnerability is implied."] if references else []
    return {"ok": True, "js_url": js_url, "references": references, "count": len(references), "warnings": warnings}


def detect_sourcemap_references_for_campaign(campaign_id: str, js_url: str) -> dict:
    """Fetch JS safely, detect source map references, and save campaign analysis."""
    dirs = _sourcemap_dirs(campaign_id)
    if not dirs.get("ok"):
        return dirs
    try:
        js_text = http_fetch.safe_get_text(js_url)
    except http_fetch.BoundedReadError as exc:
        result = {**exc.as_result(js_url), "campaign_id": campaign_id, "js_url": js_url}
        write_audit_event(campaign_id, "detect_sourcemap_references_for_campaign", target=js_url, ok=False, warnings=[result["error"]], metadata={"configured_maximum_bytes": exc.maximum, "bytes_observed": exc.observed, "rejected": True})
        return result
    except (ScopeError, httpx.HTTPError) as exc:
        result = {"ok": False, "campaign_id": campaign_id, "js_url": js_url, "error": f"Could not fetch JavaScript safely: {exc}"}
        write_audit_event(campaign_id, "detect_sourcemap_references_for_campaign", target=js_url, ok=False, warnings=[result["error"]])
        return result

    detection = detect_sourcemap_references(js_text, js_url=js_url)
    downloadable = []
    skipped = []
    for reference in detection["references"]:
        resolved_url = reference.get("resolved_url")
        if not resolved_url:
            skipped.append({**reference, "skip_reason": "No resolved URL to scope-check or download."})
            continue
        scope_decision = resolve_scope_target(resolved_url)
        item = {**reference, "scope_decision": scope_decision}
        if reference.get("safe_to_download") and scope_decision.get("in_scope"):
            downloadable.append(item)
        else:
            skipped.append({**item, "skip_reason": scope_decision.get("reason") or "Source map is not safe to download."})

    warnings = list(detection["warnings"])
    payload = {
        "ok": True,
        "campaign_id": campaign_id,
        "js_url": js_url,
        "references": detection["references"],
        "downloadable": downloadable,
        "skipped": skipped,
        "warnings": warnings,
    }
    path = _analysis_path(dirs, f"{_safe_label(js_url)}-sourcemap-detect")
    save = _write_json(path, payload)
    if not save.get("ok"):
        return save
    write_audit_event(
        campaign_id,
        "detect_sourcemap_references_for_campaign",
        target=js_url,
        ok=True,
        result_path=str(path),
        warnings=warnings,
        metadata={"detected_count": len(detection["references"]), "downloadable_count": len(downloadable)},
    )
    return {**payload, "path": str(path)}


def download_sourcemap_for_campaign(campaign_id: str, sourcemap_url: str) -> dict:
    """Download one in-scope source map using Recon MCP's safe HTTP path."""
    dirs = _sourcemap_dirs(campaign_id)
    if not dirs.get("ok"):
        return dirs
    scope_decision = resolve_scope_target(sourcemap_url)
    if not scope_decision.get("in_scope"):
        result = {"ok": False, "campaign_id": campaign_id, "sourcemap_url": sourcemap_url, "error": "Source map URL is out of scope.", "scope_decision": scope_decision}
        write_audit_event(campaign_id, "download_sourcemap_for_campaign", target=sourcemap_url, ok=False, scope_decision=scope_decision, warnings=[result["error"]])
        return result

    try:
        content, response = http_fetch.safe_get_bytes(sourcemap_url, limit("max_sourcemap_bytes"), content_type="source map")
    except http_fetch.BoundedReadError as exc:
        result = {**exc.as_result(sourcemap_url), "campaign_id": campaign_id, "sourcemap_url": sourcemap_url, "scope_decision": scope_decision}
        write_audit_event(campaign_id, "download_sourcemap_for_campaign", target=sourcemap_url, ok=False, scope_decision=scope_decision, warnings=[result["error"]], metadata={"configured_maximum_bytes": exc.maximum, "bytes_observed": exc.observed, "rejected": True})
        return result
    except (ScopeError, httpx.HTTPError) as exc:
        result = {"ok": False, "campaign_id": campaign_id, "sourcemap_url": sourcemap_url, "error": f"Could not download source map safely: {exc}", "scope_decision": scope_decision}
        write_audit_event(campaign_id, "download_sourcemap_for_campaign", target=sourcemap_url, ok=False, scope_decision=scope_decision, warnings=[result["error"]])
        return result

    try:
        sourcemap = json.loads(content.decode(response.encoding or "utf-8", errors="replace"))
    except json.JSONDecodeError as exc:
        return _error(f"Downloaded content is not valid JSON source map data: {exc}")
    if not isinstance(sourcemap, dict) or "version" not in sourcemap or not (sourcemap.get("sources") or sourcemap.get("sections")):
        return _error("Downloaded JSON does not look like a source map.")

    label = _safe_label(sourcemap_url)
    map_path = dirs["maps"] / f"{file_timestamp()}-{label}.map"
    metadata_path = _analysis_path(dirs, f"{label}-download")
    try:
        map_saved = write_artifact_bytes(campaign_id, "download_sourcemap_for_campaign", map_path, content, maximum=limit("max_sourcemap_bytes"), limits_applied={"max_sourcemap_bytes": limit("max_sourcemap_bytes")})
    except (OSError, SafeIOError) as exc:
        return _error(f"Could not save source map: {exc}")

    sources = _collect_sources(sourcemap)
    metadata = {
        "ok": True,
        "campaign_id": campaign_id,
        "sourcemap_url": sourcemap_url,
        "map_path": str(map_path),
        "size_bytes": len(content),
        "sources_count": len(sources),
        "has_sources_content": any(item.get("content") is not None for item in sources),
        "scope_decision": scope_decision,
        "warnings": [],
    }
    save = _write_json(metadata_path, metadata)
    if not save.get("ok"):
        return save
    write_audit_event(campaign_id, "download_sourcemap_for_campaign", target=sourcemap_url, ok=True, scope_decision=scope_decision, result_path=str(map_path))
    return {**metadata, "artifact_uuid": map_saved["artifact_uuid"], "artifact_sha256": map_saved["sha256"], "integrity_metadata_path": map_saved["metadata_path"], "metadata_path": str(metadata_path)}


def _collect_sources(sourcemap: dict) -> list[dict]:
    items = []
    if isinstance(sourcemap.get("sections"), list):
        for section in sourcemap["sections"]:
            nested = section.get("map") if isinstance(section, dict) else None
            if isinstance(nested, dict):
                items.extend(_collect_sources(nested))
        return items
    sources = sourcemap.get("sources") or []
    contents = sourcemap.get("sourcesContent") or []
    root = str(sourcemap.get("sourceRoot") or "")
    for index, source in enumerate(sources):
        content = contents[index] if index < len(contents) else None
        items.append({"source": str(source), "source_root": root, "content": content})
    return items


def _unsafe_source_path(raw_source: str) -> bool:
    normalized = raw_source.replace("\\", "/")
    return (
        normalized.startswith("/")
        or re.match(r"^[A-Za-z]:", raw_source) is not None
        or any(part == ".." for part in normalized.split("/"))
    )


def _safe_source_path(raw_source: str, index: int, used: set[str]) -> tuple[Path, str | None]:
    warning = None
    raw = (raw_source or f"source-{index}.js").replace("\\", "/")
    if "://" in raw:
        raw = raw.split("://", 1)[1]
    if _unsafe_source_path(raw_source):
        warning = f"Unsafe source path was sanitized: {raw_source}"
    parts = [part for part in PurePosixPath(raw).parts if part not in {"", ".", ".."}]
    safe_parts = []
    for part in parts[-6:]:
        suffix = Path(part).suffix
        stem = Path(part).stem if suffix else part
        safe = slugify(stem, fallback=f"source-{index}", max_length=60)
        if suffix and re.fullmatch(r"\.[A-Za-z0-9]{1,8}", suffix):
            safe += suffix.lower()
        safe_parts.append(safe)
    if not safe_parts:
        safe_parts = [f"source-{index}.txt"]
    candidate = Path(*safe_parts)
    base_name = str(candidate)
    suffix = 1
    while str(candidate).lower() in used:
        candidate = candidate.with_name(f"{candidate.stem}-{suffix}{candidate.suffix}")
        suffix += 1
    used.add(str(candidate).lower())
    return candidate, warning


def extract_sourcemap_sources_for_campaign(campaign_id: str, map_path: str) -> dict:
    """Extract embedded sourcesContent from a campaign-stored source map."""
    dirs = _sourcemap_dirs(campaign_id)
    if not dirs.get("ok"):
        return dirs
    maps_dir = dirs["maps"]
    raw_path = Path(map_path).expanduser()
    if raw_path.is_symlink():
        return _error("map_path must not be a symlink.")
    path = raw_path.resolve()
    if not path.is_relative_to(maps_dir):
        return _error("map_path must be inside the campaign source map maps directory.")
    if path.is_symlink():
        return _error("map_path must not be a symlink.")
    try:
        sourcemap = json.loads(read_text_bounded(path, limit("max_sourcemap_bytes")))
    except (OSError, json.JSONDecodeError, SafeIOError) as exc:
        return _error(f"Could not read source map: {exc}")
    if not isinstance(sourcemap, dict):
        return _error("Source map must be a JSON object.")

    warnings = []
    if sourcemap.get("sections"):
        warnings.append("Sectioned source maps are partially supported; nested map sources were extracted when embedded.")
    sources = _collect_sources(sourcemap)
    max_files = limit("max_extracted_source_files")
    max_total_bytes = limit("max_total_extracted_source_bytes")
    content_sources = [item for item in sources if item.get("content") is not None]
    total_source_bytes = sum(len(str(item.get("content")).encode("utf-8", errors="replace")) for item in content_sources)
    if len(content_sources) > max_files or total_source_bytes > max_total_bytes:
        result = {
            "ok": False,
            "error": "Source map extraction rejected because configured file or total-byte limits were exceeded.",
            "configured_max_files": max_files,
            "configured_max_total_bytes": max_total_bytes,
            "files_observed": len(content_sources),
            "bytes_observed": total_source_bytes,
            "truncated": False,
            "rejected": True,
        }
        write_audit_event(campaign_id, "extract_sourcemap_sources_for_campaign", ok=False, warnings=[result["error"]], metadata={key: value for key, value in result.items() if key not in {"error", "ok"}})
        return result
    map_slug = slugify(path.stem, fallback="sourcemap", max_length=90)
    extracted_dir = (dirs["extracted"] / map_slug).resolve()
    if not extracted_dir.is_relative_to(dirs["extracted"]):
        return _error("Unsafe extracted directory.")
    if extracted_dir.exists() and extracted_dir.is_symlink():
        return _error("Extracted directory must not be a symlink.")
    try:
        extracted_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        return _error(f"Could not create extracted directory: {exc}")

    used: set[str] = set()
    files_written = 0
    sources_without_content = 0
    source_index = []
    for index, source in enumerate(sources):
        relative, warning = _safe_source_path(source.get("source", ""), index, used)
        if warning:
            warnings.append(warning)
        destination = (extracted_dir / relative).resolve()
        if not destination.is_relative_to(extracted_dir):
            warnings.append(f"Skipped unsafe source path: {source.get('source')}")
            continue
        content = source.get("content")
        source_index.append({"source": source.get("source"), "source_root": source.get("source_root"), "extracted_path": str(destination) if content is not None else None})
        if content is None:
            sources_without_content += 1
            continue
        try:
            destination.parent.mkdir(parents=True, exist_ok=True)
            atomic_write_bytes(destination, str(content).encode("utf-8", errors="replace"), maximum=max_total_bytes)
            files_written += 1
        except OSError as exc:
            warnings.append(f"Could not write extracted source {source.get('source')}: {exc}")

    try:
        atomic_write_bytes(extracted_dir / "sources-index.json", (json.dumps(source_index, indent=2, sort_keys=True) + "\n").encode("utf-8"), maximum=limit("max_saved_artifact_bytes"))
    except (OSError, SafeIOError) as exc:
        warnings.append(f"Could not write source index: {exc}")

    metadata = {
        "ok": True,
        "campaign_id": campaign_id,
        "map_path": str(path),
        "extracted_dir": str(extracted_dir),
        "sources_count": len(sources),
        "files_written": files_written,
        "sources_without_content": sources_without_content,
        "warnings": warnings,
    }
    metadata_path = _analysis_path(dirs, f"{map_slug}-extract")
    save = _write_json(metadata_path, metadata)
    if not save.get("ok"):
        return save
    write_audit_event(campaign_id, "extract_sourcemap_sources_for_campaign", ok=True, result_path=str(metadata_path), warnings=warnings, metadata={"map_path": str(path)})
    return {**metadata, "metadata_path": str(metadata_path)}


def _safe_analysis_roots(dirs: dict, extracted_dir: str | None) -> tuple[list[Path], str | None]:
    extracted_root = dirs["extracted"]
    if extracted_dir:
        raw_root = Path(extracted_dir).expanduser()
        if raw_root.is_symlink():
            return [], "extracted_dir must not be a symlink."
        root = raw_root.resolve()
        if not root.is_relative_to(extracted_root):
            return [], "extracted_dir must be inside the campaign source map extracted directory."
        if root.is_symlink():
            return [], "extracted_dir must not be a symlink."
        return [root], None
    roots = []
    for path in extracted_root.iterdir():
        if path.is_dir() and not path.is_symlink():
            roots.append(path.resolve())
    return roots, None


def _redact_preview(line: str) -> str:
    preview = SENSITIVE_VALUE_PATTERN.sub(lambda match: f"{match.group(1)}=<redacted>", line.strip())
    preview = re.sub(r"""(?i)(bearer)\s+[A-Za-z0-9._~+/=-]{8,}""", r"\1 <redacted>", preview)
    return preview[:220]


def analyze_sourcemap_sources_for_campaign(campaign_id: str, extracted_dir: str | None = None) -> dict:
    """Analyze extracted source map files for endpoint and manual-review leads."""
    dirs = _sourcemap_dirs(campaign_id)
    if not dirs.get("ok"):
        return dirs
    roots, error = _safe_analysis_roots(dirs, extracted_dir)
    if error:
        return _error(error)

    files_analyzed = 0
    endpoint_candidates = []
    signals = []
    warnings = ["Signals are recon leads only; no vulnerability is implied."]
    for root in roots:
        for path in sorted(root.rglob("*")):
            if not path.is_file() or path.is_symlink() or path.suffix.lower() not in SAFE_TEXT_SUFFIXES:
                continue
            if path.name == "sources-index.json":
                continue
            try:
                if path.stat().st_size > min(MAX_EXTRACTED_SOURCE_BYTES, limit("max_javascript_bytes")):
                    warnings.append(f"Skipped oversized extracted source: {path.name}")
                    continue
                text = read_text_bounded(path, min(MAX_EXTRACTED_SOURCE_BYTES, limit("max_javascript_bytes")))
            except (OSError, SafeIOError) as exc:
                warnings.append(f"Could not read extracted source {path.name}: {exc}")
                continue
            files_analyzed += 1
            endpoints = extract_endpoints_from_js(text, source_type="raw")
            if endpoints.get("ok"):
                for endpoint in endpoints.get("endpoints", []):
                    endpoint_candidates.append({**endpoint, "file": str(path)})
            lower_lines = text.splitlines()
            for line_number, line in enumerate(lower_lines, start=1):
                lowered = line.lower()
                for term in MANUAL_SIGNAL_TERMS:
                    if term.lower() in lowered:
                        signals.append(
                            {
                                "file": str(path),
                                "line": line_number,
                                "type": term,
                                "preview": _redact_preview(line),
                                "manual_validation_required": True,
                            }
                        )
                        if len(signals) >= limit("max_analysis_signals"):
                            break
                if len(signals) >= limit("max_analysis_signals"):
                    break
            if len(endpoint_candidates) >= limit("max_endpoint_candidates") or len(signals) >= limit("max_analysis_signals"):
                warnings.append("Analysis results were truncated at configured limits.")
                break

    scored = score_endpoints([item.get("value", "") for item in endpoint_candidates]).get("endpoints", [])
    payload = {
        "ok": True,
        "campaign_id": campaign_id,
        "files_analyzed": files_analyzed,
        "endpoint_candidates": endpoint_candidates[: limit("max_endpoint_candidates")],
        "scored_endpoints": scored[: limit("max_endpoint_candidates")],
        "signals": signals[: limit("max_analysis_signals")],
        "warnings": warnings,
    }
    path = _analysis_path(dirs, "sourcemap-source-analysis")
    save = _write_json(path, payload)
    if not save.get("ok"):
        return save
    write_audit_event(
        campaign_id,
        "analyze_sourcemap_sources_for_campaign",
        ok=True,
        result_path=str(path),
        warnings=warnings,
        metadata={"files_analyzed": files_analyzed, "signals_count": len(signals), "endpoint_count": len(scored)},
    )
    return {**payload, "path": str(path)}


def sourcemap_workflow_for_campaign(campaign_id: str, js_url: str) -> dict:
    """Run safe detect, download, extract, and analyze steps for one JS URL."""
    detection = detect_sourcemap_references_for_campaign(campaign_id, js_url)
    if not detection.get("ok"):
        return detection
    if not detection.get("references"):
        record_negative_result(campaign_id, js_url, "sourcemap_discovery", "No source map reference found.")
        return {
            "ok": True,
            "campaign_id": campaign_id,
            "js_url": js_url,
            "detected_count": 0,
            "message": "No source map reference found.",
            "suggest_record_negative_result": True,
            "warnings": detection.get("warnings", []),
        }

    downloads = []
    extractions = []
    analyzed_dirs = []
    warnings = list(detection.get("warnings", []))
    for reference in detection.get("downloadable", []):
        download = download_sourcemap_for_campaign(campaign_id, reference["resolved_url"])
        if download.get("ok"):
            downloads.append(download)
            extraction = extract_sourcemap_sources_for_campaign(campaign_id, download["map_path"])
            if extraction.get("ok"):
                extractions.append(extraction)
                analyzed_dirs.append(extraction["extracted_dir"])
            else:
                warnings.append(extraction.get("error", "Source map extraction failed."))
        else:
            warnings.append(download.get("error", "Source map download failed."))

    analysis = analyze_sourcemap_sources_for_campaign(campaign_id) if extractions else {"files_analyzed": 0, "scored_endpoints": [], "signals": [], "warnings": []}
    warnings.extend(analysis.get("warnings", []))
    summary = {
        "ok": True,
        "campaign_id": campaign_id,
        "js_url": js_url,
        "detected_count": len(detection.get("references", [])),
        "downloaded_count": len(downloads),
        "extracted_count": len(extractions),
        "files_analyzed": analysis.get("files_analyzed", 0),
        "top_scored_endpoints": analysis.get("scored_endpoints", [])[:10],
        "signals_count": len(analysis.get("signals", [])),
        "detection_path": detection.get("path"),
        "downloaded": downloads,
        "extracted": extractions,
        "analysis_path": analysis.get("path"),
        "warnings": warnings,
    }
    write_audit_event(campaign_id, "sourcemap_workflow_for_campaign", target=js_url, ok=True, result_path=analysis.get("path"), warnings=warnings)
    return summary


def external_sourcemapper_info() -> dict:
    """Explain safe local-only external sourcemapper usage; does not execute it."""
    return {
        "ok": True,
        "message": "External sourcemapper can be useful for local source map reconstruction, but Recon MCP does not run it in remote URL modes.",
        "unsafe_modes_not_used": ["sourcemapper -jsurl https://target/app.js", "sourcemapper -url https://target/app.js.map"],
        "safe_model": [
            "Recon MCP downloads source maps itself after scope checks.",
            "Any future external integration must accept only campaign-local .map files.",
            "It must write only inside the campaign extracted source map directory.",
            "It must never receive cookies, Authorization headers, custom auth headers, or remote URLs.",
        ],
        "local_only_example": "sourcemapper -map output/campaigns/<campaign_id>/recon/sourcemaps/maps/app.map -output output/campaigns/<campaign_id>/recon/sourcemaps/extracted/app",
        "executed": False,
    }
