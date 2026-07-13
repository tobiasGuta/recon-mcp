"""Deterministic local-only scanning for redacted sensitive-artifact leads."""

from __future__ import annotations

import hashlib
import math
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Pattern

from recon.audit import write_audit_event
from recon.campaigns import file_timestamp, get_campaign_paths
from recon.evidence_graph import add_evidence_batch
from recon.memory import record_negative_result
from recon.safeio import SafeIOError, artifact_envelope, limit, read_text_bounded, safe_campaign_path, write_json_artifact

TEXT_SUFFIXES = {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".json", ".vue", ".svelte", ".map", ".txt"}
PLACEHOLDERS = re.compile(r"(?i)(example|sample|dummy|changeme|your[_-]?(token|secret|key)|replace[_-]?me|xxxx|test[_-]?(token|secret|key))")
REPEATED = re.compile(r"^(.)\1{7,}$")


@dataclass(frozen=True)
class Detector:
    detector_id: str
    description: str
    priority: str
    pattern: Pattern[str]
    prefix: int = 4
    suffix: int = 4
    entropy: float | None = None
    minimum: int = 8
    maximum: int = 4096
    private_key: bool = False


DETECTORS = (
    Detector("aws_access_key_id", "AWS access-key identifier format.", "high", re.compile(r"\b(?:AKIA|ASIA|AIDA|AROA)[A-Z0-9]{16}\b"), 4, 4),
    Detector("github_token", "GitHub token format.", "high", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,255}|github_pat_[A-Za-z0-9_]{20,255})\b"), 6, 4),
    Detector("gitlab_token", "GitLab token format.", "high", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,255}\b"), 6, 4),
    Detector("slack_token", "Slack token format.", "high", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,255}\b"), 5, 4),
    Detector("slack_webhook", "Slack webhook URL format.", "high", re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/_-]{20,300}"), 24, 4),
    Detector("stripe_secret_key", "Stripe secret-key format.", "high", re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9]{16,255}\b"), 8, 4),
    Detector("jwt", "JWT-shaped value.", "medium", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), 3, 4),
    Detector("pem_private_key", "PEM private-key block.", "critical", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]{0,65536}?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"), 0, 0, maximum=65536, private_key=True),
    Detector("database_connection_string", "Database connection string with credentials.", "high", re.compile(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^\s'\"<>]{8,2048}", re.I), 8, 4),
    Detector("cloud_storage_connection_string", "Cloud storage connection string.", "high", re.compile(r"(?i)DefaultEndpointsProtocol=https?;[^\r\n'\"]{20,2048}"), 8, 4),
    Detector("authorization_header", "Hardcoded Authorization header value.", "high", re.compile(r"(?i)(?:authorization|proxy-authorization)\s*[:=]\s*['\"](?:bearer|basic)\s+([^'\"\s]{8,2048})['\"]"), 2, 4),
    Detector("oauth_client_secret", "OAuth client-secret assignment.", "high", re.compile(r"(?i)(?:client[_-]?secret|oauth[_-]?secret)\s*[:=]\s*['\"]([^'\"]{8,512})['\"]"), 2, 4, 2.5),
    Detector("generic_secret_assignment", "High-entropy value assigned to a secret-like name.", "medium", re.compile(r"(?i)(?:api[_-]?secret|secret[_-]?key|access[_-]?token|auth[_-]?token|password|passwd)\s*[:=]\s*['\"]([^'\"]{12,512})['\"]"), 2, 4, 3.0),
)

PUBLIC_SIGNALS = (
    ("stripe_publishable_key", re.compile(r"\bpk_(?:live|test)_[A-Za-z0-9]{12,255}\b")),
    ("sentry_dsn", re.compile(r"https://[A-Za-z0-9]+@[^\s'\"]+\.ingest\.sentry\.io/\d+")),
    ("firebase_client_config", re.compile(r"(?i)\b(?:firebaseConfig|authDomain|projectId)\b")),
    ("google_browser_api_key", re.compile(r"\bAIza[A-Za-z0-9_-]{30,50}\b")),
)


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    return -sum((count / len(value)) * math.log2(count / len(value)) for count in counts.values())


def _value(match: re.Match[str]) -> str:
    return match.group(1) if match.lastindex else match.group(0)


def _redact(value: str, detector: Detector) -> str:
    if detector.private_key:
        return "<private-key-header-redacted>"
    if detector.detector_id == "database_connection_string":
        return f"{value.split(':', 1)[0]}://****"
    if detector.detector_id == "cloud_storage_connection_string":
        return "DefaultEndpointsProtocol=****"
    prefix = value[: detector.prefix] if detector.prefix else ""
    suffix = value[-detector.suffix :] if detector.suffix and len(value) > detector.prefix else ""
    return f"{prefix}****{suffix}"


def _placeholder(value: str) -> bool:
    compact = re.sub(r"[^A-Za-z0-9]", "", value)
    return bool(PLACEHOLDERS.search(value) or REPEATED.fullmatch(compact))


def _location(text: str, offset: int) -> tuple[int, int]:
    line = text.count("\n", 0, offset) + 1
    last = text.rfind("\n", 0, offset)
    return line, offset - last


def scan_sensitive_artifacts_for_campaign(campaign_id: str, extracted_dir: str | None = None) -> dict:
    """Scan approved campaign-local text without exposing or validating candidates."""
    paths = get_campaign_paths(campaign_id)
    if not paths.get("ok"):
        return {"ok": False, "error": paths.get("error")}
    default_root = Path(paths["paths"]["recon"]["sourcemaps"]) / "extracted"
    try:
        root = safe_campaign_path(campaign_id, extracted_dir or default_root, allowed_root=default_root, require_dir=True)
    except SafeIOError as exc:
        write_audit_event(campaign_id, "scan_sensitive_artifacts_for_campaign", ok=False, warnings=[str(exc)])
        return {"ok": False, "error": str(exc)}

    max_files = limit("max_extracted_source_files")
    max_total = limit("max_total_extracted_source_bytes")
    max_matches = limit("max_analysis_signals")
    seen: set[tuple[str, str]] = set()
    matches: list[dict] = []
    public_signals: list[dict] = []
    files_scanned = total_bytes = 0
    truncated = False
    warnings: list[str] = []
    for path in sorted(root.rglob("*")):
        if files_scanned >= max_files or len(matches) >= max_matches:
            truncated = True
            break
        if not path.is_file() or path.is_symlink() or path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        try:
            size = path.stat().st_size
            if size > limit("max_javascript_bytes") or total_bytes + size > max_total:
                truncated = True
                warnings.append(f"Skipped file at configured byte limit: {path.name}")
                continue
            text = read_text_bounded(path, limit("max_javascript_bytes"))
        except (OSError, SafeIOError) as exc:
            warnings.append(f"Skipped unreadable file {path.name}: {exc}")
            continue
        files_scanned += 1
        total_bytes += size
        relative = path.relative_to(root).as_posix()
        file_match_count = 0
        for detector in DETECTORS:
            for found in detector.pattern.finditer(text):
                value = _value(found)
                if not detector.minimum <= len(value) <= detector.maximum:
                    continue
                placeholder = _placeholder(value)
                if detector.entropy is not None and _entropy(value) < detector.entropy and not placeholder:
                    continue
                fingerprint = hashlib.sha256(value.strip().encode("utf-8")).hexdigest()
                key = (detector.detector_id, fingerprint)
                if key in seen:
                    continue
                seen.add(key)
                line, column = _location(text, found.start())
                matches.append({
                    "detector_id": detector.detector_id,
                    "classification": "candidate_secret_exposure",
                    "review_priority": "low" if placeholder else detector.priority,
                    "redacted_value": _redact(value, detector),
                    "fingerprint_sha256": fingerprint,
                    "file": relative,
                    "line": line,
                    "column": column,
                    "confidence": "low" if placeholder else ("high" if detector.priority in {"critical", "high"} else "medium"),
                    "reason": detector.description + (" Obvious placeholder or test value; downgraded." if placeholder else ""),
                    "manual_validation_required": True,
                })
                file_match_count += 1
                if file_match_count >= min(100, max_matches) or len(matches) >= max_matches:
                    if file_match_count >= min(100, max_matches):
                        warnings.append(f"Match results were truncated for file: {path.name}")
                    truncated = True
                    break
            if file_match_count >= min(100, max_matches) or len(matches) >= max_matches:
                break
        for signal_id, pattern in PUBLIC_SIGNALS:
            for found in pattern.finditer(text):
                line, column = _location(text, found.start())
                public_signals.append({"signal_id": signal_id, "classification": "client_configuration_signal", "file": relative, "line": line, "column": column, "manual_validation_required": True})
                if len(public_signals) >= max_matches:
                    truncated = True
                    break

    payload = {
        "ok": True, "campaign_id": campaign_id, "root": str(root), "files_scanned": files_scanned,
        "bytes_scanned": total_bytes, "matches": matches, "count": len(matches),
        "client_configuration_signals": public_signals[:max_matches], "truncated": truncated,
        "warnings": warnings, "manual_validation_required": True,
        "safety_note": "Candidates are recon leads only and were not validated or sent to any service.",
    }
    out_dir = Path(paths["paths"]["recon"]["sensitive"])
    envelope = artifact_envelope(campaign_id, "scan_sensitive_artifacts_for_campaign", payload, truncation_status={"truncated": truncated}, limits_applied={"max_files": max_files, "max_total_bytes": max_total, "max_matches": max_matches})
    try:
        saved = write_json_artifact(out_dir / f"{file_timestamp()}-sensitive-scan.json", envelope)
    except (OSError, SafeIOError) as exc:
        write_audit_event(campaign_id, "scan_sensitive_artifacts_for_campaign", ok=False, warnings=[str(exc)])
        return {"ok": False, "error": f"Could not save redacted scan: {exc}"}
    if not matches:
        record_negative_result(campaign_id, str(root), "sensitive_artifact_scan", "No candidate secret exposure found.")
    graph_nodes = [
        {"node_type": "secret_candidate", "normalized_value": f"{item['detector_id']}:{item['fingerprint_sha256']}", "display_label": f"{item['detector_id']} {item['redacted_value']}", "source_artifact_path": saved["path"], "confidence": item["confidence"], "metadata": {"detector_id": item["detector_id"], "fingerprint_sha256": item["fingerprint_sha256"], "redacted_value": item["redacted_value"], "file": item["file"], "line": item["line"]}}
        for item in matches
    ]
    graph_nodes.extend({"node_type": "client_configuration", "normalized_value": f"{item['signal_id']}:{item['file']}:{item['line']}", "source_artifact_path": saved["path"], "confidence": "medium", "metadata": item} for item in public_signals[:max_matches])
    add_evidence_batch(campaign_id, "scan_sensitive_artifacts_for_campaign", graph_nodes)
    write_audit_event(campaign_id, "scan_sensitive_artifacts_for_campaign", ok=True, result_path=saved["path"], warnings=warnings, metadata={"count": len(matches), "truncated": truncated, "artifact_uuid": saved["artifact_uuid"], "sha256": saved["sha256"]})
    return {**payload, **saved}
