"""Shared deterministic redaction for URLs and token-shaped text."""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

SENSITIVE_NAME = re.compile(r"(?i)(token|secret|password|passwd|authorization|cookie|session|csrf|xsrf|api[_-]?key|signature|credential|access[_-]?key)")
TOKEN_SHAPE = re.compile(r"(?i)\b(?:gh[pousr]_[A-Za-z0-9]{16,}|github_pat_[A-Za-z0-9_]{16,}|glpat-[A-Za-z0-9_-]{16,}|xox[baprs]-[A-Za-z0-9-]{10,}|sk_(?:live|test)_[A-Za-z0-9]{12,}|AKIA[A-Z0-9]{16})\b")
BEARER = re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]{8,}")
ASSIGNMENT = re.compile(r"(?i)((?:token|secret|password|passwd|authorization|cookie|session|csrf|xsrf|api[_-]?key)\s*[=:]\s*['\"]?)[^'\"&\s,;}]{4,}")


def redact_text(value: object) -> str:
    text = TOKEN_SHAPE.sub("<redacted-token>", str(value))
    text = BEARER.sub(r"\1<redacted>", text)
    return ASSIGNMENT.sub(r"\1<redacted>", text)


def redact_url(value: object, *, redact_all_query_values: bool = False) -> str:
    text = redact_text(value)
    try:
        parts = urlsplit(text)
    except ValueError:
        return text
    if not parts.scheme or not parts.netloc:
        return text
    try:
        hostname = parts.hostname or ""
        netloc = hostname
        if ":" in hostname and not hostname.startswith("["):
            netloc = f"[{hostname}]"
        if parts.port:
            netloc += f":{parts.port}"
        query = [(key, "<redacted>" if redact_all_query_values or SENSITIVE_NAME.search(key) else val) for key, val in parse_qsl(parts.query, keep_blank_values=True)]
        return urlunsplit((parts.scheme, netloc, parts.path, urlencode(query), parts.fragment))
    except ValueError:
        return "<malformed-url-redacted>"


def url_contains_sensitive_data(value: object) -> bool:
    text = str(value)
    if TOKEN_SHAPE.search(text) or BEARER.search(text):
        return True
    try:
        parts = urlsplit(text)
        return parts.username is not None or parts.password is not None or any(SENSITIVE_NAME.search(key) for key, _ in parse_qsl(parts.query, keep_blank_values=True))
    except ValueError:
        return True


def redact_endpoint(value: object) -> str:
    text = redact_text(value)
    if text.startswith("/"):
        redacted = redact_url(f"https://placeholder.invalid{text}")
        prefix = "https://placeholder.invalid"
        return redacted[len(prefix) :] if redacted.startswith(prefix) else "<redacted-endpoint>"
    return redact_url(text)


def redact_structure(value: object, key: str = "") -> object:
    """Recursively remove sensitive values while preserving useful names and shapes."""
    lowered = key.lower()
    if SENSITIVE_NAME.search(key) and not lowered.endswith(("_candidates", "_signals")) and "fingerprint" not in lowered and "redacted" not in lowered and not lowered.endswith("_present") and not lowered.endswith("_names"):
        return "<redacted>"
    if any(term in lowered for term in ("request_body", "response_body", "postdata")) and not lowered.endswith("_field_names"):
        return "<redacted>"
    if isinstance(value, dict):
        return {str(item_key): redact_structure(item_value, str(item_key)) for item_key, item_value in list(value.items())[:1000]}
    if isinstance(value, (list, tuple)):
        return [redact_structure(item) for item in value[:5000]]
    if isinstance(value, str):
        return redact_url(value) if value.lower().startswith(("http://", "https://")) else redact_text(value)
    if isinstance(value, (int, float, bool, type(None))):
        return value
    return redact_text(value)
