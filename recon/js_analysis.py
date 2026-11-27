"""JavaScript URL collection and endpoint extraction."""

from __future__ import annotations

import re
from pathlib import Path

import httpx
from bs4 import BeautifulSoup

from recon.authorization import AuthorizationError, evaluate, load_policy, parse_target, policy_failure, safe_target
from recon.http_fetch import BoundedReadError, redirect_url, safe_get_text_with_response
from recon.redaction import redact_endpoint
from recon.safeio import SafeIOError, read_text_bounded
from recon.scope import DEFAULT_LIMITS, DEFAULT_MAX_REQUESTS_PER_TOOL_CALL, ScopeError, load_scope


PROJECT_ROOT = Path(__file__).resolve().parent.parent
ALLOWED_JS_SUFFIXES = {".js", ".mjs", ".cjs", ".map"}
MAX_LOCAL_JS_BYTES = 2 * 1024 * 1024
SOURCE_MAPPING_URL_PATTERN = re.compile(
    r"""(?:\/\/[#@]\s*sourceMappingURL=|\/\*[#@]\s*sourceMappingURL=|sourceMappingURL=)(?P<value>[^\s*]+)""",
    flags=re.IGNORECASE,
)

ENDPOINT_PATTERNS = {
    "api": re.compile(r"""(?P<value>/(?:api|v1|v2)/[A-Za-z0-9_./?=&%:-]*)"""),
    "graphql": re.compile(r"""(?P<value>/graphql\b[A-Za-z0-9_./?=&%:-]*)"""),
    "auth": re.compile(r"""(?P<value>/auth/[A-Za-z0-9_./?=&%:-]*)"""),
    "admin": re.compile(r"""(?P<value>/admin/[A-Za-z0-9_./?=&%:-]*)"""),
    "full_url": re.compile(r"""(?P<value>https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+)"""),
    "relative_route": re.compile(r"""["'`](?P<value>/[A-Za-z0-9._~:/?#\[\]@!$&()*+,;=%-]{2,})["'`]"""),
    "source_map": SOURCE_MAPPING_URL_PATTERN,
}


def _fetch_text(url: str) -> tuple[str, str, dict]:
    """Read JavaScript or HTML and keep the final authorized response URL."""
    suffix = Path(parse_target(url).path).suffix.lower()
    is_javascript = suffix in ALLOWED_JS_SUFFIXES
    text, response = safe_get_text_with_response(
        url, limit_name="max_javascript_bytes" if is_javascript else "max_html_bytes",
        content_type="JavaScript" if is_javascript else "HTML",
    )
    return text, str(response.url), response.extensions["scope_decision"]


def get_max_requests_per_tool_call() -> int:
    """Return the configured per-tool request ceiling."""
    return max(1, int(load_scope().get("max_requests_per_tool_call", DEFAULT_MAX_REQUESTS_PER_TOOL_CALL)))


def collect_js_urls(url: str) -> dict:
    """Collect script URLs permitted by the active URL policy."""
    page_url = safe_target(url)
    try:
        html, base, scope_decision = _fetch_text(url)
        maximum = get_max_requests_per_tool_call()
        policy = load_policy()
    except (ScopeError, OSError) as exc:
        failure = getattr(exc, "decision", None) or policy_failure(exc)
        return {"ok": False, "page_url": page_url, "error": failure["reason"], "scope_decision": failure}
    except (httpx.HTTPError, BoundedReadError):
        return {"ok": False, "page_url": page_url, "error": "Could not read a bounded HTTP response."}

    soup = BeautifulSoup(html, "html.parser")
    js_urls = set()
    for script in soup.find_all("script"):
        src = script.get("src")
        if not isinstance(src, str) or not src:
            continue
        try:
            target = parse_target(redirect_url(base, src))
        except AuthorizationError:
            continue
        if evaluate(policy, target, expected_fingerprint=scope_decision["policy_fingerprint"])["authorized"]:
            js_urls.add(target.redacted)
            if len(js_urls) > maximum:
                return {
                    "ok": True, "page_url": page_url, "scope_decision": scope_decision,
                    "js_urls": sorted(js_urls)[:maximum], "count": maximum, "truncated": True,
                    "warning": "JavaScript URL results were truncated at the configured limit.",
                    "max_requests_per_tool_call": maximum,
                }
    return {"ok": True, "page_url": page_url, "scope_decision": scope_decision,
            "js_urls": sorted(js_urls), "count": len(js_urls), "truncated": False}


def _read_local_js_file(file_or_url: str) -> str:
    """Read JavaScript from a restricted local file path."""
    path = Path(file_or_url).expanduser().resolve()
    if not path.is_relative_to(PROJECT_ROOT):
        raise OSError("Local JavaScript files must be inside the Recon MCP project directory.")
    if path.suffix.lower() not in ALLOWED_JS_SUFFIXES:
        raise OSError("Local JavaScript input must use a .js, .mjs, .cjs, or .map extension.")
    if path.is_symlink():
        raise OSError("Local JavaScript input must not be a symlink.")
    maximum = min(int(load_scope().get("max_javascript_bytes", DEFAULT_LIMITS["max_javascript_bytes"])), MAX_LOCAL_JS_BYTES)
    if path.stat().st_size > maximum:
        raise OSError(f"Local JavaScript input exceeds MAX_LOCAL_JS_BYTES/configured maximum ({maximum}).")
    try:
        return read_text_bounded(path, maximum)
    except SafeIOError as exc:
        raise OSError(str(exc)) from exc


def js_input_type(file_or_url: str, source_type: str | None) -> str:
    if source_type is not None:
        return source_type.lower()
    if "\n" in file_or_url or "function " in file_or_url or "=>" in file_or_url:
        return "raw"
    return "url" if re.match(r"^https?://", file_or_url, flags=re.IGNORECASE) else "file"


def _categorize_endpoint(category: str, value: str) -> str:
    """Map regex categories to stable output labels."""
    if category == "full_url":
        return "full_url"
    if category == "source_map":
        return "source_map"
    if category == "relative_route":
        return "relative_route"
    return category


def parse_sourcemap_references(js_text: str, js_url: str | None = None, *, request_urls: dict[int, str] | None = None) -> list[dict]:
    """Parse sourceMappingURL comments without downloading anything."""
    references = []
    seen = set()
    for match in SOURCE_MAPPING_URL_PATTERN.finditer(js_text or ""):
        raw = match.group("value").strip().strip("'\"").rstrip("*/")
        if not raw or raw in seen:
            continue
        seen.add(raw)
        lowered = raw.lower()
        resolved_url = None
        if lowered.startswith("data:"):
            kind = "data_uri"
            reason = "inline data URI source map; manual review only"
            safe_to_download = False
            display_raw = "<inline-data-uri-redacted>"
        else:
            absolute = lowered.startswith(("http://", "https://"))
            kind = "absolute" if absolute else "relative" if js_url else "unknown"
            reason = "Source map URL requires scope validation."
            safe_to_download = False
            display_raw = redact_endpoint(raw.split("?", 1)[0].split("#", 1)[0])
            if "?" in raw:
                display_raw += "?<redacted>"
            try:
                target = parse_target(raw if absolute or not js_url else redirect_url(js_url, raw))
            except AuthorizationError:
                reason = "Source map reference could not be safely resolved."
                if absolute:
                    display_raw = safe_target(raw)
                elif raw.startswith("//"):
                    display_raw = "<redacted-invalid-or-sensitive-reference>"
            else:
                safe_to_download = True
                resolved_url = target.redacted
                if request_urls is not None:
                    request_urls[len(references)] = target.url
        references.append(
            {
                "raw": display_raw,
                "kind": kind,
                "resolved_url": resolved_url,
                "safe_to_download": safe_to_download,
                "reason": reason,
            }
        )
    return references


def extract_endpoints_from_js(file_or_url: str, source_type: str | None = None) -> dict:
    """Extract likely endpoints from a JavaScript URL, local file, or source string."""
    resolved_source_type = js_input_type(file_or_url, source_type)
    source = safe_target(file_or_url) if resolved_source_type == "url" else (
        "provided_raw" if resolved_source_type == "raw" else redact_endpoint(file_or_url)
    )
    scope_decision = None
    try:
        if resolved_source_type == "url":
            js_text, _, scope_decision = _fetch_text(file_or_url)
        elif resolved_source_type == "file":
            js_text = _read_local_js_file(file_or_url)
        elif resolved_source_type == "raw":
            js_text = file_or_url
            if len(js_text.encode("utf-8")) > int(load_scope().get("max_javascript_bytes", DEFAULT_LIMITS["max_javascript_bytes"])):
                return {"ok": False, "source": source, "source_type": "raw", "error": "Raw JavaScript exceeds configured maximum."}
        else:
            return {"ok": False, "source_type": source_type, "error": "source_type must be one of: url, file, raw."}
    except ScopeError as exc:
        return {"ok": False, "source": source, "error": str(exc), "scope_decision": getattr(exc, "decision", None)}
    except (httpx.HTTPError, BoundedReadError):
        return {"ok": False, "source": source, "error": "Could not read a bounded HTTP response."}
    except OSError as exc:
        return {"ok": False, "source": source, "error": f"Could not read JavaScript: {exc}"}

    seen_values = set()
    endpoints = []
    maximum = int(load_scope().get("max_endpoint_candidates", DEFAULT_LIMITS["max_endpoint_candidates"]))
    truncated = False
    for category, pattern in ENDPOINT_PATTERNS.items():
        for match in pattern.finditer(js_text):
            value = redact_endpoint(match.group("value").strip().rstrip(");,"))
            if value in seen_values:
                continue
            seen_values.add(value)
            endpoints.append({"category": _categorize_endpoint(category, value), "value": value})
            if len(endpoints) >= maximum:
                truncated = True
                break
        if truncated:
            break

    endpoints.sort(key=lambda item: (item["category"], item["value"]))
    return {
        "ok": True,
        "source": source,
        "scope_decision": scope_decision,
        "source_type": resolved_source_type,
        "endpoints": endpoints,
        "count": len(endpoints),
        "truncated": truncated,
        "notes": ["Possible endpoints require manual validation; no vulnerability is implied."],
    }
