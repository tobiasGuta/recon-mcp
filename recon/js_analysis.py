"""JavaScript URL collection and endpoint extraction."""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urljoin, urlsplit

import httpx
from bs4 import BeautifulSoup

from recon.http_fetch import BoundedReadError, safe_get_text
from recon.redaction import redact_endpoint
from recon.safeio import SafeIOError, read_text_bounded
from recon.scope import DEFAULT_LIMITS, DEFAULT_MAX_REQUESTS_PER_TOOL_CALL, ScopeError, check_scope, load_scope


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


def _fetch_text(url: str) -> str:
    """Fetch text from an in-scope URL."""
    suffix = Path(urlsplit(url).path).suffix.lower()
    is_javascript = suffix in ALLOWED_JS_SUFFIXES
    return safe_get_text(url, limit_name="max_javascript_bytes" if is_javascript else "max_html_bytes", content_type="JavaScript" if is_javascript else "HTML")


def get_max_requests_per_tool_call() -> int:
    """Return the configured per-tool request ceiling."""
    return max(1, int(load_scope().get("max_requests_per_tool_call", DEFAULT_MAX_REQUESTS_PER_TOOL_CALL)))


def _is_same_origin_or_in_scope(page_url: str, candidate_url: str) -> bool:
    """Return True when a script URL is same-origin or allowed by configured scope."""
    page = urlsplit(page_url)
    candidate = urlsplit(candidate_url)
    if page.scheme == candidate.scheme and page.netloc.lower() == candidate.netloc.lower():
        return True
    return bool(check_scope(candidate_url).get("in_scope"))


def collect_js_urls(url: str) -> dict:
    """Collect same-origin or in-scope JavaScript URLs from an HTML page."""
    try:
        html = _fetch_text(url)
    except ScopeError as exc:
        return {"ok": False, "page_url": url, "error": str(exc)}
    except (httpx.HTTPError, BoundedReadError) as exc:
        return {"ok": False, "page_url": url, "error": f"HTTP request failed: {exc}"}

    soup = BeautifulSoup(html, "html.parser")
    js_urls = set()
    for script in soup.find_all("script"):
        src = script.get("src")
        if not src:
            continue
        absolute_url = urljoin(url, src)
        if _is_same_origin_or_in_scope(url, absolute_url):
            js_urls.add(absolute_url)
            if len(js_urls) > get_max_requests_per_tool_call():
                return {
                    "ok": True,
                    "page_url": url,
                    "js_urls": sorted(js_urls)[: get_max_requests_per_tool_call()],
                    "count": get_max_requests_per_tool_call(),
                    "truncated": True,
                    "warning": "JavaScript URL results were truncated at the configured limit.",
                    "max_requests_per_tool_call": get_max_requests_per_tool_call(),
                }

    return {
        "ok": True,
        "page_url": url,
        "js_urls": sorted(js_urls),
        "count": len(js_urls),
        "truncated": False,
    }


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


def _read_js_input(file_or_url: str) -> tuple[str, str]:
    """Read JavaScript from a URL or local file path for backward compatibility."""
    if re.match(r"^https?://", file_or_url, flags=re.IGNORECASE):
        return _fetch_text(file_or_url), "url"
    return _read_local_js_file(file_or_url), "file"


def _categorize_endpoint(category: str, value: str) -> str:
    """Map regex categories to stable output labels."""
    if category == "full_url":
        return "full_url"
    if category == "source_map":
        return "source_map"
    if category == "relative_route":
        return "relative_route"
    return category


def parse_sourcemap_references(js_text: str, js_url: str | None = None) -> list[dict]:
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
        elif lowered.startswith(("http://", "https://")):
            kind = "absolute"
            resolved_url = raw
            reason = "absolute source map URL"
            safe_to_download = True
            display_raw = redact_endpoint(raw)
        elif js_url:
            kind = "relative"
            resolved_url = urljoin(js_url, raw)
            reason = "relative source map resolved against JS URL"
            safe_to_download = True
            display_raw = redact_endpoint(raw)
        else:
            kind = "unknown"
            reason = "relative source map cannot be resolved without js_url"
            safe_to_download = False
            display_raw = redact_endpoint(raw)
        if resolved_url:
            redacted_resolved = redact_endpoint(resolved_url)
            if redacted_resolved != resolved_url:
                safe_to_download = False
                reason += "; sensitive URL values were redacted and will not be requested"
            resolved_url = redacted_resolved
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
    try:
        if source_type is not None:
            normalized_source_type = source_type.lower()
            if normalized_source_type == "url":
                js_text = _fetch_text(file_or_url)
            elif normalized_source_type == "file":
                js_text = _read_local_js_file(file_or_url)
            elif normalized_source_type == "raw":
                js_text = file_or_url
                if len(js_text.encode("utf-8")) > int(load_scope().get("max_javascript_bytes", DEFAULT_LIMITS["max_javascript_bytes"])):
                    return {"ok": False, "source": "provided_raw", "source_type": "raw", "error": "Raw JavaScript exceeds configured maximum."}
            else:
                return {
                    "ok": False,
                    "source": file_or_url,
                    "source_type": source_type,
                    "error": "source_type must be one of: url, file, raw.",
                }
            resolved_source_type = normalized_source_type
        elif "\n" in file_or_url or "function " in file_or_url or "=>" in file_or_url:
            js_text, resolved_source_type = file_or_url, "raw"
        else:
            js_text, resolved_source_type = _read_js_input(file_or_url)
    except ScopeError as exc:
        return {"ok": False, "source": file_or_url, "error": str(exc)}
    except (OSError, httpx.HTTPError, BoundedReadError) as exc:
        return {"ok": False, "source": file_or_url, "error": f"Could not read JavaScript: {exc}"}

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
        "source": file_or_url if resolved_source_type != "raw" else "provided_raw",
        "source_type": resolved_source_type,
        "endpoints": endpoints,
        "count": len(endpoints),
        "truncated": truncated,
        "notes": ["Possible endpoints require manual validation; no vulnerability is implied."],
    }
