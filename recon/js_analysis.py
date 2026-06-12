"""JavaScript URL collection and endpoint extraction."""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urljoin, urlsplit

import httpx
from bs4 import BeautifulSoup

from recon.http_fetch import MAX_REDIRECTS, TIMEOUT_SECONDS, USER_AGENT
from recon.scope import ScopeError, assert_in_scope, check_scope


PROJECT_ROOT = Path(__file__).resolve().parent.parent
ALLOWED_JS_SUFFIXES = {".js", ".mjs", ".cjs", ".map"}
MAX_LOCAL_JS_BYTES = 2 * 1024 * 1024

ENDPOINT_PATTERNS = {
    "api": re.compile(r"""(?P<value>/(?:api|v1|v2)/[A-Za-z0-9_./?=&%:-]*)"""),
    "graphql": re.compile(r"""(?P<value>/graphql\b[A-Za-z0-9_./?=&%:-]*)"""),
    "auth": re.compile(r"""(?P<value>/auth/[A-Za-z0-9_./?=&%:-]*)"""),
    "admin": re.compile(r"""(?P<value>/admin/[A-Za-z0-9_./?=&%:-]*)"""),
    "full_url": re.compile(r"""(?P<value>https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+)"""),
    "relative_route": re.compile(r"""["'`](?P<value>/[A-Za-z0-9._~:/?#\[\]@!$&()*+,;=%-]{2,})["'`]"""),
    "source_map": re.compile(r"""sourceMappingURL=(?P<value>[^\s]+)"""),
}


def _fetch_text(url: str) -> str:
    """Fetch text from an in-scope URL."""
    current_url = url
    with httpx.Client(timeout=TIMEOUT_SECONDS, follow_redirects=False, headers={"User-Agent": USER_AGENT}) as client:
        for _ in range(MAX_REDIRECTS + 1):
            assert_in_scope(current_url)
            response = client.get(current_url)
            if not response.is_redirect:
                response.raise_for_status()
                return response.text

            location = response.headers.get("location")
            if not location:
                response.raise_for_status()
                return response.text

            next_url = urljoin(str(response.url), location)
            try:
                assert_in_scope(next_url)
            except ScopeError as exc:
                raise ScopeError(f"Redirect blocked because target is out of scope: {next_url} ({exc})") from exc
            current_url = next_url

    raise ScopeError(f"Too many redirects; stopped after {MAX_REDIRECTS} redirects.")


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
    except httpx.HTTPError as exc:
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

    return {
        "ok": True,
        "page_url": url,
        "js_urls": sorted(js_urls),
        "count": len(js_urls),
    }


def _read_js_input(file_or_url: str) -> tuple[str, str]:
    """Read JavaScript from a URL or local file path."""
    if re.match(r"^https?://", file_or_url, flags=re.IGNORECASE):
        return _fetch_text(file_or_url), "url"

    path = Path(file_or_url).expanduser().resolve()
    if not path.is_relative_to(PROJECT_ROOT):
        raise OSError("Local JavaScript files must be inside the Recon MCP project directory.")
    if path.suffix.lower() not in ALLOWED_JS_SUFFIXES:
        raise OSError("Local JavaScript input must use a .js, .mjs, .cjs, or .map extension.")
    if path.stat().st_size > MAX_LOCAL_JS_BYTES:
        raise OSError("Local JavaScript input is too large to read safely.")

    return path.read_text(encoding="utf-8", errors="replace"), "file"


def _categorize_endpoint(category: str, value: str) -> str:
    """Map regex categories to stable output labels."""
    if category == "full_url":
        return "full_url"
    if category == "source_map":
        return "source_map"
    if category == "relative_route":
        return "relative_route"
    return category


def extract_endpoints_from_js(file_or_url: str) -> dict:
    """Extract likely endpoints from a JavaScript URL, local file, or source string."""
    try:
        if "\n" in file_or_url or "function " in file_or_url or "=>" in file_or_url:
            js_text, source_type = file_or_url, "string"
        else:
            js_text, source_type = _read_js_input(file_or_url)
    except ScopeError as exc:
        return {"ok": False, "source": file_or_url, "error": str(exc)}
    except (OSError, httpx.HTTPError) as exc:
        return {"ok": False, "source": file_or_url, "error": f"Could not read JavaScript: {exc}"}

    seen_values = set()
    endpoints = []
    for category, pattern in ENDPOINT_PATTERNS.items():
        for match in pattern.finditer(js_text):
            value = match.group("value").strip().rstrip(");,")
            if value in seen_values:
                continue
            seen_values.add(value)
            endpoints.append({"category": _categorize_endpoint(category, value), "value": value})

    endpoints.sort(key=lambda item: (item["category"], item["value"]))
    return {
        "ok": True,
        "source": file_or_url if source_type != "string" else "provided_string",
        "source_type": source_type,
        "endpoints": endpoints,
        "count": len(endpoints),
        "notes": ["Possible endpoints require manual validation; no vulnerability is implied."],
    }
