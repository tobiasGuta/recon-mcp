"""Low-risk HTTP fetch helpers for in-scope targets."""

from __future__ import annotations

import re
import time
import xml.etree.ElementTree as ET
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpx

from recon.scope import (
    DEFAULT_FETCH_HEADERS_METHOD,
    DEFAULT_REQUEST_DELAY_MS,
    DEFAULT_USER_AGENT,
    ScopeError,
    assert_in_scope,
    load_scope,
)


USER_AGENT = DEFAULT_USER_AGENT
TIMEOUT_SECONDS = 10.0
MAX_REDIRECTS = 5
SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]


def _origin_url(url: str) -> str:
    """Return the origin for a URL."""
    parts = urlsplit(url)
    return urlunsplit((parts.scheme or "https", parts.netloc, "", "", ""))


def _headers_dict(response: httpx.Response) -> dict:
    """Convert response headers into a plain dictionary."""
    return {key: value for key, value in response.headers.items()}


def _client() -> httpx.Client:
    """Create a conservative HTTP client for read-only requests."""
    return httpx.Client(
        timeout=TIMEOUT_SECONDS,
        follow_redirects=False,
        headers={"User-Agent": get_user_agent()},
    )


def _error_result(url: str, message: str) -> dict:
    """Build a consistent error response."""
    return {"ok": False, "url": url, "error": message}


def get_user_agent() -> str:
    """Return the configured User-Agent with a safe default."""
    return str(load_scope().get("user_agent") or DEFAULT_USER_AGENT)


def get_request_delay_ms() -> int:
    """Return the configured per-request delay in milliseconds."""
    return max(0, int(load_scope().get("request_delay_ms", DEFAULT_REQUEST_DELAY_MS)))


def get_fetch_headers_method() -> str:
    """Return the configured header fetch method."""
    method = str(load_scope().get("fetch_headers_method") or DEFAULT_FETCH_HEADERS_METHOD).upper()
    return method if method in {"HEAD", "GET"} else DEFAULT_FETCH_HEADERS_METHOD


def _request_delay() -> None:
    """Apply the configured low-rate request delay."""
    delay_ms = get_request_delay_ms()
    if delay_ms:
        time.sleep(delay_ms / 1000)


def _safe_request(client: httpx.Client, method: str, url: str, *, headers_only: bool = False) -> httpx.Response:
    """Request a URL and validate every redirect target before following it."""
    current_url = url
    for _ in range(MAX_REDIRECTS + 1):
        assert_in_scope(current_url)
        _request_delay()
        if headers_only and method.upper() == "GET":
            request = client.build_request("GET", current_url, headers={"Range": "bytes=0-0"})
            response = client.send(request, stream=True)
            response.close()
        else:
            response = client.request(method.upper(), current_url)
        if not response.is_redirect:
            return response

        location = response.headers.get("location")
        if not location:
            return response

        next_url = urljoin(str(response.url), location)
        try:
            assert_in_scope(next_url)
        except ScopeError as exc:
            raise ScopeError(f"Redirect blocked because target is out of scope: {next_url} ({exc})") from exc
        current_url = next_url

    raise ScopeError(f"Too many redirects; stopped after {MAX_REDIRECTS} redirects.")


def _safe_get(client: httpx.Client, url: str) -> httpx.Response:
    """GET a URL and validate every redirect target before following it."""
    return _safe_request(client, "GET", url)


def _safe_get_headers(client: httpx.Client, url: str) -> httpx.Response:
    """GET a URL for headers without intentionally downloading a full body."""
    return _safe_request(client, "GET", url, headers_only=True)


def _safe_head(client: httpx.Client, url: str) -> httpx.Response:
    """HEAD a URL and validate every redirect target before following it."""
    return _safe_request(client, "HEAD", url)


def fetch_headers(url: str) -> dict:
    """Fetch response headers from an in-scope URL using HEAD with safe GET fallback."""
    method_used = get_fetch_headers_method()
    fallback_reason = None
    try:
        with _client() as client:
            if method_used == "HEAD":
                try:
                    response = _safe_head(client, url)
                    if response.status_code in {403, 405}:
                        fallback_reason = f"HEAD returned {response.status_code}"
                        method_used = "GET"
                        response = _safe_get_headers(client, url)
                except httpx.HTTPError as exc:
                    fallback_reason = f"HEAD request failed: {exc}"
                    method_used = "GET"
                    response = _safe_get_headers(client, url)
            else:
                response = _safe_get_headers(client, url)
    except ScopeError as exc:
        return _error_result(url, str(exc))
    except httpx.HTTPError as exc:
        return _error_result(url, f"HTTP request failed: {exc}")

    headers = _headers_dict(response)
    interesting_headers = {
        name: headers.get(name) or headers.get(name.lower())
        for name in SECURITY_HEADERS
        if headers.get(name) or headers.get(name.lower())
    }
    notes = []

    for header in SECURITY_HEADERS:
        if header not in interesting_headers:
            notes.append(f"{header} not observed; manual review recommended.")

    cookie_headers = response.headers.get_list("set-cookie")
    for cookie in cookie_headers:
        cookie_lower = cookie.lower()
        if "secure" not in cookie_lower or "httponly" not in cookie_lower or "samesite" not in cookie_lower:
            notes.append("Set-Cookie observed without all common flags; manual review recommended.")
            break

    return {
        "ok": True,
        "url": url,
        "final_url": str(response.url),
        "status_code": response.status_code,
        "method": method_used,
        "headers": headers,
        "interesting_headers": interesting_headers,
        "notes": notes,
        "fallback_reason": fallback_reason,
    }


def fetch_robots(url: str) -> dict:
    """Fetch and parse robots.txt from an in-scope URL origin."""
    try:
        assert_in_scope(url)
        robots_url = urljoin(f"{_origin_url(url)}/", "robots.txt")
        with _client() as client:
            response = _safe_get(client, robots_url)
    except ScopeError as exc:
        return _error_result(url, str(exc))
    except httpx.HTTPError as exc:
        return _error_result(url, f"HTTP request failed: {exc}")

    disallow = []
    allow = []
    for line in response.text.splitlines():
        if match := re.match(r"^\s*Disallow\s*:\s*(.*?)\s*$", line, flags=re.IGNORECASE):
            disallow.append(match.group(1))
        elif match := re.match(r"^\s*Allow\s*:\s*(.*?)\s*$", line, flags=re.IGNORECASE):
            allow.append(match.group(1))

    return {
        "ok": True,
        "url": robots_url,
        "final_url": str(response.url),
        "status_code": response.status_code,
        "content_preview": response.text[:2000],
        "disallow": disallow,
        "allow": allow,
    }


def fetch_sitemap(url: str) -> dict:
    """Fetch and parse sitemap.xml from an in-scope URL origin."""
    try:
        assert_in_scope(url)
        sitemap_url = urljoin(f"{_origin_url(url)}/", "sitemap.xml")
        with _client() as client:
            response = _safe_get(client, sitemap_url)
    except ScopeError as exc:
        return _error_result(url, str(exc))
    except httpx.HTTPError as exc:
        return _error_result(url, f"HTTP request failed: {exc}")

    discovered_urls = []
    parse_error = None
    if response.text.strip():
        try:
            root = ET.fromstring(response.text)
            for element in root.iter():
                if element.tag.endswith("loc") and element.text:
                    discovered_urls.append(element.text.strip())
        except ET.ParseError as exc:
            parse_error = f"Sitemap XML could not be parsed: {exc}"

    return {
        "ok": True,
        "url": sitemap_url,
        "final_url": str(response.url),
        "status_code": response.status_code,
        "discovered_urls": sorted(set(discovered_urls)),
        "count": len(set(discovered_urls)),
        "content_preview": response.text[:2000],
        "parse_error": parse_error,
    }
