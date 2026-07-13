"""Low-risk HTTP fetch helpers for in-scope targets."""

from __future__ import annotations

import re
import socket
import time
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpx
from defusedxml import ElementTree as ET
from defusedxml.common import DefusedXmlException
from recon.redaction import redact_text, redact_url, url_contains_sensitive_data

from recon.scope import (
    DEFAULT_FETCH_HEADERS_METHOD,
    DEFAULT_REQUEST_DELAY_MS,
    DEFAULT_USER_AGENT,
    DEFAULT_LIMITS,
    ScopeError,
    assert_in_scope,
    is_private_or_loopback_host,
    load_scope,
    normalize_domain,
)


USER_AGENT = DEFAULT_USER_AGENT
TIMEOUT_SECONDS = 10.0
MAX_REDIRECTS = 5
MAX_ROBOTS_BYTES = 512 * 1024
MAX_SITEMAP_BYTES = 1024 * 1024
SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]


class BoundedReadError(ValueError):
    """Raised as soon as a streamed response exceeds its configured limit."""

    def __init__(self, maximum: int, observed: int, *, content_type: str) -> None:
        self.maximum = maximum
        self.observed = observed
        self.content_type = content_type
        super().__init__(f"{content_type} response exceeds configured maximum of {maximum} bytes.")

    def as_result(self, url: str) -> dict:
        return {
            "ok": False,
            "url": url,
            "error": str(self),
            "error_code": "response_too_large",
            "configured_maximum_bytes": self.maximum,
            "bytes_observed": self.observed,
            "truncated": True,
            "rejected": True,
        }


def _origin_url(url: str) -> str:
    """Return the origin for a URL."""
    parts = urlsplit(url)
    return urlunsplit((parts.scheme or "https", parts.netloc, "", "", ""))


def _headers_dict(response: httpx.Response) -> dict:
    """Convert response headers into a plain dictionary."""
    return {key: value for key, value in response.headers.items()}


def get_limit(name: str) -> int:
    """Return one validated processing limit from scope configuration."""
    return int(load_scope().get(name, DEFAULT_LIMITS[name]))


def _read_bounded(response: httpx.Response, maximum: int, *, content_type: str) -> bytes:
    """Read a response incrementally and stop before retaining an oversized body."""
    content_length = response.headers.get("content-length")
    if content_length:
        try:
            declared = int(content_length)
        except ValueError:
            declared = 0
        if declared > maximum:
            raise BoundedReadError(maximum, declared, content_type=content_type)
    chunks: list[bytes] = []
    observed = 0
    for chunk in response.iter_bytes():
        observed += len(chunk)
        if observed > maximum:
            raise BoundedReadError(maximum, observed, content_type=content_type)
        chunks.append(chunk)
    return b"".join(chunks)


def _client() -> httpx.Client:
    """Create a conservative HTTP client for read-only requests."""
    return httpx.Client(
        timeout=TIMEOUT_SECONDS,
        follow_redirects=False,
        headers={"User-Agent": get_user_agent()},
    )


def _error_result(url: str, message: str) -> dict:
    """Build a consistent error response."""
    return {"ok": False, "url": redact_url(url), "error": redact_text(message)}


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


def resolve_host_ips(host: str) -> list[str]:
    """Resolve a hostname to IP strings for DNS safety checks."""
    resolved = []
    seen = set()
    for item in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM):
        ip = item[4][0]
        if ip not in seen:
            resolved.append(ip)
            seen.add(ip)
    return resolved


def assert_resolved_host_is_public(url: str) -> None:
    """Resolve a URL hostname and raise ScopeError if any resolved IP is unsafe."""
    host = urlsplit(url).hostname
    if not host:
        raise ScopeError("URL has no hostname for DNS safety check.")

    normalized = normalize_domain(host)
    if normalized == "localhost" or normalized.endswith(".localhost"):
        raise ScopeError(f"Hostname is blocked by DNS safety rules: {host}")
    if is_private_or_loopback_host(normalized):
        raise ScopeError(f"Hostname is an unsafe local/private IP: {host}")

    try:
        resolved_ips = resolve_host_ips(normalized)
    except OSError as exc:
        raise ScopeError(f"DNS resolution failed for {host}; failing closed: {exc}") from exc
    if not resolved_ips:
        raise ScopeError(f"DNS resolution returned no addresses for {host}; failing closed.")

    unsafe_ips = [ip for ip in resolved_ips if is_private_or_loopback_host(ip)]
    if unsafe_ips:
        raise ScopeError(f"Hostname {host} resolved to unsafe local/private IP(s): {', '.join(unsafe_ips)}")


def _safe_request(client: httpx.Client, method: str, url: str, *, headers_only: bool = False) -> httpx.Response:
    """Request a URL and validate every redirect target before following it."""
    current_url = url
    for _ in range(MAX_REDIRECTS + 1):
        if url_contains_sensitive_data(current_url):
            raise ScopeError("URL contains credential-like user information or sensitive query values; request rejected.")
        assert_in_scope(current_url)
        assert_resolved_host_is_public(current_url)
        _request_delay()
        headers = {"Range": "bytes=0-0"} if headers_only and method.upper() == "GET" else None
        request = client.build_request(method.upper(), current_url, headers=headers)
        response = client.send(request, stream=True)
        if not response.is_redirect:
            return response

        location = response.headers.get("location")
        if not location:
            return response

        next_url = urljoin(str(response.url), location)
        try:
            assert_resolved_host_is_public(next_url)
            assert_in_scope(next_url)
        except ScopeError as exc:
            response.close()
            raise ScopeError(f"Redirect blocked because target is unsafe or out of scope: {redact_url(next_url)} ({redact_text(exc)})") from exc
        response.close()
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


def safe_get_text(url: str, *, limit_name: str = "max_javascript_bytes", content_type: str = "JavaScript") -> str:
    """GET text from an in-scope URL using the shared redirect-safety path."""
    with _client() as client:
        response = _safe_get(client, url)
        try:
            response.raise_for_status()
            content = _read_bounded(response, get_limit(limit_name), content_type=content_type)
            return content.decode(response.encoding or "utf-8", errors="replace")
        finally:
            response.close()


def safe_get_bytes(url: str, maximum: int, *, content_type: str) -> tuple[bytes, httpx.Response]:
    """Stream one safe in-scope response into a bounded byte string."""
    client = _client()
    try:
        response = _safe_get(client, url)
        response.raise_for_status()
        content = _read_bounded(response, maximum, content_type=content_type)
        response.close()
        client.close()
        return content, response
    except Exception:
        client.close()
        raise


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

    result = {
        "ok": True,
        "url": redact_url(url),
        "final_url": redact_url(response.url),
        "status_code": response.status_code,
        "method": method_used,
        "headers": headers,
        "interesting_headers": interesting_headers,
        "notes": notes,
        "fallback_reason": fallback_reason,
    }
    response.close()
    return result


def fetch_robots(url: str) -> dict:
    """Fetch and parse robots.txt from an in-scope URL origin."""
    try:
        assert_in_scope(url)
        robots_url = urljoin(f"{_origin_url(url)}/", "robots.txt")
        content, response = safe_get_bytes(robots_url, get_limit("max_robots_bytes"), content_type="robots.txt")
    except ScopeError as exc:
        return _error_result(url, str(exc))
    except httpx.HTTPError as exc:
        return _error_result(url, f"HTTP request failed: {exc}")
    except BoundedReadError as exc:
        return exc.as_result(robots_url)

    robots_text = content.decode(response.encoding or "utf-8", errors="replace")
    content_truncated = False

    disallow = []
    allow = []
    entry_limit = get_limit("max_analysis_signals")
    result_truncated = False
    for line in robots_text.splitlines():
        if match := re.match(r"^\s*Disallow\s*:\s*(.*?)\s*$", line, flags=re.IGNORECASE):
            disallow.append(match.group(1))
        elif match := re.match(r"^\s*Allow\s*:\s*(.*?)\s*$", line, flags=re.IGNORECASE):
            allow.append(match.group(1))
        if len(disallow) + len(allow) >= entry_limit:
            result_truncated = True
            break

    return {
        "ok": True,
        "url": robots_url,
        "final_url": redact_url(response.url),
        "status_code": response.status_code,
        "content_preview": robots_text[:2000],
        "content_truncated": content_truncated,
        "results_truncated": result_truncated,
        "disallow": disallow,
        "allow": allow,
    }


def fetch_sitemap(url: str) -> dict:
    """Fetch and parse sitemap.xml from an in-scope URL origin."""
    try:
        assert_in_scope(url)
        sitemap_url = urljoin(f"{_origin_url(url)}/", "sitemap.xml")
        content, response = safe_get_bytes(sitemap_url, get_limit("max_sitemap_bytes"), content_type="sitemap")
    except ScopeError as exc:
        return _error_result(url, str(exc))
    except httpx.HTTPError as exc:
        return _error_result(url, f"HTTP request failed: {exc}")
    except BoundedReadError as exc:
        return exc.as_result(sitemap_url)

    sitemap_text = content.decode(response.encoding or "utf-8", errors="replace")
    content_truncated = False

    discovered_urls = []
    parse_error = None
    if content_truncated:
        parse_error = "Response too large to parse."
    elif sitemap_text.strip():
        try:
            root = ET.fromstring(sitemap_text)
            result_limit = get_limit("max_endpoint_candidates")
            for element in root.iter():
                if element.tag.endswith("loc") and element.text:
                    discovered_urls.append(element.text.strip())
                    if len(discovered_urls) >= result_limit:
                        break
        except (ET.ParseError, DefusedXmlException) as exc:
            parse_error = f"Sitemap XML could not be parsed: {exc}"

    return {
        "ok": True,
        "url": sitemap_url,
        "final_url": redact_url(response.url),
        "status_code": response.status_code,
        "discovered_urls": sorted(set(discovered_urls)),
        "count": len(set(discovered_urls)),
        "content_preview": sitemap_text[:2000],
        "content_truncated": content_truncated,
        "results_truncated": len(discovered_urls) >= get_limit("max_endpoint_candidates"),
        "parse_error": parse_error,
    }
