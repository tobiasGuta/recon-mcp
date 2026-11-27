"""Low-risk HTTP fetch helpers for in-scope targets."""

from __future__ import annotations

import ipaddress
import re
import socket
import time
from urllib.parse import urljoin, urlsplit

import httpx
from defusedxml import ElementTree as ET
from defusedxml.common import DefusedXmlException
from recon.authorization import AuthorizationError, MAX_URL_LENGTH, Target, parse_target, require_url, safe_target
from recon.campaign_scope import audit_dispatch, current_grant, verify_current_binding
from recon.pinned_transport import DESTINATIONS, MAX_DNS_ADDRESSES, PinnedTransport, validated_addresses
from recon.redaction import SENSITIVE_NAME, redact_embedded_urls, redact_endpoint, redact_structure, redact_text

from recon.scope import (
    DEFAULT_FETCH_HEADERS_METHOD,
    DEFAULT_REQUEST_DELAY_MS,
    DEFAULT_USER_AGENT,
    DEFAULT_LIMITS,
    ScopeError,

    load_scope,

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
            "url": safe_target(url),
            "error": str(self),
            "error_code": "response_too_large",
            "configured_maximum_bytes": self.maximum,
            "bytes_observed": self.observed,
            "truncated": True,
            "rejected": True,
        }


def _headers_dict(response: httpx.Response) -> dict:
    """Preserve header names while avoiding credentials and redirect query values."""
    headers = {}
    for key, value in response.headers.items():
        if SENSITIVE_NAME.search(key) or key in {"www-authenticate", "proxy-authenticate"}:
            headers[key] = "<redacted>"
        elif key == "location":
            try:
                headers[key] = safe_target(redirect_url(str(response.url), value))
            except AuthorizationError:
                headers[key] = "<redacted-invalid-location>"
        else:
            headers[key] = redact_embedded_urls(value)
    return headers


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


def _client(*, timeout: float = TIMEOUT_SECONDS) -> httpx.Client:
    """Create a conservative HTTP client for read-only requests."""
    return httpx.Client(
        timeout=timeout,
        follow_redirects=False,
        trust_env=False,
        transport=PinnedTransport(),
        headers={"User-Agent": get_user_agent()},
    )


def _error_result(url: str, error: str | Exception) -> dict:
    result = {"ok": False, "url": safe_target(url), "error": redact_text(error)}
    if isinstance(error, AuthorizationError):
        result["scope_decision"] = redact_structure(error.decision)
        result["error_code"] = error.code
    return result


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
            if len(resolved) > MAX_DNS_ADDRESSES:
                raise OSError("Resolver exceeded the address limit.")
    return resolved


def assert_resolved_host_is_public(url: str) -> list[str]:
    """Reject unexpected DNS answers or any address outside public ranges."""
    host = parse_target(url).host
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        try:
            addresses = resolve_host_ips(host)
        except OSError as exc:
            raise AuthorizationError(f"DNS resolution failed for {host}; failing closed.", code="dns_failed") from exc
    else:
        addresses = [str(literal)]
    try:
        return list(validated_addresses(addresses))
    except ValueError as exc:
        code = "unsafe_target" if str(exc).startswith("Hostname resolved") else "dns_failed"
        raise AuthorizationError(f"{exc} Failing closed.", code=code) from exc


def _checked_target(url: str, expected_fingerprint: str | None = None) -> tuple[Target, dict]:
    grant = current_grant()
    try:
        verify_current_binding()
        return require_url(url, expected_fingerprint=grant.fingerprint if grant else expected_fingerprint)
    except AuthorizationError as exc:
        if exc.decision:
            audit_dispatch(exc.decision, phase="policy")
        raise


def checked_dns(url: str, *, expected_fingerprint: str | None = None,
                dns_only: bool = False) -> tuple[Target, dict, list[str]]:
    """Authorize the canonical URL before any address lookup."""
    target, decision = _checked_target(url, expected_fingerprint)
    if dns_only:
        audit_dispatch(decision, phase="dns")
        _checked_target(target.url, decision["policy_fingerprint"])
    try:
        ips = assert_resolved_host_is_public(target.url)
    except AuthorizationError as exc:
        rejected = {**decision, "authorized": False, "in_scope": False, "network_execution_permitted": False,
                    "reason_code": exc.code, "reason": str(exc)}
        audit_dispatch(rejected, phase="dns")
        raise AuthorizationError(str(exc), code=exc.code, decision=rejected) from exc
    return target, decision, ips


def redirect_url(base: str, location: str) -> str:
    """Resolve only unambiguous URI references."""
    if (not location or len(location) > MAX_URL_LENGTH or location.startswith("///") or "\\" in location
            or "#" in location or any(c.isspace() or ord(c) < 33 or ord(c) == 127 for c in location)):
        raise AuthorizationError("Invalid or ambiguous URL reference.", code="invalid_url")
    try:
        parts = urlsplit(location)
    except ValueError as exc:
        raise AuthorizationError("Invalid URL reference.", code="invalid_url") from exc
    if ((parts.scheme and not parts.netloc) or "//" in parts.path
            or {".", ".."}.intersection(parts.path.split("/"))):
        raise AuthorizationError("Invalid or ambiguous URL reference.", code="invalid_url")
    resolved = urljoin(base, location)
    if "?" in location and not parts.query:
        resolved = resolved.split("?", 1)[0] + "?"
    return resolved


def _safe_request(client: httpx.Client, method: str, url: str, *, headers_only: bool = False,
                  expected_fingerprint: str | None = None, follow_redirects: bool = True) -> httpx.Response:
    """Enforce the same active policy on the actual outbound request and every hop."""
    current_url = url
    if method not in {"HEAD", "GET"}:
        raise AuthorizationError("Only HEAD and GET are permitted.", code="invalid_method")
    for hop in range(MAX_REDIRECTS + 1):
        try:
            target, initial = _checked_target(current_url, expected_fingerprint)
            expected_fingerprint = initial["policy_fingerprint"]
            headers = {"Range": "bytes=0-0"} if headers_only and method == "GET" else None
            request = client.build_request(method, target.url, headers=headers)
            request.headers.pop("Cookie", None)
            request.headers.pop("Authorization", None)
            if parse_target(str(request.url)) != target:
                raise AuthorizationError("HTTP client changed the authorized URL.", code="invalid_url")
            _request_delay()
            _, _, addresses = checked_dns(target.url, expected_fingerprint=expected_fingerprint)
            wire_target, decision = _checked_target(str(request.url), expected_fingerprint)
            audit_dispatch(decision, phase="http")
            if current_grant() is not None:
                _checked_target(wire_target.url, expected_fingerprint)
            request.extensions[DESTINATIONS] = ((wire_target.scheme, wire_target.host, wire_target.port), tuple(addresses))
            response = client.send(request, stream=True, auth=None, follow_redirects=False)
        except AuthorizationError as exc:
            if not hop:
                raise
            raise AuthorizationError(f"Redirect blocked: {exc}", code=exc.code, decision=exc.decision) from exc
        except httpx.InvalidURL as exc:
            raise AuthorizationError("HTTP client rejected an invalid request or redirect URL.", code="invalid_url") from exc

        location = response.headers.get("location") if response.has_redirect_location else None
        if not follow_redirects or not location:
            response.extensions["scope_decision"] = decision
            return response
        response.close()
        if hop == MAX_REDIRECTS:
            break
        try:
            current_url = redirect_url(wire_target.url, location)
        except AuthorizationError as exc:
            rejected = {**decision, "target": None, "normalized_url": None, "authorized": False, "in_scope": False,
                        "matched_inclusion_rule": None, "matched_exclusion_rule": None, "matched_restriction_rule": None,
                        "network_execution_permitted": False, "reason_code": exc.code, "reason": str(exc)}
            audit_dispatch(rejected, phase="redirect")
            raise AuthorizationError(f"Redirect blocked: {exc}", code=exc.code, decision=rejected) from exc
    raise AuthorizationError(f"Too many redirects; stopped after {MAX_REDIRECTS} redirects.", code="redirect_limit")


def safe_get_text(url: str, *, limit_name: str = "max_javascript_bytes", content_type: str = "JavaScript") -> str:
    return safe_get_text_with_response(url, limit_name=limit_name, content_type=content_type)[0]


def safe_get_text_with_response(url: str, *, limit_name: str = "max_javascript_bytes",
                                content_type: str = "JavaScript") -> tuple[str, httpx.Response]:
    """GET text from an in-scope URL using the shared redirect-safety path."""
    _, initial = _checked_target(url)
    with _client() as client:
        response = _safe_request(client, "GET", url, expected_fingerprint=initial["policy_fingerprint"])
        try:
            response.raise_for_status()
            content = _read_bounded(response, get_limit(limit_name), content_type=content_type)
            return content.decode(response.encoding or "utf-8", errors="replace"), response
        finally:
            response.close()


def safe_get_bytes(url: str, maximum: int, *, content_type: str, expected_fingerprint: str | None = None,
                   follow_redirects: bool = True, timeout: float | None = None) -> tuple[bytes, httpx.Response]:
    """Stream one safe in-scope response into a bounded byte string."""
    _, initial = _checked_target(url, expected_fingerprint)
    with (_client() if timeout is None else _client(timeout=timeout)) as client:
        response = _safe_request(client, "GET", url, expected_fingerprint=initial["policy_fingerprint"], follow_redirects=follow_redirects)
        try:
            response.raise_for_status()
            return _read_bounded(response, maximum, content_type=content_type), response
        finally:
            response.close()


def _header_result(url: str, response: httpx.Response, method_used: str, fallback_reason: str | None) -> dict:
    """Extract the fields while the caller owns the open response."""
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
        "url": safe_target(url),
        "final_url": safe_target(str(response.url)),
        "status_code": response.status_code,
        "method": method_used,
        "headers": headers,
        "interesting_headers": interesting_headers,
        "notes": notes,
        "fallback_reason": fallback_reason,
        "scope_decision": response.extensions["scope_decision"],
    }


def fetch_headers(url: str) -> dict:
    """Fetch response headers from an in-scope URL using HEAD with safe GET fallback."""
    fallback_reason = None
    try:
        _, initial = _checked_target(url)
        fingerprint = initial["policy_fingerprint"]
        method = get_fetch_headers_method()
        with _client() as client:
            response = None
            try:
                if method == "HEAD":
                    try:
                        response = _safe_request(client, "HEAD", url, expected_fingerprint=fingerprint)
                    except httpx.HTTPError:
                        fallback_reason = "HEAD request failed."
                    else:
                        if response.status_code in {403, 405}:
                            fallback_reason = f"HEAD returned {response.status_code}"
                            head, response = response, None
                            head.close()
                    if fallback_reason:
                        method = "GET"
                if method == "GET":
                    response = _safe_request(client, "GET", url, headers_only=True, expected_fingerprint=fingerprint)
                return _header_result(url, response, method, fallback_reason)
            finally:
                if response is not None:
                    response.close()
    except ScopeError as exc:
        return _error_result(url, exc)
    except httpx.HTTPError:
        return _error_result(url, "HTTP request failed.")


def fetch_robots(url: str) -> dict:
    """Fetch and parse robots.txt from an in-scope URL origin."""
    try:
        target, initial = _checked_target(url)
        robots_url = target.origin + "/robots.txt"
        content, response = safe_get_bytes(robots_url, get_limit("max_robots_bytes"), content_type="robots.txt",
                                           expected_fingerprint=initial["policy_fingerprint"])
    except ScopeError as exc:
        return _error_result(url, exc)
    except httpx.HTTPError:
        return _error_result(url, "HTTP request failed.")
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
            disallow.append(redact_endpoint(match.group(1)))
        elif match := re.match(r"^\s*Allow\s*:\s*(.*?)\s*$", line, flags=re.IGNORECASE):
            allow.append(redact_endpoint(match.group(1)))
        if len(disallow) + len(allow) >= entry_limit:
            result_truncated = True
            break

    return {
        "ok": True,
        "url": robots_url,
        "final_url": safe_target(str(response.url)),
        "status_code": response.status_code,
        "scope_decision": response.extensions["scope_decision"],
        "content_preview": redact_embedded_urls(robots_text[:2000]),
        "content_truncated": content_truncated,
        "results_truncated": result_truncated,
        "disallow": disallow,
        "allow": allow,
    }


def fetch_sitemap(url: str) -> dict:
    """Fetch and parse sitemap.xml from an in-scope URL origin."""
    try:
        target, initial = _checked_target(url)
        sitemap_url = target.origin + "/sitemap.xml"
        content, response = safe_get_bytes(sitemap_url, get_limit("max_sitemap_bytes"), content_type="sitemap",
                                           expected_fingerprint=initial["policy_fingerprint"])
    except ScopeError as exc:
        return _error_result(url, exc)
    except httpx.HTTPError:
        return _error_result(url, "HTTP request failed.")
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

    safe_discovered_urls = sorted({safe_target(url) for url in discovered_urls})
    return {
        "ok": True,
        "url": sitemap_url,
        "final_url": safe_target(str(response.url)),
        "status_code": response.status_code,
        "scope_decision": response.extensions["scope_decision"],
        "discovered_urls": safe_discovered_urls,
        "count": len(safe_discovered_urls),
        "content_preview": redact_embedded_urls(sitemap_text[:2000]),
        "content_truncated": content_truncated,
        "results_truncated": len(discovered_urls) >= get_limit("max_endpoint_candidates"),
        "parse_error": parse_error,
    }
