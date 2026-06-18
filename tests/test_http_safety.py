import httpx
import pytest
from defusedxml.common import DefusedXmlException

from recon.http_fetch import (
    MAX_ROBOTS_BYTES,
    MAX_SITEMAP_BYTES,
    fetch_headers,
    fetch_robots,
    fetch_sitemap,
    get_request_delay_ms,
    safe_get_text,
)
from recon.scope import ScopeError


def scoped_config(**overrides):
    config = {
        "scope_source": "manual",
        "allowed_domains": ["example.com"],
        "blocked_domains": [],
        "user_agent": "ReconMCP/0.1",
        "request_delay_ms": 0,
        "max_requests_per_tool_call": 20,
        "fetch_headers_method": "HEAD",
    }
    config.update(overrides)
    return config


def patch_scope(monkeypatch, **overrides):
    config = scoped_config(**overrides)
    monkeypatch.setattr("recon.scope.load_scope", lambda: config)
    monkeypatch.setattr("recon.http_fetch.load_scope", lambda: config)
    monkeypatch.setattr("recon.http_fetch.resolve_host_ips", lambda host: ["93.184.216.34"])
    return config


def test_fetch_headers_uses_head_first(monkeypatch):
    requested_methods = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested_methods.append(request.method)
        return httpx.Response(200, headers={"x-test": "ok"})

    def client():
        return httpx.Client(
            transport=httpx.MockTransport(handler),
            timeout=10.0,
            follow_redirects=False,
            headers={"User-Agent": "ReconMCP/0.1"},
        )

    patch_scope(monkeypatch)
    monkeypatch.setattr("recon.http_fetch._client", client)

    result = fetch_headers("https://example.com/")

    assert result["ok"] is True
    assert result["method"] == "HEAD"
    assert requested_methods == ["HEAD"]


def test_fetch_headers_falls_back_to_safe_get_on_head_405(monkeypatch):
    requested = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested.append((request.method, request.headers.get("range")))
        if request.method == "HEAD":
            return httpx.Response(405)
        return httpx.Response(200, headers={"x-test": "ok"}, text="small preview")

    def client():
        return httpx.Client(
            transport=httpx.MockTransport(handler),
            timeout=10.0,
            follow_redirects=False,
            headers={"User-Agent": "ReconMCP/0.1"},
        )

    patch_scope(monkeypatch)
    monkeypatch.setattr("recon.http_fetch._client", client)

    result = fetch_headers("https://example.com/")

    assert result["ok"] is True
    assert result["method"] == "GET"
    assert result["fallback_reason"] == "HEAD returned 405"
    assert requested == [("HEAD", None), ("GET", "bytes=0-0")]


def test_configurable_user_agent_is_applied(monkeypatch):
    observed_user_agents = []
    original_client = httpx.Client

    def handler(request: httpx.Request) -> httpx.Response:
        observed_user_agents.append(request.headers.get("user-agent"))
        return httpx.Response(200)

    patch_scope(monkeypatch, user_agent="CustomRecon/9")
    monkeypatch.setattr("recon.http_fetch.time.sleep", lambda _: None)
    monkeypatch.setattr(
        "recon.http_fetch.httpx.Client",
        lambda **kwargs: original_client(transport=httpx.MockTransport(handler), **kwargs),
    )

    result = fetch_headers("https://example.com/")

    assert result["ok"] is True
    assert observed_user_agents == ["CustomRecon/9"]


def test_request_delay_config_is_loaded(monkeypatch):
    patch_scope(monkeypatch, request_delay_ms=123)
    assert get_request_delay_ms() == 123


def test_fetch_headers_blocks_out_of_scope_redirect_before_following(monkeypatch):
    requested_urls = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested_urls.append(str(request.url))
        if str(request.url) == "https://example.com/":
            return httpx.Response(302, headers={"location": "https://evil.test/"})
        return httpx.Response(200, text="should not be requested")

    def client():
        return httpx.Client(
            transport=httpx.MockTransport(handler),
            timeout=10.0,
            follow_redirects=False,
            headers={"User-Agent": "ReconMCP/0.1"},
        )

    patch_scope(monkeypatch)
    monkeypatch.setattr("recon.http_fetch._client", client)

    result = fetch_headers("https://example.com/")

    assert result["ok"] is False
    assert "redirect blocked" in result["error"].lower()
    assert requested_urls == ["https://example.com/"]


def test_fetch_headers_blocks_out_of_scope_redirect_during_get_fallback(monkeypatch):
    requested = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested.append((request.method, str(request.url)))
        if request.method == "HEAD":
            return httpx.Response(405)
        return httpx.Response(302, headers={"location": "https://evil.test/"})

    def client():
        return httpx.Client(
            transport=httpx.MockTransport(handler),
            timeout=10.0,
            follow_redirects=False,
            headers={"User-Agent": "ReconMCP/0.1"},
        )

    patch_scope(monkeypatch)
    monkeypatch.setattr("recon.http_fetch._client", client)

    result = fetch_headers("https://example.com/")

    assert result["ok"] is False
    assert "redirect blocked" in result["error"].lower()
    assert requested == [("HEAD", "https://example.com/"), ("GET", "https://example.com/")]


def test_fetch_robots_truncates_large_body(monkeypatch):
    large_body = b"Disallow: /private\n" + (b"A" * (MAX_ROBOTS_BYTES + 1))

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=large_body)

    def client():
        return httpx.Client(
            transport=httpx.MockTransport(handler),
            timeout=10.0,
            follow_redirects=False,
            headers={"User-Agent": "ReconMCP/0.1"},
        )

    patch_scope(monkeypatch)
    monkeypatch.setattr("recon.http_fetch._client", client)

    result = fetch_robots("https://example.com/")

    assert result["ok"] is True
    assert result["content_truncated"] is True
    assert len(result["content_preview"]) <= 2000
    assert result["disallow"] == ["/private"]


def test_fetch_sitemap_rejects_oversized_body(monkeypatch):
    large_body = b"<urlset>" + (b"A" * (MAX_SITEMAP_BYTES + 1)) + b"</urlset>"

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=large_body)

    def client():
        return httpx.Client(
            transport=httpx.MockTransport(handler),
            timeout=10.0,
            follow_redirects=False,
            headers={"User-Agent": "ReconMCP/0.1"},
        )

    patch_scope(monkeypatch)
    monkeypatch.setattr("recon.http_fetch._client", client)

    result = fetch_sitemap("https://example.com/")

    assert result["ok"] is True
    assert result["content_truncated"] is True
    assert result["parse_error"] == "Response too large to parse."
    assert result["discovered_urls"] == []


def test_fetch_robots_out_of_scope_url_is_rejected(monkeypatch):
    patch_scope(monkeypatch)

    result = fetch_robots("https://evil.test/")

    assert result["ok"] is False
    assert "out of scope" in result["error"].lower() or "does not match" in result["error"].lower()


def test_fetch_sitemap_out_of_scope_url_is_rejected(monkeypatch):
    patch_scope(monkeypatch)

    result = fetch_sitemap("https://evil.test/")

    assert result["ok"] is False
    assert "out of scope" in result["error"].lower() or "does not match" in result["error"].lower()


def test_safe_get_text_raises_scope_error_for_out_of_scope_url(monkeypatch):
    patch_scope(monkeypatch)

    try:
        safe_get_text("https://evil.test/")
    except ScopeError as exc:
        assert "out of scope" in str(exc).lower() or "does not match" in str(exc).lower()
    else:
        raise AssertionError("safe_get_text should reject out-of-scope URLs")


def test_safe_get_text_follows_redirects_within_scope(monkeypatch):
    requested_urls = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested_urls.append(str(request.url))
        if str(request.url) == "https://example.com/start":
            return httpx.Response(302, headers={"location": "/final"})
        return httpx.Response(200, text="done")

    def client():
        return httpx.Client(
            transport=httpx.MockTransport(handler),
            timeout=10.0,
            follow_redirects=False,
            headers={"User-Agent": "ReconMCP/0.1"},
        )

    patch_scope(monkeypatch)
    monkeypatch.setattr("recon.http_fetch._client", client)

    result = safe_get_text("https://example.com/start")

    assert result == "done"
    assert requested_urls == ["https://example.com/start", "https://example.com/final"]


def test_safe_request_blocks_hostname_resolving_to_loopback(monkeypatch):
    patch_scope(monkeypatch)
    monkeypatch.setattr("recon.http_fetch.resolve_host_ips", lambda host: ["127.0.0.1"])

    result = fetch_headers("https://example.com/")

    assert result["ok"] is False
    assert "unsafe" in result["error"].lower()
    assert "127.0.0.1" in result["error"]


def test_safe_request_blocks_hostname_resolving_to_private_ip(monkeypatch):
    patch_scope(monkeypatch)
    monkeypatch.setattr("recon.http_fetch.resolve_host_ips", lambda host: ["10.0.0.1"])

    result = fetch_headers("https://example.com/")

    assert result["ok"] is False
    assert "unsafe" in result["error"].lower()
    assert "10.0.0.1" in result["error"]


def test_safe_request_blocks_hostname_resolving_to_link_local_ip(monkeypatch):
    patch_scope(monkeypatch)
    monkeypatch.setattr("recon.http_fetch.resolve_host_ips", lambda host: ["169.254.1.10"])

    result = fetch_headers("https://example.com/")

    assert result["ok"] is False
    assert "unsafe" in result["error"].lower()
    assert "169.254.1.10" in result["error"]


def test_safe_request_blocks_hostname_resolving_to_ipv6_loopback(monkeypatch):
    patch_scope(monkeypatch)
    monkeypatch.setattr("recon.http_fetch.resolve_host_ips", lambda host: ["::1"])

    result = fetch_headers("https://example.com/")

    assert result["ok"] is False
    assert "unsafe" in result["error"].lower()
    assert "::1" in result["error"]


def test_safe_request_fails_closed_on_dns_resolution_error(monkeypatch):
    patch_scope(monkeypatch)

    def fail_dns(host):
        raise OSError("mock dns failure")

    monkeypatch.setattr("recon.http_fetch.resolve_host_ips", fail_dns)

    result = fetch_headers("https://example.com/")

    assert result["ok"] is False
    assert "dns resolution failed" in result["error"].lower()
    assert "failing closed" in result["error"].lower()


def test_safe_request_checks_redirect_resolved_ip_before_following(monkeypatch):
    requested_urls = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested_urls.append(str(request.url))
        if str(request.url) == "https://example.com/":
            return httpx.Response(302, headers={"location": "https://sub.example.com/final"})
        return httpx.Response(200, text="should not be requested")

    def client():
        return httpx.Client(
            transport=httpx.MockTransport(handler),
            timeout=10.0,
            follow_redirects=False,
            headers={"User-Agent": "ReconMCP/0.1"},
        )

    def resolve(host):
        if host == "sub.example.com":
            return ["10.0.0.5"]
        return ["93.184.216.34"]

    patch_scope(monkeypatch)
    monkeypatch.setattr("recon.http_fetch.resolve_host_ips", resolve)
    monkeypatch.setattr("recon.http_fetch._client", client)

    result = fetch_headers("https://example.com/")

    assert result["ok"] is False
    assert "redirect blocked" in result["error"].lower()
    assert "10.0.0.5" in result["error"]
    assert requested_urls == ["https://example.com/"]


def test_safe_request_allows_public_resolved_ip(monkeypatch):
    requested_urls = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested_urls.append(str(request.url))
        return httpx.Response(200, headers={"x-test": "ok"})

    def client():
        return httpx.Client(
            transport=httpx.MockTransport(handler),
            timeout=10.0,
            follow_redirects=False,
            headers={"User-Agent": "ReconMCP/0.1"},
        )

    patch_scope(monkeypatch)
    monkeypatch.setattr("recon.http_fetch.resolve_host_ips", lambda host: ["93.184.216.34"])
    monkeypatch.setattr("recon.http_fetch._client", client)

    result = fetch_headers("https://example.com/")

    assert result["ok"] is True
    assert requested_urls == ["https://example.com/"]


def test_fetch_sitemap_blocks_xml_entity_expansion(monkeypatch):
    body = """<?xml version="1.0"?>
<!DOCTYPE lolz [
 <!ENTITY lol "lol">
 <!ENTITY lol1 "&lol;&lol;&lol;&lol;">
]>
<urlset><url><loc>&lol1;</loc></url></urlset>"""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=body)

    def client():
        return httpx.Client(
            transport=httpx.MockTransport(handler),
            timeout=10.0,
            follow_redirects=False,
            headers={"User-Agent": "ReconMCP/0.1"},
        )

    patch_scope(monkeypatch)
    monkeypatch.setattr("recon.http_fetch._client", client)

    result = fetch_sitemap("https://example.com/")

    assert result["ok"] is True
    assert result["discovered_urls"] == []
    assert result["parse_error"]
    assert "parsed" in result["parse_error"].lower()


def test_fetch_sitemap_handles_defusedxml_exception_safely(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<urlset />")

    def client():
        return httpx.Client(
            transport=httpx.MockTransport(handler),
            timeout=10.0,
            follow_redirects=False,
            headers={"User-Agent": "ReconMCP/0.1"},
        )

    def blocked_xml(text):
        raise DefusedXmlException("blocked by test")

    patch_scope(monkeypatch)
    monkeypatch.setattr("recon.http_fetch._client", client)
    monkeypatch.setattr("recon.http_fetch.ET.fromstring", blocked_xml)

    result = fetch_sitemap("https://example.com/")

    assert result["ok"] is True
    assert result["discovered_urls"] == []
    assert "blocked by test" in result["parse_error"]
