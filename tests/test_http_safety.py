import httpx

from recon.http_fetch import fetch_headers, get_request_delay_ms


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
