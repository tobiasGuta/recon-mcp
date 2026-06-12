import httpx

from recon.http_fetch import fetch_headers


def scoped_config():
    return {
        "scope_source": "manual",
        "allowed_domains": ["example.com"],
        "blocked_domains": [],
    }


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

    monkeypatch.setattr("recon.scope.load_scope", scoped_config)
    monkeypatch.setattr("recon.http_fetch._client", client)

    result = fetch_headers("https://example.com/")

    assert result["ok"] is False
    assert "redirect blocked" in result["error"].lower()
    assert requested_urls == ["https://example.com/"]
