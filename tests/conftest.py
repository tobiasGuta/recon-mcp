import pytest


@pytest.fixture
def campaign_env(monkeypatch, tmp_path):
    root = tmp_path / "campaigns"
    archive_root = tmp_path / "archived_campaigns"
    monkeypatch.setattr("recon.campaigns.CAMPAIGNS_DIR", root)
    monkeypatch.setattr("recon.campaigns.ARCHIVED_CAMPAIGNS_DIR", archive_root)
    config = {
        "scope_source": "manual",
        "allowed_domains": ["example.com"],
        "allowed_assets": [{"value": "*.example.com", "match": "wildcard"}],
        "blocked_domains": [],
        "user_agent": "ReconMCP/0.1",
        "request_delay_ms": 0,
        "max_requests_per_tool_call": 20,
        "fetch_headers_method": "HEAD",
    }
    monkeypatch.setattr("recon.scope.load_scope", lambda: config)
    monkeypatch.setattr("recon.http_fetch.load_scope", lambda: config)
    monkeypatch.setattr("recon.js_analysis.load_scope", lambda: config)
    monkeypatch.setattr("recon.http_fetch.resolve_host_ips", lambda host: ["93.184.216.34"])
    return root


@pytest.fixture(autouse=True)
def isolated_policy_and_network(monkeypatch, tmp_path):
    """Use an isolated default policy and fail if tests reach real DNS or sockets."""
    monkeypatch.setattr("recon.scope.DEFAULT_SCOPE_PATH", tmp_path / "default-scope.json")
    monkeypatch.setattr("recon.campaigns.CAMPAIGNS_DIR", tmp_path / "default-campaigns")
    monkeypatch.setattr("recon.campaigns.ARCHIVED_CAMPAIGNS_DIR", tmp_path / "default-archived-campaigns")

    def unexpected_network(*args, **kwargs):
        raise AssertionError("Tests must use mocked network I/O.")

    monkeypatch.setattr("socket.getaddrinfo", unexpected_network)
    monkeypatch.setattr("socket.socket.connect", unexpected_network)
    monkeypatch.setattr("socket.socket.connect_ex", unexpected_network)
