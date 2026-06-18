import pytest


@pytest.fixture
def campaign_env(monkeypatch, tmp_path):
    root = tmp_path / "campaigns"
    monkeypatch.setattr("recon.campaigns.CAMPAIGNS_DIR", root)
    config = {
        "scope_source": "manual",
        "allowed_domains": ["example.com"],
        "blocked_domains": [],
        "user_agent": "ReconMCP/0.1",
        "request_delay_ms": 0,
        "max_requests_per_tool_call": 20,
        "fetch_headers_method": "HEAD",
    }
    monkeypatch.setattr("recon.scope.load_scope", lambda: config)
    monkeypatch.setattr("recon.http_fetch.load_scope", lambda: config)
    monkeypatch.setattr("recon.js_analysis.load_scope", lambda: config)
    return root
