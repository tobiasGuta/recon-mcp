import pytest


@pytest.fixture
def campaign_env(monkeypatch, tmp_path):
    root = tmp_path / "campaigns"
    monkeypatch.setattr("recon.campaigns.CAMPAIGNS_DIR", root)
    monkeypatch.setattr(
        "recon.scope.load_scope",
        lambda: {
            "scope_source": "manual",
            "allowed_domains": ["example.com"],
            "blocked_domains": [],
            "user_agent": "ReconMCP/0.1",
            "request_delay_ms": 0,
            "max_requests_per_tool_call": 20,
            "fetch_headers_method": "HEAD",
        },
    )
    return root
