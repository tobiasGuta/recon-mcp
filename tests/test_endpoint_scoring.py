from recon.endpoint_scoring import score_endpoint, score_endpoints


def test_endpoint_scoring_prioritizes_api_admin_query():
    result = score_endpoint("/api/v1/admin/users?id=123")

    assert result["ok"] is True
    assert result["priority"] == "high"
    assert result["score"] >= 12
    assert "API route" in result["reasons"]


def test_endpoint_scoring_deprioritizes_static_assets():
    result = score_endpoint("/assets/app.css")

    assert result["priority"] == "low"
    assert result["score"] < 0


def test_score_endpoints_sorts_highest_first():
    result = score_endpoints(["/assets/app.css", "/graphql", "/account?tab=billing"])

    assert result["ok"] is True
    assert result["endpoints"][0]["value"] == "/graphql"
