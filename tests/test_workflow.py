import json
from pathlib import Path

from recon.campaigns import create_campaign, get_campaign_paths
from recon.workflow import (
    extract_endpoints_for_campaign,
    fetch_headers_for_campaign,
    generate_manual_test_plan_for_campaign,
)


def test_fetch_headers_for_campaign_saves_artifact_and_audit(campaign_env, monkeypatch):
    campaign_id = create_campaign("Demo", "example.com")["campaign_id"]
    monkeypatch.setattr(
        "recon.workflow.fetch_headers",
        lambda url: {"ok": True, "url": url, "headers": {"x-test": "ok"}, "interesting_headers": {}},
    )

    result = fetch_headers_for_campaign(campaign_id, "https://example.com")

    assert result["ok"] is True
    artifact = json.loads(Path(result["path"]).read_text(encoding="utf-8"))
    assert artifact["result"]["headers"]["x-test"] == "ok"
    audit = Path(get_campaign_paths(campaign_id)["paths"]["audit_jsonl"]).read_text(encoding="utf-8")
    assert "fetch_headers_for_campaign" in audit


def test_extract_endpoints_for_campaign_scores_and_saves(campaign_env):
    campaign_id = create_campaign("Demo", "example.com")["campaign_id"]

    result = extract_endpoints_for_campaign(campaign_id, "fetch('/api/v1/admin/users?id=1')", source_type="raw")

    assert result["ok"] is True
    assert result["scored_endpoints"][0]["priority"] == "high"
    artifact = json.loads(Path(result["path"]).read_text(encoding="utf-8"))
    assert artifact["scored_endpoints"]


def test_generate_manual_test_plan_for_campaign_lists_top_endpoints(campaign_env):
    campaign_id = create_campaign("Demo", "example.com")["campaign_id"]
    extract_endpoints_for_campaign(campaign_id, "fetch('/graphql'); fetch('/assets/app.css')", source_type="raw")

    result = generate_manual_test_plan_for_campaign(campaign_id)

    assert result["ok"] is True
    content = Path(result["path"]).read_text(encoding="utf-8")
    assert "/graphql" in content
    assert "DirFuzz Handoff" in content
