from pathlib import Path

from recon.campaigns import create_campaign, get_campaign, get_campaign_paths, list_campaigns


def test_campaign_creation_fails_closed_out_of_scope(campaign_env):
    result = create_campaign("Demo", "https://evil.test")

    assert result["ok"] is False
    assert not campaign_env.exists()


def test_campaign_creation_creates_expected_layout(campaign_env):
    result = create_campaign("Demo Program", "https://app.example.com/path", notes="authorized")

    assert result["ok"] is True
    campaign_id = result["campaign_id"]
    paths = get_campaign_paths(campaign_id)
    assert paths["ok"] is True
    root = Path(paths["paths"]["root"])
    assert root.parent == campaign_env.resolve()
    assert (root / "campaign.json").exists()
    assert (root / "scope.json").exists()
    assert (root / "recon" / "headers").is_dir()
    assert (root / "findings" / "hallucinations").is_dir()
    assert (root / "memory" / "negative_results.jsonl").parent.is_dir()

    loaded = get_campaign(campaign_id)
    assert loaded["ok"] is True
    assert loaded["campaign"]["normalized_host"] == "app.example.com"
    assert list_campaigns()["count"] == 1


def test_campaign_path_traversal_is_blocked(campaign_env):
    result = get_campaign_paths("../outside")

    assert result["ok"] is False
    assert "unsafe" in result["error"].lower()


def test_campaign_core_symlink_is_rejected(campaign_env, monkeypatch):
    created = create_campaign("Demo", "example.com")
    evidence = Path(get_campaign_paths(created["campaign_id"])["paths"]["evidence"])
    monkeypatch.setattr(type(evidence), "is_symlink", lambda self: self == evidence)

    result = get_campaign_paths(created["campaign_id"])

    assert result["ok"] is False
    assert "symlink" in result["error"].lower()
