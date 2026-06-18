from pathlib import Path

import server
from recon.campaigns import (
    archive_campaign,
    create_campaign,
    delete_archived_campaign,
    get_archived_campaign,
    get_campaign,
    get_campaign_paths,
    list_archived_campaigns,
    list_campaigns,
)


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


def test_archive_campaign_moves_campaign_to_archive(campaign_env):
    created = create_campaign("Demo", "example.com")
    campaign_id = created["campaign_id"]

    result = archive_campaign(campaign_id, reason="finished")

    assert result["ok"] is True
    assert result["campaign_id"] == campaign_id
    assert result["reason"] == "finished"
    assert not (campaign_env / campaign_id).exists()
    assert Path(result["archived_path"]).parent == campaign_env.parent / "archived_campaigns"
    assert Path(result["archived_path"]).exists()


def test_archive_campaign_rejects_unsafe_campaign_id(campaign_env):
    result = archive_campaign("../outside")

    assert result["ok"] is False
    assert "unsafe" in result["error"].lower()


def test_archive_campaign_rejects_missing_campaign(campaign_env):
    result = archive_campaign("missing-campaign")

    assert result["ok"] is False
    assert "does not exist" in result["error"].lower()


def test_archive_campaign_does_not_overwrite_existing_archive(campaign_env):
    created = create_campaign("Demo", "example.com")
    campaign_id = created["campaign_id"]
    archive_dir = campaign_env.parent / "archived_campaigns" / campaign_id
    archive_dir.mkdir(parents=True)

    result = archive_campaign(campaign_id)

    assert result["ok"] is False
    assert "overwrite" in result["error"].lower()
    assert (campaign_env / campaign_id).exists()


def test_archive_campaign_updates_metadata(campaign_env):
    created = create_campaign("Demo", "example.com")
    campaign_id = created["campaign_id"]

    archive_campaign(campaign_id, reason="done testing")
    result = get_archived_campaign(campaign_id)

    assert result["ok"] is True
    metadata = result["campaign"]
    assert metadata["status"] == "archived"
    assert metadata["archive_reason"] == "done testing"
    assert metadata["archived_at"]
    assert metadata["updated_at"] == metadata["archived_at"]


def test_list_archived_campaigns(campaign_env):
    first = create_campaign("Demo One", "example.com")
    second = create_campaign("Demo Two", "example.com")
    archive_campaign(first["campaign_id"], reason="one")
    archive_campaign(second["campaign_id"], reason="two")

    result = list_archived_campaigns()

    assert result["ok"] is True
    assert result["count"] == 2
    assert {item["campaign_id"] for item in result["campaigns"]} == {first["campaign_id"], second["campaign_id"]}


def test_get_archived_campaign(campaign_env):
    created = create_campaign("Demo", "example.com")
    archive_campaign(created["campaign_id"])

    result = get_archived_campaign(created["campaign_id"])

    assert result["ok"] is True
    assert result["campaign"]["campaign_id"] == created["campaign_id"]


def test_delete_archived_campaign_requires_matching_confirmation(campaign_env):
    created = create_campaign("Demo", "example.com")
    archive_campaign(created["campaign_id"])

    result = delete_archived_campaign(created["campaign_id"], confirm_campaign_id="wrong-id")

    assert result["ok"] is False
    assert "confirmation" in result["error"].lower()
    assert (campaign_env.parent / "archived_campaigns" / created["campaign_id"]).exists()


def test_delete_archived_campaign_rejects_active_campaign(campaign_env):
    created = create_campaign("Demo", "example.com")

    result = delete_archived_campaign(created["campaign_id"], confirm_campaign_id=created["campaign_id"])

    assert result["ok"] is False
    assert "archived campaign does not exist" in result["error"].lower()
    assert (campaign_env / created["campaign_id"]).exists()


def test_delete_archived_campaign_rejects_symlink(campaign_env, monkeypatch):
    created = create_campaign("Demo", "example.com")
    archive_campaign(created["campaign_id"])
    archived = campaign_env.parent / "archived_campaigns" / created["campaign_id"]
    monkeypatch.setattr(type(archived), "is_symlink", lambda self: self == archived)

    result = delete_archived_campaign(created["campaign_id"], confirm_campaign_id=created["campaign_id"])

    assert result["ok"] is False
    assert "symlink" in result["error"].lower()
    assert archived.exists()


def test_delete_archived_campaign_deletes_only_after_confirmation(campaign_env):
    created = create_campaign("Demo", "example.com")
    campaign_id = created["campaign_id"]
    archive_campaign(campaign_id)
    archived = campaign_env.parent / "archived_campaigns" / campaign_id

    result = delete_archived_campaign(campaign_id, confirm_campaign_id=campaign_id)

    assert result["ok"] is True
    assert result["deleted"] is True
    assert "permanently deleted" in result["warning"].lower()
    assert not archived.exists()


def test_health_lists_campaign_cleanup_tools():
    tools = server.health()["available_tools"]

    assert "archive_campaign" in tools
    assert "list_archived_campaigns" in tools
    assert "get_archived_campaign" in tools
    assert "delete_archived_campaign" in tools
