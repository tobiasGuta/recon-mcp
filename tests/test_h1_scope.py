import json

from recon.h1_scope import (
    extract_allowed_hosts_from_h1_entries,
    load_h1_snapshots,
    normalise_h1_asset_identifier,
)
from recon.scope import check_scope


def write_snapshot(tmp_path, handle, entries):
    snapshot = tmp_path / f"{handle}.json"
    snapshot.write_text(json.dumps(entries), encoding="utf-8")
    return snapshot


def h1_scope_config(snapshot_dir, bounty=False, submission=True):
    return {
        "scope_source": "h1_snapshots",
        "h1_snapshot_dir": str(snapshot_dir),
        "include_only_bounty_eligible": bounty,
        "include_only_submission_eligible": submission,
        "allowed_domains": [],
        "blocked_domains": ["localhost", "127.0.0.1", "0.0.0.0", "::1"],
    }


def test_loads_valid_h1_snapshot_file(tmp_path):
    write_snapshot(
        tmp_path,
        "security",
        [{"asset_type": "URL", "asset_identifier": "https://example.com", "eligible_for_submission": True}],
    )

    entries = load_h1_snapshots(str(tmp_path))

    assert len(entries) == 1
    assert entries[0]["_program_handle"] == "security"
    assert entries[0]["_source_file"].endswith("security.json")


def test_extracts_hostname_from_url():
    assert normalise_h1_asset_identifier("https://example.com/path?q=1") == ["example.com"]


def test_handles_wildcard_domain():
    assert normalise_h1_asset_identifier("*.example.com") == ["*.example.com"]


def test_respects_submission_eligible():
    entries = [
        {"asset_identifier": "eligible.example.com", "eligible_for_submission": True},
        {"asset_identifier": "ineligible.example.com", "eligible_for_submission": False},
    ]

    result = extract_allowed_hosts_from_h1_entries(entries, False, True)

    assert [item["host"] for item in result["allowed_hosts"]] == ["eligible.example.com"]


def test_respects_bounty_eligible():
    entries = [
        {"asset_identifier": "bounty.example.com", "eligible_for_bounty": True},
        {"asset_identifier": "no-bounty.example.com", "eligible_for_bounty": False},
    ]

    result = extract_allowed_hosts_from_h1_entries(entries, True, False)

    assert [item["host"] for item in result["allowed_hosts"]] == ["bounty.example.com"]


def test_blocks_localhost_and_private_ip_entries():
    entries = [
        {"asset_identifier": "localhost"},
        {"asset_identifier": "127.0.0.1"},
        {"asset_identifier": "192.168.1.10"},
        {"asset_identifier": "example.com"},
    ]

    result = extract_allowed_hosts_from_h1_entries(entries, False, False)

    assert [item["host"] for item in result["allowed_hosts"]] == ["example.com"]


def test_out_of_scope_domain_returns_false(tmp_path, monkeypatch):
    write_snapshot(
        tmp_path,
        "security",
        [{"asset_type": "URL", "asset_identifier": "https://example.com", "eligible_for_submission": True}],
    )
    monkeypatch.setattr("recon.scope.load_scope", lambda: h1_scope_config(tmp_path))

    result = check_scope("bad.com")

    assert result["in_scope"] is False
    assert result["reason"] == "No matching H1 scope entry found."


def test_subdomain_of_allowed_domain_returns_true(tmp_path, monkeypatch):
    write_snapshot(
        tmp_path,
        "security",
        [
            {
                "asset_type": "URL",
                "asset_identifier": "https://example.com",
                "eligible_for_bounty": True,
                "eligible_for_submission": True,
                "max_severity": "critical",
                "instruction": "Test carefully.",
            }
        ],
    )
    monkeypatch.setattr("recon.scope.load_scope", lambda: h1_scope_config(tmp_path))

    result = check_scope("api.example.com")

    assert result["in_scope"] is True
    assert result["matched_scope"] == "example.com"
    assert result["scope_source"] == "h1_snapshots"
    assert result["program_handle"] == "security"
    assert result["asset_type"] == "URL"
    assert result["eligible_for_bounty"] is True
    assert result["eligible_for_submission"] is True
    assert result["max_severity"] == "critical"


def test_wildcard_allows_subdomain_but_not_base_or_suffix_trick(tmp_path, monkeypatch):
    write_snapshot(
        tmp_path,
        "security",
        [{"asset_type": "WILDCARD", "asset_identifier": "*.example.com", "eligible_for_submission": True}],
    )
    monkeypatch.setattr("recon.scope.load_scope", lambda: h1_scope_config(tmp_path))

    assert check_scope("api.example.com")["in_scope"] is True
    assert check_scope("example.com")["in_scope"] is False
    assert check_scope("badexample.com")["in_scope"] is False


def test_missing_snapshot_directory_fails_closed(monkeypatch):
    missing_dir = "Z:/definitely/not/a/real/h1/snapshot/dir"
    monkeypatch.setattr("recon.scope.load_scope", lambda: h1_scope_config(missing_dir))

    result = check_scope("example.com")

    assert result["ok"] is False
    assert result["in_scope"] is False
    assert "does not exist" in result["reason"]


def test_empty_snapshot_file_fails_closed(tmp_path, monkeypatch):
    write_snapshot(tmp_path, "security", [])
    monkeypatch.setattr("recon.scope.load_scope", lambda: h1_scope_config(tmp_path))

    result = check_scope("example.com")

    assert result["ok"] is False
    assert result["in_scope"] is False
    assert "no usable scope entries" in result["reason"].lower()
