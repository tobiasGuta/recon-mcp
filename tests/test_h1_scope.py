import json

from recon.h1_scope import (
    _is_private_or_loopback_host,
    extract_allowed_hosts_from_h1_entries,
    load_h1_snapshots,
    normalise_h1_asset_identifier,
)
from recon.scope import (
    check_scope,
    check_scope_batch,
    explain_scope_decision,
    get_scope_map,
    recommend_bugmap_parent,
    resolve_scope_target,
)


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


def test_h1_scope_blocks_api_localhost():
    assert _is_private_or_loopback_host("api.localhost") is True


def test_h1_scope_does_not_block_non_localhost_domain():
    assert _is_private_or_loopback_host("example.com") is False


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


def test_check_scope_h1_returns_same_in_scope_as_resolve_scope_target(tmp_path, monkeypatch):
    write_snapshot(
        tmp_path,
        "security",
        [{"asset_type": "URL", "asset_identifier": "https://example.com", "eligible_for_submission": True}],
    )
    monkeypatch.setattr("recon.scope.load_scope", lambda: h1_scope_config(tmp_path))

    check_result = check_scope("api.example.com")
    resolve_result = resolve_scope_target("api.example.com")

    assert check_result["in_scope"] == resolve_result["in_scope"]
    assert check_result["reason_code"] == resolve_result["reason_code"]


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


def test_resolve_scope_target_exact_host_match(tmp_path, monkeypatch):
    write_snapshot(
        tmp_path,
        "program",
        [
            {
                "asset_type": "URL",
                "asset_identifier": "api.example.com",
                "eligible_for_bounty": True,
                "eligible_for_submission": True,
                "max_severity": "critical",
            }
        ],
    )
    monkeypatch.setattr("recon.scope.load_scope", lambda: h1_scope_config(tmp_path))

    result = resolve_scope_target("api.example.com")

    assert result["in_scope"] is True
    assert result["bounty_eligible"] is True
    assert result["submission_eligible"] is True
    assert result["program_handle"] == "program"
    assert result["match_type"] == "exact"
    assert result["exact_matched_asset"] == "api.example.com"
    assert result["reason_code"] == "in_scope_bounty_eligible"
    assert result["scope_metadata"]["total_assets_loaded"] == 1


def test_resolve_scope_target_wildcard_match(tmp_path, monkeypatch):
    write_snapshot(
        tmp_path,
        "program",
        [
            {
                "asset_type": "WILDCARD",
                "asset_identifier": "*.example.com",
                "eligible_for_bounty": True,
                "eligible_for_submission": True,
            }
        ],
    )
    monkeypatch.setattr("recon.scope.load_scope", lambda: h1_scope_config(tmp_path))

    result = resolve_scope_target("api.example.com")

    assert result["in_scope"] is True
    assert result["match_type"] == "wildcard"
    assert result["wildcard_matched_asset"] == "*.example.com"
    assert result["confidence"] == "medium"


def test_resolve_scope_target_non_bounty_eligible_wildcard(tmp_path, monkeypatch):
    write_snapshot(
        tmp_path,
        "program",
        [
            {
                "asset_type": "WILDCARD",
                "asset_identifier": "*.example.com",
                "eligible_for_bounty": False,
                "eligible_for_submission": True,
            }
        ],
    )
    monkeypatch.setattr("recon.scope.load_scope", lambda: h1_scope_config(tmp_path))

    result = resolve_scope_target("api.example.com")

    assert result["in_scope"] is True
    assert result["bounty_eligible"] is False
    assert result["reason_code"] == "in_scope_not_bounty_eligible"


def test_resolve_scope_target_out_of_scope_reason_code(tmp_path, monkeypatch):
    write_snapshot(
        tmp_path,
        "program",
        [{"asset_type": "URL", "asset_identifier": "example.com", "eligible_for_submission": True}],
    )
    monkeypatch.setattr("recon.scope.load_scope", lambda: h1_scope_config(tmp_path))

    result = resolve_scope_target("outside.test")

    assert result["in_scope"] is False
    assert result["reason_code"] == "no_matching_asset"
    assert result["severity_allowed"] is None


def test_resolve_scope_target_url_port_and_uppercase_normalization(tmp_path, monkeypatch):
    write_snapshot(
        tmp_path,
        "program",
        [{"asset_type": "URL", "asset_identifier": "api.example.com", "eligible_for_submission": True}],
    )
    monkeypatch.setattr("recon.scope.load_scope", lambda: h1_scope_config(tmp_path))

    result = resolve_scope_target("https://API.Example.com:8443/path?q=1")

    assert result["normalized_host"] == "api.example.com"
    assert result["match_type"] == "exact"


def test_recommend_bugmap_parent_prefers_exact_host(tmp_path, monkeypatch):
    write_snapshot(
        tmp_path,
        "program",
        [
            {
                "asset_type": "URL",
                "asset_identifier": "api.example.com",
                "eligible_for_bounty": True,
                "eligible_for_submission": True,
            }
        ],
    )
    monkeypatch.setattr("recon.scope.load_scope", lambda: h1_scope_config(tmp_path))

    result = recommend_bugmap_parent(
        "api.example.com",
        [
            {"id": "root", "label": "program"},
            {"id": "api", "label": "api.example.com"},
            {"id": "other", "label": "other.example.com"},
        ],
    )

    assert result["recommended_parent_id"] == "api"
    assert result["recommended_parent_label"] == "api.example.com"


def test_check_scope_batch_returns_structured_results(tmp_path, monkeypatch):
    write_snapshot(
        tmp_path,
        "program",
        [{"asset_type": "URL", "asset_identifier": "one.example.com", "eligible_for_submission": True}],
    )
    monkeypatch.setattr("recon.scope.load_scope", lambda: h1_scope_config(tmp_path))

    result = check_scope_batch(["one.example.com", "two.example.com"])

    assert result["count"] == 2
    assert result["results"][0]["in_scope"] is True
    assert result["results"][1]["reason_code"] == "no_matching_asset"


def test_check_scope_batch_respects_max_batch_size(monkeypatch):
    monkeypatch.setattr(
        "recon.scope.load_scope",
        lambda: {"scope_source": "manual", "allowed_domains": ["example.com"], "blocked_domains": []},
    )

    result = check_scope_batch(["example.com"] * 201)

    assert result["ok"] is False
    assert result["max_batch_size"] == 200
    assert "exceeds maximum" in result["error"]


def test_check_scope_batch_at_max_returns_results(monkeypatch):
    monkeypatch.setattr(
        "recon.scope.load_scope",
        lambda: {"scope_source": "manual", "allowed_domains": ["example.com"], "blocked_domains": []},
    )

    result = check_scope_batch(["example.com"] * 200)

    assert result["ok"] is True
    assert result["count"] == 200
    assert len(result["results"]) == 200


def test_get_scope_map_returns_normalized_entries(tmp_path, monkeypatch):
    write_snapshot(
        tmp_path,
        "program",
        [
            {
                "asset_type": "URL",
                "asset_identifier": "https://api.example.com/path",
                "eligible_for_bounty": True,
                "eligible_for_submission": True,
                "max_severity": "high",
            }
        ],
    )
    monkeypatch.setattr("recon.scope.load_scope", lambda: h1_scope_config(tmp_path))

    result = get_scope_map()

    assert result["ok"] is True
    assert result["entries"][0]["normalized_host"] == "api.example.com"
    assert result["entries"][0]["program_handle"] == "program"
    assert result["entries"][0]["match_patterns"] == ["api.example.com"]


def test_explain_scope_decision_includes_human_text(tmp_path, monkeypatch):
    write_snapshot(
        tmp_path,
        "program",
        [{"asset_type": "URL", "asset_identifier": "api.example.com", "eligible_for_submission": True}],
    )
    monkeypatch.setattr("recon.scope.load_scope", lambda: h1_scope_config(tmp_path))

    result = explain_scope_decision("api.example.com")

    assert "api.example.com is in scope" in result["explanation"]
    assert result["normalized_host"] == "api.example.com"


def test_resolve_scope_target_mcp_interop_format(tmp_path, monkeypatch):
    write_snapshot(
        tmp_path,
        "program",
        [
            {
                "asset_type": "URL",
                "asset_identifier": "api.example.com",
                "eligible_for_bounty": True,
                "eligible_for_submission": True,
            }
        ],
    )
    monkeypatch.setattr("recon.scope.load_scope", lambda: h1_scope_config(tmp_path))

    result = resolve_scope_target("api.example.com", format="mcp_interop")

    assert result["mcp_interop"]["scope_ok"] is True
    assert result["mcp_interop"]["can_scan"] is True
    assert result["mcp_interop"]["recommended_bugmap_target_label"] == "api.example.com"
