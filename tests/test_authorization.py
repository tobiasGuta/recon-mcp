import json
import os
import time

import pytest

from recon import authorization as auth
from recon import scope


def write_json(path, value):
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


@pytest.fixture
def config(tmp_path, monkeypatch):
    path = tmp_path / "scope.json"
    monkeypatch.setattr(scope, "DEFAULT_SCOPE_PATH", path)
    return path


def burp_export(path, include, exclude=()):
    return write_json(
        path,
        {
            "target": {
                "scope": {
                    "advanced_mode": True,
                    "include": list(include),
                    "exclude": list(exclude),
                }
            }
        },
    )


def burp_rule(**overrides):
    return {
        "enabled": True,
        "protocol": "https",
        "host": r"^api\.example\.test$",
        "port": "^443$",
        "file": "^/api/.*$",
        **overrides,
    }


@pytest.mark.parametrize(
    ("url", "allowed"),
    [
        ("https://example.test/", True),
        ("http://EXAMPLE.TEST.:8080/other?color=red", True),
        ("https://api.example.test/", False),
        ("https://assets.test/", False),
        ("https://cdn.assets.test/", True),
        ("https://deep.cdn.assets.test/", True),
        ("https://anotherassets.test/", False),
        ("https://assets.test.other.test/", False),
        ("https://blocked.assets.test/", False),
        ("https://sub.blocked.assets.test/", False),
        ("https://bücher.example./path", True),
        ("https://faß.example/", True),
        ("https://fass.example/", False),
    ],
)
def test_manual_host_authorization(config, url, allowed):
    write_json(
        config,
        {
            "allowed_domains": [
                "example.test",
                "*.assets.test",
                "bücher.example",
                "faß.example",
            ],
            "blocked_domains": ["blocked.assets.test"],
        },
    )
    result = auth.check_url_scope(url)
    assert result["authorized"] is allowed
    assert result["network_execution_permitted"] is allowed
    assert result["policy_schema_version"] == 1
    assert result["policy_fingerprint"]
    assert result["decision_id"]
    assert result["timestamp"]


@pytest.mark.parametrize(
    ("url", "reason"),
    [
        ("https://api.example.test/api/users?view=public", "allowed"),
        ("https://api.example.test:443/api/users?view=public", "allowed"),
        ("http://api.example.test:443/api/users?view=public", "protocol_mismatch"),
        ("https://api.example.test:8443/api/users?view=public", "port_mismatch"),
        ("https://api.example.test/apiary?view=public", "path_mismatch"),
        ("https://api.example.test/api/users?view=other", "query_mismatch"),
        ("https://api.example.test/api/admin?view=public", "explicit_exclusion"),
        ("https://other.test/api/users?view=public", "no_matching_inclusion"),
    ],
)
def test_manual_restrictions_intersect_inventory(config, url, reason):
    write_json(
        config,
        {
            "allowed_domains": ["api.example.test"],
            "url_include": [
                {
                    "value": "api.example.test",
                    "scheme": "https",
                    "port": 443,
                    "path_prefix": "/api/",
                    "query": "view=public",
                },
                {"value": "other.test", "path_prefix": "/api/"},
            ],
            "url_exclude": [{"value": "api.example.test", "path": "/api/admin"}],
        },
    )
    result = auth.check_url_scope(url)
    assert result["reason_code"] == reason
    assert result["normalized_url"]["hostname"] == url.split("/")[2].split(":")[0]
    if reason == "explicit_exclusion":
        assert result["matched_exclusion_rule"]["rule_id"]
        assert result["matched_inclusion_rule"]["rule_id"]
    assert "view=public" not in json.dumps(result)
    assert scope.check_scope("api.example.test")["network_execution_permitted"] is False


def test_legacy_manual_complete_url_restrictions_survive(config):
    write_json(
        config, {"allowed_domains": ["https://api.example.test:8443/one?color=blue"]}
    )
    assert auth.check_url_scope("https://api.example.test:8443/one?color=blue")[
        "authorized"
    ]
    assert (
        auth.check_url_scope("http://api.example.test:8443/one?color=blue")[
            "reason_code"
        ]
        == "protocol_mismatch"
    )
    assert (
        auth.check_url_scope("https://api.example.test/one?color=blue")["reason_code"]
        == "port_mismatch"
    )
    assert (
        auth.check_url_scope("https://api.example.test:8443/two?color=blue")[
            "reason_code"
        ]
        == "path_mismatch"
    )
    assert (
        auth.check_url_scope("https://api.example.test:8443/one?color=red")[
            "reason_code"
        ]
        == "query_mismatch"
    )


@pytest.mark.parametrize(
    "policy",
    [
        {"allowed_domains": ["api.example.test"], "url_include": []},
        {"allowed_domains": []},
        {"allowed_assets": [{"value": "api.example.test", "protcol": "https"}]},
        {"allowed_assets": [{"value": "*.example.test", "match": "exact"}]},
        {"allowed_assets": [{"value": "api.example.test", "port": True}]},
        {
            "allowed_assets": [
                {"value": "api.example.test", "path": "/a", "path_prefix": "/a/"}
            ]
        },
        {
            "allowed_domains": ["api.example.test"],
            "blocked_domains": ["https://api.example.test/private"],
        },
        {"allowed_domains": ["api.example.test"], "url_exclude": None},
        {"allowed_assets": [{"value": "api.example.test", "query": None}]},
        {"allowed_domains": ["api.example.test"], "burp_scope_file": "/other.json"},
        {"scope_source": "unsupported", "allowed_domains": ["api.example.test"]},
    ],
)
def test_empty_or_invalid_manual_configuration_denies(config, policy):
    write_json(config, policy)
    assert not auth.check_url_scope("https://api.example.test/")["authorized"]
    assert not auth.validate_scope_policy()["safe_to_activate"]


@pytest.mark.parametrize(
    "url",
    [
        "api.example.test",
        "https:api.example.test/",
        "https:///api.example.test/",
        "https://api.example.test:/",
        "https://api.example.test:0443/",
        "https://api.example.test:65536/",
        "https://api.example.test/../private",
        "https://api.example.test/api//users",
        "https://api.example.test/path;params",
        "https://api.example.test/a%2Fb",
        "https://api.example.test/a%2eb",
        "https://api.example.test/?a=%ZZ",
        "https://api.example.test./#private",
        "https://api.example.test\\@other.test/",
        "https://api.example.test\t/okay",
        "https://api.example.test../",
        "https://127.1/",
        "https://2130706433/",
        "https://0x7f000001/",
        "https://%61pi.example.test/",
        "https://[fe80::1%25local]/",
        "https://api.example.test/" + "x" * auth.MAX_URL_LENGTH,
    ],
)
def test_ambiguous_url_denials(config, url):
    write_json(config, {"allowed_domains": ["api.example.test"]})
    result = auth.check_url_scope(url)
    assert not result["network_execution_permitted"]
    assert result["reason_code"] == "invalid_url"


@pytest.mark.parametrize(
    "host",
    [
        "localhost",
        "api.localhost",
        "127.0.0.1",
        "169.254.1.2",
        "192.168.1.1",
        "224.0.0.1",
        "100.64.0.1",
        "[::1]",
        "[::ffff:127.0.0.1]",
    ],
)
def test_unsafe_literal_targets_denied_by_open_burp_rule(config, tmp_path, host):
    export = burp_export(tmp_path / "burp.json", [burp_rule(host="", file="")])
    write_json(
        config, {"scope_source": "burp_advanced", "burp_scope_file": str(export)}
    )
    assert auth.check_url_scope(f"https://{host}/")["reason_code"] == "unsafe_target"


def test_burp_enabled_rules_and_exclusion_precedence(config, tmp_path):
    export = burp_export(
        tmp_path / "burp.json",
        [
            burp_rule(),
            burp_rule(
                host=r"^.*\.assets\.test$",
                port="^80[0-9][0-9]$",
                protocol="any",
                file="",
            ),
            burp_rule(enabled=False, host="unrepresentable disabled expression"),
        ],
        [
            burp_rule(file="^/api/private/.*$"),
            burp_rule(enabled=False, file="^/api/.*$"),
        ],
    )
    write_json(
        config, {"scope_source": "burp_advanced", "burp_scope_file": str(export)}
    )
    summary = auth.validate_scope_policy()
    assert summary["valid"] is True
    assert (
        summary["inclusion_count"],
        summary["exclusion_count"],
        summary["disabled_rule_count"],
    ) == (2, 1, 2)
    cases = {
        "https://api.example.test/api/users?view=public": "allowed",
        "https://api.example.test:443/api/users": "allowed",
        "http://api.example.test:443/api/users": "protocol_mismatch",
        "https://api.example.test:444/api/users": "port_mismatch",
        "https://api.example.test/another": "path_mismatch",
        "https://api.example.test/api/private/user": "explicit_exclusion",
        "https://sub.api.example.test/api/users": "no_matching_inclusion",
        "https://assets.test:8010/": "no_matching_inclusion",
        "http://deep.cdn.assets.test:8010/": "allowed",
    }
    assert {url: auth.check_url_scope(url)["reason_code"] for url in cases} == cases


@pytest.mark.parametrize(
    "bad_fields",
    [
        {"host": "api.example.test"},
        {"host": r"^(a+)+$"},
        {"host": r"^(?i)api\.example\.test$"},
        {"host": r"^(api)\1$"},
        {"host": "192.0.2.0/24"},
        {"host": "^.*.*$"},
        {"port": "^44[9-1]$"},
        {"port": 443},
        {"protocol": "ftp"},
        {"file": r"^/(?=path).*$"},
        {"file": "^/foo|/bar$"},
        {"file": "^" + "x" * auth.MAX_PATTERN_LENGTH + "$"},
        {"query": "ignored-is-unsafe"},
        {"enabled": "false"},
    ],
)
def test_invalid_burp_exclusion_disables_whole_policy(config, tmp_path, bad_fields):
    export = burp_export(
        tmp_path / "burp.json", [burp_rule()], [burp_rule(**bad_fields)]
    )
    write_json(
        config, {"scope_source": "burp_advanced", "burp_scope_file": str(export)}
    )
    validation = auth.validate_scope_policy()
    assert validation["valid"] is False
    assert validation["safe_to_activate"] is False
    assert validation["unsupported_rules"]
    assert "exclude[0]" in validation["errors"][0]
    assert (
        auth.check_url_scope("https://api.example.test/api/users")["reason_code"]
        == "unsupported_policy"
    )


@pytest.mark.parametrize(
    "content",
    [
        "{invalid",
        '{"allowed_domains":[],"allowed_domains":["api.example.test"]}',
        '{"allowed_domains": NaN}',
        "[]",
    ],
)
def test_malformed_active_json_fails_closed_immediately(config, content):
    write_json(config, {"allowed_domains": ["api.example.test"]})
    assert auth.check_url_scope("https://api.example.test/")["authorized"]
    config.write_text(content, encoding="utf-8")
    assert (
        auth.check_url_scope("https://api.example.test/")["reason_code"]
        == "invalid_policy"
    )
    config.unlink()
    assert not auth.check_url_scope("https://api.example.test/")["authorized"]


def test_burp_export_replacement_and_deletion(config, tmp_path):
    export = burp_export(tmp_path / "burp.json", [burp_rule()])
    write_json(
        config, {"scope_source": "burp_advanced", "burp_scope_file": str(export)}
    )
    url = "https://api.example.test/api/users"
    first = auth.check_url_scope(url)
    edited = burp_export(tmp_path / "replacement.json", [burp_rule()], [burp_rule()])
    edited.replace(export)
    second = auth.check_url_scope(url)
    assert first["authorized"] and not second["authorized"]
    assert first["policy_fingerprint"] != second["policy_fingerprint"]
    export.unlink()
    assert not auth.check_url_scope(url)["authorized"]


@pytest.mark.parametrize(
    "kind",
    ["relative", "remote", "symlink", "parent_symlink", "fifo", "large", "rules"],
)
def test_burp_local_policy_resource_limits(config, tmp_path, kind):
    source = tmp_path / "burp.json"
    if kind == "relative":
        source = "burp.json"
    elif kind == "remote":
        source = "https://config.example.test/scope.json"
    elif kind in {"symlink", "parent_symlink"}:
        try:
            if kind == "symlink":
                source.symlink_to(burp_export(tmp_path / "real.json", [burp_rule()]))
            else:
                real = tmp_path / "real"
                real.mkdir()
                burp_export(real / "burp.json", [burp_rule()])
                alias = tmp_path / "alias"
                alias.symlink_to(real, target_is_directory=True)
                source = alias / "burp.json"
        except OSError:
            pytest.skip("Symlink creation unavailable")
    elif kind == "fifo":
        if not hasattr(os, "mkfifo"):
            pytest.skip("FIFO creation unavailable")
        os.mkfifo(source)
    elif kind == "large":
        source.write_bytes(b" " * (1024 * 1024 + 1))
    else:
        burp_export(source, [burp_rule()] * (auth.MAX_BURP_RULES + 1))
    write_json(
        config, {"scope_source": "burp_advanced", "burp_scope_file": str(source)}
    )
    assert not auth.validate_scope_policy()["valid"]
    assert not auth.check_url_scope("https://api.example.test/api/users")["authorized"]


def test_h1_network_constraints_and_explicit_denials(config, tmp_path):
    snapshots = tmp_path / "snapshots"
    snapshots.mkdir()
    write_json(
        config,
        {
            "scope_source": "h1_snapshots",
            "h1_snapshot_dir": str(snapshots),
            "include_only_bounty_eligible": True,
        },
    )
    path = write_json(
        snapshots / "program.json",
        [
            {
                "asset_type": "WILDCARD",
                "asset_identifier": "*.example.test",
                "eligible_for_submission": True,
                "eligible_for_bounty": True,
            },
            {
                "asset_type": "URL",
                "asset_identifier": "https://assets.test:8443/public?color=blue",
                "eligible_for_submission": True,
                "eligible_for_bounty": True,
            },
            {
                "asset_type": "URL",
                "asset_identifier": "https://api.example.test/admin",
                "eligible_for_submission": False,
                "eligible_for_bounty": False,
            },
            {
                "asset_type": "DOMAIN",
                "asset_identifier": "internal.example.test",
                "eligible_for_submission": True,
                "eligible_for_bounty": False,
            },
            {
                "asset_type": "DOMAIN",
                "asset_identifier": "review.example.test",
                "eligible_for_submission": True,
                "eligible_for_bounty": True,
                "instruction": "Ask first.",
            },
        ],
    )
    assert auth.check_url_scope("https://api.example.test/services")["authorized"]
    assert auth.check_url_scope("https://assets.test:8443/public?color=blue")[
        "authorized"
    ]
    assert (
        auth.check_url_scope("https://assets.test:8443/private?color=blue")[
            "reason_code"
        ]
        == "path_mismatch"
    )
    assert (
        auth.check_url_scope("https://assets.test:8443/public?color=red")["reason_code"]
        == "query_mismatch"
    )
    assert (
        auth.check_url_scope("https://sub.assets.test:8443/public?color=blue")[
            "reason_code"
        ]
        == "no_matching_inclusion"
    )
    for url in (
        "https://api.example.test/admin",
        "https://internal.example.test/",
        "https://review.example.test/",
    ):
        assert auth.check_url_scope(url)["reason_code"] == "explicit_exclusion"
    path.write_text("invalid", encoding="utf-8")
    assert not auth.check_url_scope("https://api.example.test/services")["authorized"]


def test_h1_freshness_and_future_timestamp(config, tmp_path):
    snapshots = tmp_path / "snapshots"
    snapshots.mkdir()
    write_json(
        config,
        {
            "scope_source": "h1_snapshots",
            "h1_snapshot_dir": str(snapshots),
            "h1_snapshot_max_age_seconds": 120,
        },
    )
    path = write_json(
        snapshots / "program.json",
        [
            {
                "asset_type": "DOMAIN",
                "asset_identifier": "assets.test",
                "eligible_for_submission": True,
            }
        ],
    )
    assert auth.check_url_scope("https://assets.test/")["authorized"]
    for timestamp in (time.time() - 600, time.time() + 600):
        os.utime(path, (timestamp, timestamp))
        assert not auth.validate_scope_policy()["valid"]
        assert not auth.check_url_scope("https://assets.test/")["authorized"]


def test_offline_batch_is_bounded_redacted_and_uses_one_policy(config):
    write_json(config, {"allowed_domains": ["api.example.test"]})
    result = auth.check_url_scope_batch(
        [
            "https://api.example.test/?color=hidden-value",
            "https://alice:credential-value@api.example.test/",
            "https://api.example.test/?token=token-value",
            "https://other.test/",
        ]
    )
    assert [item["reason_code"] for item in result["results"]] == [
        "allowed",
        "sensitive_url",
        "sensitive_url",
        "no_matching_inclusion",
    ]
    assert {item["policy_fingerprint"] for item in result["results"]} == {
        result["policy_fingerprint"]
    }
    for value in ("hidden-value", "credential-value", "token-value", "alice"):
        assert value not in json.dumps(result)
    assert not auth.check_url_scope_batch(["https://api.example.test/"] * 101)["ok"]
    assert not auth.check_url_scope_batch(
        ["https://api.example.test/" + "y" * 4000] * 40
    )["ok"]
    assert not auth.check_url_scope_batch(["https://api.example.test/" + "y" * 4300])[
        "ok"
    ]


def test_fingerprints_and_conservative_comparison(config, tmp_path, monkeypatch):
    comparison = tmp_path / "policies"
    comparison.mkdir()
    monkeypatch.setattr(auth, "COMPARISON_ROOT", comparison)
    rules = [
        {
            "value": "api.example.test",
            "scheme": "https",
            "port": 443,
            "path": "/before",
            "query": "key=old-value",
        }
    ]
    blocked = [{"value": "blocked.example.test", "path": "/private"}]
    write_json(config, {"allowed_assets": rules, "url_exclude": blocked})
    active = auth.get_scope_policy_summary()["policy_fingerprint"]
    write_json(
        comparison / "before.json", {"url_exclude": blocked, "allowed_assets": rules}
    )
    write_json(
        comparison / "same.json",
        {
            "allowed_assets": rules + rules,
            "url_exclude": blocked,
            "user_agent": "Different",
        },
    )
    write_json(
        comparison / "after.json",
        {
            "allowed_assets": [
                {
                    "value": "api.example.test",
                    "scheme": "http",
                    "port": 80,
                    "path": "/after",
                    "query": "key=new-value",
                }
            ]
        },
    )
    assert auth.compare_scope_policies("before", "same")["comparison"] == "identical"
    delta = auth.compare_scope_policies("before", "after")
    assert delta["comparison"] == "indeterminate"
    assert delta["exclusions_changed"]
    assert (
        delta["potential_authorization_expansion"]
        and delta["potential_authorization_reduction"]
    )
    assert set(delta["possible_modified_rules"][0]["changed_fields"]) == {
        "scheme",
        "port",
        "path",
        "query",
    }
    assert "old-value" not in json.dumps(delta) and "new-value" not in json.dumps(delta)
    assert not auth.compare_scope_policies("../scope", "after")["ok"]
    assert auth.get_scope_policy_summary()["policy_fingerprint"] == active


@pytest.mark.parametrize(
    "unknown", [{"asset_type": "CIDR"}, {"excluded": True}, {"instruction": []}]
)
def test_h1_unsupported_scope_data_invalidates_whole_policy(config, tmp_path, unknown):
    snapshots = tmp_path / "snapshots"
    snapshots.mkdir()
    write_json(
        config, {"scope_source": "h1_snapshots", "h1_snapshot_dir": str(snapshots)}
    )
    write_json(
        snapshots / "program.json",
        [
            {
                "asset_type": "WILDCARD",
                "asset_identifier": "*.example.test",
                "eligible_for_submission": True,
            },
            {
                "asset_type": "DOMAIN",
                "asset_identifier": "blocked.example.test",
                "eligible_for_submission": True,
                **unknown,
            },
        ],
    )
    assert not auth.validate_scope_policy()["valid"]
    assert not auth.check_url_scope("https://api.example.test/")["authorized"]


def test_burp_host_projection_requires_a_complete_url(config, tmp_path):
    export = burp_export(tmp_path / "burp.json", [burp_rule()])
    write_json(
        config, {"scope_source": "burp_advanced", "burp_scope_file": str(export)}
    )
    projection = scope.resolve_scope_target("API.example.test.")
    assert projection["evaluation_kind"] == "host_match"
    assert projection["host_rule_match"]
    assert not projection["network_execution_permitted"]
    assert auth.check_url_scope("https://api.example.test/api/users")["authorized"]


def test_h1_multi_program_directory_requires_explicit_selection(config, tmp_path):
    snapshots = tmp_path / "snapshots"
    snapshots.mkdir()
    for program, host in [
        ("first", "one.example.test"),
        ("second", "two.example.test"),
    ]:
        write_json(
            snapshots / (program + ".json"),
            [
                {
                    "asset_type": "DOMAIN",
                    "asset_identifier": host,
                    "eligible_for_submission": True,
                }
            ],
        )
    settings = {"scope_source": "h1_snapshots", "h1_snapshot_dir": str(snapshots)}
    write_json(config, settings)
    assert not auth.validate_scope_policy()["valid"]
    assert not auth.check_url_scope("https://one.example.test/")["authorized"]
    assert scope.check_scope("one.example.test")["evaluation_kind"] == "host_inventory"

    write_json(config, {**settings, "h1_snapshot_program": "first"})
    first = auth.check_url_scope("https://one.example.test/")
    assert first["authorized"]
    assert not auth.check_url_scope("https://two.example.test/")["authorized"]
    write_json(config, {**settings, "h1_snapshot_program": "second"})
    assert auth.check_url_scope("https://two.example.test/")["authorized"]
    assert (
        auth.check_url_scope("https://one.example.test/")["policy_fingerprint"]
        != first["policy_fingerprint"]
    )
    write_json(config, {**settings, "h1_snapshot_program": "../first"})
    assert not auth.validate_scope_policy()["valid"]
