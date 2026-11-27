import io
import json
from pathlib import Path

import httpx
import pytest

import server
from recon import authorization as auth
from recon import redaction, scope, scope_cli
from recon.audit import write_audit_event
from recon.campaigns import create_campaign, get_campaign, get_campaign_paths
from recon.http_fetch import fetch_headers
from recon.passive import discover_subdomains_passive_for_campaign


def set_policy(monkeypatch, **values):
    config = {"allowed_domains": ["api.example.test"], "request_delay_ms": 0, **values}
    monkeypatch.setattr(scope, "load_scope", lambda: config)
    monkeypatch.setattr("recon.http_fetch.load_scope", lambda: config)
    return config


def forbid_dispatch(monkeypatch):
    def unexpected(*args, **kwargs):
        pytest.fail("A denied request reached DNS or HTTP.")

    monkeypatch.setattr("recon.http_fetch.resolve_host_ips", unexpected)
    monkeypatch.setattr("recon.http_fetch._client", unexpected)


@pytest.mark.parametrize(
    "query",
    [
        "view=public;token=AUDIT-QUERY-MARKER",
        "a=1%3B%74oken%3DAUDIT-QUERY-MARKER",
        "%2574oken=AUDIT-QUERY-MARKER",
        "next=%2Fa%3Fpass%2577ord%3DAUDIT-QUERY-MARKER",
        "view=prefix+authorization%3AAUDIT-QUERY-MARKER",
        "x=%FF-AUDIT-QUERY-MARKER",
        "x=%GG-AUDIT-QUERY-MARKER",
        "%252525252574oken=AUDIT-QUERY-MARKER",
    ],
)
def test_sensitive_and_ambiguous_queries_are_denied_without_dns_or_http(
    monkeypatch, query
):
    set_policy(monkeypatch)
    forbid_dispatch(monkeypatch)
    url = f"https://api.example.test/public/?{query}"
    offline = auth.check_url_scope(url)
    assert offline["reason_code"] in {"sensitive_url", "invalid_url"}
    for output in (
        offline,
        fetch_headers(url),
        scope.explain_scope_decision(url),
        redaction.redact_url(url),
        redaction.redact_embedded_urls(f"request failed for {url}"),
    ):
        assert "AUDIT-QUERY-MARKER" not in json.dumps(output)
    assert auth.check_url_scope("https://api.example.test/public/?color=blue%20green")[
        "authorized"
    ]


@pytest.mark.parametrize(
    "url",
    [
        "https://AUDIT-CREDENTIAL:secret@api.example.test/?token=AUDIT-QUERY-MARKER",
        "https://[AUDIT-CREDENTIAL:secret@api.example.test/",
        "//AUDIT-CREDENTIAL:secret@api.example.test/?other=AUDIT-QUERY-MARKER",
        "api.example.test/?token=AUDIT-QUERY-MARKER",
    ],
)
def test_scope_diagnostics_and_nested_audit_omit_rejected_input(campaign_env, url):
    cid = create_campaign("Synthetic", "example.com")["campaign_id"]
    diagnostic = server.explain_scope_decision(url)
    assert not diagnostic["in_scope"]
    assert diagnostic["reason_code"] in {"invalid_url", "sensitive_url"}
    decisions = [
        diagnostic,
        server.resolve_scope_target(url, "mcp_interop"),
        server.check_scope_batch([url], "mcp_interop"),
        server.check_url_scope_batch([url]),
        server.recommend_bugmap_parent(url, []),
    ]
    audit = write_audit_event(cid, "synthetic", scope_decision={"nested": decisions})
    outcomes = json.dumps([decisions, audit])
    assert "AUDIT-CREDENTIAL" not in outcomes
    assert "AUDIT-QUERY-MARKER" not in outcomes
    log = Path(get_campaign_paths(cid)["paths"]["audit_jsonl"]).read_text()
    assert "AUDIT-CREDENTIAL" not in log and "AUDIT-QUERY-MARKER" not in log


def test_scope_mcp_invalid_policy_is_structured(monkeypatch, tmp_path):
    path = tmp_path / "policy.json"
    monkeypatch.setattr(scope, "DEFAULT_SCOPE_PATH", path)
    path.write_text('{"allowed_domains":["api.example.test"]}')
    assert server.get_scope_map()["ok"]
    path.write_text(
        '{"allowed_domains":["api.example.test"],"url_exclude":[{"raw":"AUDIT-CONFIG-MARKER"}]}'
    )
    for result in (
        server.get_scope_map(),
        server.list_loaded_scope(),
        server.check_scope("api.example.test"),
        server.resolve_scope_target("https://api.example.test/", "mcp_interop"),
    ):
        assert not result["ok"] and not result["in_scope"]
        assert result["reason_code"] == "invalid_policy"
        assert "AUDIT-CONFIG-MARKER" not in json.dumps(result)


def test_interop_authorization_and_eligibility_are_separate(monkeypatch):
    set_policy(monkeypatch)
    host = scope.resolve_scope_target("api.example.test", "mcp_interop")
    url = scope.resolve_scope_target("https://api.example.test/", "mcp_interop")
    for result in (host, url):
        flags = result["mcp_interop"]
        assert (
            result["submission_eligible"] is None and result["bounty_eligible"] is None
        )
        assert not flags["can_test"] and not flags["can_scan"] and not flags["scope_ok"]
        assert not flags["can_store_evidence"]
    assert not host["mcp_interop"]["authorized_url"]
    assert url["mcp_interop"]["authorized_url"]
    assert scope.get_scope_map()["entries"][0]["eligible_for_submission"] is None


def test_passive_rejects_individual_invalid_candidates_and_classifies_regex(
    campaign_env, monkeypatch, tmp_path
):
    config = tmp_path / "burp.json"
    config.write_text(
        json.dumps(
            {
                "target": {
                    "scope": {
                        "advanced_mode": True,
                        "include": [
                            {
                                "enabled": True,
                                "host": r"^api\.example\.test$",
                                "protocol": "https",
                            },
                            {
                                "enabled": True,
                                "host": r"^.*\.api\.example\.test$",
                                "protocol": "https",
                            },
                        ],
                        "exclude": [
                            {
                                "enabled": True,
                                "host": r"^blocked\.api\.example\.test$",
                                "protocol": "https",
                            }
                        ],
                    }
                }
            }
        )
    )
    set_policy(
        monkeypatch,
        scope_source="burp_advanced",
        burp_scope_file=str(config),
        allowed_domains=[],
    )
    cid = create_campaign("Synthetic", "api.example.test")["campaign_id"]
    monkeypatch.setattr(
        "recon.passive._query",
        lambda *_: [
            "sub.api.example.test",
            "blocked.api.example.test",
            "a/b.api.example.test",
            {},
            "glpat-AUDITsecretmarker.api.example.test",
            "https://AUDIT-CREDENTIAL@api.example.test/",
        ],
    )
    forbid_dispatch(monkeypatch)
    result = discover_subdomains_passive_for_campaign(
        cid, "api.example.test", providers=["certificate_transparency"]
    )
    assert result["ok"]
    classifications = {
        entry["host"]: entry["scope_classification"] for entry in result["results"]
    }
    assert classifications == {
        "sub.api.example.test": "regex_in_scope",
        "blocked.api.example.test": "rejected",
    }
    assert result["candidate_rejections"] == {"rejected": 1, "unsupported": 3}
    assert all("resolved_public_ips" not in item for item in result["results"])
    assert "AUDITsecretmarker" not in json.dumps(
        result
    ) and "AUDIT-CREDENTIAL" not in json.dumps(result)
    assert not any(
        "AUDITsecretmarker" in file.read_text()
        for file in campaign_env.rglob("cache-*.json")
    )


def test_passive_policy_revocation_after_provider_io_blocks_publication(
    campaign_env, monkeypatch
):
    config = set_policy(
        monkeypatch,
        allowed_domains=[
            "api.example.test",
            "*.api.example.test",
            "lookup.example.test",
        ],
    )
    cid = create_campaign("Synthetic", "api.example.test")["campaign_id"]
    monkeypatch.setattr(
        "recon.passive._provider_url", lambda *_: "https://lookup.example.test/"
    )
    calls = []

    def handle(request):
        calls.append(request.url.host)
        config["url_exclude"] = [{"value": "*.api.example.test"}]
        return httpx.Response(200, json=[{"name_value": "sub.api.example.test"}])

    monkeypatch.setattr(
        "recon.http_fetch._client",
        lambda **kwargs: httpx.Client(transport=httpx.MockTransport(handle)),
    )
    result = discover_subdomains_passive_for_campaign(
        cid, "api.example.test", providers=["certificate_transparency"]
    )
    assert result["error_code"] == "policy_changed"
    assert "results" not in result and calls == ["lookup.example.test"]
    assert not list(campaign_env.rglob("cache-*.json"))
    assert not list(campaign_env.rglob("*-passive-*.json"))


@pytest.mark.parametrize(
    ("tool", "arguments"),
    [
        (
            server.extract_endpoints_from_js,
            {
                "file_or_url": "https://api.example.test/blocked.js",
                "source_type": "url",
            },
        ),
        (server.collect_js_urls, {"url": "https://api.example.test/blocked.js"}),
        (server.fetch_robots_for_campaign, {"url": "https://api.example.test/public/"}),
        (
            server.fetch_sitemap_for_campaign,
            {"url": "https://api.example.test/public/"},
        ),
        (
            server.collect_js_urls_for_campaign,
            {"url": "https://api.example.test/blocked.js"},
        ),
        (
            server.extract_endpoints_for_campaign,
            {
                "file_or_url": "https://api.example.test/blocked.js",
                "source_type": "url",
            },
        ),
        (
            server.detect_sourcemap_references_for_campaign,
            {"js_url": "https://api.example.test/blocked.js"},
        ),
        (
            server.download_sourcemap_for_campaign,
            {"sourcemap_url": "https://api.example.test/blocked.map"},
        ),
        (
            server.sourcemap_workflow_for_campaign,
            {"js_url": "https://api.example.test/blocked.js"},
        ),
        (
            server.discover_subdomains_passive_for_campaign,
            {
                "root_domain": "api.example.test",
                "providers": ["certificate_transparency"],
            },
        ),
    ],
)
def test_network_entry_points_deny_before_dns_or_http(
    campaign_env, monkeypatch, tool, arguments
):
    import inspect

    set_policy(monkeypatch, allowed_domains=["https://api.example.test/public/"])
    cid = create_campaign("Synthetic", "https://api.example.test/public/")[
        "campaign_id"
    ]
    if "campaign_id" in inspect.signature(tool).parameters:
        arguments["campaign_id"] = cid
    forbid_dispatch(monkeypatch)
    assert not tool(**arguments)["ok"]


def test_cli_policy_validation_check_and_compare(monkeypatch, tmp_path, capsys):
    staging = tmp_path / "policies"
    staging.mkdir()
    monkeypatch.setattr(auth, "COMPARISON_ROOT", staging)
    before = staging / "before.json"
    before.write_text(
        '{"allowed_domains":["api.example.test"],"url_include":[{"value":"api.example.test","path":"/public/"}]}'
    )
    after = staging / "after.json"
    after.write_text('{"allowed_domains":["api.example.test"]}')
    malformed = tmp_path / "broken.json"
    malformed.write_text("{")
    tests = [
        (["validate", "--config", str(before)], 0, "valid", True),
        (["validate", "--config", str(malformed)], 1, "valid", False),
        (
            ["check", "https://api.example.test/public/", "--config", str(before)],
            0,
            "authorized",
            True,
        ),
        (
            ["check", "https://api.example.test/private/", "--config", str(before)],
            1,
            "authorized",
            False,
        ),
        (["compare", "before", "after"], 0, "potential_authorization_expansion", True),
        (["compare", "../before", "after"], 1, "ok", False),
    ]
    for args, expected, key, value in tests:
        assert scope_cli.main(args) == expected
        assert json.loads(capsys.readouterr().out)[key] == value


def test_cli_campaign_binding_requires_tty_fingerprint_and_correct_anchor(
    campaign_env, monkeypatch, capsys
):
    config = set_policy(
        monkeypatch, allowed_domains=["api.example.test", "elsewhere.example.test"]
    )
    cid = create_campaign("Synthetic", "api.example.test")["campaign_id"]
    before = get_campaign(cid)["campaign"]["scope_binding"]
    config["url_exclude"] = [{"value": "api.example.test", "path": "/denied"}]
    fingerprint = auth.get_scope_policy_summary()["policy_fingerprint"]

    class Terminal(io.StringIO):
        def isatty(self):
            return True

    def command(target, value, expected):
        assert (
            scope_cli.main(
                ["reauthorize-campaign", cid, target, "--confirm-fingerprint", value]
            )
            == expected
        )
        return json.loads(capsys.readouterr().out)

    monkeypatch.setattr(scope_cli.sys, "stdin", io.StringIO())
    assert (
        "interactive"
        in command("https://api.example.test/public/", fingerprint, 1)["error"]
    )
    monkeypatch.setattr(scope_cli.sys, "stdin", Terminal())
    command("https://api.example.test/public/", "incorrect", 1)
    command("https://elsewhere.example.test/", fingerprint, 1)
    command("https://api.example.test/denied", fingerprint, 1)
    assert get_campaign(cid)["campaign"]["scope_binding"] == before
    command("https://api.example.test/public/", fingerprint, 0)
    assert (
        get_campaign(cid)["campaign"]["scope_binding"]["decision"]["policy_fingerprint"]
        == fingerprint
    )


def test_compare_rejects_external_source_and_proves_narrowing_diff(
    monkeypatch, tmp_path
):
    staging = tmp_path / "policies"
    staging.mkdir()
    monkeypatch.setattr(auth, "COMPARISON_ROOT", staging)
    unexplored = tmp_path / "outside.json"
    unexplored.write_text("{}")
    (staging / "outside.json").write_text(
        json.dumps(
            {"scope_source": "burp_advanced", "burp_scope_file": str(unexplored)}
        )
    )
    (staging / "a.json").write_text(
        '{"allowed_domains":["api.example.test"],"url_include":[{"value":"api.example.test","path_prefix":"/a/"}]}'
    )
    (staging / "b.json").write_text(
        '{"allowed_domains":["api.example.test"],"url_include":[{"value":"api.example.test","path_prefix":"/b/"}]}'
    )
    changed = auth.compare_scope_policies("a", "b")
    assert changed["comparison"] == "indeterminate"
    assert (
        changed["potential_authorization_expansion"]
        and changed["potential_authorization_reduction"]
    )
    assert changed["possible_modified_rules"][0]["changed_fields"] == ["path"]
    assert not auth.compare_scope_policies("a", "outside")["ok"]


def test_combined_rule_count_limit_is_fail_closed(monkeypatch):
    set_policy(
        monkeypatch,
        allowed_domains=["api.example.test"] * auth.MAX_RULES,
        url_exclude=[{"value": "api.example.test", "path": "/blocked"}],
    )
    assert not auth.validate_scope_policy()["valid"]
    assert not auth.check_url_scope("https://api.example.test/")["authorized"]


def test_campaign_policy_change_during_dispatch_audit_stops_http(
    campaign_env, monkeypatch
):
    from recon import http_fetch

    config = set_policy(monkeypatch)
    cid = create_campaign("Synthetic", "api.example.test")["campaign_id"]
    write_audit = http_fetch.audit_dispatch
    requests = []

    def dispatch(decision, *, phase):
        write_audit(decision, phase=phase)
        if phase == "http":
            config["url_exclude"] = [{"value": "api.example.test"}]

    def observe(request):
        requests.append(request)
        return httpx.Response(200)

    monkeypatch.setattr(http_fetch, "audit_dispatch", dispatch)
    monkeypatch.setattr(
        http_fetch,
        "_client",
        lambda: httpx.Client(transport=httpx.MockTransport(observe)),
    )
    outcome = server.fetch_headers_for_campaign(cid, "https://api.example.test/")
    assert outcome["result"]["error_code"] == "policy_changed"
    assert requests == []
