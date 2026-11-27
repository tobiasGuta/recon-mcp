import json
import os
import subprocess
import sys
from pathlib import Path

import httpx
import pytest

from recon.authorization import check_url_scope, get_scope_policy_summary
from recon.campaigns import (
    create_campaign,
    get_campaign,
    get_campaign_paths,
    reauthorize_campaign,
)
from recon.http_fetch import fetch_headers, fetch_robots, fetch_sitemap
from recon.integrity import verify_campaign_artifacts
from recon.js_analysis import collect_js_urls
from recon.passive import discover_subdomains_passive_for_campaign
from recon.sourcemaps import sourcemap_workflow_for_campaign
from recon.workflow import fetch_headers_for_campaign


@pytest.fixture
def network(monkeypatch):
    """Record requests and DNS calls through mock I/O only."""
    requests = []
    addresses = []

    def handler(request):
        return httpx.Response(200, text="ok")

    def resolve(host):
        addresses.append(host)
        return ["93.184.216.34"]

    def observe(request):
        requests.append(request)
        return handler(request)

    def install(callback=None):
        nonlocal handler
        if callback:
            handler = callback
        monkeypatch.setattr(
            "recon.http_fetch._client",
            lambda **_: httpx.Client(
                transport=httpx.MockTransport(observe), follow_redirects=False
            ),
        )
        monkeypatch.setattr("recon.http_fetch.resolve_host_ips", resolve)
        return requests, addresses

    return install


def policy(monkeypatch, **overrides):
    config = {
        "scope_source": "manual",
        "allowed_domains": ["api.example.test"],
        "request_delay_ms": 0,
        **overrides,
    }
    monkeypatch.setattr("recon.scope.load_scope", lambda: config)
    monkeypatch.setattr("recon.http_fetch.load_scope", lambda: config)
    return config


@pytest.mark.parametrize(
    "url",
    [
        "https://outside.test/path",
        "http://api.example.test/path",
        "https://api.example.test:444/path",
        "https://api.example.test/other",
        "https://api.example.test/path/private",
        "https://api.example.test/path/?token=hidden",
        "https://api.example.test/path/..",
    ],
)
def test_denied_initial_requests_reach_neither_dns_nor_transport(
    monkeypatch, network, url
):
    policy(
        monkeypatch,
        url_include=[
            {
                "value": "api.example.test",
                "scheme": "https",
                "port": 443,
                "path_prefix": "/path/",
            }
        ],
        url_exclude=[{"value": "api.example.test", "path": "/path/private"}],
    )
    requests, dns = network()
    result = fetch_headers(url)
    assert not result["ok"]
    assert requests == dns == []
    assert "hidden" not in json.dumps(result)


@pytest.mark.parametrize(
    "location",
    [
        "https://outside.test/public",
        "http://api.example.test/public",
        "//api.example.test:444/public",
        "/private",
        "/public/../private",
        "/public?authorization=hidden",
        "https:///outside.test/public",
    ],
)
def test_denied_redirect_is_checked_before_dns(monkeypatch, network, location):
    policy(
        monkeypatch,
        url_include=[{"value": "api.example.test", "scheme": "https", "port": 443}],
        url_exclude=[{"value": "api.example.test", "path": "/private"}],
    )
    requests, dns = network(
        lambda request: httpx.Response(302, headers={"location": location})
    )
    result = fetch_headers("https://api.example.test/start")
    assert not result["ok"]
    assert "redirect" in result["error"].lower()
    assert [str(request.url) for request in requests] == [
        "https://api.example.test/start"
    ]
    assert dns == ["api.example.test"]
    assert "hidden" not in json.dumps(result)


def test_redirect_and_fallback_do_not_send_cookies(monkeypatch, network):
    policy(monkeypatch)

    def handler(request):
        if request.method == "HEAD":
            return httpx.Response(405, headers={"set-cookie": "headauth=cookie-value"})
        if request.url.path == "/start":
            return httpx.Response(
                302,
                headers={"location": "/end", "set-cookie": "redirectauth=cookie-value"},
            )
        return httpx.Response(200, headers={"set-cookie": "finalauth=cookie-value"})

    requests, dns = network(handler)
    result = fetch_headers("https://API.Example.TEST.:443/start")
    assert result["ok"]
    assert result["headers"]["set-cookie"] == "<redacted>"
    assert all("cookie" not in request.headers for request in requests)
    assert [(request.method, request.url.path) for request in requests] == [
        ("HEAD", "/start"),
        ("GET", "/start"),
        ("GET", "/end"),
    ]
    assert dns == ["api.example.test"] * 3
    assert "cookie-value" not in json.dumps(result)


def test_head_fallback_reloads_current_policy(monkeypatch, network):
    config = policy(monkeypatch)

    def handler(request):
        config["url_exclude"] = [{"value": "api.example.test", "path": "/start"}]
        return httpx.Response(405)

    requests, dns = network(handler)
    result = fetch_headers("https://api.example.test/start")
    assert result["error_code"] == "policy_changed"
    assert [request.method for request in requests] == ["HEAD"]
    assert dns == ["api.example.test"]


def test_changed_policy_during_dns_prevents_transport(monkeypatch, network):
    config = policy(monkeypatch)
    requests, _ = network()

    def resolve(host):
        config["allowed_domains"] = []
        return ["93.184.216.34"]

    monkeypatch.setattr("recon.http_fetch.resolve_host_ips", resolve)
    result = fetch_headers("https://api.example.test/")
    assert result["error_code"] == "policy_changed"
    assert requests == []


def test_reader_rejects_mixed_dns_answers(monkeypatch, network):
    policy(monkeypatch)
    requests, _ = network()
    monkeypatch.setattr(
        "recon.http_fetch.resolve_host_ips",
        lambda host: ["93.184.216.34", "100.64.0.1"],
    )
    result = fetch_headers("https://api.example.test/")
    assert result["error_code"] == "unsafe_target"
    assert not result["scope_decision"]["network_execution_permitted"]
    assert requests == []


@pytest.mark.parametrize("fetch", [fetch_robots, fetch_sitemap])
def test_derived_origin_endpoint_rechecked_before_dns(monkeypatch, network, fetch):
    policy(monkeypatch, allowed_domains=["https://api.example.test/public/"])
    requests, dns = network()
    result = fetch("https://api.example.test/public/")
    assert result["error_code"] == "path_mismatch"
    assert requests == dns == []


def test_js_collection_resolves_from_final_page_and_checks_paths(monkeypatch, network):
    policy(
        monkeypatch,
        url_include=[
            {"value": "api.example.test", "scheme": "https", "path_prefix": "/allowed/"}
        ],
        url_exclude=[{"value": "api.example.test", "path": "/allowed/excluded.js"}],
    )

    def handler(request):
        if request.url.path == "/allowed/start":
            return httpx.Response(302, headers={"location": "/allowed/final/page.html"})
        return httpx.Response(
            200,
            text='<script src="script.js"></script><script src="/allowed/excluded.js"></script>'
            '<script src="/other/script.js"></script><script src="http://api.example.test/allowed/insecure.js"></script>',
        )

    requests, _ = network(handler)
    result = collect_js_urls("https://api.example.test/allowed/start")
    assert result["js_urls"] == ["https://api.example.test/allowed/final/script.js"]
    assert [request.url.path for request in requests] == [
        "/allowed/start",
        "/allowed/final/page.html",
    ]


def test_sourcemap_workflow_derived_url_and_query_is_private(
    campaign_env, monkeypatch, network
):
    config = policy(
        monkeypatch,
        allowed_domains=["https://api.example.test/app/"],
        allowed_assets=[
            {
                "value": "api.example.test",
                "scheme": "https",
                "path_prefix": "/app/allowed/",
            }
        ],
        url_exclude=[{"value": "api.example.test", "path": "/app/allowed/private.map"}],
    )
    monkeypatch.setattr("recon.js_analysis.load_scope", lambda: config)
    campaign_id = create_campaign("Synthetic", "https://api.example.test/app/")[
        "campaign_id"
    ]

    def handler(request):
        if request.url.path == "/app/allowed/start.js":
            return httpx.Response(
                302, headers={"location": "/app/allowed/assets/script.js"}
            )
        if request.url.path == "/app/allowed/assets/script.js":
            return httpx.Response(
                200,
                text="//# sourceMappingURL=app.map?v=undisclosed\n"
                "//# sourceMappingURL=/app/allowed/private.map",
            )
        return httpx.Response(
            200,
            json={
                "version": 3,
                "sources": ["main.js"],
                "sourcesContent": ["let n = 1;"],
            },
        )

    requests, dns = network(handler)
    result = sourcemap_workflow_for_campaign(
        campaign_id, "https://api.example.test/app/allowed/start.js"
    )
    assert result["downloaded_count"] == 1
    assert [str(request.url) for request in requests] == [
        "https://api.example.test/app/allowed/start.js",
        "https://api.example.test/app/allowed/assets/script.js",
        "https://api.example.test/app/allowed/assets/app.map?v=undisclosed",
    ]
    assert dns == ["api.example.test"] * 3
    assert "undisclosed" not in json.dumps(result)
    assert all(
        "undisclosed" not in path.read_text(encoding="utf-8")
        for path in campaign_env.rglob("*.json*")
    )


def test_policy_change_pauses_legacy_or_existing_campaign_and_reauthorization_preserves_evidence(
    campaign_env, monkeypatch, network
):
    config = policy(monkeypatch)
    campaign_id = create_campaign("Synthetic", "api.example.test")["campaign_id"]
    root = Path(get_campaign_paths(campaign_id)["paths"]["root"])
    original_scope = (root / "scope.json").read_bytes()
    requests, dns = network()

    assert fetch_headers_for_campaign(campaign_id, "https://api.example.test/old")["ok"]
    config["url_exclude"] = [{"value": "api.example.test", "path": "/old"}]
    fingerprint = get_scope_policy_summary()["policy_fingerprint"]
    denied = fetch_headers_for_campaign(campaign_id, "https://api.example.test/new")
    assert denied["error_code"] == "policy_changed"
    assert len(requests) == len(dns) == 1
    assert verify_campaign_artifacts(campaign_id)["ok"]
    assert not reauthorize_campaign(campaign_id, "https://api.example.test/", "wrong")[
        "ok"
    ]
    assert not reauthorize_campaign(
        campaign_id, "https://api.example.test/old", fingerprint
    )["ok"]

    metadata_path = root / "campaign.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    del metadata["scope_binding"]
    metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
    assert get_campaign(campaign_id)["ok"]
    assert (
        fetch_headers_for_campaign(campaign_id, "https://api.example.test/new")[
            "error_code"
        ]
        == "invalid_campaign_binding"
    )
    assert len(requests) == len(dns) == 1
    assert reauthorize_campaign(campaign_id, "https://api.example.test/", fingerprint)[
        "ok"
    ]
    assert (root / "scope.json").read_bytes() == original_scope
    assert not fetch_headers_for_campaign(campaign_id, "https://api.example.test/old")[
        "ok"
    ]
    allowed = fetch_headers_for_campaign(campaign_id, "https://api.example.test/new")
    assert allowed["ok"]
    assert len(requests) == len(dns) == 2
    provenance = json.loads(Path(allowed["path"]).read_text(encoding="utf-8"))
    assert provenance["policy_fingerprint"] == fingerprint
    assert provenance["scope_decision"]["policy_fingerprint"] == fingerprint
    events = [
        json.loads(line)
        for line in (root / "audit.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert any(
        event["scope_decision"].get("reason_code") == "policy_changed"
        for event in events
    )
    assert any(event["tool"] == "reauthorize_campaign" for event in events)
    assert any(
        event["scope_decision"].get("matched_inclusion_rule") for event in events
    )


def test_invalid_active_policy_preserves_historical_campaign_reads(
    campaign_env, monkeypatch, network
):
    policy(monkeypatch)
    campaign_id = create_campaign("Synthetic", "api.example.test")["campaign_id"]
    requests, dns = network()
    assert fetch_headers_for_campaign(campaign_id, "https://api.example.test/")["ok"]
    policy(monkeypatch, url_exclude=[{}])
    assert not fetch_headers_for_campaign(campaign_id, "https://api.example.test/")[
        "ok"
    ]
    assert get_campaign(campaign_id)["ok"]
    assert verify_campaign_artifacts(campaign_id)["ok"]
    assert len(requests) == len(dns) == 1


def test_campaign_anchor_cannot_authorize_unrelated_urls_or_store_queries(
    campaign_env, monkeypatch
):
    policy(monkeypatch, allowed_domains=["https://api.example.test/allowed/"])
    assert not create_campaign("Synthetic", "api.example.test")["ok"]
    assert not create_campaign("Synthetic", "https://api.example.test/denied")["ok"]
    assert not create_campaign(
        "Synthetic", "https://api.example.test/allowed/?color=undisclosed"
    )["ok"]
    assert create_campaign("Synthetic", "https://api.example.test/allowed/")["ok"]


def test_passive_provider_and_dns_use_current_policy(
    campaign_env, monkeypatch, network
):
    endpoint = "lookup.example.test"
    monkeypatch.setattr(
        "recon.passive._provider_url",
        lambda provider, root: f"https://{endpoint}/?q=%25.{root}&output=json",
    )
    policy(monkeypatch, allowed_domains=["api.example.test", "in.api.example.test"])
    campaign_id = create_campaign("Synthetic", "api.example.test")["campaign_id"]

    def handler(request):
        return httpx.Response(
            200, json=[{"name_value": "in.api.example.test\nout.api.example.test"}]
        )

    requests, dns = network(handler)
    denied = discover_subdomains_passive_for_campaign(
        campaign_id, "api.example.test", providers=["certificate_transparency"]
    )
    assert not denied["ok"]
    assert requests == dns == []

    policy(
        monkeypatch,
        allowed_domains=["api.example.test", "in.api.example.test"],
        allowed_assets=[
            {
                "value": endpoint,
                "scheme": "https",
                "port": 443,
                "path": "/",
                "query": "q=%25.api.example.test&output=json",
            }
        ],
    )
    fingerprint = get_scope_policy_summary()["policy_fingerprint"]
    assert reauthorize_campaign(campaign_id, "https://api.example.test/", fingerprint)[
        "ok"
    ]
    result = discover_subdomains_passive_for_campaign(
        campaign_id,
        "api.example.test",
        providers=["certificate_transparency"],
        resolve_dns=True,
    )
    assert result["ok"]
    assert len(requests) == 1 and requests[0].url.host == endpoint
    assert dns == [endpoint, "in.api.example.test"]
    assert result["results"][1]["testable"] is False
    assert "resolved_public_ips" not in result["results"][1]


def test_scope_query_and_redirect_header_values_redacted(monkeypatch, network):
    policy(monkeypatch)
    requests, _ = network(
        lambda request: httpx.Response(
            200,
            headers={
                "location": "https://alice:credential-value@api.example.test/?color=hidden-location",
                "link": "<https://api.example.test/next?color=hidden-link>",
            },
        )
    )
    result = fetch_headers("https://api.example.test/?color=hidden-target")
    assert result["ok"]
    assert requests[0].url.query == b"color=hidden-target"
    for value in (
        "credential-value",
        "hidden-location",
        "hidden-link",
        "hidden-target",
    ):
        assert value not in json.dumps(result)
        assert value not in json.dumps(
            check_url_scope("https://api.example.test/?color=" + value)
        )


@pytest.mark.skipif(os.name != "posix", reason="POSIX local-file append behavior")
def test_local_audit_appends_from_independent_processes(campaign_env):
    campaign_id = create_campaign("Synthetic", "example.com")["campaign_id"]
    script = """import sys
from pathlib import Path
from recon import campaigns
from recon.audit import write_audit_event
campaigns.CAMPAIGNS_DIR = Path(sys.argv[1])
for index in range(30):
    result = write_audit_event(sys.argv[2], 'parallel_test', metadata={'worker': sys.argv[3], 'index': index})
    if not result['ok']:
        raise SystemExit(1)
"""
    processes = [
        subprocess.Popen(
            [sys.executable, "-c", script, str(campaign_env), campaign_id, str(worker)]
        )
        for worker in range(3)
    ]
    try:
        assert all(process.wait(timeout=20) == 0 for process in processes)
    finally:
        for process in processes:
            if process.poll() is None:
                process.kill()
                process.wait()
    path = Path(get_campaign_paths(campaign_id)["paths"]["audit_jsonl"])
    events = [
        json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()
    ]
    entries = {
        (event["metadata"]["worker"], event["metadata"]["index"])
        for event in events
        if event["tool"] == "parallel_test"
    }
    assert len(entries) == 90
    assert len(events) == 91
