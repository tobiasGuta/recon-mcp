import json
from pathlib import Path

from recon.campaigns import create_campaign, get_campaign_paths
from recon.contracts import extract_api_contracts_for_campaign, extract_contracts_from_text
from recon.differential import compare_campaign_recon
from recon.evidence_graph import add_evidence_batch, get_evidence_graph_summary, query_evidence_graph
from recon.imports import import_burp_xml_for_campaign, import_har_for_campaign
from recon.integrity import verify_campaign_artifacts
from recon.passive import discover_subdomains_passive_for_campaign
from recon.sensitive import scan_sensitive_artifacts_for_campaign
from recon.sourcemaps import extract_sourcemap_sources_for_campaign
from recon.js_analysis import extract_endpoints_from_js
from recon.scope import resolve_scope_target


def _campaign() -> tuple[str, dict]:
    campaign_id = create_campaign("Demo", "example.com")["campaign_id"]
    return campaign_id, get_campaign_paths(campaign_id)["paths"]


def _source_dir(paths: dict, name: str = "bundle") -> Path:
    directory = Path(paths["recon"]["sourcemaps"]) / "extracted" / name
    directory.mkdir(parents=True)
    return directory


def test_sensitive_scan_never_returns_or_persists_complete_secret(campaign_env):
    campaign_id, paths = _campaign()
    source = _source_dir(paths)
    secret = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"
    (source / "app.js").write_text(
        f'const token = "{secret}"; const placeholder = "changeme"; const publicKey = "pk_live_abcdefghijklmnop";',
        encoding="utf-8",
    )

    result = scan_sensitive_artifacts_for_campaign(campaign_id, str(source))

    assert result["ok"] is True
    assert result["matches"][0]["manual_validation_required"] is True
    assert result["matches"][0]["redacted_value"] != secret
    assert result["matches"][0]["fingerprint_sha256"]
    assert any(item["signal_id"] == "stripe_publishable_key" for item in result["client_configuration_signals"])
    assert secret not in json.dumps(result)
    assert secret not in Path(result["path"]).read_text(encoding="utf-8")
    assert secret not in Path(paths["audit_jsonl"]).read_text(encoding="utf-8")


def test_placeholder_secret_assignment_is_downgraded(campaign_env):
    campaign_id, paths = _campaign()
    source = _source_dir(paths)
    (source / "config.ts").write_text('const client_secret = "your_token_here_123456";', encoding="utf-8")

    result = scan_sensitive_artifacts_for_campaign(campaign_id, str(source))

    assert result["matches"][0]["confidence"] == "low"
    assert result["matches"][0]["review_priority"] == "low"


def test_contract_extraction_marks_dynamic_segments_and_redacts_auth(campaign_env):
    text = """fetch(`/api/v2/users/${userId}`, {
      method: 'POST',
      headers: {'Content-Type': 'application/json', 'Authorization': 'Bearer superSecretValue123'},
      body: JSON.stringify({ email, name, role })
    });
    mutation UpdateUser { updateUser { id } }
    """

    contracts = extract_contracts_from_text(text, "services/users.ts")

    request = next(item for item in contracts if item["client"] == "fetch")
    assert request["endpoint_uncertainty"] == "partially_dynamic"
    assert request["method"] == "POST"
    assert request["body_fields"] == ["email", "name", "role"]
    assert request["authentication_header_present"] is True
    assert "superSecretValue123" not in request["evidence_preview"]
    graphql = next(item for item in contracts if item["client"] == "graphql")
    assert graphql["graphql_operation_type"] == "mutation"
    assert graphql["manual_validation_required"] is True


def test_campaign_contract_tool_rejects_path_outside_extracted_root(campaign_env, tmp_path):
    campaign_id, _ = _campaign()
    outside = tmp_path / "outside"
    outside.mkdir()

    result = extract_api_contracts_for_campaign(campaign_id, str(outside))

    assert result["ok"] is False
    assert "campaign" in result["error"].lower() or "approved" in result["error"].lower()


def test_contract_extraction_supports_axios_config_wrapper_and_openapi_reference(campaign_env):
    text = """
    axios({url: '/api/admin', method: 'DELETE', headers: {'Authorization': auth}});
    request('/api/upload', {method: 'POST', body: new FormData()});
    const spec = '/docs/openapi.json';
    """

    contracts = extract_contracts_from_text(text, "client.ts")

    assert any(item["client"] == "axios" and item["method"] == "DELETE" for item in contracts)
    assert any(item["client"] == "request_wrapper:request" and item["endpoint"] == "/api/upload" for item in contracts)
    assert any(item["client"] == "openapi_reference" and item["endpoint"] == "/docs/openapi.json" for item in contracts)


def test_graph_deduplicates_node_and_preserves_observation_history(campaign_env):
    campaign_id, _ = _campaign()
    node = {"id": "endpoint", "node_type": "endpoint", "normalized_value": "POST /api/users", "confidence": "high"}

    first = add_evidence_batch(campaign_id, "test_tool", [node])
    second = add_evidence_batch(campaign_id, "test_tool", [node])
    summary = get_evidence_graph_summary(campaign_id)
    neighborhood = query_evidence_graph(campaign_id, first["node_ids"]["endpoint"])

    assert first["nodes_added"] == 1
    assert second["nodes_observed"] == 1
    assert summary["nodes_by_type"]["endpoint"] == 1
    assert len(neighborhood["nodes"][0]["observations"]) == 2


def test_har_import_redacts_values_and_never_replays(campaign_env):
    campaign_id, paths = _campaign()
    secret = "Bearer secret-token-value-123456"
    har = {
        "log": {"entries": [{
            "request": {
                "url": "https://example.com/api/users?token=topsecret&view=small",
                "method": "POST",
                "headers": [{"name": "Authorization", "value": secret}],
                "cookies": [{"name": "sessionid", "value": "cookie-secret"}],
                "queryString": [{"name": "token", "value": "topsecret"}, {"name": "view", "value": "small"}],
                "postData": {"mimeType": "application/json", "text": '{"password":"hidden","name":"Ada"}'},
            },
            "response": {"status": 200, "content": {"mimeType": "application/json", "text": '{"id":1,"token":"hidden"}'}},
        }]},
    }
    path = Path(paths["imports"]) / "traffic.har"
    path.write_text(json.dumps(har), encoding="utf-8")

    result = import_har_for_campaign(campaign_id, str(path))

    assert result["ok"] is True
    assert result["replayed"] is False
    observation = result["observations"][0]
    assert observation["authentication_mechanisms_present"] == ["Authorization"]
    assert observation["cookie_names"] == ["sessionid"]
    assert observation["request_body_field_names"] == ["name", "password"]
    persisted = Path(result["path"]).read_text(encoding="utf-8")
    assert secret not in persisted
    assert "cookie-secret" not in persisted
    assert "topsecret" not in persisted


def test_burp_xml_rejects_doctype_and_entities(campaign_env):
    campaign_id, paths = _campaign()
    path = Path(paths["imports"]) / "bad.xml"
    path.write_text('<!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><items><item><url>&xxe;</url></item></items>', encoding="utf-8")

    result = import_burp_xml_for_campaign(campaign_id, str(path))

    assert result["ok"] is False
    assert "rejected" in result["error"].lower()


def test_integrity_verification_detects_modified_artifact(campaign_env):
    campaign_id, paths = _campaign()
    source = _source_dir(paths)
    (source / "app.js").write_text('const token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456";', encoding="utf-8")
    scan = scan_sensitive_artifacts_for_campaign(campaign_id, str(source))

    before = verify_campaign_artifacts(campaign_id)
    assert any(item["path"].endswith("sensitive-scan.json") for item in before["verified_artifacts"])
    Path(scan["path"]).write_text("modified", encoding="utf-8")
    after = verify_campaign_artifacts(campaign_id)

    assert after["ok"] is False
    assert any(item["path"].endswith("sensitive-scan.json") for item in after["modified_artifacts"])


def test_differential_uses_secret_fingerprint_not_value(campaign_env):
    baseline_id, _ = _campaign()
    current_id, current_paths = _campaign()
    source = _source_dir(current_paths)
    secret = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"
    (source / "app.js").write_text(f'const token = "{secret}";', encoding="utf-8")
    scan_sensitive_artifacts_for_campaign(current_id, str(source))

    result = compare_campaign_recon(current_id, baseline_id)

    assert result["ok"] is True
    assert result["changes"]["secret_candidates"]["added"]
    assert secret not in json.dumps(result)
    assert secret not in Path(result["path"]).read_text(encoding="utf-8")


def test_source_map_extraction_rejects_excess_files_before_writing(campaign_env, monkeypatch):
    campaign_id, paths = _campaign()
    maps = Path(paths["recon"]["sourcemaps"]) / "maps"
    map_path = maps / "too-many.map"
    map_path.write_text(json.dumps({"version": 3, "sources": ["a.js", "b.js"], "sourcesContent": ["a", "b"]}), encoding="utf-8")
    monkeypatch.setattr("recon.safeio.load_scope", lambda: {"max_extracted_source_files": 1})

    result = extract_sourcemap_sources_for_campaign(campaign_id, str(map_path))

    assert result["ok"] is False
    assert result["rejected"] is True
    assert result["files_observed"] == 2
    assert not (Path(paths["recon"]["sourcemaps"]) / "extracted" / "too-many").exists()


def test_passive_discovery_classifies_wildcard_children_and_partial_failures(campaign_env, monkeypatch):
    campaign_id, _ = _campaign()

    def query(provider, root):
        if provider == "alienvault_otx":
            raise ValueError("provider unavailable")
        return ["API.EXAMPLE.COM.", "*.deep.example.com", "evil.test", "bad host.example.com"]

    monkeypatch.setattr("recon.passive._query", query)

    result = discover_subdomains_passive_for_campaign(campaign_id, "example.com", providers=["certificate_transparency", "alienvault_otx"])

    assert result["ok"] is True
    assert [item["host"] for item in result["results"]] == ["api.example.com", "deep.example.com"]
    assert all(item["scope_classification"] == "wildcard_in_scope" for item in result["results"])
    assert result["partial_failures"][0]["provider"] == "alienvault_otx"
    assert result["resolve_dns"] is False


def test_burp_xml_success_retains_names_not_values(campaign_env):
    campaign_id, paths = _campaign()
    raw_request = "GET /api HTTP/1.1\r\nHost: example.com\r\nAuthorization: Bearer never-store-this\r\nCookie: session=also-secret; theme=dark\r\n\r\n"
    xml = f"<items><item><url>https://example.com/api</url><method>GET</method><status>200</status><mimetype>application/json</mimetype><request base64=\"false\">{raw_request}</request></item></items>"
    path = Path(paths["imports"]) / "burp.xml"
    path.write_text(xml, encoding="utf-8")

    result = import_burp_xml_for_campaign(campaign_id, str(path))

    assert result["ok"] is True
    assert result["observations"][0]["authentication_mechanisms_present"] == ["Authorization"]
    assert result["observations"][0]["cookie_names"] == ["session", "theme"]
    persisted = Path(result["path"]).read_text(encoding="utf-8")
    assert "never-store-this" not in persisted
    assert "also-secret" not in persisted


def test_scope_endpoint_and_audit_outputs_redact_sensitive_url_values(campaign_env):
    campaign_id, paths = _campaign()
    secret = "never-persist-this-value"

    scope = resolve_scope_target(f"https://example.com/api?token={secret}&page=1")
    endpoints = extract_endpoints_from_js(f'fetch("/api?token={secret}&page=1")', source_type="raw")
    add_evidence_batch(campaign_id, "redaction_test", [{"node_type": "url", "normalized_value": f"https://example.com/api?token={secret}"}])

    assert secret not in json.dumps(scope)
    assert secret not in json.dumps(endpoints)
    assert secret not in (Path(paths["recon"]["graph"]) / "evidence-graph.json").read_text(encoding="utf-8")
    assert secret not in Path(paths["audit_jsonl"]).read_text(encoding="utf-8")
