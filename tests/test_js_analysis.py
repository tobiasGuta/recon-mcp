from recon.js_analysis import extract_endpoints_from_js


SAMPLE_JS = """
const api = "/api/users?id=1";
const apiAgain = "/api/users?id=1";
const v1 = "/v1/accounts";
const v2 = "/v2/reports";
const gql = "/graphql";
const auth = "/auth/session";
const admin = "/admin/panel";
const absolute = "https://example.com/api/public";
//# sourceMappingURL=app.js.map
"""


def test_extracting_endpoints_from_sample_js_string():
    result = extract_endpoints_from_js(SAMPLE_JS)
    values = {item["value"] for item in result["endpoints"]}
    assert result["ok"] is True
    assert "/api/users?id=1" in values
    assert "/v1/accounts" in values
    assert "/v2/reports" in values
    assert "/graphql" in values
    assert "/auth/session" in values
    assert "/admin/panel" in values
    assert "https://example.com/api/public" in values


def test_extracting_source_mapping_url():
    result = extract_endpoints_from_js(SAMPLE_JS)
    source_maps = [item for item in result["endpoints"] if item["category"] == "source_map"]
    assert source_maps == [{"category": "source_map", "value": "app.js.map"}]


def test_deduping_endpoint_results():
    result = extract_endpoints_from_js(SAMPLE_JS)
    api_values = [item for item in result["endpoints"] if item["value"] == "/api/users?id=1"]
    assert len(api_values) == 1


def test_local_file_reads_must_stay_inside_project(tmp_path):
    outside_js = tmp_path / "outside.js"
    outside_js.write_text('const api = "/api/outside";', encoding="utf-8")

    result = extract_endpoints_from_js(str(outside_js))

    assert result["ok"] is False
    assert "inside the recon mcp project" in result["error"].lower()


def test_local_file_reads_require_javascript_extension(tmp_path, monkeypatch):
    project_file = tmp_path / "not-js.txt"
    project_file.write_text('const api = "/api/nope";', encoding="utf-8")
    monkeypatch.setattr("recon.js_analysis.PROJECT_ROOT", tmp_path)

    result = extract_endpoints_from_js(str(project_file))

    assert result["ok"] is False
    assert ".js" in result["error"]
