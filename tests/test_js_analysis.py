from recon.js_analysis import collect_js_urls, extract_endpoints_from_js


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
    assert result["source_type"] == "raw"


def test_extracting_endpoints_from_raw_source_type():
    result = extract_endpoints_from_js('fetch("/api/raw");', source_type="raw")

    assert result["ok"] is True
    assert result["source_type"] == "raw"
    assert {item["value"] for item in result["endpoints"]} == {"/api/raw"}


def test_extracting_endpoints_from_url_source_type(monkeypatch):
    monkeypatch.setattr("recon.js_analysis._fetch_text", lambda url: 'fetch("/api/from-url");')

    result = extract_endpoints_from_js("https://example.com/app.js", source_type="url")

    assert result["ok"] is True
    assert result["source_type"] == "url"
    assert {item["value"] for item in result["endpoints"]} == {"/api/from-url"}


def test_extracting_endpoints_from_file_source_type(tmp_path, monkeypatch):
    project_file = tmp_path / "app.js"
    project_file.write_text('fetch("/api/from-file");', encoding="utf-8")
    monkeypatch.setattr("recon.js_analysis.PROJECT_ROOT", tmp_path)

    result = extract_endpoints_from_js(str(project_file), source_type="file")

    assert result["ok"] is True
    assert result["source_type"] == "file"
    assert {item["value"] for item in result["endpoints"]} == {"/api/from-file"}


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


def test_local_file_size_limit_surfaces_constant(tmp_path, monkeypatch):
    project_file = tmp_path / "large.js"
    project_file.write_text("x" * 6, encoding="utf-8")
    monkeypatch.setattr("recon.js_analysis.PROJECT_ROOT", tmp_path)
    monkeypatch.setattr("recon.js_analysis.MAX_LOCAL_JS_BYTES", 5)

    result = extract_endpoints_from_js(str(project_file), source_type="file")

    assert result["ok"] is False
    assert "MAX_LOCAL_JS_BYTES" in result["error"]
    assert "5" in result["error"]


def test_collect_js_urls_truncates_above_max_requests_per_tool_call(monkeypatch):
    config = {
        "scope_source": "manual",
        "allowed_domains": ["example.com"],
        "blocked_domains": [],
        "max_requests_per_tool_call": 2,
        "request_delay_ms": 0,
    }
    html = """
    <script src="/one.js"></script>
    <script src="/two.js"></script>
    <script src="/three.js"></script>
    """

    monkeypatch.setattr("recon.js_analysis._fetch_text", lambda url: html)
    monkeypatch.setattr("recon.js_analysis.load_scope", lambda: config)

    result = collect_js_urls("https://example.com/")

    assert result["ok"] is True
    assert result["max_requests_per_tool_call"] == 2
    assert result["count"] == 2
    assert result["truncated"] is True


def test_collect_js_urls_allows_at_exactly_max_limit(monkeypatch):
    config = {
        "scope_source": "manual",
        "allowed_domains": ["example.com"],
        "blocked_domains": [],
        "max_requests_per_tool_call": 2,
        "request_delay_ms": 0,
    }
    html = """
    <script src="/one.js"></script>
    <script src="/two.js"></script>
    """

    monkeypatch.setattr("recon.js_analysis._fetch_text", lambda url: html)
    monkeypatch.setattr("recon.js_analysis.load_scope", lambda: config)

    result = collect_js_urls("https://example.com/")

    assert result["ok"] is True
    assert result["count"] == 2
    assert result["truncated"] is False
