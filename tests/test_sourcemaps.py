import json
from pathlib import Path

import httpx

import server
from recon.campaigns import create_campaign, get_campaign_paths
from recon.sourcemaps import (
    MAX_SOURCEMAP_BYTES,
    analyze_sourcemap_sources_for_campaign,
    detect_sourcemap_references,
    detect_sourcemap_references_for_campaign,
    download_sourcemap_for_campaign,
    extract_sourcemap_sources_for_campaign,
    sourcemap_workflow_for_campaign,
)


def _campaign_id(campaign_env):
    return create_campaign("Demo", "example.com")["campaign_id"]


def _mock_client(handler):
    return httpx.Client(
        transport=httpx.MockTransport(handler),
        timeout=10.0,
        follow_redirects=False,
        headers={"User-Agent": "ReconMCP/0.1"},
    )


def _patch_http(monkeypatch, handler):
    monkeypatch.setattr("recon.http_fetch._client", lambda: _mock_client(handler))


def _valid_map(**overrides):
    payload = {
        "version": 3,
        "file": "app.js",
        "sources": ["src/app.js"],
        "sourcesContent": ["fetch('/api/v1/admin/users?id=1'); const token='secret-token-value';"],
        "mappings": "",
    }
    payload.update(overrides)
    return payload


def test_detect_relative_sourcemap_reference():
    result = detect_sourcemap_references("//# sourceMappingURL=app.js.map", "https://example.com/static/app.js")

    assert result["ok"] is True
    assert result["references"][0]["kind"] == "relative"
    assert result["references"][0]["resolved_url"] == "https://example.com/static/app.js.map"


def test_detect_absolute_in_scope_sourcemap_reference():
    result = detect_sourcemap_references("//@ sourceMappingURL=https://example.com/app.js.map", "https://example.com/app.js")

    assert result["references"][0]["kind"] == "absolute"
    assert result["references"][0]["safe_to_download"] is True


def test_detect_data_uri_reference_is_bounded_manual_review_only():
    result = detect_sourcemap_references("/*# sourceMappingURL=data:application/json;base64,AAAA */", "https://example.com/app.js")

    assert result["references"][0]["kind"] == "data_uri"
    assert result["references"][0]["safe_to_download"] is False


def test_campaign_detection_skips_out_of_scope_reference(campaign_env, monkeypatch):
    campaign_id = _campaign_id(campaign_env)

    def handler(request):
        return httpx.Response(200, text="//# sourceMappingURL=https://evil.test/app.js.map")

    _patch_http(monkeypatch, handler)

    result = detect_sourcemap_references_for_campaign(campaign_id, "https://example.com/app.js")

    assert result["ok"] is True
    assert result["downloadable"] == []
    assert result["skipped"]
    assert Path(result["path"]).exists()


def test_download_rejects_out_of_scope_map_url(campaign_env):
    campaign_id = _campaign_id(campaign_env)

    result = download_sourcemap_for_campaign(campaign_id, "https://evil.test/app.js.map")

    assert result["ok"] is False
    assert "out of scope" in result["error"].lower()


def test_download_rejects_oversized_map_body(campaign_env, monkeypatch):
    campaign_id = _campaign_id(campaign_env)

    def handler(request):
        return httpx.Response(200, content=b"{" + (b" " * (MAX_SOURCEMAP_BYTES + 1)) + b"}")

    _patch_http(monkeypatch, handler)

    result = download_sourcemap_for_campaign(campaign_id, "https://example.com/app.js.map")

    assert result["ok"] is False
    assert "exceeds" in result["error"].lower()


def test_download_accepts_valid_sourcemap_json(campaign_env, monkeypatch):
    campaign_id = _campaign_id(campaign_env)

    def handler(request):
        return httpx.Response(200, json=_valid_map())

    _patch_http(monkeypatch, handler)

    result = download_sourcemap_for_campaign(campaign_id, "https://example.com/app.js.map")

    assert result["ok"] is True
    assert result["sources_count"] == 1
    assert result["has_sources_content"] is True
    assert Path(result["map_path"]).exists()
    assert Path(result["metadata_path"]).exists()


def test_extraction_writes_sources_content_files(campaign_env, monkeypatch):
    campaign_id = _campaign_id(campaign_env)

    def handler(request):
        return httpx.Response(200, json=_valid_map())

    _patch_http(monkeypatch, handler)
    download = download_sourcemap_for_campaign(campaign_id, "https://example.com/app.js.map")

    result = extract_sourcemap_sources_for_campaign(campaign_id, download["map_path"])

    assert result["ok"] is True
    assert result["files_written"] == 1
    assert list(Path(result["extracted_dir"]).rglob("*.js"))


def test_extraction_blocks_path_traversal_source_names(campaign_env):
    campaign_id = _campaign_id(campaign_env)
    paths = get_campaign_paths(campaign_id)["paths"]
    maps_dir = Path(paths["recon"]["sourcemaps"]) / "maps"
    maps_dir.mkdir(parents=True, exist_ok=True)
    map_path = maps_dir / "unsafe.map"
    map_path.write_text(json.dumps(_valid_map(sources=["../evil.js"], sourcesContent=["console.log('x')"])), encoding="utf-8")

    result = extract_sourcemap_sources_for_campaign(campaign_id, str(map_path))

    assert result["ok"] is True
    assert any("sanitized" in warning.lower() for warning in result["warnings"])
    assert not (Path(result["extracted_dir"]).parent / "evil.js").exists()


def test_extraction_blocks_absolute_and_windows_drive_paths(campaign_env):
    campaign_id = _campaign_id(campaign_env)
    paths = get_campaign_paths(campaign_id)["paths"]
    maps_dir = Path(paths["recon"]["sourcemaps"]) / "maps"
    maps_dir.mkdir(parents=True, exist_ok=True)
    map_path = maps_dir / "absolute.map"
    map_path.write_text(
        json.dumps(_valid_map(sources=["/etc/passwd", "C:\\temp\\secret.js"], sourcesContent=["a", "b"])),
        encoding="utf-8",
    )

    result = extract_sourcemap_sources_for_campaign(campaign_id, str(map_path))

    assert result["ok"] is True
    assert len([warning for warning in result["warnings"] if "sanitized" in warning.lower()]) == 2
    for path in Path(result["extracted_dir"]).rglob("*"):
        assert path.resolve().is_relative_to(Path(result["extracted_dir"]).resolve())


def test_extraction_handles_missing_sources_content_without_fetching(campaign_env):
    campaign_id = _campaign_id(campaign_env)
    paths = get_campaign_paths(campaign_id)["paths"]
    maps_dir = Path(paths["recon"]["sourcemaps"]) / "maps"
    maps_dir.mkdir(parents=True, exist_ok=True)
    map_path = maps_dir / "missing-content.map"
    map_path.write_text(json.dumps({"version": 3, "sources": ["https://example.com/source.js"], "mappings": ""}), encoding="utf-8")

    result = extract_sourcemap_sources_for_campaign(campaign_id, str(map_path))

    assert result["ok"] is True
    assert result["files_written"] == 0
    assert result["sources_without_content"] == 1
    assert (Path(result["extracted_dir"]) / "sources-index.json").exists()


def test_analysis_extracts_endpoints_and_redacts_secrets(campaign_env, monkeypatch):
    campaign_id = _campaign_id(campaign_env)

    def handler(request):
        return httpx.Response(200, json=_valid_map())

    _patch_http(monkeypatch, handler)
    download = download_sourcemap_for_campaign(campaign_id, "https://example.com/app.js.map")
    extraction = extract_sourcemap_sources_for_campaign(campaign_id, download["map_path"])

    result = analyze_sourcemap_sources_for_campaign(campaign_id, extraction["extracted_dir"])

    assert result["ok"] is True
    assert result["files_analyzed"] == 1
    assert result["scored_endpoints"]
    assert any(signal["type"].lower() == "token" for signal in result["signals"])
    assert all("secret-token-value" not in signal["preview"] for signal in result["signals"])


def test_full_workflow_returns_counts_and_artifacts(campaign_env, monkeypatch):
    campaign_id = _campaign_id(campaign_env)

    def handler(request):
        if str(request.url).endswith("/app.js"):
            return httpx.Response(200, text="//# sourceMappingURL=app.js.map")
        return httpx.Response(200, json=_valid_map())

    _patch_http(monkeypatch, handler)

    result = sourcemap_workflow_for_campaign(campaign_id, "https://example.com/app.js")

    assert result["ok"] is True
    assert result["detected_count"] == 1
    assert result["downloaded_count"] == 1
    assert result["extracted_count"] == 1
    assert result["files_analyzed"] == 1
    assert result["signals_count"] >= 1
    assert Path(result["analysis_path"]).exists()


def test_full_workflow_records_negative_suggestion_when_no_map(campaign_env, monkeypatch):
    campaign_id = _campaign_id(campaign_env)

    def handler(request):
        return httpx.Response(200, text="console.log('no map')")

    _patch_http(monkeypatch, handler)

    result = sourcemap_workflow_for_campaign(campaign_id, "https://example.com/app.js")

    assert result["ok"] is True
    assert result["detected_count"] == 0
    assert result["suggest_record_negative_result"] is True


def test_server_health_lists_sourcemap_tools():
    tools = server.health()["available_tools"]

    assert "detect_sourcemap_references_for_campaign" in tools
    assert "sourcemap_workflow_for_campaign" in tools
    assert "external_sourcemapper_info" in tools
