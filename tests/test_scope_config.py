import json

import pytest

import recon.scope as scope_module


@pytest.fixture(autouse=True)
def clear_scope_cache():
    scope_module._invalidate_scope_cache()
    yield
    scope_module._invalidate_scope_cache()


def test_load_scope_is_cached_until_invalidated(tmp_path, monkeypatch):
    scope_path = tmp_path / "scope.json"
    scope_path.write_text(json.dumps({"scope_source": "manual", "user_agent": "First/1"}), encoding="utf-8")
    monkeypatch.setattr(scope_module, "DEFAULT_SCOPE_PATH", scope_path)
    scope_module._invalidate_scope_cache()

    first = scope_module.load_scope()
    scope_path.write_text(json.dumps({"scope_source": "manual", "user_agent": "Second/2"}), encoding="utf-8")
    second = scope_module.load_scope()

    assert first["user_agent"] == "First/1"
    assert second["user_agent"] == "First/1"

    scope_module._invalidate_scope_cache()
    third = scope_module.load_scope()

    assert third["user_agent"] == "Second/2"


def test_load_scope_returns_default_on_missing_file(tmp_path, monkeypatch):
    monkeypatch.setattr(scope_module, "DEFAULT_SCOPE_PATH", tmp_path / "missing.json")
    scope_module._invalidate_scope_cache()

    result = scope_module.load_scope()

    assert result["scope_source"] == "manual"
    assert result["allowed_domains"] == []


@pytest.mark.parametrize("name,value", [("max_html_bytes", -1), ("max_sourcemap_bytes", 101 * 1024 * 1024), ("max_analysis_signals", 0), ("max_extracted_source_files", "many")])
def test_load_scope_rejects_invalid_processing_limits(tmp_path, monkeypatch, name, value):
    scope_path = tmp_path / "scope.json"
    scope_path.write_text(json.dumps({"scope_source": "manual", name: value}), encoding="utf-8")
    monkeypatch.setattr(scope_module, "DEFAULT_SCOPE_PATH", scope_path)
    scope_module._invalidate_scope_cache()

    with pytest.raises(scope_module.ScopeError):
        scope_module.load_scope()


@pytest.mark.parametrize("name,value", [("request_delay_ms", -1), ("request_delay_ms", 60001), ("max_requests_per_tool_call", 0), ("max_requests_per_tool_call", 1001), ("fetch_headers_method", "POST")])
def test_load_scope_rejects_invalid_request_controls(tmp_path, monkeypatch, name, value):
    scope_path = tmp_path / "scope.json"
    scope_path.write_text(json.dumps({"scope_source": "manual", name: value}), encoding="utf-8")
    monkeypatch.setattr(scope_module, "DEFAULT_SCOPE_PATH", scope_path)
    scope_module._invalidate_scope_cache()

    with pytest.raises(scope_module.ScopeError):
        scope_module.load_scope()
