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
