import pytest

from recon.scope import check_scope, is_private_or_loopback_host, normalize_domain


def manual_scope():
    return {
        "scope_source": "manual",
        "allowed_domains": ["example.com", "example.org"],
        "blocked_domains": ["localhost", "127.0.0.1", "0.0.0.0", "::1"],
    }


@pytest.fixture(autouse=True)
def use_manual_scope(monkeypatch):
    monkeypatch.setattr("recon.scope.load_scope", manual_scope)


def test_exact_domain_match():
    result = check_scope("example.com")
    assert result["in_scope"] is True
    assert result["matched_scope"] == "example.com"


def test_child_of_legacy_exact_domain_is_not_implicitly_authorized():
    result = check_scope("api.example.com")
    assert result["in_scope"] is False
    assert result["reason_code"] == "no_matching_asset"


def test_explicit_wildcard_matches_children_but_not_apex(monkeypatch):
    monkeypatch.setattr(
        "recon.scope.load_scope",
        lambda: {"scope_source": "manual", "allowed_assets": [{"value": "*.example.com", "match": "wildcard"}], "allowed_domains": [], "blocked_domains": []},
    )
    assert check_scope("api.example.com")["reason_code"] == "wildcard_scope_match"
    assert check_scope("deep.api.example.com")["in_scope"] is True
    assert check_scope("example.com")["in_scope"] is False


def test_out_of_scope_domain():
    result = check_scope("not-example.net")
    assert result["in_scope"] is False


def test_localhost_blocked():
    result = check_scope("localhost")
    assert result["in_scope"] is False
    assert "blocked" in result["reason"].lower()


def test_private_ip_blocked():
    assert is_private_or_loopback_host("192.168.1.10") is True
    result = check_scope("http://192.168.1.10")
    assert result["in_scope"] is False


def test_localhost_blocked_even_without_blocked_domains(monkeypatch):
    monkeypatch.setattr(
        "recon.scope.load_scope",
        lambda: {"scope_source": "manual", "allowed_domains": ["localhost"], "blocked_domains": []},
    )

    result = check_scope("localhost")

    assert result["in_scope"] is False
    assert "blocked" in result["reason"].lower()


def test_suffix_trick_does_not_match_allowed_domain():
    result = check_scope("badexample.com")

    assert result["in_scope"] is False


def test_empty_manual_scope_fails_closed(monkeypatch):
    monkeypatch.setattr(
        "recon.scope.load_scope",
        lambda: {"scope_source": "manual", "allowed_domains": [], "blocked_domains": []},
    )

    result = check_scope("example.com")

    assert result["ok"] is False
    assert result["in_scope"] is False
    assert "failing closed" in result["reason"].lower()


def test_url_input_normalization():
    assert normalize_domain("https://API.Example.com:443/path?q=1") == "api.example.com"
    result = check_scope("https://Example.com:443/path?q=1")
    assert result["in_scope"] is True


def test_normalize_domain_authority_header_format():
    assert normalize_domain(":authority:api.example.com") == "api.example.com"


def test_normalize_domain_host_header_format():
    assert normalize_domain("host:api.example.com") == "api.example.com"


def test_manual_scope_normalizes_case_trailing_dot_and_idn(monkeypatch):
    monkeypatch.setattr(
        "recon.scope.load_scope",
        lambda: {"scope_source": "manual", "allowed_assets": [{"value": "BÜCHER.Example.", "match": "exact"}], "allowed_domains": [], "blocked_domains": []},
    )

    result = check_scope("https://bücher.example./path")

    assert result["in_scope"] is True
    assert result["normalized_host"] == "xn--bcher-kva.example"
    assert result["reason_code"] == "exact_scope_match"


def test_manual_scope_supports_public_ipv4_and_ipv6_exact_assets(monkeypatch):
    monkeypatch.setattr(
        "recon.scope.load_scope",
        lambda: {"scope_source": "manual", "allowed_assets": [{"value": "8.8.8.8", "match": "exact"}, {"value": "2001:4860:4860::8888", "match": "exact"}], "allowed_domains": [], "blocked_domains": []},
    )

    assert check_scope("8.8.8.8")["in_scope"] is True
    assert check_scope("https://[2001:4860:4860::8888]/")["in_scope"] is True


def test_malformed_manual_asset_is_not_authorized(monkeypatch):
    monkeypatch.setattr(
        "recon.scope.load_scope",
        lambda: {"scope_source": "manual", "allowed_assets": [{"value": "bad host", "match": "exact"}], "allowed_domains": [], "blocked_domains": []},
    )

    result = check_scope("bad host")

    assert result["in_scope"] is False
    assert result["reason_code"] == "unsupported_asset"
