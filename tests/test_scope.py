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


def test_subdomain_match():
    result = check_scope("api.example.com")
    assert result["in_scope"] is True
    assert result["matched_scope"] == "example.com"


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
    result = check_scope("https://API.Example.com:443/path?q=1")
    assert result["in_scope"] is True


def test_normalize_domain_authority_header_format():
    assert normalize_domain(":authority:api.example.com") == "api.example.com"


def test_normalize_domain_host_header_format():
    assert normalize_domain("host:api.example.com") == "api.example.com"
