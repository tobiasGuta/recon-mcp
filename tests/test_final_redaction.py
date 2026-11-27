"""Regression coverage for the remaining userinfo disclosure and scope gaps."""

import json
from pathlib import Path
from urllib.parse import quote

import httpx
import pytest

import server
from recon import http_fetch, redaction
from recon.audit import write_audit_event
from recon.authorization import check_url_scope
from recon.campaigns import create_campaign
from recon.safeio import write_artifact_bytes
from recon.scope import ScopeError

USER = "RCUSER6302"
PASSWORD = "RCVALUE9571"
INNER = f"https://{USER}:{PASSWORD}@nested.example.test/a"
OUTER = "https://example.com/?view=public&next="


def encoded(value, layers=1):
    for _ in range(layers):
        value = quote(value, safe="")
    return value


def assert_private(value):
    text = json.dumps(value)
    assert USER not in text
    assert PASSWORD not in text


@pytest.mark.parametrize(
    "value",
    [
        INNER,
        f"Connection failed for {INNER} while reading headers",
        f"Connection failed for {encoded(INNER)}",
        f"Location: {encoded(INNER, 4)}",
        f"https://{USER}%3A{PASSWORD}%40nested.example.test/",
        f'https://{USER}:"{PASSWORD}"@nested.example.test/',
        f"//{USER}:{PASSWORD}@nested.example.test/",
        f"https:\\/\\/{USER}:{PASSWORD}@nested.example.test/",
        OUTER + INNER,
        OUTER + encoded(INNER, 2),
        f"https://{USER}:<{PASSWORD}>@nested.example.test/",
        f"Read failed for https://{USER}:{PASSWORD}\t@nested.example.test/",
    ],
)
def test_public_redactors_hide_raw_and_encoded_userinfo(value):
    assert_private(redaction.redact_text(value))
    assert_private(redaction.redact_url(value))
    assert_private(redaction.redact_embedded_urls(value))
    assert_private(
        redaction.redact_structure({"url_map": {value: [value, {"next": value}]}})
    )
    assert_private(redaction.redact_structure({"details": [f"Observed {value}"]}))


def test_redaction_preserves_safe_context_and_has_bounded_inspection():
    assert redaction.redact_text(f"Failed at {INNER} with timeout") == (
        "Failed at https://nested.example.test/a with timeout"
    )
    assert (
        redaction.redact_url(OUTER + encoded(INNER))
        == "https://example.com/?<redacted>"
    )
    harmless = "https://example.com/?next=https%3A%2F%2Fnested.example.test%2Fa"
    assert redaction.redact_url(harmless) == harmless
    assert_private(
        redaction.redact_text("?" * (redaction.MAX_TEXT_SCAN_LENGTH + 1) + INNER)
    )
    tree = [INNER]
    tree.append(tree)
    assert_private(redaction.redact_structure(tree))


@pytest.mark.parametrize(
    "suffix",
    [
        INNER,
        encoded(INNER),
        encoded(INNER, 2),
        encoded(INNER, 4),
        f"https://{USER}%3A{PASSWORD}%40nested.example.test/",
        f"https%3A%2F%2F{USER}%3A{PASSWORD}%EF%BC%A0nested.example.test/",
        encoded("//" + INNER.split("//", 1)[1], 2),
        encoded(
            r"https\u003a\u002f\u002f"
            + USER
            + ":"
            + PASSWORD
            + r"\u0040nested.example.test/"
        ),
    ],
)
def test_nested_url_query_is_denied_before_dns_or_http_and_never_echoed(
    campaign_env, monkeypatch, suffix
):
    def unexpected(*args, **kwargs):
        pytest.fail("Unauthorized nested credentials reached network preparation.")

    monkeypatch.setattr(http_fetch, "resolve_host_ips", unexpected)
    monkeypatch.setattr(http_fetch, "_client", unexpected)
    url = OUTER + suffix
    offline = check_url_scope(url)
    assert offline["reason_code"] == "sensitive_url"
    assert not offline["network_execution_permitted"]
    assert_private(offline)
    denied = http_fetch.fetch_headers(url)
    assert denied["error_code"] == "sensitive_url"
    assert_private(denied)
    assert_private(server.explain_scope_decision(url))
    assert check_url_scope(OUTER + encoded("https://nested.example.test/a"))[
        "authorized"
    ]


def test_ambiguous_query_beyond_decode_limit_fails_closed(campaign_env):
    decision = check_url_scope(OUTER + encoded(INNER, 6))
    assert decision["reason_code"] == "invalid_url"
    assert not decision["network_execution_permitted"]
    assert_private(decision)


@pytest.mark.parametrize(
    "detail",
    [
        INNER,
        OUTER + encoded(INNER, 2),
        OUTER + encoded(INNER.replace("@", " @", 1)),
    ],
    ids=["literal", "nested", "whitespace-nested"],
)
def test_http_error_boundary_redacts_nested_decision_and_error(
    campaign_env, monkeypatch, detail
):
    from recon.authorization import AuthorizationError

    def deny(*args, **kwargs):
        raise AuthorizationError(
            f"Resolution detail {detail}",
            code="sensitive_url",
            decision={"detail": [detail]},
        )

    monkeypatch.setattr(http_fetch, "_checked_target", deny)
    result = http_fetch.fetch_headers("https://example.com/")
    assert result["error_code"] == "sensitive_url"
    assert_private(result)
    assert "Resolution detail" in result["error"] or "redacted" in result["error"]


@pytest.mark.parametrize("gap", ["", " ", "\u00a0"], ids=["literal", "space", "nbsp"])
def test_audit_and_artifact_metadata_do_not_retain_userinfo(campaign_env, gap):
    cid = create_campaign("Synthetic", "example.com")["campaign_id"]
    embedded = INNER.replace("@", gap + "@", 1)
    detail = OUTER + encoded(embedded, 2)
    audit = write_audit_event(
        cid,
        "fixture",
        warnings=[f"Response from {embedded}"],
        metadata={embedded: [detail]},
    )
    assert audit["ok"]
    assert_private(audit)
    assert_private(Path(audit["path"]).read_text())
    artifact = campaign_env / cid / "evidence" / "synthetic.bin"
    saved = write_artifact_bytes(
        cid,
        f"Fixture {INNER}",
        artifact,
        b"controlled bytes",
        limits_applied={"next": [detail]},
    )
    assert_private(Path(saved["metadata_path"]).read_text())
    assert artifact.read_bytes() == b"controlled bytes"


def test_header_response_closes_when_extraction_fails(campaign_env, monkeypatch):
    closed = []

    class Stream(httpx.SyncByteStream):
        def close(self):
            closed.append("closed")

    def handler(request):
        return httpx.Response(200, stream=Stream())

    def fail(response):
        raise ScopeError(f"Synthetic processing error at {INNER}")

    monkeypatch.setattr(
        http_fetch,
        "_client",
        lambda: httpx.Client(transport=httpx.MockTransport(handler)),
    )
    monkeypatch.setattr(http_fetch, "_headers_dict", fail)
    result = http_fetch.fetch_headers("https://example.com/")
    assert not result["ok"]
    assert_private(result)
    assert "Synthetic processing error" in result["error"]
    assert closed == ["closed"]


def whitespace_userinfo(separator, placement):
    username = USER
    password = PASSWORD
    host = "nested.example.test"
    if placement == "scheme":
        return f"https:{separator}//{username}:{password}@{host}/a"
    if placement == "before-user":
        return f"https://{separator}{username}:{password}@{host}/a"
    if placement == "username":
        return f"https://{username}{separator}:{password}@{host}/a"
    if placement == "password":
        return f"https://{username}:{separator}{password}@{host}/a"
    return f"https://{username}:{password}{separator}@{host}/a"


@pytest.mark.parametrize(
    ("separator", "separator_id"),
    [
        (" ", "space"),
        ("\u00a0", "nbsp"),
        ("\u2009", "thin-space"),
        ("\u3000", "ideographic-space"),
        ("\t", "tab"),
        ("\n", "lf"),
        ("\r", "cr"),
        ("\x00", "nul"),
        ("\u0085", "nel"),
        ("\u200b", "format-control"),
        (r"\u0020", "escaped-space"),
        (r"\u00a0", "escaped-nbsp"),
        (r"\t", "escaped-tab"),
    ],
    ids=lambda item: ascii(item) if item != " " else "space",
)
@pytest.mark.parametrize(
    "placement", ["scheme", "before-user", "username", "password", "before-at"]
)
@pytest.mark.parametrize("encoding", ["percent", "form", "nested"])
def test_whitespace_userinfo_matrix(
    campaign_env, monkeypatch, separator, separator_id, placement, encoding
):
    """Test the same representation at admission and every display boundary."""
    from urllib.parse import quote_plus

    inner = whitespace_userinfo(separator, placement)
    if encoding == "form":
        value = quote_plus(inner, safe="")
    elif encoding == "nested":
        intermediate = "https://relay.example.test/?dest=" + encoded(inner)
        value = encoded(intermediate)
    else:
        value = encoded(inner)
    query = "view=public&destination=" + value
    url = "https://example.com/?" + query
    case = f"{encoding}/{separator_id}/{placement}"
    assert (
        redaction.inspect_sensitive_data(query, query=True)
        is not redaction.Inspection.CLEAN
    ), case
    assert redaction.inspect_sensitive_data(url) is not redaction.Inspection.CLEAN, case

    def unexpected(*args, **kwargs):
        pytest.fail(f"Nonclean URL reached DNS or HTTP preparation: {case}")

    monkeypatch.setattr(http_fetch, "resolve_host_ips", unexpected)
    monkeypatch.setattr(http_fetch, "_client", unexpected)
    offline = check_url_scope(url)
    assert offline["reason_code"] in {"sensitive_url", "invalid_url"}, case
    assert not offline["network_execution_permitted"], case
    for rendered in (
        offline,
        http_fetch.fetch_headers(url),
        server.explain_scope_decision(url),
        redaction.redact_url(url),
        redaction.redact_text(f"Connection detail {url}"),
        redaction.redact_embedded_urls(f"Connection detail {url}"),
        redaction.redact_structure({"details": {url: [url, {"value": url}]}}),
        redaction.redact_text(inner),
        redaction.redact_url(inner),
        redaction.redact_embedded_urls(f"Observed {inner}"),
        redaction.redact_structure({"details": {inner: inner}}),
    ):
        assert_private(rendered)


@pytest.mark.parametrize(
    "nested",
    [
        lambda: f"https:/{USER}:{PASSWORD}@nested.example.test/",
        lambda: f"https://{USER}:{PASSWORD}%@nested.example.test/",
        lambda: f"https://{USER} : {PASSWORD} ＠nested.example.test/",
        lambda: f"https://{USER}:{PASSWORD}@",
        lambda: f"https://{USER}:{PASSWORD}@nested.example.test:bad/",
        lambda: f"https://{USER}:{PASSWORD} @nested.example.test/",
    ],
    ids=[
        "missing-slash",
        "bad-percent",
        "normalized-at",
        "empty-host",
        "invalid-port",
        "space",
    ],
)
def test_malformed_url_like_values_fail_conservatively(
    campaign_env, monkeypatch, nested
):
    def unexpected(*args, **kwargs):
        pytest.fail("Malformed or sensitive URL reached DNS or HTTP preparation")

    monkeypatch.setattr(http_fetch, "resolve_host_ips", unexpected)
    monkeypatch.setattr(http_fetch, "_client", unexpected)
    url = OUTER + encoded(nested())
    assert not check_url_scope(url)["network_execution_permitted"]
    assert not http_fetch.fetch_headers(url)["ok"]
    for sanitize in (
        redaction.redact_text,
        redaction.redact_url,
        redaction.redact_embedded_urls,
        redaction.redact_structure,
    ):
        assert_private(sanitize(url))


@pytest.mark.parametrize(
    "query",
    [
        "q=north+east&n=1&n=2",
        "q=wide%C2%A0space",
        "next=https%3A%2F%2Fnested.example.test%2Fa%3Fsort%3Ddesc",
        "next=https://nested.example.test/a&lang=en",
        "q=caf%C3%A9&view=public",
        "q=%2f%3a%2B&flag=",
        "note=100%25+finished",
    ],
)
def test_clean_url_inspection_preserves_request_target_bytes(
    campaign_env, monkeypatch, query
):
    assert (
        redaction.inspect_sensitive_data(query, query=True)
        is redaction.Inspection.CLEAN
    )
    assert (
        redaction.inspect_sensitive_data("HTTP: response received normally")
        is redaction.Inspection.CLEAN
    )
    original = "https://example.com/p?" + query
    assert check_url_scope(original)["authorized"]
    sent = []

    def respond(request):
        sent.append((request.method, request.url.raw_path))
        return httpx.Response(200)

    monkeypatch.setattr(
        http_fetch,
        "_client",
        lambda: httpx.Client(transport=httpx.MockTransport(respond)),
    )
    result = http_fetch.fetch_headers(original)
    assert result["ok"], result
    assert sent == [("HEAD", ("/p?" + query).encode("ascii"))]


@pytest.mark.parametrize(
    "reason", ["query-length", "decode-depth", "invalid-utf8", "text-length"]
)
def test_inspection_limits_mask_uncertain_values(reason):
    values = {
        "query-length": ("q=" + "x" * redaction.MAX_QUERY_SCAN_LENGTH + INNER, True),
        "decode-depth": (
            "next=" + encoded(INNER, redaction.MAX_DECODE_LAYERS + 2),
            True,
        ),
        "invalid-utf8": ("next=%FF" + encoded(INNER), True),
        "text-length": ("x" * redaction.MAX_TEXT_SCAN_LENGTH + INNER, False),
    }
    value, is_query = values[reason]
    assert (
        redaction.inspect_sensitive_data(value, query=is_query)
        is redaction.Inspection.AMBIGUOUS
    )
    assert_private(redaction.redact_text(value))
    assert_private(redaction.redact_url("https://example.com/?" + value))


def test_nonstructural_unicode_escape_does_not_crash_inspection():
    value = r"documentation \u2100 example"
    assert redaction.inspect_sensitive_data(value) is redaction.Inspection.CLEAN
    assert redaction.redact_text(value) == value


@pytest.mark.parametrize(
    "nested",
    [
        "https:/nested.example.test/a",
        "https://nested.example.test:bad/",
        "https://[broken",
        "https://nest ed.example.test/a",
        "https://nested.example.test :443/a",
    ],
)
def test_malformed_nested_authorities_are_ambiguous_without_userinfo(
    campaign_env, nested
):
    query = "next=" + encoded(nested)
    url = "https://example.com/?" + query
    assert (
        redaction.inspect_sensitive_data(query, query=True)
        is redaction.Inspection.AMBIGUOUS
    )
    assert redaction.inspect_sensitive_data(url) is redaction.Inspection.AMBIGUOUS
    result = check_url_scope(url)
    assert result["reason_code"] == "invalid_url"
    assert not result["network_execution_permitted"]
    assert redaction.redact_url(url) == "https://example.com/?<redacted>"
