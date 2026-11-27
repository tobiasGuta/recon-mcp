import socket
import ssl

import httpx
import pytest

from recon import http_fetch, pinned_transport


@pytest.fixture
def wire(monkeypatch):
    state = {
        "dns": [],
        "dials": [],
        "tls": [],
        "sent": [],
        "responses": [],
        "answers": [],
    }
    config = {
        "allowed_domains": ["api.example.test", "next.example.test"],
        "request_delay_ms": 0,
    }
    monkeypatch.setattr("recon.scope.load_scope", lambda: config)
    monkeypatch.setattr("recon.http_fetch.load_scope", lambda: config)

    def dns(host, port, *, type):
        state["dns"].append(host)
        answers = state["answers"].pop(0) if state["answers"] else ["127.0.0.1"]
        return [(None, None, None, None, (value, 0)) for value in answers]

    class Socket:
        def __init__(self, family, kind):
            self.family = family

        def settimeout(self, timeout):
            self.timeout = timeout

        def connect(self, endpoint):
            self.endpoint = endpoint
            state["dials"].append((self.family, endpoint, self.timeout))
            if endpoint[0] in state.get("fail_connect", []):
                raise ConnectionRefusedError()

        def getpeername(self):
            return state.get("reported_peer", self.endpoint)

        def setsockopt(self, *args):
            pass

        def sendall(self, data):
            state["sent"].append(data)

        def recv(self, maximum):
            return state["responses"].pop(0)

        def close(self):
            pass

    def wrap(context, sock, *, server_hostname):
        state["tls"].append(
            (
                server_hostname,
                context.check_hostname,
                context.verify_mode,
                bool(context.get_ca_certs()),
            )
        )
        if state.get("reject_tls"):
            raise ssl.SSLCertVerificationError("synthetic certificate failure")
        return sock

    monkeypatch.setattr("recon.http_fetch.socket.getaddrinfo", dns)
    monkeypatch.setattr(pinned_transport, "open_tcp_socket", Socket)
    monkeypatch.setattr(ssl.SSLContext, "wrap_socket", wrap)
    return state


OK = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"


def test_pinned_socket_connects_only_to_preflight_answer_and_preserves_tls(
    wire, monkeypatch
):
    # The mock resolver would return loopback if the transport queried it again.
    wire["answers"].append(["93.184.216.34"])
    wire["responses"].append(OK)
    for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
        monkeypatch.setenv(key, "http://proxy.example.test:8222")
    result = http_fetch.fetch_headers("https://api.example.test/")
    assert result["ok"]
    assert wire["dns"] == ["api.example.test"]
    assert [dial[:2] for dial in wire["dials"]] == [
        (socket.AF_INET, ("93.184.216.34", 443))
    ]
    assert wire["tls"] == [("api.example.test", True, ssl.CERT_REQUIRED, True)]
    assert b"host: api.example.test\r\n" in b"".join(wire["sent"]).lower()


def test_pinned_transport_uses_bounded_ipv6_and_ipv4_candidates(wire):
    wire["answers"].append(["2606:4700:4700::1111", "93.184.216.34"])
    wire["fail_connect"] = ["2606:4700:4700::1111"]
    wire["responses"].append(OK)
    assert http_fetch.fetch_headers("http://api.example.test:8080/")["ok"]
    assert [dial[:2] for dial in wire["dials"]] == [
        (socket.AF_INET6, ("2606:4700:4700::1111", 8080, 0, 0)),
        (socket.AF_INET, ("93.184.216.34", 8080)),
    ]
    assert 0 < wire["dials"][1][2] <= wire["dials"][0][2] <= 10
    assert wire["tls"] == []


@pytest.mark.parametrize(
    "answers",
    [
        [],
        ["93.184.216.34", "127.0.0.1"],
        ["::ffff:127.0.0.1"],
        ["fe80::1%eth0"],
        ["AUDIT-DNS-LEAK"],
    ],
)
def test_invalid_dns_sets_never_connect(wire, answers):
    wire["answers"].append(answers)
    result = http_fetch.fetch_headers("https://api.example.test/")
    assert not result["ok"]
    assert not wire["dials"]
    assert "AUDIT-DNS-LEAK" not in str(result)


def test_reported_peer_mismatch_stops_before_tls_and_http(wire):
    wire["reported_peer"] = ("127.0.0.1", 443)
    wire["answers"].extend([["93.184.216.34"], ["93.184.216.34"]])
    assert not http_fetch.fetch_headers("https://api.example.test/")["ok"]
    assert wire["tls"] == wire["sent"] == []


def test_tls_verification_failure_retries_only_with_fresh_approved_addresses(wire):
    wire["reject_tls"] = True
    wire["answers"].extend([["93.184.216.34"], ["127.0.0.1"]])
    assert not http_fetch.fetch_headers("https://api.example.test/")["ok"]
    assert len(wire["dns"]) == 2
    assert len(wire["tls"]) == len(wire["dials"]) == 1
    assert not wire["sent"]


def test_each_redirect_and_get_fallback_use_their_own_address(wire):
    wire["answers"].extend([["93.184.216.34"], ["1.1.1.1"], ["8.8.8.8"]])
    wire["responses"].extend(
        [
            b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n",
            b"HTTP/1.1 302 Found\r\nLocation: https://next.example.test/final\r\nContent-Length: 0\r\n\r\n",
            OK,
        ]
    )
    result = http_fetch.fetch_headers("https://api.example.test/")
    assert result["ok"] and result["method"] == "GET"
    assert wire["dns"] == ["api.example.test", "api.example.test", "next.example.test"]
    assert [dial[1][0] for dial in wire["dials"]] == [
        "93.184.216.34",
        "1.1.1.1",
        "8.8.8.8",
    ]
    assert [record[0] for record in wire["tls"]] == wire["dns"]


def test_redirect_limit_prevents_extra_dns_and_connection(wire):
    wire["answers"].extend([["93.184.216.34"]] * 6)
    wire["responses"].extend(
        [b"HTTP/1.1 302 Found\r\nLocation: /next\r\nContent-Length: 0\r\n\r\n"] * 6
    )
    result = http_fetch.fetch_headers("https://api.example.test/")
    assert result["error_code"] == "redirect_limit"
    assert len(wire["dns"]) == len(wire["dials"]) == http_fetch.MAX_REDIRECTS + 1


def test_pinned_transport_requires_authorized_origin_metadata(wire):
    with httpx.Client(
        transport=pinned_transport.PinnedTransport(), trust_env=False
    ) as client:
        with pytest.raises(httpx.TransportError):
            client.get("https://api.example.test/")
        with pytest.raises(httpx.TransportError):
            client.get(
                "https://api.example.test/",
                extensions={
                    pinned_transport.DESTINATIONS: (
                        ("https", "other.example.test", 443),
                        ("93.184.216.34",),
                    )
                },
            )
    assert not wire["dials"]
