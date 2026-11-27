"""Real TLS qualification against a temporary loopback-only HTTPS fixture."""

from __future__ import annotations

import json
import shutil
import socket
import ssl
import subprocess
import threading
from contextlib import contextmanager

import httpx
import pytest

from recon import http_fetch, pinned_transport, scope

ORIGINAL_CONNECT = socket.socket.connect
HOST = "tls.example.test"
WRONG_HOST = "wrong.example.test"


@pytest.fixture(scope="module")
def test_certificates(tmp_path_factory):
    openssl = shutil.which("openssl")
    if openssl is None:
        pytest.skip("OpenSSL CLI required for temporary TLS certificates.")
    directory = tmp_path_factory.mktemp("recon-tls")
    (directory / "leaf.ext").write_text(
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature\n"
        "extendedKeyUsage=serverAuth\n"
        f"subjectAltName=DNS:{HOST}\n",
        encoding="ascii",
    )

    def run(*args):
        subprocess.run(
            [openssl, *args], cwd=directory, check=True, capture_output=True, timeout=10
        )

    run(
        "req",
        "-x509",
        "-newkey",
        "ec",
        "-pkeyopt",
        "ec_paramgen_curve:P-256",
        "-nodes",
        "-keyout",
        "ca.key",
        "-out",
        "ca.pem",
        "-days",
        "1",
        "-subj",
        "/CN=Recon MCP Synthetic Test CA",
        "-addext",
        "basicConstraints=critical,CA:TRUE",
        "-addext",
        "keyUsage=critical,keyCertSign,cRLSign",
    )
    run(
        "req",
        "-new",
        "-newkey",
        "ec",
        "-pkeyopt",
        "ec_paramgen_curve:P-256",
        "-nodes",
        "-keyout",
        "leaf.key",
        "-out",
        "leaf.csr",
        "-subj",
        f"/CN={HOST}",
    )
    run(
        "x509",
        "-req",
        "-in",
        "leaf.csr",
        "-CA",
        "ca.pem",
        "-CAkey",
        "ca.key",
        "-CAcreateserial",
        "-out",
        "leaf.pem",
        "-days",
        "1",
        "-extfile",
        "leaf.ext",
    )
    try:
        yield directory
    finally:
        shutil.rmtree(directory)


@contextmanager
def local_https(certificates):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certificates / "leaf.pem", certificates / "leaf.key")
    context.set_alpn_protocols(["http/1.1"])
    observations = {"sni": [], "request": b"", "handshake": False, "peer_closed": False}
    context.set_servername_callback(
        lambda sock, name, ctx: observations["sni"].append(name)
    )

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        try:
            listener.bind(("127.0.0.1", 0))
        except OSError as exc:
            pytest.skip(f"Isolated loopback listener unavailable: {exc}")
        listener.listen(1)
        listener.settimeout(4)
        endpoint = listener.getsockname()
        errors = []

        def serve():
            try:
                client, _ = listener.accept()
                with client:
                    client.settimeout(4)
                    try:
                        conn = context.wrap_socket(client, server_side=True)
                    except ssl.SSLError:
                        # The client rejected our certificate during the real handshake.
                        return
                    with conn:
                        observations["handshake"] = True
                        observations["version"] = conn.version()
                        while b"\r\n\r\n" not in observations["request"]:
                            data = conn.recv(1024)
                            if not data:
                                return
                            observations["request"] += data
                            if len(observations["request"]) > 8192:
                                raise AssertionError("Unexpected test request size.")
                        conn.sendall(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nX-Test-Tls: yes\r\n\r\n"
                        )
                        observations["peer_closed"] = conn.recv(1024) == b""
            except (AssertionError, OSError) as exc:
                errors.append(exc)

        worker = threading.Thread(target=serve, daemon=True)
        worker.start()
        try:
            yield endpoint, observations
        finally:
            worker.join(timeout=6)
            assert not worker.is_alive(), (
                "TLS test listener did not release its resources."
            )
            assert not errors, errors


def permit_only_fixture(monkeypatch, tmp_path, endpoint):
    _, port = endpoint
    config = tmp_path / "test-scope.json"
    config.write_text(
        json.dumps(
            {
                "allowed_domains": [
                    f"https://{host}:{port}/" for host in (HOST, WRONG_HOST)
                ],
                "request_delay_ms": 0,
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(scope, "DEFAULT_SCOPE_PATH", config)

    def resolve(host):
        assert host in (HOST, WRONG_HOST)
        return ["127.0.0.1"]

    def connect(sock, destination):
        assert destination == endpoint, (
            "TLS fixture can only dial its own loopback endpoint."
        )
        return ORIGINAL_CONNECT(sock, destination)

    # The test substitutes only the address classification of its loopback IP.
    # Auth, canonical URL checks, numeric connection, peer checks, TLS, HTTP,
    # and production response cleanup all still execute.
    forbid_ip = pinned_transport.is_private_or_loopback_host
    monkeypatch.setattr(
        pinned_transport,
        "is_private_or_loopback_host",
        lambda ip: ip != "127.0.0.1" and forbid_ip(ip),
    )
    monkeypatch.setattr(http_fetch, "resolve_host_ips", resolve)
    monkeypatch.setattr(socket.socket, "connect", connect)


def test_tls_trusted_handshake_preserves_sni_host_and_closes(
    test_certificates, tmp_path, monkeypatch
):
    with local_https(test_certificates) as (endpoint, seen):
        permit_only_fixture(monkeypatch, tmp_path, endpoint)
        monkeypatch.setattr(
            pinned_transport.certifi, "where", lambda: str(test_certificates / "ca.pem")
        )
        result = http_fetch.fetch_headers(f"https://{HOST}:{endpoint[1]}/")
    assert result["ok"], result
    assert result["headers"]["x-test-tls"] == "yes"
    assert seen["handshake"] and seen["version"] in {"TLSv1.2", "TLSv1.3"}
    assert seen["sni"] == [HOST]
    assert f"\r\nhost: {HOST}:{endpoint[1]}\r\n".encode() in seen["request"].lower()
    assert seen["peer_closed"]


@pytest.mark.parametrize(
    "trusted,host,message",
    [
        (False, HOST, "issuer"),
        (True, WRONG_HOST, "hostname mismatch"),
    ],
)
def test_tls_rejects_untrusted_and_hostname_mismatch(
    test_certificates, tmp_path, monkeypatch, trusted, host, message
):
    verification_errors = []
    wrap_socket = ssl.SSLContext.wrap_socket

    def observe_verification(context, *args, **kwargs):
        try:
            return wrap_socket(context, *args, **kwargs)
        except ssl.SSLCertVerificationError as exc:
            verification_errors.append(exc.verify_message)
            raise

    # A pass-through observer sees OpenSSL's verification result before
    # HTTPCore changes the exception chain. The handshake itself is unchanged.
    monkeypatch.setattr(ssl.SSLContext, "wrap_socket", observe_verification)
    with local_https(test_certificates) as (endpoint, seen):
        permit_only_fixture(monkeypatch, tmp_path, endpoint)
        if trusted:
            monkeypatch.setattr(
                pinned_transport.certifi,
                "where",
                lambda: str(test_certificates / "ca.pem"),
            )
        with pytest.raises(httpx.TransportError):
            http_fetch.safe_get_text(f"https://{host}:{endpoint[1]}/")
    assert len(verification_errors) == 1
    assert message in verification_errors[0].lower()
    assert not seen["handshake"] and seen["request"] == b""
    assert seen["sni"] == [host]
