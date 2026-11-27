"""HTTPX transport with a fresh, validated numeric destination for every request."""

from __future__ import annotations

import ipaddress
import socket
import ssl
import time
from contextlib import contextmanager
from socket import socket as open_tcp_socket

import certifi
import httpcore
import httpx

from recon.scope import is_private_or_loopback_host

DESTINATIONS = "recon.validated_destinations"
MAX_DNS_ADDRESSES = 64
MAX_CONNECT_ATTEMPTS = 8


def validated_addresses(values: list[str] | tuple[str, ...]) -> tuple[str, ...]:
    """Validate every answer before selecting any connection candidate."""
    if (
        not isinstance(values, (list, tuple))
        or not 1 <= len(values) <= MAX_DNS_ADDRESSES
    ):
        raise ValueError("Expected a bounded, nonempty list of DNS addresses.")
    addresses = []
    for value in values:
        if not isinstance(value, str) or len(value) > 45 or "%" in value:
            raise ValueError("DNS returned an invalid or scoped address.")
        try:
            address = str(ipaddress.ip_address(value))
        except ValueError as exc:
            raise ValueError("DNS returned an invalid address.") from exc
        if is_private_or_loopback_host(address):
            raise ValueError(f"Hostname resolved to unsafe address(es): {address}.")
        addresses.append(address)
    return tuple(dict.fromkeys(addresses))


@contextmanager
def _httpx_errors(request: httpx.Request):
    try:
        yield
    except httpcore.TimeoutException as exc:
        raise httpx.TimeoutException(
            "Pinned HTTP transport timed out.", request=request
        ) from exc
    except (
        httpcore.NetworkError,
        httpcore.ProtocolError,
        httpcore.UnsupportedProtocol,
    ) as exc:
        raise httpx.TransportError(
            "Pinned HTTP transport failed.", request=request
        ) from exc


class _SocketStream(httpcore.NetworkStream):
    def __init__(self, sock: socket.socket, hostname: str):
        self.sock = sock
        self.hostname = hostname

    def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        try:
            self.sock.settimeout(timeout)
            return self.sock.recv(max_bytes)
        except TimeoutError as exc:
            raise httpcore.ReadTimeout() from exc
        except OSError as exc:
            raise httpcore.ReadError() from exc

    def write(self, buffer: bytes, timeout: float | None = None) -> None:
        try:
            self.sock.settimeout(timeout)
            self.sock.sendall(buffer)
        except TimeoutError as exc:
            raise httpcore.WriteTimeout() from exc
        except OSError as exc:
            raise httpcore.WriteError() from exc

    def start_tls(self, ssl_context, server_hostname=None, timeout=None):
        try:
            if (
                server_hostname != self.hostname
                or not ssl_context.check_hostname
                or ssl_context.verify_mode != ssl.CERT_REQUIRED
            ):
                raise httpcore.ConnectError(
                    "TLS verification must use the authorized hostname."
                )
            self.sock.settimeout(timeout)
            self.sock = ssl_context.wrap_socket(
                self.sock, server_hostname=server_hostname
            )
            return self
        except TimeoutError as exc:
            self.close()
            raise httpcore.ConnectTimeout() from exc
        except OSError as exc:
            self.close()
            raise httpcore.ConnectError() from exc
        except BaseException:
            self.close()
            raise

    def get_extra_info(self, info: str):
        if info == "ssl_object" and isinstance(self.sock, ssl.SSLSocket):
            return self.sock
        if info == "server_addr":
            return self.sock.getpeername()
        return None

    def close(self) -> None:
        self.sock.close()


class _PinnedBackend(httpcore.NetworkBackend):
    def __init__(self, hostname: str, port: int, addresses: tuple[str, ...]):
        self.hostname = hostname
        self.port = port
        self.addresses = addresses

    def connect_tcp(
        self, host, port, timeout=None, local_address=None, socket_options=None
    ):
        if (
            (host, port) != (self.hostname, self.port)
            or local_address is not None
            or socket_options
        ):
            raise httpcore.ConnectError(
                "Connection parameters differ from the approved destination."
            )
        if timeout is None or not 0 < timeout <= 60:
            raise httpcore.ConnectError("A bounded connect timeout is required.")
        deadline = time.monotonic() + timeout
        last_error = None
        for value in self.addresses[:MAX_CONNECT_ATTEMPTS]:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise httpcore.ConnectTimeout() from last_error
            address = ipaddress.ip_address(value)
            family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
            endpoint = (value, port, 0, 0) if address.version == 6 else (value, port)
            sock = None
            try:
                sock = open_tcp_socket(family, socket.SOCK_STREAM)
                sock.settimeout(remaining)
                sock.connect(endpoint)
                peer = sock.getpeername()
                if ipaddress.ip_address(peer[0]) != address or peer[1] != port:
                    raise httpcore.ConnectError(
                        "Connected peer differs from the approved destination."
                    )
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                return _SocketStream(sock, host)
            except OSError as exc:
                last_error = exc
                if sock is not None:
                    sock.close()
            except BaseException:
                if sock is not None:
                    sock.close()
                raise
        if isinstance(last_error, TimeoutError):
            raise httpcore.ConnectTimeout() from last_error
        raise httpcore.ConnectError() from last_error

    def connect_unix_socket(self, path, timeout=None, socket_options=None):
        raise httpcore.ConnectError("Unix socket transport is disabled.")


class _ResponseStream(httpx.SyncByteStream):
    def __init__(
        self,
        response: httpcore.Response,
        pool: httpcore.ConnectionPool,
        request: httpx.Request,
    ):
        self.response = response
        self.pool = pool
        self.request = request

    def __iter__(self):
        with _httpx_errors(self.request):
            yield from self.response.iter_stream()

    def close(self):
        with _httpx_errors(self.request):
            try:
                self.response.close()
            finally:
                self.pool.close()


class PinnedTransport(httpx.BaseTransport):
    """Bridge public HTTPX and HTTPCore APIs without rewriting URL authority."""

    def __init__(self):
        self.ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        try:
            self.ssl_context.load_verify_locations(certifi.where())
        except OSError as exc:
            raise httpx.TransportError(
                "Could not initialize the TLS trust store."
            ) from exc

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        scheme = request.url.scheme
        port = request.url.port or (443 if scheme == "https" else 80)
        host = request.url.raw_host.decode("ascii")
        if scheme not in {"http", "https"} or request.method not in {"HEAD", "GET"}:
            raise httpx.TransportError(
                "Pinned transport requires HTTP(S) HEAD or GET.", request=request
            )
        try:
            origin, answers = request.extensions[DESTINATIONS]
            if origin != (scheme, host, port):
                raise ValueError("Origin does not match destination authorization.")
            addresses = validated_addresses(answers)
        except (KeyError, TypeError, ValueError) as exc:
            raise httpx.TransportError(
                "Missing or invalid destination authorization.", request=request
            ) from exc
        authority = f"[{host}]" if ":" in host else host
        if request.url.port is not None:
            authority += f":{port}"
        if request.headers.get_list("host") != [authority]:
            raise httpx.TransportError(
                "Host header differs from the authorized origin.", request=request
            )

        pool = httpcore.ConnectionPool(
            ssl_context=self.ssl_context,
            max_connections=1,
            max_keepalive_connections=0,
            retries=0,
            network_backend=_PinnedBackend(host, port, addresses),
        )
        try:
            with _httpx_errors(request):
                response = pool.handle_request(
                    httpcore.Request(
                        method=request.method,
                        url=httpcore.URL(
                            scheme=scheme,
                            host=host,
                            port=request.url.port,
                            target=request.url.raw_path,
                        ),
                        headers=request.headers.raw,
                        content=request.stream,
                        extensions={"timeout": request.extensions.get("timeout", {})},
                    )
                )
            return httpx.Response(
                response.status,
                headers=response.headers,
                stream=_ResponseStream(response, pool, request),
                extensions=response.extensions,
            )
        except BaseException:
            pool.close()
            raise
