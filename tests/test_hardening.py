from __future__ import annotations

import asyncio
import base64
import json
import socket
import threading
import time
from types import SimpleNamespace

import anyio
import httpx2
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from joserfc import jwk
from starlette.requests import ClientDisconnect, Request

from mcp_auth_bridge.app import _challenge, create_app, create_ops_app
from mcp_auth_bridge.config import (
    BridgeSettings,
    ConfigurationError,
    Policy,
)
from mcp_auth_bridge.discovery import IssuerDiscovery
from mcp_auth_bridge.egress import EgressError, SafeFetcher, resolve_vetted
from mcp_auth_bridge.proxy import RequestPermit, proxy_request
from mcp_auth_bridge.scopes import parse_scope_value
from mcp_auth_bridge.strict_json import StrictJSONError, strict_loads
from mcp_auth_bridge.tokens import JwksCache, TokenError, parse_scopes, validate_token


def _settings(**changes: object) -> BridgeSettings:
    values: dict[str, object] = {
        "public_resource": "http://127.0.0.1:8080/mcp",
        "issuer": "http://127.0.0.1:8180/issuer",
        "upstream": "http://127.0.0.1:8000/mcp",
        "allow_insecure_loopback": True,
    }
    values.update(changes)
    return BridgeSettings(**values)  # type: ignore[arg-type]


def _public_jwk(kid: str) -> dict[str, str | list[str]]:
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return jwk.import_key(
        pem, "RSA", parameters={"kid": kid, "alg": "RS256", "use": "sig"}
    ).as_dict()


@pytest.mark.parametrize(
    "value",
    [
        '{"x":1,"x":2}',
        "NaN",
        "Infinity",
        "1e400",
        "{" * 65 + "0" + "}" * 65,
        b"\xff",
    ],
)
def test_strict_json_rejects_ambiguous_non_finite_or_deep_input(value: str | bytes) -> None:
    with pytest.raises(StrictJSONError):
        strict_loads(value)


@pytest.mark.parametrize(
    "value", ['bad"scope', "bad\\scope", "café", "a\u00a0b", "a\tb", " a", "a ", "a  b"]
)
def test_scope_grammar_rejects_header_injection_and_non_ascii_separators(value: str) -> None:
    with pytest.raises(ValueError):
        parse_scope_value(value)
    with pytest.raises(ValueError):
        parse_scopes({"scope": value})


def test_scope_grammar_and_initial_challenge_are_unambiguous() -> None:
    assert parse_scope_value("mcp:use mcp:execute") == frozenset({"mcp:use", "mcp:execute"})
    with pytest.raises(ConfigurationError):
        Policy(global_scopes=frozenset({'mcp:use",error="invalid_token'}))
    challenge = _challenge(_settings())
    assert 'scope="mcp:use"' in challenge
    assert "mcp:admin" not in challenge


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "header,payload",
    [
        ('{"alg":"RS256","alg":"RS256"}', "{}"),
        ("[]", "{}"),
        ('{"alg":"RS256"}', '{"iss":"a","iss":"b"}'),
        ('{"alg":"RS256"}', '{"exp":NaN}'),
        ('{"alg":"RS256"}', "{" * 65 + "0" + "}" * 65),
    ],
)
async def test_malformed_compact_jwt_is_a_token_error(header: str, payload: str) -> None:
    encode = lambda part: base64.urlsafe_b64encode(part.encode()).rstrip(b"=").decode()
    token = f"{encode(header)}.{encode(payload)}.AA"
    with pytest.raises(TokenError):
        await validate_token(token, _settings(), SimpleNamespace())


@pytest.mark.asyncio
async def test_cache_readiness_expires_without_traffic_even_during_cooldown(monkeypatch) -> None:
    instant = [100.0]
    monkeypatch.setattr("mcp_auth_bridge.tokens.time.monotonic", lambda: instant[0])
    cache = JwksCache(SimpleNamespace(), SimpleNamespace())
    cache.keys = [{"kid": "trusted"}]
    cache.loaded_at = 100.0
    cache.last_attempt = 99.0
    cache._ready = True
    assert cache.ready
    instant[0] += cache.FRESH_SECONDS + cache.STALE_SECONDS - 0.01
    assert cache.ready
    instant[0] += 0.01
    assert not cache.ready
    cache.last_attempt = instant[0] - 1
    assert not await cache.refresh()


@pytest.mark.asyncio
async def test_jwks_duplicate_members_keep_cache_unready() -> None:
    class Fetcher:
        async def get_json(self, _url: str) -> tuple[int, bytes]:
            return 200, b'{"keys":[],"keys":[]}'

    class Discovery:
        jwks_uri = "https://issuer.example/jwks"
        fetcher = Fetcher()

        async def load(self) -> None:
            return None

    cache = JwksCache(
        SimpleNamespace(max_jwks_keys=32, algorithms=frozenset({"RS256", "ES256"})),
        Discovery(),
    )
    assert not await cache.refresh(force=True)
    assert not cache.ready


@pytest.mark.asyncio
async def test_jwks_with_no_configured_signing_algorithm_leaves_app_unready(monkeypatch) -> None:
    rsa_private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rsa_pem = rsa_private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    rsa_key = jwk.import_key(
        rsa_pem, "RSA", parameters={"kid": "wrong-rsa", "alg": "ES256", "use": "sig"}
    ).as_dict()

    ec_private = ec.generate_private_key(ec.SECP256R1())
    ec_pem = ec_private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    ec_key = jwk.import_key(
        ec_pem, "EC", parameters={"kid": "wrong-ec", "alg": "RS256", "use": "sig"}
    ).as_dict()

    class Fetcher:
        async def get_json(self, _url: str) -> tuple[int, bytes]:
            return 200, json.dumps({"keys": [rsa_key, ec_key]}).encode()

    class Discovery:
        jwks_uri = "https://issuer.example/jwks"
        fetcher = Fetcher()

        async def load(self) -> None:
            return None

    settings = _settings()
    cache = JwksCache(settings, Discovery())
    assert not await cache.refresh(force=True)
    assert not cache.ready

    app = create_app(settings)
    app.state.bridge_runtime.keys = cache
    app.state.bridge_runtime.started = True
    operations = create_ops_app(app)

    async def unavailable(*_args: object, **_kwargs: object) -> None:
        from mcp_auth_bridge.tokens import TrustUnavailable

        raise TrustUnavailable()

    monkeypatch.setattr("mcp_auth_bridge.app.validate_token", unavailable)
    async with httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=operations), base_url="http://ops.test"
    ) as client:
        assert (await client.get("/readyz")).status_code == 503
    async with httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app), base_url="http://bridge.test"
    ) as client:
        response = await client.post(
            "/mcp", headers={"Authorization": "Bearer invalid"}, content=b"{}"
        )
        assert response.status_code == 503


@pytest.mark.asyncio
async def test_dns_deadline_does_not_release_capacity_until_lookup_finishes(monkeypatch) -> None:
    entered = threading.Event()
    release = threading.Event()
    finished = threading.Event()

    def blocked_lookup(*_args: object, **_kwargs: object) -> list[tuple[object, ...]]:
        entered.set()
        release.wait(2)
        finished.set()
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 8180))]

    monkeypatch.setattr("mcp_auth_bridge.egress.socket.getaddrinfo", blocked_lookup)
    with pytest.raises(EgressError, match="timed out"):
        await resolve_vetted("localhost", 8180, allow_loopback=True, timeout=0.01)
    assert entered.is_set()
    release.set()
    assert await asyncio.to_thread(finished.wait, 1)


@pytest.mark.asyncio
async def test_two_timed_out_dns_lookups_hold_both_slots_until_completion(monkeypatch) -> None:
    lock = threading.Lock()
    release = threading.Event()
    both_started = threading.Event()
    finished = 0

    def blocked_lookup(*_args: object, **_kwargs: object) -> list[tuple[object, ...]]:
        nonlocal finished
        with lock:
            if len(started) < 2:
                started.append(True)
                if len(started) == 2:
                    both_started.set()
        release.wait(2)
        with lock:
            finished += 1
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 8180))]

    started: list[bool] = []
    monkeypatch.setattr("mcp_auth_bridge.egress.socket.getaddrinfo", blocked_lookup)
    first = asyncio.create_task(resolve_vetted("slow-a.invalid", 8180, True, timeout=0.02))
    second = asyncio.create_task(resolve_vetted("slow-b.invalid", 8180, True, timeout=0.02))
    assert await asyncio.to_thread(both_started.wait, 1)
    first_result, second_result = await asyncio.gather(first, second, return_exceptions=True)
    assert isinstance(first_result, EgressError)
    assert isinstance(second_result, EgressError)
    with pytest.raises(EgressError, match="capacity is exhausted"):
        await resolve_vetted("third.invalid", 8180, True, timeout=0.02)

    release.set()
    assert await asyncio.to_thread(_wait_for_count, lock, lambda: finished, 2)
    assert await resolve_vetted("recovered.invalid", 8180, True, timeout=1) == ["127.0.0.1"]


def _wait_for_count(lock: threading.Lock, read_count, wanted: int) -> bool:
    import time

    deadline = time.monotonic() + 1
    while time.monotonic() < deadline:
        with lock:
            if read_count() >= wanted:
                return True
        time.sleep(0.005)
    return False


@pytest.mark.asyncio
async def test_total_fetch_deadline_covers_dns(monkeypatch) -> None:
    async def slow_resolve(*_args: object, **_kwargs: object) -> list[str]:
        await asyncio.sleep(1)
        return ["127.0.0.1"]

    monkeypatch.setattr("mcp_auth_bridge.egress.resolve_vetted", slow_resolve)
    fetcher = SafeFetcher(1024, allow_loopback=True, fetch_timeout=0.01, dns_timeout=1)
    with pytest.raises(EgressError, match="time limit"):
        await fetcher.get_json("http://localhost:8180/metadata")


@pytest.mark.asyncio
async def test_http_trickle_download_hits_total_fetch_deadline(monkeypatch) -> None:
    closed = asyncio.Event()

    async def trickle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            await reader.readuntil(b"\r\n\r\n")
            writer.write(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                b"Content-Length: 200\r\nConnection: close\r\n\r\n"
            )
            await writer.drain()
            for _ in range(20):
                writer.write(b"{")
                await writer.drain()
                await asyncio.sleep(0.025)
        except (ConnectionError, OSError):
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass
            closed.set()

    listener = await asyncio.start_server(trickle, "127.0.0.1", 0)
    port = int(listener.sockets[0].getsockname()[1])

    async def loopback(_host: str, _port: int, _allow_loopback: bool, _timeout: float) -> list[str]:
        return ["127.0.0.1"]

    monkeypatch.setattr("mcp_auth_bridge.egress.resolve_vetted", loopback)
    fetcher = SafeFetcher(1024, allow_loopback=True, fetch_timeout=0.09, dns_timeout=0.5)
    try:
        with pytest.raises(EgressError, match="time limit"):
            await fetcher.get_json(f"http://localhost:{port}/metadata")
        assert await asyncio.wait_for(closed.wait(), timeout=1)
    finally:
        listener.close()
        await listener.wait_closed()


@pytest.mark.asyncio
async def test_actual_http_issuer_jwks_rotation_outage_and_stale_readiness(monkeypatch) -> None:
    state: dict[str, object] = {
        "jwks_status": 200,
        "jwks_body": b"",
        "jwks_calls": 0,
    }

    async def issuer(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            request = await reader.readuntil(b"\r\n\r\n")
            target = request.split(b" ", 2)[1].decode("ascii")
            if target.startswith("/.well-known/oauth-authorization-server/issuer"):
                body = json.dumps(
                    {
                        "issuer": configured_issuer,
                        "jwks_uri": f"http://localhost:{port}/jwks",
                    }
                ).encode()
                status = 200
            elif target == "/jwks":
                state["jwks_calls"] = int(state["jwks_calls"]) + 1
                body = state["jwks_body"]  # type: ignore[assignment]
                status = int(state["jwks_status"])
            else:
                body = b"{}"
                status = 404
            reason = b"OK" if status == 200 else b"Service Unavailable"
            writer.write(
                b"HTTP/1.1 "
                + str(status).encode("ascii")
                + b" "
                + reason
                + b"\r\nContent-Type: application/json\r\nContent-Length: "
                + str(len(body)).encode("ascii")
                + b"\r\nConnection: close\r\n\r\n"
                + body
            )
            await writer.drain()
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass

    listener = await asyncio.start_server(issuer, "127.0.0.1", 0)
    port = int(listener.sockets[0].getsockname()[1])
    configured_issuer = f"http://localhost:{port}/issuer"
    first_key = _public_jwk("old-key")
    second_key = _public_jwk("new-key")
    state["jwks_body"] = json.dumps({"keys": [first_key]}).encode()

    async def loopback(_host: str, _port: int, _allow_loopback: bool, _timeout: float) -> list[str]:
        return ["127.0.0.1"]

    monkeypatch.setattr("mcp_auth_bridge.egress.resolve_vetted", loopback)
    settings = _settings(issuer=configured_issuer)
    discovery = IssuerDiscovery(settings)
    cache = JwksCache(settings, discovery)
    try:
        await cache.start()
        assert cache.ready
        assert await cache.key_for("old-key", "RS256") is not None

        state["jwks_body"] = json.dumps({"keys": [first_key, second_key]}).encode()
        cache.last_attempt = time.monotonic() - cache.REFRESH_COOLDOWN - 1
        assert await cache.key_for("new-key", "RS256") is not None
        assert {item["kid"] for item in cache.keys} == {"old-key", "new-key"}

        calls_before_flood = int(state["jwks_calls"])
        for index in range(cache.NEGATIVE_MAX + 20):
            assert await cache.key_for(f"missing-{index}", "RS256") is None
        assert len(cache.negative) == cache.NEGATIVE_MAX
        assert int(state["jwks_calls"]) == calls_before_flood

        state["jwks_status"] = 503
        cache.loaded_at = time.monotonic() - cache.FRESH_SECONDS - 1
        cache.last_attempt = time.monotonic() - cache.REFRESH_COOLDOWN - 1
        assert await cache.refresh()
        assert cache.ready

        cache.loaded_at = time.monotonic() - cache.FRESH_SECONDS - cache.STALE_SECONDS - 1
        cache.last_attempt = time.monotonic()
        assert not cache.ready
        assert not await cache.refresh()
    finally:
        listener.close()
        await listener.wait_closed()


@pytest.mark.asyncio
@pytest.mark.parametrize("failing_message", ["http.response.start", "http.response.body"])
async def test_proxy_response_failure_closes_resources_and_releases_once(
    monkeypatch, failing_message: str
) -> None:
    class Upstream:
        status = 200

        def __init__(self) -> None:
            self.closed = 0
            self.headers = [(b"content-type", b"text/event-stream")]

        @property
        def stream(self):
            async def values():
                yield b"first chunk"

            return values()

        async def aclose(self) -> None:
            self.closed += 1

    upstream = Upstream()

    class Pool:
        def __init__(self, **_kwargs: object) -> None:
            self.closed = 0

        async def handle_async_request(self, _request: object) -> Upstream:
            return upstream

        async def aclose(self) -> None:
            self.closed += 1

    pool = Pool()
    monkeypatch.setattr("mcp_auth_bridge.proxy.httpcore.AsyncConnectionPool", lambda **_: pool)

    async def receive() -> dict[str, object]:
        return {"type": "http.request", "body": b"", "more_body": False}

    scope: dict[str, object] = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.4"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/mcp",
        "raw_path": b"/mcp",
        "query_string": b"",
        "headers": [],
        "server": ("127.0.0.1", 8080),
        "client": ("127.0.0.1", 12345),
        "root_path": "",
    }
    request = Request(scope, receive)  # type: ignore[arg-type]
    semaphore = anyio.Semaphore(1)
    semaphore.acquire_nowait()
    response = proxy_request(request, b"{}", _settings(), RequestPermit(semaphore), "request-id")

    async def send(message: dict[str, object]) -> None:
        if message["type"] == failing_message:
            raise OSError("simulated client disconnect")

    with pytest.raises(ClientDisconnect):
        await response(scope, receive, send)  # type: ignore[arg-type]
    assert upstream.closed == 1
    assert pool.closed == 1
    semaphore.acquire_nowait()
    with pytest.raises(anyio.WouldBlock):
        semaphore.acquire_nowait()
