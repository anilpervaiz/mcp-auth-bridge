from __future__ import annotations

import json
import socket
import time
from types import SimpleNamespace

import httpx2
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from joserfc import jwk

from mcp_auth_bridge.config import (
    BridgeSettings,
    ConfigurationError,
    Policy,
    load_policy,
    origin_is_allowed,
)
from mcp_auth_bridge.discovery import authorization_server_metadata_url, oidc_metadata_url
from mcp_auth_bridge.egress import EgressError, resolve_vetted
from mcp_auth_bridge.protocol import ProtocolError, inspect_request
from mcp_auth_bridge.proxy import sanitized_request_headers, sanitized_response_headers
from mcp_auth_bridge.tokens import JwksCache


def local_settings(**kwargs):
    values = {
        "public_resource": "http://127.0.0.1:8080/mcp",
        "issuer": "http://127.0.0.1:8180/issuer",
        "upstream": "http://127.0.0.1:8000/mcp",
        "allow_insecure_loopback": True,
    }
    values.update(kwargs)
    return BridgeSettings(**values)


def test_resource_metadata_url_is_path_inserted_and_exact():
    settings = local_settings()
    assert settings.metadata_url == "http://127.0.0.1:8080/.well-known/oauth-protected-resource/mcp"
    assert settings.protected_resource_metadata()["resource"] == settings.public_resource


def test_authorization_server_discovery_urls():
    assert authorization_server_metadata_url("https://id.example/realm") == (
        "https://id.example/.well-known/oauth-authorization-server/realm"
    )
    assert oidc_metadata_url("https://id.example/realm") == (
        "https://id.example/realm/.well-known/openid-configuration"
    )


def test_insecure_urls_require_literal_loopback_opt_in():
    with pytest.raises(ConfigurationError):
        BridgeSettings("http://example.test/mcp", "https://id.test", "http://upstream/mcp")
    with pytest.raises(ConfigurationError):
        BridgeSettings(
            "http://example.test/mcp",
            "http://id.test",
            "http://upstream/mcp",
            allow_insecure_loopback=True,
        )
    with pytest.raises(ConfigurationError, match="port zero"):
        BridgeSettings(
            "https://resource.test:0/mcp", "https://id.test", "https://upstream.test/mcp"
        )


def test_origin_must_match_resource_origin():
    settings = local_settings()
    assert origin_is_allowed("http://127.0.0.1:8080", settings)
    assert origin_is_allowed("http://127.0.0.1:8080/", settings)
    assert not origin_is_allowed("null", settings)
    assert not origin_is_allowed("https://evil.example", settings)
    assert not origin_is_allowed("http://127.0.0.1:8080/path", settings)


def test_policy_requirements_accumulate():
    policy = Policy(
        global_scopes=frozenset({"mcp:use"}),
        method_scopes={"tools/call": frozenset({"mcp:execute"})},
        tool_scopes={"sensitive": frozenset({"mcp:admin"})},
    )
    assert policy.required_for("tools/call", "sensitive") == {"mcp:use", "mcp:execute", "mcp:admin"}
    with pytest.raises(TypeError):
        policy.method_scopes["tools/call"] = frozenset()


def test_yaml_policy_shape():
    from pathlib import Path

    policy = load_policy(Path(__file__).parents[1] / "examples/demo/policy.yaml")
    assert policy.required_for("tools/call", "sensitive_status") == {
        "mcp:use",
        "mcp:execute",
        "mcp:admin",
    }


def request_body(method="tools/call", name="naïve"):
    return json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": {
                "name": name,
                "_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28"},
            },
        }
    ).encode()


def test_modern_request_and_encoded_name_match():
    import base64

    encoded = base64.b64encode("naïve".encode()).decode()
    method, name, _ = inspect_request(
        request_body(), "2026-07-28", "tools/call", f"=?base64?{encoded}?="
    )
    assert (method, name) == ("tools/call", "naïve")


@pytest.mark.parametrize(
    "version,method,name",
    [
        ("2025-11-25", "tools/call", "naïve"),
        ("2026-07-28", "tools/list", "unexpected"),
        ("2026-07-28", "resources/read", None),
    ],
)
def test_protocol_disagreements_fail_closed(version, method, name):
    with pytest.raises(ProtocolError):
        inspect_request(request_body(), version, method, name)


def test_duplicate_json_keys_fail_closed():
    body = b'{"jsonrpc":"2.0","jsonrpc":"1.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}'
    with pytest.raises(ProtocolError, match="duplicate_json_field"):
        inspect_request(body, "2026-07-28", "tools/list", None)


def test_proxy_removes_client_identity_and_reconstructs_framing():
    headers = [
        (b"authorization", b"Bearer canary"),
        (b"cookie", b"canary=1"),
        (b"connection", b"keep-alive, x-secret"),
        (b"x-secret", b"canary"),
        (b"x-forwarded-for", b"198.51.100.8"),
        (b"x-mcp-auth-bridge-subject", b"spoof"),
        (b"x-authenticated-user", b"spoof"),
        (b"content-length", b"999"),
    ]
    sanitized = sanitized_request_headers(headers, 12)
    assert all(
        name
        not in {
            b"authorization",
            b"cookie",
            b"x-secret",
            b"x-forwarded-for",
            b"x-mcp-auth-bridge-subject",
            b"x-authenticated-user",
        }
        for name, _ in sanitized
    )
    assert [value for name, value in sanitized if name == b"content-length"] == [b"12"]
    response = sanitized_response_headers(
        [
            (b"location", b"https://evil.example"),
            (b"set-cookie", b"secret"),
            (b"mcp-session-id", b"legacy"),
        ]
    )
    assert response == []


@pytest.mark.asyncio
async def test_unexpected_request_failure_logs_no_credentials_or_spoofed_identity(
    monkeypatch, caplog
):
    from mcp_auth_bridge.app import create_app

    async def fail_validation(*_args, **_kwargs):
        raise RuntimeError("synthetic validation failure")

    monkeypatch.setattr("mcp_auth_bridge.app.validate_token", fail_validation)
    app = create_app(local_settings())
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {"_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28"}},
        }
    )
    canaries = (
        "AUTHORIZATION-CANARY",
        "COOKIE-CANARY",
        "SPOOFED-SUBJECT-CANARY",
        "FORWARDED-IP-CANARY",
    )

    async with httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app), base_url="http://bridge.test"
    ) as client:
        response = await client.post(
            "/mcp",
            content=body,
            headers={
                "Authorization": f"Bearer {canaries[0]}",
                "Cookie": f"session={canaries[1]}",
                "X-Mcp-Auth-Bridge-Subject": canaries[2],
                "X-Forwarded-For": canaries[3],
            },
        )

    assert response.status_code == 500
    assert "request failed request_id=" in caplog.text
    assert all(canary not in caplog.text for canary in canaries)


@pytest.mark.asyncio
async def test_issuer_dns_rejects_mixed_public_and_private_answers(monkeypatch):
    answers = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.1.1.1", 443)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443)),
    ]
    monkeypatch.setattr(
        "mcp_auth_bridge.egress.socket.getaddrinfo", lambda *_args, **_kwargs: answers
    )
    with pytest.raises(EgressError, match="forbidden network"):
        await resolve_vetted("issuer.example", 443, allow_loopback=False)


def _public_jwk(kid: str) -> dict[str, str | list[str]]:
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return jwk.import_key(
        pem, "RSA", parameters={"kid": kid, "alg": "RS256", "use": "sig"}
    ).as_dict()


@pytest.mark.asyncio
async def test_jwks_rotation_outage_stale_limit_and_unknown_kid_bound():
    class Fetcher:
        status = 200
        body = b""
        calls = 0

        async def get_json(self, _url: str) -> tuple[int, bytes]:
            self.calls += 1
            return self.status, self.body

    class Discovery:
        jwks_uri = "https://issuer.example/jwks"

        def __init__(self, fetcher: Fetcher) -> None:
            self.fetcher = fetcher

        async def load(self) -> dict[str, object]:
            return {"issuer": "https://issuer.example"}

    old_key = _public_jwk("old-key")
    new_key = _public_jwk("new-key")
    fetcher = Fetcher()
    fetcher.body = json.dumps({"keys": [old_key]}).encode()
    cache = JwksCache(
        SimpleNamespace(max_jwks_keys=32, algorithms=frozenset({"RS256", "ES256"})),
        Discovery(fetcher),
    )
    await cache.start()
    assert cache.ready
    assert (await cache.key_for("old-key", "RS256")) is not None

    fetcher.body = json.dumps({"keys": [old_key, new_key]}).encode()
    cache.last_attempt -= cache.REFRESH_COOLDOWN + 1
    assert (await cache.key_for("new-key", "RS256")) is not None
    assert len(cache.keys) == 2

    calls_before_flood = fetcher.calls
    for index in range(cache.NEGATIVE_MAX + 20):
        assert await cache.key_for(f"unknown-{index}", "RS256") is None
    assert len(cache.negative) == cache.NEGATIVE_MAX
    assert fetcher.calls == calls_before_flood

    fetcher.status = 503
    cache.loaded_at = time.monotonic() - cache.FRESH_SECONDS - 1
    cache.last_attempt = time.monotonic() - cache.REFRESH_COOLDOWN - 1
    assert await cache.refresh()
    assert (await cache.key_for("old-key", "RS256")) is not None

    cache.loaded_at = time.monotonic() - cache.FRESH_SECONDS - cache.STALE_SECONDS - 1
    cache.last_attempt = time.monotonic() - cache.REFRESH_COOLDOWN - 1
    assert not await cache.refresh()
    assert await cache.key_for("old-key", "RS256") is None
