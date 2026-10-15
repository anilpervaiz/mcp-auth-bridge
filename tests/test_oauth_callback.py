from __future__ import annotations

import asyncio
from urllib.parse import parse_qs, urlsplit

import pytest
from mcp.client.auth import OAuthClientProvider, OAuthFlowError
from mcp.shared.auth import (
    AuthorizationCodeResult,
    OAuthClientInformationFull,
    OAuthClientMetadata,
    OAuthMetadata,
)

from scripts.oauth_callback import CallbackError, CallbackListener


async def _send_callback(port: int, target: str) -> int:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(
        f"GET {target} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n".encode()
    )
    await writer.drain()
    response = await reader.read()
    writer.close()
    await writer.wait_closed()
    return int(response.split(b" ", 2)[1])


@pytest.mark.asyncio
async def test_callback_preserves_decoded_values_for_sdk() -> None:
    async with CallbackListener(port=0) as callback:
        status = await _send_callback(
            callback.bound_port,
            "/callback?code=code%2Bvalue&state=state%3Dvalue&iss=http%3A%2F%2F127.0.0.1%3A8180%2Frealms%2Fmab-demo",
        )
        result = await callback.result()
    assert status == 200
    assert result == AuthorizationCodeResult(
        code="code+value",
        state="state=value",
        iss="http://127.0.0.1:8180/realms/mab-demo",
    )


@pytest.mark.asyncio
async def test_callback_listener_supports_scope_step_up_on_same_loopback_port() -> None:
    async with CallbackListener(port=0) as callback:
        port = callback.bound_port
        first_status = await _send_callback(port, "/callback?code=first&state=one")
        first = await callback.result()
        assert callback._server is None
        await callback.arm()
        second_status = await _send_callback(port, "/callback?code=second&state=two")
        second = await callback.result()
    assert first_status == second_status == 200
    assert (first.code, first.state) == ("first", "one")
    assert (second.code, second.state) == ("second", "two")


@pytest.mark.asyncio
async def test_callback_rejects_duplicate_parameters() -> None:
    async with CallbackListener(port=0) as callback:
        status = await _send_callback(
            callback.bound_port, "/callback?code=one&code=two&state=state"
        )
        with pytest.raises(CallbackError, match="duplicated"):
            await callback.result()
    assert status == 400


@pytest.mark.asyncio
async def test_callback_cancellation_is_safe_and_does_not_echo_error() -> None:
    async with CallbackListener(port=0) as callback:
        status = await _send_callback(
            callback.bound_port, "/callback?error=access_denied&state=private-state"
        )
        with pytest.raises(CallbackError, match="authorization server returned an error"):
            await callback.result()
    assert status == 400


@pytest.mark.asyncio
async def test_callback_timeout_is_bounded_and_listener_closes() -> None:
    listener = CallbackListener(port=0, timeout_seconds=0.01)
    async with listener as callback:
        port = callback.bound_port
        with pytest.raises(CallbackError, match="timed out"):
            await callback.result()
    with pytest.raises(OSError):
        await asyncio.open_connection("127.0.0.1", port)


@pytest.mark.asyncio
async def test_slow_callback_connection_cannot_extend_attempt_deadline() -> None:
    listener = CallbackListener(port=0, timeout_seconds=0.05)
    async with listener as callback:
        port = callback.bound_port
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"GET /callback?code=partial")
        await writer.drain()
        with pytest.raises(CallbackError, match="timed out"):
            await callback.result()
        assert callback._server is None
        assert not callback._tasks
        writer.close()
        await writer.wait_closed()
        await reader.read()


@pytest.mark.asyncio
async def test_callback_cancellation_closes_listener() -> None:
    async with CallbackListener(port=0) as callback:
        port = callback.bound_port
        wait_for_callback = asyncio.create_task(callback.result())
        await asyncio.sleep(0)
        wait_for_callback.cancel()
        with pytest.raises(asyncio.CancelledError):
            await wait_for_callback
        assert callback._server is None
    with pytest.raises(OSError):
        await asyncio.open_connection("127.0.0.1", port)


def _provider(result: AuthorizationCodeResult) -> OAuthClientProvider:
    async def redirect(_: str) -> None:
        return None

    async def callback() -> AuthorizationCodeResult:
        return result

    provider = OAuthClientProvider(
        server_url="http://127.0.0.1:8080/mcp",
        client_metadata=OAuthClientMetadata(
            redirect_uris=["http://127.0.0.1:8765/callback"], scope="mcp:use"
        ),
        storage=_MemoryStorage(),
        redirect_handler=redirect,
        callback_handler=callback,
    )
    provider.context.client_info = OAuthClientInformationFull(
        client_id="mab-sdk-client",
        redirect_uris=["http://127.0.0.1:8765/callback"],
        token_endpoint_auth_method="none",
        issuer="http://127.0.0.1:8180/realms/mab-demo",
    )
    provider.context.oauth_metadata = OAuthMetadata(
        issuer="http://127.0.0.1:8180/realms/mab-demo",
        authorization_endpoint="http://127.0.0.1:8180/realms/mab-demo/protocol/openid-connect/auth",
        token_endpoint="http://127.0.0.1:8180/realms/mab-demo/protocol/openid-connect/token",
        authorization_response_iss_parameter_supported=True,
    )
    return provider


class _MemoryStorage:
    async def get_tokens(self) -> None:
        return None

    async def set_tokens(self, tokens: object) -> None:
        return None

    async def get_client_info(self) -> None:
        return None

    async def set_client_info(self, client_info: object) -> None:
        return None


@pytest.mark.asyncio
async def test_official_sdk_rejects_wrong_callback_state() -> None:
    provider = _provider(
        AuthorizationCodeResult(
            code="disposable", state="wrong-state", iss="http://127.0.0.1:8180/realms/mab-demo"
        )
    )
    with pytest.raises(OAuthFlowError, match="State parameter mismatch"):
        await provider._perform_authorization_code_grant()


@pytest.mark.asyncio
async def test_official_sdk_checks_callback_issuer_after_correct_state() -> None:
    async def redirect(url: str) -> None:
        state = parse_qs(urlsplit(url).query)["state"][0]

        async def callback() -> AuthorizationCodeResult:
            return AuthorizationCodeResult(
                code="disposable", state=state, iss="http://evil.invalid"
            )

        provider.context.callback_handler = callback

    provider = _provider(AuthorizationCodeResult(code="unused", state=None, iss=None))
    provider.context.redirect_handler = redirect
    with pytest.raises(OAuthFlowError, match="Authorization response iss mismatch"):
        await provider._perform_authorization_code_grant()
