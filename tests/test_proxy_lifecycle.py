from __future__ import annotations

import asyncio

import anyio
import pytest

from mcp_auth_bridge.app import create_app
from mcp_auth_bridge.config import BridgeSettings
from mcp_auth_bridge.tokens import Principal


async def _disconnect_full_app(monkeypatch, *, stream_response: bool) -> None:
    received_upstream_request = asyncio.Event()
    upstream_closed = asyncio.Event()
    client_disconnect = asyncio.Event()
    request_body = (
        b'{"jsonrpc":"2.0","id":1,"method":"tools/list","params":'
        b'{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}'
    )

    async def upstream(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            headers = await reader.readuntil(b"\r\n\r\n")
            fields = [line.lower() for line in headers.split(b"\r\n")]
            length = next(
                int(line.split(b":", 1)[1].strip())
                for line in fields
                if line.startswith(b"content-length:")
            )
            await reader.readexactly(length)
            received_upstream_request.set()
            if stream_response:
                writer.write(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n"
                    b"Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
                    b"5\r\nfirst\r\n"
                )
                await writer.drain()
            await reader.read()
        finally:
            upstream_closed.set()
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass

    listener = await asyncio.start_server(upstream, "127.0.0.1", 0)
    port = listener.sockets[0].getsockname()[1]
    settings = BridgeSettings(
        public_resource="http://127.0.0.1:8080/mcp",
        issuer="http://127.0.0.1:8180/issuer",
        upstream=f"http://127.0.0.1:{port}/mcp",
        allow_insecure_loopback=True,
        max_concurrent_requests=1,
    )
    app = create_app(settings)
    runtime = app.state.bridge_runtime

    async def permit_test_token(*_args: object, **_kwargs: object) -> Principal:
        return Principal(
            issuer=settings.issuer,
            subject="test-subject",
            client_id="test-client",
            scopes=frozenset({"mcp:use"}),
        )

    monkeypatch.setattr("mcp_auth_bridge.app.validate_token", permit_test_token)
    sent_request = False
    messages: list[dict[str, object]] = []

    async def receive() -> dict[str, object]:
        nonlocal sent_request
        if not sent_request:
            sent_request = True
            return {"type": "http.request", "body": request_body, "more_body": False}
        await client_disconnect.wait()
        return {"type": "http.disconnect"}

    async def send(message: dict[str, object]) -> None:
        messages.append(message)
        if (
            stream_response
            and message.get("type") == "http.response.body"
            and message.get("body") == b"first"
        ):
            client_disconnect.set()

    scope: dict[str, object] = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.4"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/mcp",
        "raw_path": b"/mcp",
        "query_string": b"",
        "headers": [
            (b"authorization", b"Bearer safe-test-token"),
            (b"content-type", b"application/json"),
            (b"content-length", str(len(request_body)).encode("ascii")),
            (b"mcp-protocol-version", b"2026-07-28"),
            (b"mcp-method", b"tools/list"),
        ],
        "server": ("127.0.0.1", 8080),
        "client": ("127.0.0.1", 12345),
        "root_path": "",
    }
    app_task = asyncio.create_task(app(scope, receive, send))  # type: ignore[arg-type]
    try:
        await asyncio.wait_for(received_upstream_request.wait(), timeout=2)
        if not stream_response:
            client_disconnect.set()
        await asyncio.wait_for(app_task, timeout=2)
        await asyncio.wait_for(upstream_closed.wait(), timeout=2)
        response_starts = [item for item in messages if item["type"] == "http.response.start"]
        if stream_response:
            assert response_starts and response_starts[0]["status"] == 200
            assert any(item.get("body") == b"first" for item in messages)
        else:
            assert not response_starts
        runtime.semaphore.acquire_nowait()
        with pytest.raises(anyio.WouldBlock):
            runtime.semaphore.acquire_nowait()
        runtime.semaphore.release()
    finally:
        client_disconnect.set()
        if not app_task.done():
            app_task.cancel()
            await asyncio.gather(app_task, return_exceptions=True)
        listener.close()
        await listener.wait_closed()


@pytest.mark.asyncio
async def test_full_app_disconnect_while_waiting_for_upstream_headers_releases_once(
    monkeypatch,
) -> None:
    await _disconnect_full_app(monkeypatch, stream_response=False)


@pytest.mark.asyncio
async def test_full_app_disconnect_during_upstream_stream_releases_once(monkeypatch) -> None:
    await _disconnect_full_app(monkeypatch, stream_response=True)
