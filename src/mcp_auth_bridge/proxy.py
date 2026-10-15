"""Single-upstream streaming proxy with a centralized header boundary."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterable, AsyncIterator
from urllib.parse import urlsplit

import anyio
import anyio.lowlevel
import httpcore
from starlette.requests import ClientDisconnect, Request
from starlette.responses import Response
from starlette.types import Receive, Scope, Send

from .config import BridgeSettings

_ALWAYS_REMOVE = {
    b"authorization",
    b"proxy-authorization",
    b"cookie",
    b"set-cookie",
    b"forwarded",
    b"host",
    b"connection",
    b"keep-alive",
    b"proxy-authenticate",
    b"content-length",
    b"te",
    b"trailer",
    b"transfer-encoding",
    b"upgrade",
    b"origin",
    b"referer",
    b"www-authenticate",
    b"authentication-info",
    b"proxy-authentication-info",
    b"location",
    b"refresh",
    b"access-control-allow-origin",
    b"access-control-allow-credentials",
    b"access-control-allow-headers",
    b"access-control-allow-methods",
    b"access-control-expose-headers",
    b"access-control-max-age",
    b"mcp-session-id",
    b"last-event-id",
}


class RequestPermit:
    """An idempotent lease for one active protected request."""

    def __init__(self, semaphore: anyio.Semaphore) -> None:
        self._semaphore = semaphore
        self._released = False

    def release(self) -> None:
        if not self._released:
            self._released = True
            self._semaphore.release()


class _ManagedProxyResponse(Response):
    """Own the upstream exchange, client disconnect watcher, and request permit."""

    def __init__(
        self,
        request: Request,
        body: bytes,
        settings: BridgeSettings,
        permit: RequestPermit,
        request_id: str,
    ) -> None:
        super().__init__(content=b"")
        self.request = request
        self.body = body
        self.settings = settings
        self.permit = permit
        self.request_id = request_id

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        pool: httpcore.AsyncConnectionPool | None = None
        upstream: httpcore.Response | None = None
        client_disconnected = anyio.Event()

        async def close_upstream() -> None:
            if upstream is not None:
                try:
                    await upstream.aclose()
                except Exception as exc:  # noqa: BLE001 - cleanup must continue to the pool
                    del exc
            if pool is not None:
                try:
                    await pool.aclose()
                except Exception as exc:  # noqa: BLE001 - cleanup must still release the permit
                    del exc

        async def watch_disconnect() -> None:
            while True:
                try:
                    message = await receive()
                except OSError:
                    client_disconnected.set()
                    return
                if message["type"] == "http.disconnect":
                    client_disconnected.set()
                    return
                # The bounded body has already been completely consumed. This can only be
                # a redundant ASGI request event; it does not contain data for the proxy.
                await anyio.lowlevel.checkpoint()

        async def send_to_client(message: dict[str, object]) -> None:
            try:
                await send(message)
            except OSError:
                raise ClientDisconnect() from None

        async def send_failure(status: int, message: bytes) -> None:
            await send_to_client(
                {
                    "type": "http.response.start",
                    "status": status,
                    "headers": [
                        (b"content-type", b"text/plain; charset=utf-8"),
                        (b"content-length", str(len(message)).encode("ascii")),
                        (b"cache-control", b"no-store"),
                        (b"x-request-id", self.request_id.encode("ascii")),
                    ],
                }
            )

            await send_to_client(
                {"type": "http.response.body", "body": message, "more_body": False}
            )

        async def exchange() -> None:
            nonlocal pool, upstream
            p = urlsplit(self.settings.upstream)
            path = p.path or "/"
            target = f"{p.scheme}://{p.netloc}{path}"
            pool = httpcore.AsyncConnectionPool(
                max_connections=1,
                max_keepalive_connections=0,
                retries=0,
            )
            upstream_headers = sanitized_request_headers(
                list(self.request.headers.raw), len(self.body)
            )
            host = p.hostname
            if host is None:
                raise ValueError("configured upstream URL has no host")
            host_header = f"[{host}]" if ":" in host else host.encode("idna").decode("ascii")
            port = p.port
            default_port = 443 if p.scheme == "https" else 80
            if port is not None and port != default_port:
                host_header += f":{port}"
            upstream_headers.append((b"host", host_header.encode("ascii")))
            try:
                upstream = await pool.handle_async_request(
                    httpcore.Request(
                        method=self.request.method,
                        url=target,
                        headers=upstream_headers,
                        content=bytes(self.body),
                        extensions={
                            "timeout": {
                                "connect": self.settings.connect_timeout,
                                "read": self.settings.upstream_read_timeout,
                                "write": 10.0,
                                "pool": 1.0,
                            }
                        },
                    )
                )
            except (
                httpcore.NetworkError,
                httpcore.ProtocolError,
                httpcore.TimeoutException,
                OSError,
                TimeoutError,
            ):
                if not client_disconnected.is_set():
                    await send_failure(502, b"upstream unavailable")
                return
            if 300 <= upstream.status < 400:
                await close_upstream()
                upstream = None
                pool = None
                await send_failure(502, b"upstream redirects are disabled")
                return

            response_headers = sanitized_response_headers(list(upstream.headers))
            response_headers.append((b"x-request-id", self.request_id.encode("ascii")))
            await send_to_client(
                {
                    "type": "http.response.start",
                    "status": upstream.status,
                    "headers": response_headers,
                }
            )
            stream = upstream.stream
            assert isinstance(stream, AsyncIterable)
            iterator: AsyncIterator[bytes] = stream.__aiter__()
            while not client_disconnected.is_set():
                try:
                    chunk = await iterator.__anext__()
                except StopAsyncIteration:
                    break
                except (
                    httpcore.NetworkError,
                    httpcore.ProtocolError,
                    httpcore.TimeoutException,
                    OSError,
                    TimeoutError,
                ):
                    break
                await send_to_client(
                    {"type": "http.response.body", "body": chunk, "more_body": True}
                )
            if not client_disconnected.is_set():
                await send_to_client(
                    {"type": "http.response.body", "body": b"", "more_body": False}
                )

        disconnect_task = asyncio.create_task(watch_disconnect())
        exchange_task = asyncio.create_task(exchange())
        try:
            completed, _ = await asyncio.wait(
                {disconnect_task, exchange_task}, return_when=asyncio.FIRST_COMPLETED
            )
            if disconnect_task in completed:
                await disconnect_task
                exchange_task.cancel()
            else:
                await exchange_task
        finally:
            with anyio.CancelScope(shield=True):
                disconnect_task.cancel()
                exchange_task.cancel()
                await asyncio.gather(disconnect_task, exchange_task, return_exceptions=True)
                try:
                    await close_upstream()
                finally:
                    self.permit.release()


def _drop_header(name: bytes, nominated: set[bytes]) -> bool:
    lower = name.lower()
    return (
        lower in _ALWAYS_REMOVE
        or lower in nominated
        or lower.startswith(
            (b"x-forwarded-", b"x-mcp-auth-bridge-", b"x-authenticated-", b"x-auth-request-")
        )
        or lower in {b"x-authenticated-user", b"x-remote-user", b"remote-user"}
    )


def sanitized_request_headers(
    raw: list[tuple[bytes, bytes]], body_size: int
) -> list[tuple[bytes, bytes]]:
    nominated: set[bytes] = set()
    for name, value in raw:
        if name.lower() == b"connection":
            nominated.update(token.strip().lower() for token in value.split(b","))
    allowed = {
        b"accept",
        b"accept-encoding",
        b"content-type",
        b"cache-control",
        b"mcp-protocol-version",
        b"mcp-method",
        b"mcp-name",
    }
    headers = [
        (name, value)
        for name, value in raw
        if not _drop_header(name, nominated)
        and (name.lower() in allowed or name.lower().startswith(b"mcp-param-"))
    ]
    headers.append((b"content-length", str(body_size).encode("ascii")))
    return headers


def sanitized_response_headers(raw: list[tuple[bytes, bytes]]) -> list[tuple[bytes, bytes]]:
    nominated: set[bytes] = set()
    for name, value in raw:
        if name.lower() == b"connection":
            nominated.update(token.strip().lower() for token in value.split(b","))
    return [(name, value) for name, value in raw if not _drop_header(name, nominated)]


async def read_bounded_body(request: Request, settings: BridgeSettings) -> bytes:
    announced_values = [
        value for name, value in request.headers.raw if name.lower() == b"content-length"
    ]
    transfer_encoding = any(name.lower() == b"transfer-encoding" for name, _ in request.headers.raw)
    if len(announced_values) > 1 or (announced_values and transfer_encoding):
        from .protocol import ProtocolError

        raise ProtocolError(400, "ambiguous_request_framing")
    if announced_values:
        try:
            length = int(announced_values[0])
        except ValueError as exc:
            from .protocol import ProtocolError

            raise ProtocolError(400, "invalid_content_length") from exc
        if length < 0:
            from .protocol import ProtocolError

            raise ProtocolError(400, "invalid_content_length")
        if length > settings.max_body_bytes:
            from .protocol import ProtocolError

            raise ProtocolError(413, "request_body_too_large")
    chunks: list[bytes] = []
    size = 0
    try:
        with anyio.fail_after(settings.body_timeout):
            async for chunk in request.stream():
                size += len(chunk)
                if size > settings.max_body_bytes:
                    from .protocol import ProtocolError

                    raise ProtocolError(413, "request_body_too_large")
                chunks.append(chunk)
    except TimeoutError as exc:
        from .protocol import ProtocolError

        raise ProtocolError(408, "request_body_timeout") from exc
    return b"".join(chunks)


def proxy_request(
    request: Request,
    body: bytes,
    settings: BridgeSettings,
    permit: RequestPermit,
    request_id: str,
) -> Response:
    return _ManagedProxyResponse(request, body, settings, permit, request_id)
