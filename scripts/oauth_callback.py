"""Loopback OAuth callback handling for the isolated local demonstration client."""

from __future__ import annotations

import asyncio
from contextlib import AbstractAsyncContextManager
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from mcp.shared.auth import AuthorizationCodeResult
from typing_extensions import Self


class CallbackError(RuntimeError):
    """A callback could not safely provide one authorization result."""


class CallbackListener(AbstractAsyncContextManager["CallbackListener"]):
    """A bounded, one-result callback server bound only to the loopback interface."""

    def __init__(
        self,
        *,
        host: str = "127.0.0.1",
        port: int = 8765,
        path: str = "/callback",
        timeout_seconds: float = 180.0,
    ) -> None:
        if host != "127.0.0.1":
            raise ValueError("OAuth callback must bind to 127.0.0.1")
        if not 0 <= port <= 65535:
            raise ValueError("callback port is outside the valid range")
        if path != "/callback" or timeout_seconds <= 0:
            raise ValueError("invalid callback path or deadline")
        self.host = host
        self.port = port
        self.path = path
        self.timeout_seconds = timeout_seconds
        self._server: asyncio.Server | None = None
        self._result: asyncio.Future[AuthorizationCodeResult] | None = None
        self._callback_seen = False
        self._deadline: float | None = None
        self._writers: set[asyncio.StreamWriter] = set()
        self._tasks: set[asyncio.Task[Any]] = set()
        self.authorization_error: str | None = None

    async def __aenter__(self) -> Self:
        self._result = asyncio.get_running_loop().create_future()
        await self.arm()
        return self

    async def __aexit__(self, exc_type: object, exc: object, traceback: object) -> None:
        await self._close()
        if self._result is not None and not self._result.done():
            self._result.cancel()

    async def arm(self) -> None:
        """Start listening for exactly one upcoming OAuth redirect."""
        if self._server is not None:
            return
        loop = asyncio.get_running_loop()
        if self._result is None or self._result.done():
            self._result = loop.create_future()
        self._callback_seen = False
        self._deadline = loop.time() + self.timeout_seconds
        self.authorization_error = None
        self._server = await asyncio.start_server(
            self._serve_callback,
            self.host,
            self.port,
            limit=8192,
            start_serving=True,
        )
        if self.port == 0:
            self.port = self.bound_port

    async def _close(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        current = asyncio.current_task()
        tasks = [task for task in self._tasks if task is not current and not task.done()]
        for writer in tuple(self._writers):
            writer.close()
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        self._writers.clear()
        self._tasks.difference_update(tasks)

    @property
    def deadline(self) -> float:
        if self._deadline is None:
            raise RuntimeError("callback authorization attempt has not started")
        return self._deadline

    def _remaining(self) -> float:
        remaining = self.deadline - asyncio.get_running_loop().time()
        if remaining <= 0:
            raise TimeoutError("authorization attempt timed out")
        return remaining

    @property
    def bound_port(self) -> int:
        if self._server is None or not self._server.sockets:
            raise RuntimeError("callback listener has not started")
        address = self._server.sockets[0].getsockname()
        return int(address[1])

    async def result(self) -> AuthorizationCodeResult:
        if self._result is None:
            raise RuntimeError("callback listener has not started")
        current = self._result
        try:
            result = await asyncio.wait_for(asyncio.shield(current), timeout=self._remaining())
        except (TimeoutError, asyncio.TimeoutError) as exc:
            await self._close()
            raise CallbackError("browser sign-in timed out") from exc
        except BaseException:
            await self._close()
            raise
        await self._close()
        return result

    async def _readline(self, reader: asyncio.StreamReader) -> bytes:
        return await asyncio.wait_for(reader.readline(), timeout=self._remaining())

    async def _serve_callback(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        task = asyncio.current_task()
        self._writers.add(writer)
        if task is not None:
            self._tasks.add(task)
        status = b"400 Bad Request"
        response_body = b"Sign-in could not be completed. Return to the MCP client."
        result: AuthorizationCodeResult | None = None
        failure: CallbackError | None = None
        try:
            request_line = await self._readline(reader)
            if len(request_line) > 2048:
                raise CallbackError("callback request was too large")
            headers_size = 0
            while True:
                line = await self._readline(reader)
                headers_size += len(line)
                if headers_size > 4096:
                    raise CallbackError("callback headers were too large")
                if line in {b"\r\n", b"\n", b""}:
                    break
            parts = request_line.decode("ascii").rstrip("\r\n").split(" ")
            if len(parts) != 3 or parts[0] != "GET" or parts[2] != "HTTP/1.1":
                raise CallbackError("callback request was malformed")
            parsed = urlsplit(parts[1])
            if parsed.path != self.path or parsed.fragment or parsed.scheme or parsed.netloc:
                raise CallbackError("callback path was invalid")
            if self._callback_seen:
                raise CallbackError("callback was already used")
            self._callback_seen = True
            try:
                pairs = parse_qsl(
                    parsed.query,
                    keep_blank_values=True,
                    strict_parsing=True,
                    encoding="utf-8",
                    errors="strict",
                    max_num_fields=32,
                )
            except (UnicodeError, ValueError) as exc:
                raise CallbackError("callback parameters were malformed") from exc
            names = [name for name, _ in pairs]
            if len(names) != len(set(names)):
                raise CallbackError("callback parameters were duplicated")
            params = dict(pairs)
            if "error" in params:
                self.authorization_error = (
                    "invalid_target"
                    if params["error"] == "invalid_target"
                    else "authorization_error"
                )
                raise CallbackError("authorization server returned an error")
            if "code" not in params or not params["code"]:
                raise CallbackError("authorization code was missing")
            assert self._result is not None
            if self._result.done():
                raise CallbackError("callback listener is no longer waiting")
            result = AuthorizationCodeResult(
                code=params["code"],
                state=params.get("state"),
                iss=params.get("iss"),
            )
            status = b"200 OK"
            response_body = b"Sign-in complete. You can close this browser tab."
        except (
            UnicodeError,
            ValueError,
            asyncio.IncompleteReadError,
            TimeoutError,
            asyncio.TimeoutError,
            CallbackError,
        ) as exc:
            if isinstance(exc, CallbackError):
                failure = exc
            elif isinstance(exc, (TimeoutError, asyncio.TimeoutError)):
                failure = CallbackError("browser sign-in timed out")
            else:
                failure = CallbackError("callback was malformed")
        finally:
            try:
                writer.write(
                    b"HTTP/1.1 "
                    + status
                    + b"\r\nContent-Type: text/plain; charset=utf-8\r\n"
                    + b"Cache-Control: no-store\r\nConnection: close\r\nContent-Length: "
                    + str(len(response_body)).encode("ascii")
                    + b"\r\n\r\n"
                    + response_body
                )
                await writer.drain()
            except (ConnectionError, OSError, RuntimeError):
                pass
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except (ConnectionError, OSError, RuntimeError):
                    pass
                self._writers.discard(writer)
                if task is not None:
                    self._tasks.discard(task)
                if self._result is not None and not self._result.done():
                    if failure is not None:
                        self._result.set_exception(failure)
                    elif result is not None:
                        self._result.set_result(result)
