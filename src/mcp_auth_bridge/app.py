"""Public protected-resource and private operations ASGI applications."""

from __future__ import annotations

import logging
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from urllib.parse import urlsplit

import anyio
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.requests import ClientDisconnect, Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route
from starlette.types import ASGIApp, Receive, Scope, Send

from .config import BridgeSettings, origin_is_allowed
from .discovery import IssuerDiscovery
from .protocol import ProtocolError, inspect_request
from .proxy import RequestPermit, proxy_request, read_bounded_body
from .tokens import JwksCache, TokenError, TrustUnavailable, validate_token

logger = logging.getLogger("mcp_auth_bridge")


class ProtectedResourceMiddleware:
    """Pure ASGI boundary for the exact configured MCP resource path."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        resource_path: str,
        handler: Callable[[Request], Awaitable[Response]],
    ) -> None:
        self.app = app
        self.resource_path = resource_path
        self.handler = handler

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http" and scope.get("path") == self.resource_path:
            request = Request(scope, receive)
            response = await self.handler(request)
            await response(scope, receive, send)
            return
        await self.app(scope, receive, send)


class BridgeRuntime:
    def __init__(self, settings: BridgeSettings) -> None:
        self.settings = settings
        self.discovery = IssuerDiscovery(settings)
        self.keys = JwksCache(settings, self.discovery)
        self.semaphore = anyio.Semaphore(settings.max_concurrent_requests)
        self.started = False

    async def start(self) -> None:
        await self.keys.start()
        self.started = True


def _challenge(
    settings: BridgeSettings, *, invalid: bool = False, insufficient: frozenset[str] | None = None
) -> str:
    if insufficient:
        return f'Bearer error="insufficient_scope", scope="{" ".join(sorted(insufficient))}"'
    metadata = settings.metadata_url.replace("\\", "\\\\").replace('"', '\\"')
    fields = []
    if settings.policy.global_scopes:
        fields.append(f'scope="{" ".join(sorted(settings.policy.global_scopes))}"')
    if invalid:
        fields.append('error="invalid_token"')
    fields.append(f'resource_metadata="{metadata}"')
    return "Bearer " + ", ".join(fields)


def _error(
    status: int,
    reason: str,
    request_id: str,
    challenge: str | None = None,
    retry_after: str | None = None,
) -> Response:
    headers = {"Cache-Control": "no-store", "X-Request-ID": request_id}
    if challenge:
        headers["WWW-Authenticate"] = challenge
    if retry_after:
        headers["Retry-After"] = retry_after
    return JSONResponse(
        {"error": reason, "request_id": request_id}, status_code=status, headers=headers
    )


def _bearer(request: Request, max_bytes: int) -> tuple[str | None, str | None]:
    values = [value for name, value in request.headers.raw if name.lower() == b"authorization"]
    if not values:
        return None, None
    if len(values) != 1:
        return None, "invalid_request"
    try:
        text = values[0].decode("ascii")
    except UnicodeDecodeError:
        return None, "invalid_request"
    parts = text.split()
    if len(parts) != 2:
        return None, "invalid_request"
    if parts[0].casefold() != "bearer" or len(parts[1]) > max_bytes:
        return None, "invalid_request"
    return parts[1], None


def _one_header(request: Request, key: bytes) -> str | None:
    values = [value for name, value in request.headers.raw if name.lower() == key.lower()]
    if len(values) > 1:
        raise ProtocolError(400, "duplicate_protocol_header")
    try:
        return values[0].decode("ascii") if values else None
    except UnicodeDecodeError as exc:
        raise ProtocolError(400, "invalid_protocol_header") from exc


def create_app(settings: BridgeSettings) -> Starlette:
    runtime = BridgeRuntime(settings)

    @asynccontextmanager
    async def lifespan(app: Starlette) -> AsyncIterator[None]:
        await runtime.start()
        yield

    async def metadata(_: Request) -> Response:
        return JSONResponse(
            settings.protected_resource_metadata(), headers={"Cache-Control": "public, max-age=300"}
        )

    async def protected(request: Request) -> Response:
        request_id = str(uuid.uuid4())
        request.state.request_id = request_id
        permit: RequestPermit | None = None
        if request.url.path != settings.resource_path:
            return _error(404, "not_found", request_id)
        try:
            origins = [value for name, value in request.headers.raw if name.lower() == b"origin"]
            if len(origins) > 1:
                return _error(403, "origin_denied", request_id)
            try:
                origin = origins[0].decode("ascii") if origins else None
            except UnicodeDecodeError:
                return _error(403, "origin_denied", request_id)
            if origin is not None and not origin_is_allowed(origin, settings):
                return _error(403, "origin_denied", request_id)
            token, auth_error = _bearer(request, settings.max_token_bytes)
            if auth_error:
                return _error(400, auth_error, request_id, _challenge(settings))
            if token is None:
                return _error(401, "authentication_required", request_id, _challenge(settings))
            try:
                principal = await validate_token(token, settings, runtime.keys)
            except TrustUnavailable:
                return _error(503, "trusted_keys_unavailable", request_id, retry_after="60")
            except TokenError:
                return _error(401, "invalid_token", request_id, _challenge(settings, invalid=True))
            missing_global = settings.policy.global_scopes - principal.scopes
            if missing_global:
                return _error(
                    403,
                    "insufficient_scope",
                    request_id,
                    _challenge(settings, insufficient=missing_global),
                )
            if request.method != "POST":
                return _error(405, "method_not_allowed", request_id)
            if "access_token" in request.query_params:
                return _error(400, "invalid_request", request_id)
            try:
                runtime.semaphore.acquire_nowait()
                permit = RequestPermit(runtime.semaphore)
            except anyio.WouldBlock:
                return _error(503, "too_many_requests", request_id, retry_after="1")
            body = await read_bounded_body(request, settings)
            protocol_version = _one_header(request, b"mcp-protocol-version")
            method_header = _one_header(request, b"mcp-method")
            name_header = _one_header(request, b"mcp-name")
            method, name, _ = inspect_request(body, protocol_version, method_header, name_header)
            required = settings.policy.required_for(method, name)
            missing = required - principal.scopes
            if missing:
                return _error(
                    403,
                    "insufficient_scope",
                    request_id,
                    _challenge(settings, insufficient=frozenset(missing)),
                )
            assert permit is not None
            response = proxy_request(request, body, settings, permit, request_id)
            permit = None
            response.headers["X-Request-ID"] = request_id
            return response
        except ProtocolError as exc:
            return _error(exc.status, exc.reason, request_id)
        except ClientDisconnect:
            raise
        except Exception:  # noqa: BLE001 - isolate unexpected request failures without logging data
            logger.error("request failed request_id=%s", request_id)
            return _error(500, "internal_error", request_id)
        finally:
            if permit is not None:
                permit.release()

    resource_path = settings.resource_path
    metadata_path = urlsplit(settings.metadata_url).path
    routes = [Route(metadata_path, metadata, methods=["GET"])]
    app = Starlette(
        routes=routes,
        middleware=[
            Middleware(
                ProtectedResourceMiddleware,
                resource_path=resource_path,
                handler=protected,
            )
        ],
        lifespan=lifespan,
    )
    app.router.redirect_slashes = False
    app.state.bridge_runtime = runtime
    return app


def create_ops_app(public_app: Starlette) -> Starlette:
    runtime: BridgeRuntime = public_app.state.bridge_runtime

    async def live(_: Request) -> Response:
        return Response(status_code=200, content="ok\n", media_type="text/plain")

    async def ready(_: Request) -> Response:
        if runtime.started and runtime.keys.ready:
            return Response(status_code=200, content="ready\n", media_type="text/plain")
        return Response(status_code=503, content="not ready\n", media_type="text/plain")

    return Starlette(routes=[Route("/livez", live), Route("/readyz", ready)])
