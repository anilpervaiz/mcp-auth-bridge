"""Small unauthenticated Streamable HTTP MCP fixture for end-to-end tests."""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from typing import Any

import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response, StreamingResponse
from starlette.routing import Route

_calls = 0
_last_header_names: list[str] = []


async def handle(request: Request) -> Response:
    global _calls, _last_header_names
    try:
        body = await request.json()
    except ValueError:
        return JSONResponse({"error": "invalid request"}, status_code=400)
    if not isinstance(body, dict):
        return JSONResponse({"error": "invalid request"}, status_code=400)
    method = body.get("method")
    params = body.get("params", {})
    request_id = body.get("id")
    _last_header_names = sorted(
        name.decode("latin-1").lower() for name, _ in request.scope["headers"]
    )
    if method == "server/discover":
        return _reply(
            request_id,
            {
                "resultType": "complete",
                "supportedVersions": ["2026-07-28"],
                "capabilities": {"tools": {}},
                "_meta": {
                    "io.modelcontextprotocol/serverInfo": {"name": "mab-demo", "version": "0.1.0"}
                },
                "cacheScope": "private",
                "ttlMs": 0,
            },
        )
    if method == "tools/list":
        tools = [
            {"name": name, "description": description, "inputSchema": schema}
            for name, description, schema in [
                (
                    "echo",
                    "Echo a string",
                    {
                        "type": "object",
                        "properties": {"message": {"type": "string"}},
                        "required": ["message"],
                    },
                ),
                (
                    "inspect_headers",
                    "Return received header names only",
                    {"type": "object", "properties": {}},
                ),
                (
                    "call_count",
                    "Count tools that reached the upstream",
                    {"type": "object", "properties": {}},
                ),
                (
                    "sensitive_status",
                    "Scope-protected admin demo",
                    {"type": "object", "properties": {}},
                ),
            ]
        ]
        return _reply(
            request_id,
            {
                "tools": tools,
                "cacheScope": "private",
                "resultType": "complete",
                "ttlMs": 0,
            },
        )
    if method == "tools/call":
        name = params.get("name")
        if name == "call_count":
            text = str(_calls)
        elif name == "inspect_headers":
            text = json.dumps(_last_header_names)
            _calls += 1
        elif name == "echo":
            text = str(params.get("arguments", {}).get("message", ""))
            _calls += 1
        elif name == "sensitive_status":
            text = "admin tool reached"
            _calls += 1
        else:
            return JSONResponse(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {"code": -32601, "message": "unknown tool"},
                }
            )
        result = {
            "content": [{"type": "text", "text": text}],
            "isError": False,
            "resultType": "complete",
        }
        return _reply(request_id, result)
    if method == "test/redirect":
        return Response(
            status_code=302,
            headers={"Location": "http://127.0.0.1:8180/.well-known/jwks"},
        )
    if method == "test/stream":

        async def messages() -> AsyncIterator[bytes]:
            result = json.dumps({"jsonrpc": "2.0", "id": request_id, "result": {"chunk": "first"}})
            yield f"event: message\ndata: {result}\n\n".encode()
            await asyncio.sleep(3)
            yield b": second chunk\n\n"

        return StreamingResponse(
            messages(), media_type="text/event-stream", headers={"X-Accel-Buffering": "no"}
        )
    return JSONResponse(
        {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {"code": -32601, "message": "unsupported method"},
        },
        status_code=404,
    )


def _reply(request_id: Any, result: dict[str, Any]) -> JSONResponse:
    return JSONResponse(
        {"jsonrpc": "2.0", "id": request_id, "result": result},
        headers={"Mcp-Session-Id": "should-not-escape"},
    )


app = Starlette(routes=[Route("/mcp", handle, methods=["POST"])])


def main() -> None:
    try:
        uvicorn.run(app, host="127.0.0.1", port=8000, log_level="warning", access_log=False)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
