"""End-to-end checks against the running local demo, including the official SDK."""

from __future__ import annotations

import argparse
import asyncio
import base64
import json
import subprocess
import sys
import time

import httpx2
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

from mcp_auth_bridge.egress import SafeFetcher

URL = "http://127.0.0.1:8080/mcp"
RESOURCE = "http://127.0.0.1:8080/mcp"
ISSUER = "http://127.0.0.1:8180/issuer"


def token(
    *scopes: str, audience: str = RESOURCE, issuer: str = ISSUER, exp_delta: int = 300
) -> str:
    args = [
        sys.executable,
        "scripts/demo_token.py",
        "--scope",
        *scopes,
        "--audience",
        audience,
        "--issuer",
        issuer,
        "--expires-in",
        str(exp_delta),
    ]
    return subprocess.check_output(args, text=True).strip()


def _request(method: str, name: str | None, call_id: int = 1) -> tuple[dict[str, str], bytes]:
    params: dict[str, object] = {
        "_meta": {
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientInfo": {"name": "local-test", "version": "1"},
            "io.modelcontextprotocol/clientCapabilities": {},
        }
    }
    if name is not None:
        params["name"] = name
        params["arguments"] = {"message": "security-check"}
    body = {"jsonrpc": "2.0", "id": call_id, "method": method, "params": params}
    headers = {
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
        "MCP-Protocol-Version": "2026-07-28",
        "Mcp-Method": method,
    }
    if name is not None:
        headers["Mcp-Name"] = name
    return headers, json.dumps(body).encode()


def _content_text(content: object) -> str:
    text = getattr(content, "text", None)
    if not isinstance(text, str):
        raise TypeError("expected a text content block")
    return text


async def run() -> None:
    redirect_status, _ = await SafeFetcher(256 * 1024, allow_loopback=True).get_json(
        "http://127.0.0.1:8180/redirect"
    )
    assert redirect_status == 302
    async with httpx2.AsyncClient(timeout=5, trust_env=False) as metadata_client:
        metadata_response = await metadata_client.get(
            "http://127.0.0.1:8080/.well-known/oauth-protected-resource/mcp"
        )
        assert metadata_response.status_code == 200
        metadata = metadata_response.json()
    assert metadata["resource"] == RESOURCE
    assert metadata["authorization_servers"] == [ISSUER]
    async with httpx2.AsyncClient(timeout=5, trust_env=False) as route_client:
        assert (await route_client.get("http://127.0.0.1:8080/readyz")).status_code == 404
        assert (await route_client.get("http://127.0.0.1:9090/readyz")).status_code == 200

    authenticated = token("mcp:use", "mcp:execute")
    async with httpx2.AsyncClient(timeout=5, trust_env=False) as discovery_client:
        headers, body = _request("server/discover", None)
        headers["Authorization"] = f"Bearer {authenticated}"
        response = await discovery_client.post(URL, headers=headers, content=body)
        assert response.status_code == 200
        result = response.json()["result"]
        assert result["supportedVersions"] == ["2026-07-28"]
        assert result["capabilities"] == {"tools": {}}
        assert result["_meta"]["io.modelcontextprotocol/serverInfo"]["name"] == "mab-demo"
    async with (
        httpx2.AsyncClient(
            headers={
                "Authorization": f"Bearer {authenticated}",
                "Cookie": "canary=private",
                "X-Forwarded-For": "203.0.113.9",
                "X-Mcp-Auth-Bridge-Subject": "spoofed",
                "X-Authenticated-User": "spoofed",
                "X-Api-Key": "credential-canary",
                "X-User-Id": "identity-canary",
                "X-User": "identity-canary",
                "X-Email": "identity-canary",
            },
            timeout=httpx2.Timeout(30, read=300),
            trust_env=False,
        ) as client,
        Client(
            streamable_http_client(URL, http_client=client), mode="2026-07-28", cache=None
        ) as mcp_client,
    ):
        tools = await mcp_client.list_tools()
        assert {item.name for item in tools.tools} >= {"echo", "inspect_headers", "call_count"}
        echoed = await mcp_client.call_tool("echo", {"message": "hello through the bridge"})
        assert _content_text(echoed.content[0]) == "hello through the bridge"
        observed = await mcp_client.call_tool("inspect_headers", {})
        forwarded = json.loads(_content_text(observed.content[0]))
        forbidden = {
            "authorization",
            "cookie",
            "x-forwarded-for",
            "x-mcp-auth-bridge-subject",
            "x-authenticated-user",
            "x-api-key",
            "x-user-id",
            "x-user",
            "x-email",
        }
        assert forbidden.isdisjoint(forwarded), forwarded

    async with httpx2.AsyncClient(timeout=10, trust_env=False) as raw:
        headers, body = _request("tools/call", "sensitive_status")
        wrong_issuer = token("mcp:use", "mcp:execute", issuer="http://127.0.0.1:8181/issuer")
        invalid_signature = authenticated.rsplit(".", 1)
        signature = bytearray(
            base64.urlsafe_b64decode(invalid_signature[1] + "=" * (-len(invalid_signature[1]) % 4))
        )
        signature[0] ^= 1
        bad_signature = (
            invalid_signature[0] + "." + base64.urlsafe_b64encode(signature).rstrip(b"=").decode()
        )
        unsupported_alg = authenticated.split(".")
        unsupported_alg[0] = (
            base64.urlsafe_b64encode(b'{"alg":"HS256","kid":"demo-key-1","typ":"JWT"}')
            .rstrip(b"=")
            .decode()
        )
        unsupported_alg_token = ".".join(unsupported_alg)
        for rejected in [
            (token("mcp:use", "mcp:execute", audience="http://127.0.0.1:9999/mcp"), 401),
            (token("mcp:use", "mcp:execute", exp_delta=-120), 401),
            (wrong_issuer, 401),
            (bad_signature, 401),
            (unsupported_alg_token, 401),
            (token("mcp:use", "mcp:execute"), 403),
        ]:
            response = await raw.post(
                URL, headers={**headers, "Authorization": f"Bearer {rejected[0]}"}, content=body
            )
            assert response.status_code == rejected[1], response.text

        _, duplicate_body = _request("tools/list", None, 8)
        duplicate_header_response = await raw.post(
            URL,
            headers=[
                ("Authorization", f"Bearer {authenticated}"),
                ("MCP-Protocol-Version", "2026-07-28"),
                ("Mcp-Method", "tools/list"),
                ("Mcp-Method", "tools/list"),
                ("Content-Type", "application/json"),
            ],
            content=duplicate_body,
        )
        assert duplicate_header_response.status_code == 400

        redirect_headers, redirect_body = _request("test/redirect", None, 9)
        redirect_response = await raw.post(
            URL,
            headers={**redirect_headers, "Authorization": f"Bearer {authenticated}"},
            content=redirect_body,
        )
        assert redirect_response.status_code == 502
        assert "location" not in redirect_response.headers

        no_scope = token("mcp:use")
        count_headers, count_body = _request("tools/call", "call_count", 2)
        count_response = await raw.post(
            URL,
            headers={**count_headers, "Authorization": f"Bearer {no_scope}"},
            content=count_body,
        )
        assert count_response.status_code == 403

        # Every failed authentication or authorization above must leave the upstream counter unchanged.
        count_response = await raw.post(
            URL,
            headers={**count_headers, "Authorization": f"Bearer {authenticated}"},
            content=count_body,
        )
        assert count_response.status_code == 200
        assert json.loads(count_response.json()["result"]["content"][0]["text"]) == 2

        mismatch_headers, mismatch_body = _request("tools/call", "echo", 3)
        mismatch_headers["Mcp-Name"] = "another-tool"
        response = await raw.post(
            URL,
            headers={**mismatch_headers, "Authorization": f"Bearer {authenticated}"},
            content=mismatch_body,
        )
        assert response.status_code == 400

        origin_headers, origin_body = _request("tools/call", "echo", 4)
        response = await raw.post(
            URL,
            headers={
                **origin_headers,
                "Authorization": f"Bearer {authenticated}",
                "Origin": "https://evil.example",
            },
            content=origin_body,
        )
        assert response.status_code == 403

        duplicate_json = b'{"jsonrpc":"2.0","id":6,"method":"tools/list","method":"tools/call","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}'
        response = await raw.post(
            URL,
            headers={
                "Authorization": f"Bearer {authenticated}",
                "MCP-Protocol-Version": "2026-07-28",
                "Mcp-Method": "tools/list",
                "Content-Type": "application/json",
            },
            content=duplicate_json,
        )
        assert response.status_code == 400

        canary_headers, canary_body = _request("tools/call", "inspect_headers", 7)
        response = await raw.post(
            URL,
            headers={
                **canary_headers,
                "Authorization": f"Bearer {authenticated}",
                "Cookie": "test=secret",
                "X-Forwarded-For": "192.0.2.8",
                "X-Mcp-Auth-Bridge-Subject": "forged",
                "X-Authenticated-User": "forged",
            },
            content=canary_body,
        )
        received = json.loads(response.json()["result"]["content"][0]["text"])
        assert {
            "authorization",
            "cookie",
            "x-forwarded-for",
            "x-mcp-auth-bridge-subject",
            "x-authenticated-user",
            "mcp-session-id",
        }.isdisjoint(received)

        # The first SSE event is delivered while the fixture is still holding the response open.
        stream_headers, stream_body = _request("test/stream", None, 5)
        async with raw.stream(
            "POST",
            URL,
            headers={**stream_headers, "Authorization": f"Bearer {authenticated}"},
            content=stream_body,
        ) as response:
            assert response.status_code == 200
            iterator = response.aiter_lines()
            first_lines = [
                await asyncio.wait_for(iterator.__anext__(), timeout=2) for _ in range(2)
            ]
            assert "data:" in first_lines[1]

        async def disconnect_stream(call_id: int) -> None:
            headers, body = _request("test/stream", None, call_id)
            async with raw.stream(
                "POST",
                URL,
                headers={**headers, "Authorization": f"Bearer {authenticated}"},
                content=body,
            ) as response:
                assert response.status_code == 200
                first_line = await asyncio.wait_for(response.aiter_lines().__anext__(), timeout=5)
                assert first_line == "event: message"

        await asyncio.gather(*(disconnect_stream(20 + index) for index in range(32)))
        after_disconnect_headers, after_disconnect_body = _request("tools/list", None, 99)
        after_disconnect = await raw.post(
            URL,
            headers={
                **after_disconnect_headers,
                "Authorization": f"Bearer {authenticated}",
            },
            content=after_disconnect_body,
        )
        assert after_disconnect.status_code == 200
    print(
        "PASS: SDK discovery and calls, token/scope rejection, credential stripping, route isolation, redirects, protocol/Origin checks, streaming, and disconnect cleanup"
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--wait", type=float, default=0)
    args = parser.parse_args()
    if args.wait:
        time.sleep(args.wait)
    asyncio.run(run())


if __name__ == "__main__":
    main()
