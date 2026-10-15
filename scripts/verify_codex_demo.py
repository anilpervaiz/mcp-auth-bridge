"""Verify the installed Codex MCP runtime against the running local OAuth demo.

No model runs are requested. Codex owns OAuth credentials and the callback listener.
Only safe comparisons are written; token values are never read by this harness.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import shutil
import socket
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx2
from playwright.async_api import async_playwright

from scripts.oauth_client import DEMO_PASSWORDS
from scripts.oauth_keycloak import CODEX_CALLBACK, RESOURCE

NAME = "mab_demo_local"


class NativeClient:
    def __init__(self) -> None:
        self.process: asyncio.subprocess.Process | None = None
        self.reader: asyncio.Task[None] | None = None
        self.pending: dict[int, asyncio.Future[dict[str, Any]]] = {}
        self.notes: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        self.sequence = 0

    async def start(self) -> None:
        binary = shutil.which("codex")
        if binary is None:
            raise RuntimeError("installed Codex CLI is required")
        # Config/read would expose unrelated values. Read just names to disable other
        # connections in this process, preserving the user's on-disk configuration.
        import re

        config = Path.home() / ".codex" / "config.toml"
        names = re.findall(r"^\[mcp_servers\.([A-Za-z0-9_-]+)\]$", config.read_text(), re.MULTILINE)
        args = [binary, "--enable", "mcp_2026_07_28"]
        for name in names:
            if name != NAME:
                args.extend(["-c", f"mcp_servers.{name}.enabled=false"])
        args.append("app-server")
        self.process = await asyncio.create_subprocess_exec(
            *args,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        self.reader = asyncio.create_task(self._read())
        await self.request(
            "initialize",
            {
                "clientInfo": {"name": "mab-native-verifier", "version": "1"},
                "capabilities": {"experimentalApi": True},
            },
        )
        assert self.process.stdin is not None
        self.process.stdin.write(b'{"method":"initialized"}\n')
        await self.process.stdin.drain()

    async def _read(self) -> None:
        assert self.process is not None and self.process.stdout is not None
        while line := await self.process.stdout.readline():
            value = json.loads(line)
            if not isinstance(value, dict):
                raise TypeError("invalid app-server envelope")
            call_id = value.get("id")
            if isinstance(call_id, int) and call_id in self.pending:
                future = self.pending.pop(call_id)
                if not future.done():
                    future.set_result(value)
            elif "method" in value:
                await self.notes.put(value)

    async def request(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        assert self.process is not None and self.process.stdin is not None
        self.sequence += 1
        future: asyncio.Future[dict[str, Any]] = asyncio.get_running_loop().create_future()
        self.pending[self.sequence] = future
        try:
            self.process.stdin.write(
                (
                    json.dumps(
                        {
                            "id": self.sequence,
                            "method": method,
                            "params": params,
                        }
                    )
                    + "\n"
                ).encode()
            )
            await self.process.stdin.drain()
            return await asyncio.wait_for(future, 180)
        finally:
            self.pending.pop(self.sequence, None)

    async def close(self) -> None:
        if self.process is not None and self.process.returncode is None:
            self.process.terminate()
            try:
                await asyncio.wait_for(self.process.wait(), 10)
            except asyncio.TimeoutError:
                self.process.kill()
                await self.process.wait()
        if self.reader is not None:
            self.reader.cancel()
            await asyncio.gather(self.reader, return_exceptions=True)

    async def tool(self, thread: str, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
        return await self.request(
            "mcpServer/tool/call",
            {
                "threadId": thread,
                "server": NAME,
                "tool": tool,
                "arguments": arguments,
            },
        )

    async def connect(self) -> tuple[str, bool]:
        response = await self.request("thread/start", {"ephemeral": True, "cwd": str(Path.cwd())})
        thread = response["result"]["thread"]["id"]
        status = await self.request(
            "mcpServerStatus/list",
            {
                "threadId": thread,
                "serverName": NAME,
                "detail": "toolsAndAuthOnly",
            },
        )
        server = next(item for item in status["result"]["data"] if item["name"] == NAME)
        return str(thread), server["runtimeStatus"] == "connected" and len(server["tools"]) == 4


async def authorize(client: NativeClient, admin: bool) -> dict[str, Any]:
    response = await client.request("mcpServer/oauth/login", {"name": NAME, "timeoutSecs": 180})
    url = response["result"]["authorizationUrl"]
    query = parse_qs(urlsplit(url).query)
    exact = query.get("resource") == [RESOURCE] and query.get("redirect_uri") == [CODEX_CALLBACK]
    if not exact or query.get("client_id") != ["mab-codex-client"]:
        raise RuntimeError("native authorization binding mismatch")
    scope_fields = query.get("scope", [])
    if len(scope_fields) != 1:
        raise RuntimeError("ambiguous native scope request")
    scopes = scope_fields[0].split(" ")
    if not set(scopes) <= {"mcp:use", "mcp:execute", "mcp:admin", "openid", "roles"}:
        raise RuntimeError("unexpected native scope request")
    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(headless=False)
        try:
            context = await browser.new_context()
            page = await context.new_page()
            await page.goto(url)
            username = "mcp-admin" if admin else "mcp-basic"
            await page.locator("#username").fill(username)
            await page.locator("#password").fill(DEMO_PASSWORDS[username])
            await page.get_by_role("button", name="Sign In").click()
            await page.wait_for_url(f"{CODEX_CALLBACK}**", timeout=180_000)
            while True:
                note = await client.notes.get()
                if note.get("method") == "mcpServer/oauthLogin/completed":
                    if note["params"].get("success") is not True:
                        raise RuntimeError("native login failed")
                    break
        finally:
            await browser.close()
    return {
        "exact_resource": True,
        "resource_parameter_count": 1,
        "exact_callback": True,
        "scope_request_mode": "client_default",
        "requested_scopes": scopes,
        "browser_login": True,
    }


def text_result(response: dict[str, Any]) -> str:
    return str(response["result"]["content"][0]["text"])


async def scenario(admin: bool, refresh: bool) -> dict[str, Any]:
    client = NativeClient()
    try:
        await client.start()
        evidence = await asyncio.wait_for(authorize(client, admin), 180)
        thread, discovered = await client.connect()
        assert discovered
        echo = await client.tool(thread, "echo", {"message": "native Codex local demo"})
        assert text_result(echo) == "native Codex local demo"
        before = int(text_result(await client.tool(thread, "call_count", {})))
        result = await client.tool(thread, "sensitive_status", {})
        after = int(text_result(await client.tool(thread, "call_count", {})))
        if admin:
            assert text_result(result) == "admin tool reached" and after == before + 1
        else:
            assert "Insufficient scope" in str(result.get("error")) and after == before
        evidence.update(
            {
                "discovery": discovered,
                "echo": True,
                "admin_allowed": admin,
                "admin_denied": not admin,
                "denied_upstream_count_unchanged": not admin,
            }
        )
        if refresh:
            # Greater than the realm's 30s lifetime plus the bridge's 30s tolerance.
            # No additional authorization call or browser is permitted in this phase.
            await asyncio.sleep(65)
            result = await client.tool(thread, "echo", {"message": "after token expiry"})
            assert text_result(result) == "after token expiry"
            evidence["expiry_driven_refresh"] = True
            evidence["refresh_wait_seconds"] = 65
            evidence["additional_authorization_requests"] = 0
        await client.close()
        replacement = NativeClient()
        try:
            await replacement.start()
            thread, discovered = await replacement.connect()
            assert discovered
            result = await replacement.tool(thread, "echo", {"message": "after client restart"})
            assert text_result(result) == "after client restart"
            evidence["native_process_restart_reconnect"] = True
        finally:
            await replacement.close()
        return evidence
    finally:
        await client.close()


async def run(report: Path) -> None:
    outcome: dict[str, Any] = {
        "schema": "mab-native-codex-v1",
        "passed": False,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "revision": (
            await asyncio.to_thread(
                subprocess.check_output, ["git", "rev-parse", "HEAD"], text=True
            )
        ).strip(),
        "versions": {
            "python": sys.version.split()[0],
            "codex": (
                await asyncio.to_thread(
                    subprocess.check_output,
                    ["codex", "--version"],
                    text=True,
                    stderr=subprocess.DEVNULL,
                )
            ).strip(),
        },
        "client_surface": "installed_codex_app_server",
        "transport_feature": "mcp_2026_07_28",
        "scenario": {},
    }
    try:
        outcome["scenario"]["basic"] = await scenario(False, True)
        outcome["scenario"]["admin"] = await scenario(True, False)
        outcome["passed"] = True
    finally:
        async with httpx2.AsyncClient(trust_env=False, timeout=2) as http:
            response = await http.get("http://127.0.0.1:9090/readyz")
            outcome["cleanup"] = {
                "native_processes_reaped": outcome["passed"],
                "provider_still_ready": response.status_code == 200,
            }
        with socket.socket() as listener_check:
            try:
                listener_check.bind(("127.0.0.1", 8766))
                outcome["cleanup"]["callback_port_released"] = True
            except OSError:
                outcome["cleanup"]["callback_port_released"] = False
                outcome["passed"] = False
        report.parent.mkdir(parents=True, exist_ok=True)
        report.write_text(json.dumps(outcome, indent=2, sort_keys=True) + "\n")
    if not outcome["passed"]:
        raise RuntimeError("native cleanup verification failed")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, default=Path("artifacts/native-codex.json"))
    args = parser.parse_args()
    try:
        asyncio.run(run(args.report))
    except Exception:  # noqa: BLE001 - raw native errors may carry OAuth data
        raise SystemExit("native Codex acceptance failed safely") from None
    print(
        "Native Codex acceptance passed: browser login, discovery, tools, policy, expiry, reconnect."
    )


if __name__ == "__main__":
    main()
