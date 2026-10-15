"""Official MCP SDK OAuth client for browser-based Keycloak demonstration flows."""

from __future__ import annotations

import argparse
import asyncio
import base64
import importlib.metadata
import json
import logging
import subprocess
import sys
import webbrowser
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlencode, urlsplit

import httpx2
from mcp import Client
from mcp.client.auth import OAuthClientProvider
from mcp.client.streamable_http import streamable_http_client
from mcp.shared.auth import OAuthClientInformationFull, OAuthClientMetadata, OAuthToken

from mcp_auth_bridge.scopes import parse_scope_value
from mcp_auth_bridge.strict_json import strict_loads
from scripts.oauth_callback import CallbackListener

RESOURCE = "http://127.0.0.1:8080/mcp"
ISSUER = "http://127.0.0.1:8180/realms/mab-demo"
CALLBACK = "http://127.0.0.1:8765/callback"
CLIENT_ID = "mab-sdk-client"
DEMO_PASSWORDS = {
    "mcp-basic": "demo-only-basic-password",
    "mcp-admin": "demo-only-admin-password",
}
UNKNOWN_RESOURCE = "http://127.0.0.1:8081/mcp"
OTHER_RESOURCE = "http://127.0.0.1:8080/other-mcp"
ROOT = Path(__file__).resolve().parents[1]


def _revision() -> str | None:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
            timeout=2,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    value = result.stdout.strip()
    return value if result.returncode == 0 and len(value) == 40 else None


@dataclass
class MemoryStorage:
    """The SDK provider's credentials remain in memory for this one process."""

    tokens: OAuthToken | None = None
    client_info: OAuthClientInformationFull | None = None
    expected_resource: str = RESOURCE
    expected_issuer: str = ISSUER
    issuance_checks: list[bool] = field(default_factory=list)

    async def get_tokens(self) -> OAuthToken | None:
        return self.tokens

    async def set_tokens(self, tokens: OAuthToken) -> None:
        claims = _jwt_claims(tokens.access_token)
        audience = claims.get("aud")
        issuer_valid = claims.get("iss") == self.expected_issuer
        audience_valid = audience == [self.expected_resource] or audience == self.expected_resource
        new_scopes = _scopes(tokens)
        previous_scopes = _scopes(self.tokens)
        if not issuer_valid or not audience_valid or not previous_scopes.issubset(new_scopes):
            raise RuntimeError("issued token failed issuer, audience, or scope continuity checks")
        self.issuance_checks.append(True)
        self.tokens = tokens

    async def get_client_info(self) -> OAuthClientInformationFull | None:
        return self.client_info

    async def set_client_info(self, client_info: OAuthClientInformationFull) -> None:
        self.client_info = client_info


@dataclass
class SafeOAuthEvidence:
    """A redacted in-memory record of resource binding and grant types."""

    storage: MemoryStorage
    authorization_resource: str = RESOURCE
    token_resource: str = RESOURCE
    expected_resource: str = RESOURCE
    authorization_resource_matches: list[bool] = field(default_factory=list)
    authorization_scopes: list[frozenset[str]] = field(default_factory=list)
    token_grants: list[tuple[str, bool]] = field(default_factory=list)
    token_response_statuses: list[int] = field(default_factory=list)
    token_error_codes: list[str | None] = field(default_factory=list)
    resource_response_statuses: list[int] = field(default_factory=list)
    refresh_input_matches_latest: list[bool] = field(default_factory=list)
    refresh_mode: bool = False
    unexpected_refresh_grants: list[bool] = field(default_factory=list)

    def record_authorization(self, url: str) -> None:
        params = parse_qs(urlsplit(url).query, keep_blank_values=True)
        resources = params.get("resource", [])
        self.authorization_resource_matches.append(resources == [self.authorization_resource])
        scopes = params.get("scope", [])
        if len(scopes) != 1 or not scopes[0]:
            self.authorization_scopes.append(frozenset())
        else:
            try:
                self.authorization_scopes.append(parse_scope_value(scopes[0]))
            except ValueError:
                self.authorization_scopes.append(frozenset())

    async def inspect_request(self, request: httpx2.Request) -> None:
        url = urlsplit(str(request.url))
        if not url.path.endswith("/token"):
            return
        try:
            form = parse_qs(request.content.decode("ascii"), keep_blank_values=True)
        except (UnicodeError, ValueError):
            self.token_grants.append(("malformed", False))
            return
        grant_types = form.get("grant_type", [])
        resources = form.get("resource", [])
        grant = grant_types[0] if len(grant_types) == 1 else "malformed"
        self.token_grants.append((grant, resources == [self.token_resource]))
        if grant == "refresh_token":
            current = self.storage.tokens.refresh_token if self.storage.tokens is not None else None
            supplied = form.get("refresh_token", [])
            self.refresh_input_matches_latest.append(bool(current and supplied == [current]))
        if self.refresh_mode and grant != "refresh_token":
            self.unexpected_refresh_grants.append(True)
            raise RuntimeError("refresh verification attempted a non-refresh OAuth grant")

    async def inspect_response(self, response: httpx2.Response) -> None:
        request_url = str(response.request.url)
        if request_url == RESOURCE:
            self.resource_response_statuses.append(response.status_code)
        elif urlsplit(request_url).path.endswith("/token"):
            self.token_response_statuses.append(response.status_code)
            try:
                body = strict_loads(await response.aread())
            except (ValueError, json.JSONDecodeError):
                body = None
            error = body.get("error") if isinstance(body, dict) else None
            self.token_error_codes.append(
                error
                if isinstance(error, str) and error in {"invalid_grant", "invalid_target"}
                else None
            )


@dataclass(frozen=True)
class ScenarioResult:
    list_tools_succeeded: bool
    echo_succeeded: bool
    admin_succeeded: bool
    admin_denied: bool
    upstream_calls_before_admin: int | None
    upstream_calls_after_admin: int | None
    refresh_count: int
    scope_step_up_preserved: bool
    resource_binding_valid: bool
    singleton_audience_valid: bool
    admin_status_code: int | None
    upstream_call_count_unchanged: bool | None
    grant_counts: dict[str, int]
    token_response_statuses: list[int]
    upstream_response_statuses: list[int]
    issuance_claims_valid: bool
    replay_status_code: int | None
    replay_error_code: str | None
    replay_session_discarded: bool


def _client_info() -> OAuthClientInformationFull:
    return OAuthClientInformationFull.model_validate(
        {
            "client_id": CLIENT_ID,
            "redirect_uris": [CALLBACK],
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"],
            "issuer": ISSUER,
        }
    )


def _jwt_claims(token: str) -> dict[str, Any]:
    parts = token.split(".")
    if len(parts) != 3:
        raise TypeError("authorization server returned an invalid access token")
    try:
        padded = parts[1] + "=" * (-len(parts[1]) % 4)
        claims = strict_loads(
            base64.b64decode(padded.encode("ascii"), altchars=b"-_", validate=True)
        )
    except (UnicodeError, ValueError, json.JSONDecodeError) as exc:
        raise RuntimeError("authorization server returned an invalid access token") from exc
    if not isinstance(claims, dict):
        raise TypeError("authorization server returned an invalid access token")
    return claims


def _response_returns_oauth_tokens(body: bytes) -> bool:
    """Inspect a token response without copying credentials into evidence."""
    payload = strict_loads(body)
    if not isinstance(payload, dict):
        raise TypeError("token endpoint response must be a JSON object")
    return any(name in payload for name in ("access_token", "refresh_token", "id_token"))


def _scopes(token: OAuthToken | None) -> set[str]:
    if token is None:
        return set()
    claims = _jwt_claims(token.access_token)
    raw = claims.get("scope", claims.get("scp", ""))
    if isinstance(raw, str):
        try:
            return set(parse_scope_value(raw))
        except ValueError:
            return set()
    if isinstance(raw, list) and all(isinstance(item, str) for item in raw):
        values: set[str] = set()
        try:
            for item in raw:
                parsed = parse_scope_value(item)
                if len(parsed) != 1:
                    return set()
                values.update(parsed)
        except ValueError:
            return set()
        return values
    return set()


async def _playwright_redirect(
    url: str,
    username: str,
    password: str,
    *,
    deadline: float,
    headless: bool,
) -> None:
    """Complete the realm login in an isolated Chromium context."""
    try:
        from playwright.async_api import async_playwright
    except ImportError as exc:
        raise RuntimeError(
            "browser mode requires the pinned Playwright development dependency"
        ) from exc

    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(headless=headless)
        try:
            context = await browser.new_context()
            page = await context.new_page()
            remaining = max(0.001, deadline - asyncio.get_running_loop().time())
            await page.goto(url, wait_until="domcontentloaded", timeout=int(remaining * 1000))
            if await page.locator("#username").count():
                await page.locator("#username").fill(username)
                await page.locator("#password").fill(password)
                await page.get_by_role("button", name="Sign In").click()
            remaining = max(0.001, deadline - asyncio.get_running_loop().time())
            await page.wait_for_url(
                "http://127.0.0.1:8765/callback**", timeout=int(remaining * 1000)
            )
            await page.wait_for_load_state("domcontentloaded")
        finally:
            await browser.close()


async def run_scenario(
    username: str,
    *,
    headless: bool,
    visible_browser: bool = False,
    refreshes: int,
    callback_timeout: float = 180.0,
    replay_old_refresh: bool = False,
) -> ScenarioResult:
    password = DEMO_PASSWORDS[username]
    storage = MemoryStorage(client_info=_client_info())
    evidence = SafeOAuthEvidence(storage=storage)
    metadata = OAuthClientMetadata.model_validate(
        {
            "redirect_uris": [CALLBACK],
            "scope": "mcp:use",
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"],
            "client_name": "MCP Auth Bridge local SDK demo",
        }
    )

    async def redirect_handler(url: str) -> None:
        evidence.record_authorization(url)
        if not evidence.authorization_resource_matches[-1]:
            raise RuntimeError("authorization request did not use the configured resource")
        if evidence.refresh_mode:
            evidence.unexpected_refresh_grants.append(True)
            raise RuntimeError("authorization fallback is disabled during refresh verification")
        await callback.arm()
        if headless or visible_browser:
            await asyncio.wait_for(
                _playwright_redirect(
                    url,
                    username,
                    password,
                    deadline=callback.deadline,
                    headless=headless,
                ),
                timeout=max(0.001, callback.deadline - asyncio.get_running_loop().time()),
            )
        elif not webbrowser.open(url):
            raise RuntimeError("could not open the system browser")

    provider = OAuthClientProvider(
        server_url=RESOURCE,
        client_metadata=metadata,
        storage=storage,
        redirect_handler=redirect_handler,
        callback_handler=None,
    )
    provider.context.client_info = storage.client_info

    async def oauth_request_hook(request: httpx2.Request) -> None:
        await evidence.inspect_request(request)

    async with CallbackListener(timeout_seconds=callback_timeout) as callback:
        provider.context.callback_handler = callback.result
        async with (
            httpx2.AsyncClient(
                auth=provider,
                trust_env=False,
                follow_redirects=False,
                timeout=httpx2.Timeout(15.0, read=70.0),
                event_hooks={
                    "request": [oauth_request_hook],
                    "response": [evidence.inspect_response],
                },
            ) as http_client,
            Client(
                streamable_http_client(RESOURCE, http_client=http_client),
                mode="2026-07-28",
                cache=None,
            ) as mcp_client,
        ):
            listed = await asyncio.wait_for(mcp_client.list_tools(), timeout=callback_timeout)
            tool_names = {tool.name for tool in listed.tools}
            list_ok = {"echo", "sensitive_status", "call_count"}.issubset(tool_names)
            if not list_ok:
                raise RuntimeError("the protected MCP tool list was incomplete")

            echo_result = await asyncio.wait_for(
                mcp_client.call_tool("echo", {"message": "browser OAuth works"}),
                timeout=callback_timeout,
            )
            echo_ok = (
                not echo_result.is_error
                and bool(echo_result.content)
                and getattr(echo_result.content[0], "text", None) == "browser OAuth works"
            )
            if not echo_ok:
                raise RuntimeError("the permitted echo tool did not succeed")

            token_after_step_up = storage.tokens
            scope_ok = {"mcp:use", "mcp:execute"}.issubset(_scopes(token_after_step_up))
            if not scope_ok:
                raise RuntimeError("scope step-up did not preserve the previously granted scope")

            calls_before_admin: int | None = None
            calls_after_admin: int | None = None
            admin_ok = False
            admin_denied = False
            admin_status_code: int | None = None
            calls_unchanged: bool | None = None
            if username == "mcp-basic":
                before = await asyncio.wait_for(
                    mcp_client.call_tool("call_count", {}), timeout=callback_timeout
                )
                calls_before_admin = int(getattr(before.content[0], "text", "-1"))
                status_index = len(evidence.resource_response_statuses)
                try:
                    admin_response = await asyncio.wait_for(
                        mcp_client.call_tool("sensitive_status", {}), timeout=callback_timeout
                    )
                    admin_ok = not admin_response.is_error
                except Exception:  # noqa: BLE001 - any auth failure must still leave upstream unchanged
                    admin_denied = True
                after = await asyncio.wait_for(
                    mcp_client.call_tool("call_count", {}), timeout=callback_timeout
                )
                calls_after_admin = int(getattr(after.content[0], "text", "-1"))
                admin_denied = admin_denied or not admin_ok
                admin_statuses = evidence.resource_response_statuses[status_index:-1]
                admin_status_code = admin_statuses[-1] if admin_statuses else None
                final_claims = _jwt_claims(storage.tokens.access_token if storage.tokens else "")
                basic_roles = final_claims.get("realm_access", {}).get("roles", [])
                if "mcp:admin" in _scopes(storage.tokens) or "mcp-admin" in basic_roles:
                    raise RuntimeError("basic account received the role-restricted admin grant")
                if not evidence.authorization_scopes or not {
                    "mcp:use",
                    "mcp:execute",
                    "mcp:admin",
                }.issubset(evidence.authorization_scopes[-1]):
                    raise RuntimeError(
                        "admin scope step-up did not preserve previously requested scopes"
                    )
                if (
                    not admin_denied
                    or not admin_statuses
                    or admin_statuses[-1] != 403
                    or calls_after_admin != calls_before_admin
                ):
                    raise RuntimeError("basic user's admin request was not denied before upstream")
                calls_unchanged = calls_after_admin == calls_before_admin
            else:
                status_index = len(evidence.resource_response_statuses)
                result = await asyncio.wait_for(
                    mcp_client.call_tool("sensitive_status", {}), timeout=callback_timeout
                )
                admin_ok = not result.is_error
                admin_statuses = evidence.resource_response_statuses[status_index:]
                admin_status_code = admin_statuses[-1] if admin_statuses else None
                if not admin_ok or not admin_statuses or admin_statuses[-1] != 200:
                    raise RuntimeError("admin user could not call the admin tool")
                if "mcp:admin" not in _scopes(storage.tokens):
                    raise RuntimeError("admin token did not carry the admin scope")
                admin_token = storage.tokens
                if admin_token is None:
                    raise RuntimeError("admin login produced no in-memory access token")
                admin_roles = _jwt_claims(admin_token.access_token)["realm_access"]["roles"]
                if "mcp-admin" not in admin_roles:
                    raise RuntimeError("admin token did not carry its dedicated role")

            initial_refresh_token = storage.tokens.refresh_token if storage.tokens else None
            previous_refresh_token = initial_refresh_token
            refresh_count = 0
            for _ in range(refreshes):
                if storage.tokens is None or storage.tokens.expires_in is None:
                    raise RuntimeError("access token expiry was not available for refresh proof")
                await asyncio.sleep(max(1, storage.tokens.expires_in + 1))
                evidence.refresh_mode = True
                await asyncio.wait_for(mcp_client.list_tools(), timeout=callback_timeout)
                evidence.refresh_mode = False
                current = storage.tokens
                if current is None or not current.refresh_token:
                    raise RuntimeError("refresh response did not include a refresh token")
                if current.refresh_token == previous_refresh_token:
                    raise RuntimeError("Keycloak did not rotate its refresh token")
                previous_refresh_token = current.refresh_token
                refresh_count += 1
                if not {"mcp:use", "mcp:execute"}.issubset(_scopes(current)):
                    raise RuntimeError("token refresh did not preserve granted scopes")

            final_token = storage.tokens
            if final_token is None:
                raise RuntimeError("OAuth login produced no in-memory access token")
            final_claims = _jwt_claims(final_token.access_token)
            audience = final_claims.get("aud")
            singleton_aud = audience == [RESOURCE] or audience == RESOURCE
            issuer_valid = final_claims.get("iss") == ISSUER
            resource_bound = (
                bool(evidence.authorization_resource_matches)
                and all(evidence.authorization_resource_matches)
                and bool(evidence.token_grants)
                and all(matched for _, matched in evidence.token_grants)
                and {"authorization_code"}.union(
                    {"refresh_token"} if refreshes else set()
                ).issubset(grant for grant, _ in evidence.token_grants)
                and all(evidence.refresh_input_matches_latest)
                and len([item for item in evidence.token_grants if item[0] == "refresh_token"])
                == refreshes
                and not evidence.unexpected_refresh_grants
            )
            if not singleton_aud or not issuer_valid:
                raise RuntimeError("access token did not have the configured singleton audience")
            if not all(storage.issuance_checks):
                raise RuntimeError("a token issuance failed issuer, audience, or scope checks")
            if refreshes and evidence.token_response_statuses[-refreshes:] != [200] * refreshes:
                raise RuntimeError("refresh exchanges did not each return HTTP 200")
            if not resource_bound:
                raise RuntimeError("OAuth requests did not retain the exact configured resource")

            replay_status_code: int | None = None
            replay_error_code: str | None = None
            replay_session_discarded = False
            if replay_old_refresh:
                if not refreshes or not initial_refresh_token:
                    raise RuntimeError(
                        "refresh replay proof requires one successful token rotation"
                    )
                current_refresh = await provider._refresh_token()
                fields = parse_qs(current_refresh.content.decode("ascii"), keep_blank_values=True)
                fields["refresh_token"] = [initial_refresh_token]
                replay_request = httpx2.Request(
                    "POST",
                    current_refresh.url,
                    headers={"content-type": "application/x-www-form-urlencoded"},
                    content=urlencode(fields, doseq=True).encode("ascii"),
                )
                async with httpx2.AsyncClient(
                    trust_env=False,
                    follow_redirects=False,
                    timeout=httpx2.Timeout(15.0, read=30.0),
                ) as replay_client:
                    replay_response = await replay_client.send(replay_request)
                    replay_status_code = replay_response.status_code
                    try:
                        replay_body = strict_loads(await replay_response.aread())
                    except (ValueError, json.JSONDecodeError):
                        replay_body = None
                    replay_error = (
                        replay_body.get("error") if isinstance(replay_body, dict) else None
                    )
                    replay_error_code = replay_error if replay_error == "invalid_grant" else None
                    await replay_response.aclose()
                provider.context.clear_tokens()
                storage.tokens = None
                replay_session_discarded = storage.tokens is None
                if replay_status_code != 400 or replay_error_code != "invalid_grant":
                    raise RuntimeError("replay of the rotated refresh token was not rejected")

    return ScenarioResult(
        list_tools_succeeded=list_ok,
        echo_succeeded=echo_ok,
        admin_succeeded=admin_ok,
        admin_denied=admin_denied,
        upstream_calls_before_admin=calls_before_admin,
        upstream_calls_after_admin=calls_after_admin,
        refresh_count=refresh_count,
        scope_step_up_preserved=scope_ok,
        resource_binding_valid=resource_bound,
        singleton_audience_valid=singleton_aud,
        admin_status_code=admin_status_code,
        upstream_call_count_unchanged=calls_unchanged,
        grant_counts={
            grant: sum(
                1 for current, _resource_matches in evidence.token_grants if current == grant
            )
            for grant in {current for current, _resource_matches in evidence.token_grants}
        },
        token_response_statuses=list(evidence.token_response_statuses),
        upstream_response_statuses=list(evidence.resource_response_statuses),
        issuance_claims_valid=all(storage.issuance_checks),
        replay_status_code=replay_status_code,
        replay_error_code=replay_error_code,
        replay_session_discarded=replay_session_discarded,
    )


async def verify_changed_resource_binding(*, headless: bool) -> dict[str, Any]:
    """Exercise registered and changed resource bindings with the pinned SDK flow."""
    good_other = await _resource_token_flow(
        headless=headless,
        authorization_resource=OTHER_RESOURCE,
        token_resource=OTHER_RESOURCE,
        expected_audience=OTHER_RESOURCE,
    )
    if (
        good_other["status"] != 200
        or not good_other["audience_valid"]
        or good_other["error"] is not None
    ):
        raise RuntimeError("registered additional resource did not receive its own token")

    changed_code = await _resource_token_flow(
        headless=headless,
        authorization_resource=RESOURCE,
        token_resource=OTHER_RESOURCE,
        expected_audience=RESOURCE,
    )
    if changed_code["status"] != 400 or changed_code["error"] != "invalid_target":
        raise RuntimeError("changed resource authorization-code exchange was not rejected")

    primary = await _resource_token_flow(
        headless=headless,
        authorization_resource=RESOURCE,
        token_resource=RESOURCE,
        expected_audience=RESOURCE,
        refresh_resource=OTHER_RESOURCE,
    )
    if (
        primary["status"] != 200
        or primary["refresh_status"] != 400
        or primary["refresh_error"] != "invalid_target"
        or primary["refresh_tokens_returned"]
    ):
        raise RuntimeError("changed refresh resource was not rejected")
    return {
        "registered_other_resource": good_other,
        "changed_code_resource": changed_code,
        "changed_refresh_resource": primary,
    }


async def verify_unknown_resource_rejected(*, headless: bool) -> dict[str, Any]:
    """Prove unknown resource indicators cannot produce an access token."""
    unknown_authorization = await _resource_token_flow(
        headless=headless,
        authorization_resource=UNKNOWN_RESOURCE,
        token_resource=UNKNOWN_RESOURCE,
        expected_audience=UNKNOWN_RESOURCE,
        allow_authorization_error=True,
    )
    unknown_exchange = await _resource_token_flow(
        headless=headless,
        authorization_resource=RESOURCE,
        token_resource=UNKNOWN_RESOURCE,
        expected_audience=RESOURCE,
    )
    if unknown_authorization["tokens_returned"] or unknown_authorization["error"] not in {
        None,
        "invalid_target",
    }:
        raise RuntimeError("unknown authorization resource was not rejected safely")
    if unknown_exchange["status"] != 400 or unknown_exchange["error"] != "invalid_target":
        raise RuntimeError("unknown token-exchange resource was not rejected at issuance")
    return {
        "unknown_authorization_resource": unknown_authorization,
        "unknown_code_exchange_resource": unknown_exchange,
    }


async def _resource_token_flow(
    *,
    headless: bool,
    authorization_resource: str,
    token_resource: str,
    expected_audience: str,
    refresh_resource: str | None = None,
    allow_authorization_error: bool = False,
) -> dict[str, Any]:
    """Run the official provider's PKCE, state, and issuer checks without MCP calls."""
    from mcp.shared.auth import OAuthMetadata, ProtectedResourceMetadata

    class AlteredResourceProvider(OAuthClientProvider):
        async def _exchange_token_authorization_code(
            self, auth_code: str, code_verifier: str
        ) -> httpx2.Request:
            request = await super()._exchange_token_authorization_code(auth_code, code_verifier)
            fields = parse_qs(request.content.decode("ascii"), keep_blank_values=True)
            fields["resource"] = [token_resource]
            return httpx2.Request(
                "POST",
                request.url,
                headers={"content-type": "application/x-www-form-urlencoded"},
                content=urlencode(fields, doseq=True).encode("ascii"),
            )

    username = "mcp-basic"
    storage = MemoryStorage(
        client_info=_client_info(),
        expected_resource=expected_audience,
    )
    evidence = SafeOAuthEvidence(
        storage=storage,
        authorization_resource=authorization_resource,
        token_resource=token_resource,
    )

    async def redirect_handler(url: str) -> None:
        evidence.record_authorization(url)
        if not evidence.authorization_resource_matches[-1]:
            raise RuntimeError("authorization request used an unexpected resource")
        await callback.arm()
        if headless:
            await asyncio.wait_for(
                _playwright_redirect(
                    url,
                    username,
                    DEMO_PASSWORDS[username],
                    deadline=callback.deadline,
                    headless=True,
                ),
                timeout=max(0.001, callback.deadline - asyncio.get_running_loop().time()),
            )
        elif not webbrowser.open(url):
            raise RuntimeError("could not open the system browser")

    async def request_hook(request: httpx2.Request) -> None:
        await evidence.inspect_request(request)

    result: dict[str, Any] = {
        "status": 0,
        "error": None,
        "audience_valid": False,
        "tokens_returned": False,
        "refresh_status": 0,
        "refresh_error": None,
        "refresh_tokens_returned": False,
        "resource_binding_valid": False,
        "grant_counts": {},
        "token_response_statuses": [],
    }
    client_metadata = OAuthClientMetadata.model_validate(
        {
            "redirect_uris": [CALLBACK],
            "scope": "mcp:use",
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"],
        }
    )
    async with CallbackListener(timeout_seconds=180) as callback:
        provider = AlteredResourceProvider(
            server_url=RESOURCE,
            client_metadata=client_metadata,
            storage=storage,
            redirect_handler=redirect_handler,
            callback_handler=callback.result,
        )
        provider.context.client_info = storage.client_info
        provider.context.oauth_metadata = OAuthMetadata.model_validate(
            {
                "issuer": ISSUER,
                "authorization_endpoint": f"{ISSUER}/protocol/openid-connect/auth",
                "token_endpoint": f"{ISSUER}/protocol/openid-connect/token",
                "authorization_response_iss_parameter_supported": True,
            }
        )
        provider.context.protected_resource_metadata = ProtectedResourceMetadata.model_validate(
            {"resource": authorization_resource, "authorization_servers": [ISSUER]}
        )
        provider.context.__dict__["get_resource_url"] = lambda: authorization_resource
        async with httpx2.AsyncClient(
            trust_env=False,
            follow_redirects=False,
            timeout=httpx2.Timeout(15.0, read=70.0),
            event_hooks={"request": [request_hook], "response": [evidence.inspect_response]},
        ) as http_client:
            try:
                request = await asyncio.wait_for(provider._perform_authorization(), timeout=180)
            except Exception:
                if (
                    not allow_authorization_error
                    or callback.authorization_error != "invalid_target"
                    or storage.tokens is not None
                ):
                    raise
                result["status"] = 400
                result["error"] = "invalid_target"
                result["tokens_returned"] = False
                return result
            response = await asyncio.wait_for(
                http_client.send(request, follow_redirects=False),
                timeout=max(0.001, callback.deadline - asyncio.get_running_loop().time()),
            )
            result["status"] = response.status_code
            result["error"] = evidence.token_error_codes[-1] if evidence.token_error_codes else None
            if response.status_code in {200, 201}:
                await provider._handle_token_response(response)
                result["tokens_returned"] = storage.tokens is not None
                token = storage.tokens
                if token is not None:
                    claims = _jwt_claims(token.access_token)
                    audience = claims.get("aud")
                    result["audience_valid"] = claims.get("iss") == ISSUER and (
                        audience == [expected_audience] or audience == expected_audience
                    )
                if refresh_resource is not None:
                    previous_token = storage.tokens.refresh_token if storage.tokens else None
                    provider.context.__dict__["get_resource_url"] = lambda: refresh_resource
                    refresh_request = await provider._refresh_token()
                    refresh_response = await http_client.send(
                        refresh_request, follow_redirects=False
                    )
                    result["refresh_status"] = refresh_response.status_code
                    result["refresh_error"] = (
                        evidence.token_error_codes[-1] if evidence.token_error_codes else None
                    )
                    result["refresh_tokens_returned"] = _response_returns_oauth_tokens(
                        refresh_response.content
                    )
                    await refresh_response.aclose()
                    if previous_token is None or storage.tokens is None:
                        raise RuntimeError("refresh test did not start from a complete token set")
                    if storage.tokens.refresh_token != previous_token:
                        raise RuntimeError(
                            "failed refresh unexpectedly replaced stored credentials"
                        )
            await response.aclose()
    result["tokens_returned"] = result["tokens_returned"] and storage.tokens is not None
    result["resource_binding_valid"] = (
        bool(evidence.authorization_resource_matches)
        and all(evidence.authorization_resource_matches)
        and bool(evidence.token_grants)
        and all(matched for _grant, matched in evidence.token_grants)
    )
    result["grant_counts"] = {
        grant: sum(1 for current, _resource_matches in evidence.token_grants if current == grant)
        for grant in {current for current, _resource_matches in evidence.token_grants}
    }
    result["token_response_statuses"] = list(evidence.token_response_statuses)
    return result


async def _run(args: argparse.Namespace) -> None:
    username = "mcp-admin" if args.scenario == "admin" else "mcp-basic"
    result = await run_scenario(
        username,
        headless=args.headless,
        visible_browser=args.visible_browser,
        refreshes=args.refreshes,
        callback_timeout=args.callback_timeout,
    )
    outcome = {
        "scenario": args.scenario,
        "tool_listing": result.list_tools_succeeded,
        "echo": result.echo_succeeded,
        "admin_tool": "allowed" if result.admin_succeeded else "denied",
        "admin_status_code": result.admin_status_code,
        "basic_admin_upstream_calls": [
            result.upstream_calls_before_admin,
            result.upstream_calls_after_admin,
        ]
        if result.upstream_calls_before_admin is not None
        else None,
        "upstream_call_count_unchanged": result.upstream_call_count_unchanged,
        "refreshes": result.refresh_count,
        "scope_step_up_preserved": result.scope_step_up_preserved,
        "resource_binding_valid": result.resource_binding_valid,
        "singleton_audience_valid": result.singleton_audience_valid,
        "issuance_claims_valid": result.issuance_claims_valid,
        "grant_counts": result.grant_counts,
        "token_response_status_codes": result.token_response_statuses,
        "upstream_response_status_codes": result.upstream_response_statuses,
    }
    print(json.dumps(outcome, sort_keys=True))
    if args.report is not None:
        from scripts.run_oauth_demo import KEYCLOAK_IMAGE

        try:
            sdk_version = importlib.metadata.version("mcp")
        except importlib.metadata.PackageNotFoundError:
            sdk_version = "unavailable"
        image, digest = KEYCLOAK_IMAGE.split("@", 1)
        report = {
            "schema": "mab-oauth-client-v1",
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "revision": _revision(),
            "versions": {
                "python": sys.version.split()[0],
                "mcp_sdk": sdk_version,
                "keycloak_image": image,
                "keycloak_image_digest": digest,
            },
            "headless": args.headless,
            "visible_browser": args.visible_browser,
            "passed": True,
            "scenario": outcome,
            "cleanup": {
                "callback_listener_closed": True,
                "isolated_browser_context_closed": args.headless or args.visible_browser,
            },
        }
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(
            json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8"
        )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario", choices=("basic", "admin", "refresh"), default="basic")
    parser.add_argument("--headless", action="store_true", help="use an isolated Chromium context")
    parser.add_argument(
        "--visible-browser",
        action="store_true",
        help="show an isolated Chromium window for the local login demonstration",
    )
    parser.add_argument(
        "--refreshes", type=int, default=0, help="number of rotating refreshes (max 2)"
    )
    parser.add_argument("--callback-timeout", type=float, default=180.0)
    parser.add_argument("--report", type=Path, help="write allow-listed JSON evidence to PATH")
    args = parser.parse_args()
    if args.refreshes < 0 or args.refreshes > 2:
        parser.error("--refreshes must be between zero and two")
    if args.callback_timeout <= 0:
        parser.error("--callback-timeout must be positive")
    if args.headless and args.visible_browser:
        parser.error("--headless and --visible-browser cannot be used together")
    if args.scenario == "refresh" and args.refreshes == 0:
        args.refreshes = 2
    # The SDK's internal exception logger may include OAuth state values in diagnostic text.
    logging.getLogger("mcp.client.auth.oauth2").disabled = True
    try:
        asyncio.run(_run(args))
    except Exception as exc:  # noqa: BLE001 - suppress SDK and remote error details
        # SDK exception text can contain remote OAuth error details; emit only a stable reason.
        del exc
        raise SystemExit("browser OAuth demonstration failed safely") from None


if __name__ == "__main__":
    main()
