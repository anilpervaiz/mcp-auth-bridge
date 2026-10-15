"""Provision and verify the disposable local OAuth realm."""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

import httpx2

ISSUER = "http://127.0.0.1:8180/realms/mab-demo"
RESOURCE = "http://127.0.0.1:8080/mcp"
CALLBACK = "http://127.0.0.1:8765/callback"
CODEX_CALLBACK = "http://127.0.0.1:8766/callback"
OTHER_RESOURCE = "http://127.0.0.1:8080/other-mcp"


class KeycloakSetupError(RuntimeError):
    """The local demonstration realm could not be safely initialized."""


async def configure_realm(admin_password: str) -> None:
    """Bind the admin scope to its realm role and verify audience/scope configuration."""
    timeout = httpx2.Timeout(5.0)
    async with httpx2.AsyncClient(
        base_url="http://127.0.0.1:8180",
        timeout=timeout,
        trust_env=False,
        follow_redirects=False,
    ) as client:
        try:
            response = await client.post(
                "/realms/master/protocol/openid-connect/token",
                data={
                    "grant_type": "password",
                    "client_id": "admin-cli",
                    "username": "mab-bootstrap",
                    "password": admin_password,
                },
            )
            response.raise_for_status()
            access_token = response.json()["access_token"]
            client.headers["Authorization"] = f"Bearer {access_token}"
            role = await _request_json(client, "GET", "/admin/realms/mab-demo/roles/mcp-admin")
            scopes = await _request_json(client, "GET", "/admin/realms/mab-demo/client-scopes")
            scope = next(item for item in scopes if item.get("name") == "mcp:admin")
            roles_scope = next(item for item in scopes if item.get("name") == "roles")
            roles_scope_id = quote(roles_scope["id"], safe="")
            role_mappers = await _request_json(
                client,
                "GET",
                f"/admin/realms/mab-demo/client-scopes/{roles_scope_id}/protocol-mappers/models",
            )
            if not any(
                mapper.get("protocolMapper") == "oidc-usermodel-realm-role-mapper"
                and mapper.get("config", {}).get("claim.name") == "realm_access.roles"
                and mapper.get("config", {}).get("access.token.claim") == "true"
                for mapper in role_mappers
            ):
                raise KeycloakSetupError("roles client scope lacks its realm-role token mapper")
            offline_scope = next(item for item in scopes if item.get("name") == "offline_access")
            offline_attributes = offline_scope.setdefault("attributes", {})
            offline_attributes["include.in.token.scope"] = "false"
            offline_attributes["include.in.openid.provider.metadata"] = "false"
            await _request_json(
                client,
                "PUT",
                f"/admin/realms/mab-demo/client-scopes/{quote(offline_scope['id'], safe='')}",
                content=offline_scope,
            )
            offline_scope = await _request_json(
                client,
                "GET",
                f"/admin/realms/mab-demo/client-scopes/{quote(offline_scope['id'], safe='')}",
            )
            if (
                offline_scope.get("attributes", {}).get("include.in.openid.provider.metadata")
                != "false"
            ):
                raise KeycloakSetupError("offline_access is not hidden from provider metadata")
            scope_id = quote(scope["id"], safe="")
            role_mappings_path = (
                f"/admin/realms/mab-demo/client-scopes/{scope_id}/scope-mappings/realm"
            )
            current_roles = await _request_json(client, "GET", role_mappings_path)
            if not any(item.get("id") == role.get("id") for item in current_roles):
                await _request_json(client, "POST", role_mappings_path, content=[role])
            current_roles = await _request_json(client, "GET", role_mappings_path)
            if {item.get("name") for item in current_roles} != {"mcp-admin"}:
                raise KeycloakSetupError("admin scope has an unexpected role mapping")

            clients = await _request_json(client, "GET", "/admin/realms/mab-demo/clients")
            resource_client = next(
                item for item in clients if item.get("clientId") == "mab-resource"
            )
            other_resource_client = next(
                item for item in clients if item.get("clientId") == "mab-other-resource"
            )
            if resource_client.get("attributes", {}).get("resource_url") != RESOURCE:
                raise KeycloakSetupError("Keycloak resource URL does not match the bridge resource")
            if other_resource_client.get("attributes", {}).get("resource_url") != OTHER_RESOURCE:
                raise KeycloakSetupError(
                    "additional resource fixture has an unexpected resource URL"
                )
            for client_name, callback in (
                ("mab-sdk-client", CALLBACK),
                ("mab-codex-client", CODEX_CALLBACK),
            ):
                public_client = next(
                    item for item in clients if item.get("clientId") == client_name
                )
                if (
                    public_client.get("publicClient") is not True
                    or public_client.get("fullScopeAllowed") is not False
                    or public_client.get("directAccessGrantsEnabled") is not False
                    or public_client.get("implicitFlowEnabled") is not False
                    or public_client.get("redirectUris") != [callback]
                    or public_client.get("defaultClientScopes") != ["roles"]
                    or public_client.get("attributes", {}).get("pkce.code.challenge.method")
                    != "S256"
                ):
                    raise KeycloakSetupError(
                        "public OAuth client does not match the PKCE-only demo profile"
                    )
                if set(public_client.get("optionalClientScopes", [])) != {
                    "mcp:use",
                    "mcp:execute",
                    "mcp:admin",
                }:
                    raise KeycloakSetupError(
                        "public OAuth client has an unexpected optional scope set"
                    )
                public_client_id = quote(public_client["id"], safe="")
                client_role_path = (
                    f"/admin/realms/mab-demo/clients/{public_client_id}/scope-mappings/realm"
                )
                client_roles = await _request_json(client, "GET", client_role_path)
                if not any(item.get("id") == role.get("id") for item in client_roles):
                    await _request_json(client, "POST", client_role_path, content=[role])
                client_roles = await _request_json(client, "GET", client_role_path)
                if {item.get("name") for item in client_roles} != {"mcp-admin"}:
                    raise KeycloakSetupError("public client has an unexpected role scope mapping")
                mappers = await _request_json(
                    client,
                    "GET",
                    f"/admin/realms/mab-demo/clients/{public_client_id}/protocol-mappers/models",
                )
                if not any(
                    mapper.get("config", {}).get("included.client.audience") == "mab-resource"
                    and mapper.get("config", {}).get("access.token.claim") == "true"
                    for mapper in mappers
                ):
                    raise KeycloakSetupError(
                        "public OAuth client is missing its resource audience mapper"
                    )
                if not any(
                    mapper.get("config", {}).get("included.client.audience") == "mab-other-resource"
                    and mapper.get("config", {}).get("access.token.claim") == "true"
                    for mapper in mappers
                ):
                    raise KeycloakSetupError(
                        "public client is missing the additional resource mapper"
                    )

            users = await _request_json(
                client,
                "GET",
                "/admin/realms/mab-demo/users?exact=true&username=mcp-basic",
            )
            basic_user = next(item for item in users if item.get("username") == "mcp-basic")
            users = await _request_json(
                client,
                "GET",
                "/admin/realms/mab-demo/users?exact=true&username=mcp-admin",
            )
            admin_user = next(item for item in users if item.get("username") == "mcp-admin")
            basic_roles = await _request_json(
                client,
                "GET",
                f"/admin/realms/mab-demo/users/{quote(basic_user['id'], safe='')}/role-mappings/realm",
            )
            admin_roles = await _request_json(
                client,
                "GET",
                f"/admin/realms/mab-demo/users/{quote(admin_user['id'], safe='')}/role-mappings/realm",
            )
            if any(item.get("name") == "mcp-admin" for item in basic_roles):
                raise KeycloakSetupError("basic demonstration user has the admin role")
            if not any(item.get("name") == "mcp-admin" for item in admin_roles):
                raise KeycloakSetupError("admin demonstration user lacks the admin role")
        except KeycloakSetupError:
            raise
        except (httpx2.HTTPError, KeyError, StopIteration, TypeError, ValueError) as exc:
            raise KeycloakSetupError("Keycloak realm provisioning failed") from exc


async def _request_json(
    client: httpx2.AsyncClient,
    method: str,
    path: str,
    *,
    content: object | None = None,
) -> Any:
    response = await client.request(method, path, json=content)
    if response.is_error:
        raise KeycloakSetupError(
            f"Keycloak admin request failed: {method} {path} ({response.status_code})"
        )
    if response.status_code == 204 or not response.content:
        return {}
    return response.json()
