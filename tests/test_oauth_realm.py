"""Security invariants for the imported, disposable OAuth clients."""

from __future__ import annotations

import json
from pathlib import Path

import pytest


@pytest.mark.parametrize(
    ("client_id", "callback"),
    [
        ("mab-sdk-client", "http://127.0.0.1:8765/callback"),
        ("mab-codex-client", "http://127.0.0.1:8766/callback"),
    ],
)
def test_public_clients_have_exact_callbacks_and_restricted_grants(
    client_id: str, callback: str
) -> None:
    realm = json.loads(Path("examples/oauth/keycloak/mab-demo-realm.json").read_text())
    clients = [item for item in realm["clients"] if item["clientId"] == client_id]
    assert len(clients) == 1
    client = clients[0]
    assert client["redirectUris"] == [callback]
    assert client["publicClient"] is True
    assert client["standardFlowEnabled"] is True
    assert client["directAccessGrantsEnabled"] is False
    assert client["implicitFlowEnabled"] is False
    assert client["fullScopeAllowed"] is False
    assert client["attributes"]["pkce.code.challenge.method"] == "S256"
    assert client["defaultClientScopes"] == ["roles"]
    assert set(client["optionalClientScopes"]) == {"mcp:use", "mcp:execute", "mcp:admin"}
    assert "secret" not in client
    mappers = client["protocolMappers"]
    assert {item["config"]["included.client.audience"] for item in mappers} == {
        "mab-resource",
        "mab-other-resource",
    }
    assert all(item["config"]["access.token.claim"] == "true" for item in mappers)
