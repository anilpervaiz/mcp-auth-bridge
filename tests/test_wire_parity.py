"""Protocol wire expectations for the self-hosted bridge."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcp_auth_bridge.config import BridgeSettings
from mcp_auth_bridge.protocol import ProtocolError, inspect_request

FIXTURES = json.loads((Path(__file__).parent / "fixtures" / "bridge-wire.json").read_text())


@pytest.mark.parametrize("case", FIXTURES["cases"], ids=lambda case: case["id"])
def test_shared_protocol_wire(case: dict[str, object]) -> None:
    headers = case["headers"]
    assert isinstance(headers, dict)
    body = case["body"]
    assert isinstance(body, str)
    args = (
        body.encode("utf-8"),
        headers.get("MCP-Protocol-Version"),
        headers.get("Mcp-Method"),
        headers.get("Mcp-Name"),
    )
    if case["status"] == 400:
        with pytest.raises(ProtocolError) as error:
            inspect_request(*args)
        assert error.value.status == 400
        return
    method, name, _ = inspect_request(*args)
    assert method == case["method"]
    assert name == case.get("name")


def test_profile_body_limits_are_explicit() -> None:
    settings = BridgeSettings(
        public_resource="http://127.0.0.1:8080/mcp",
        issuer="http://127.0.0.1:8180/issuer",
        upstream="http://127.0.0.1:8000/mcp",
        allow_insecure_loopback=True,
    )
    assert settings.max_body_bytes == FIXTURES["profiles"]["python"]["max_request_body_bytes"]
