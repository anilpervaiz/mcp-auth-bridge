"""Bounded JSON-RPC inspection for the current MCP Streamable HTTP revision."""

from __future__ import annotations

import base64
import binascii
from typing import Any

from .strict_json import StrictJSONError, strict_loads


class ProtocolError(ValueError):
    def __init__(self, status: int, reason: str) -> None:
        self.status = status
        self.reason = reason
        super().__init__(reason)


def _decode_header_value(value: str) -> str:
    prefix, suffix = "=?base64?", "?="
    if not (value.startswith(prefix) and value.endswith(suffix)):
        return value
    payload = value[len(prefix) : -len(suffix)]
    try:
        return base64.b64decode(payload, validate=True).decode("utf-8", errors="strict")
    except (binascii.Error, UnicodeDecodeError, ValueError) as exc:
        raise ProtocolError(400, "invalid_encoded_mcp_header") from exc


def inspect_request(
    body: bytes, protocol_version: str | None, mcp_method: str | None, mcp_name: str | None
) -> tuple[str, str | None, dict[str, Any]]:
    try:
        value = strict_loads(body)
    except StrictJSONError as exc:
        reason = "duplicate_json_field" if "duplicate" in str(exc) else "invalid_json"
        raise ProtocolError(400, reason) from exc
    except ValueError as exc:
        raise ProtocolError(400, "invalid_json") from exc
    if not isinstance(value, dict) or value.get("jsonrpc") != "2.0":
        raise ProtocolError(400, "invalid_jsonrpc_request")
    method = value.get("method")
    params = value.get("params", {})
    if not isinstance(method, str) or not method or not isinstance(params, dict):
        raise ProtocolError(400, "invalid_jsonrpc_request")
    metadata = params.get("_meta")
    if (
        not isinstance(metadata, dict)
        or metadata.get("io.modelcontextprotocol/protocolVersion") != "2026-07-28"
    ):
        raise ProtocolError(400, "unsupported_protocol_version")
    if protocol_version != "2026-07-28":
        raise ProtocolError(400, "protocol_version_mismatch")
    if mcp_method is None or mcp_method != method:
        raise ProtocolError(400, "method_header_mismatch")

    body_name: str | None = None
    if method == "tools/call" or method == "prompts/get":
        body_name = params.get("name")
    elif method == "resources/read":
        body_name = params.get("uri")
    if method in {"tools/call", "prompts/get", "resources/read"}:
        if not isinstance(body_name, str) or not body_name:
            raise ProtocolError(400, "missing_mcp_name")
        if mcp_name is None or _decode_header_value(mcp_name) != body_name:
            raise ProtocolError(400, "name_header_mismatch")
    elif mcp_name is not None:
        raise ProtocolError(400, "unexpected_mcp_name")
    return method, body_name, value
