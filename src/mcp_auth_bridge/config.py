"""Immutable configuration and strict URL/policy validation."""

from __future__ import annotations

import ipaddress
import math
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any
from urllib.parse import urlsplit

import yaml

from .scopes import validate_scope_token


class ConfigurationError(ValueError):
    """A configuration value cannot be used safely."""


@dataclass(frozen=True, slots=True)
class Policy:
    global_scopes: frozenset[str] = frozenset({"mcp:use"})
    method_scopes: Mapping[str, frozenset[str]] = field(default_factory=dict)
    tool_scopes: Mapping[str, frozenset[str]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for scope in self.global_scopes:
            _validate_scope(scope, "default_scopes")
        for group, rules in (("methods", self.method_scopes), ("tools", self.tool_scopes)):
            for scopes in rules.values():
                for scope in scopes:
                    _validate_scope(scope, group)
        object.__setattr__(self, "global_scopes", frozenset(self.global_scopes))
        object.__setattr__(
            self,
            "method_scopes",
            MappingProxyType({key: frozenset(value) for key, value in self.method_scopes.items()}),
        )
        object.__setattr__(
            self,
            "tool_scopes",
            MappingProxyType({key: frozenset(value) for key, value in self.tool_scopes.items()}),
        )

    def required_for(self, method: str, name: str | None) -> frozenset[str]:
        required = set(self.global_scopes)
        required.update(self.method_scopes.get(method, frozenset()))
        if name is not None:
            required.update(self.tool_scopes.get(name, frozenset()))
        return frozenset(required)


@dataclass(frozen=True, slots=True)
class BridgeSettings:
    public_resource: str
    issuer: str
    upstream: str
    policy: Policy = field(default_factory=Policy)
    allow_insecure_loopback: bool = False
    bind_host: str = "127.0.0.1"
    port: int = 8080
    ops_host: str = "127.0.0.1"
    ops_port: int = 9090
    max_token_bytes: int = 16 * 1024
    max_body_bytes: int = 1024 * 1024
    max_metadata_bytes: int = 256 * 1024
    max_jwks_keys: int = 32
    max_concurrent_requests: int = 32
    body_timeout: float = 10.0
    connect_timeout: float = 5.0
    upstream_read_timeout: float = 60.0
    trust_fetch_timeout: float = 10.0
    dns_timeout: float = 2.0
    algorithms: tuple[str, ...] = ("RS256", "ES256")

    def __post_init__(self) -> None:
        resource = _validate_url("public resource", self.public_resource)
        issuer = _validate_url("issuer", self.issuer)
        _validate_url("upstream", self.upstream)
        if urlsplit(self.metadata_url).path == (urlsplit(self.public_resource).path or "/"):
            raise ConfigurationError(
                "the protected-resource metadata path must differ from the resource path"
            )
        local_dev = self.allow_insecure_loopback
        for name, url in (("public resource", resource), ("issuer", issuer)):
            if url.scheme != "https" and not (local_dev and _literal_loopback(url.hostname)):
                raise ConfigurationError(
                    f"{name} must use HTTPS outside explicit loopback development mode"
                )
        if not self.algorithms or any(a not in {"RS256", "ES256"} for a in self.algorithms):
            raise ConfigurationError(
                "Only the explicitly supported RS256 and ES256 algorithms are allowed"
            )
        for name in (
            "body_timeout",
            "connect_timeout",
            "upstream_read_timeout",
            "trust_fetch_timeout",
            "dns_timeout",
        ):
            value = getattr(self, name)
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(value)
                or value <= 0
            ):
                raise ConfigurationError(f"{name} must be a finite positive number")
        if not (1 <= self.port <= 65535 and 1 <= self.ops_port <= 65535):
            raise ConfigurationError("listener ports must be between 1 and 65535")
        if self.port == self.ops_port and self.bind_host == self.ops_host:
            raise ConfigurationError("public and operations listeners must use different addresses")
        if (
            min(
                self.max_token_bytes,
                self.max_body_bytes,
                self.max_metadata_bytes,
                self.max_jwks_keys,
                self.max_concurrent_requests,
            )
            <= 0
        ):
            raise ConfigurationError("size and concurrency limits must be positive")
        object.__setattr__(self, "public_resource", self.public_resource)
        object.__setattr__(self, "issuer", self.issuer)
        object.__setattr__(self, "upstream", self.upstream)

    @property
    def resource_path(self) -> str:
        path = urlsplit(self.public_resource).path
        return path or "/"

    @property
    def resource_origin(self) -> tuple[str, str, int]:
        p = urlsplit(self.public_resource)
        return _origin_tuple(p)

    @property
    def metadata_url(self) -> str:
        p = urlsplit(self.public_resource)
        suffix = p.path or ""
        path = "/.well-known/oauth-protected-resource" + suffix
        return f"{p.scheme}://{p.netloc}{path}"

    def protected_resource_metadata(self) -> dict[str, Any]:
        supported = set(self.policy.global_scopes)
        for scopes in self.policy.method_scopes.values():
            supported.update(scopes)
        for scopes in self.policy.tool_scopes.values():
            supported.update(scopes)
        return {
            "resource": self.public_resource,
            "authorization_servers": [self.issuer],
            "bearer_methods_supported": ["header"],
            "scopes_supported": sorted(supported),
        }


def _literal_loopback(host: str | None) -> bool:
    if host is None:
        return False
    if host.casefold() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _validate_url(label: str, value: str) -> Any:
    try:
        parsed = urlsplit(value)
        _ = parsed.port
    except (TypeError, ValueError) as exc:
        raise ConfigurationError(f"{label} is not a valid absolute URL") from exc
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or not parsed.netloc:
        raise ConfigurationError(f"{label} must be an absolute HTTP(S) URL")
    if parsed.username is not None or parsed.password is not None:
        raise ConfigurationError(f"{label} must not contain URL credentials")
    if parsed.port == 0:
        raise ConfigurationError(f"{label} must not use port zero")
    if parsed.query or parsed.fragment:
        raise ConfigurationError(f"{label} must not contain a query or fragment")
    return parsed


def _origin_tuple(parsed: Any) -> tuple[str, str, int]:
    scheme = parsed.scheme.casefold()
    host = parsed.hostname.casefold() if parsed.hostname else ""
    port = parsed.port or (443 if scheme == "https" else 80)
    return scheme, host, port


def origin_is_allowed(value: str, settings: BridgeSettings) -> bool:
    if value == "null" or "," in value:
        return False
    try:
        parsed = urlsplit(value)
        if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
            return False
        if parsed.username is not None or parsed.password is not None or not parsed.hostname:
            return False
        _ = parsed.port
        return _origin_tuple(parsed) == settings.resource_origin
    except ValueError:
        return False


def load_policy(path: str | Path | None) -> Policy:
    if path is None:
        return Policy()
    try:
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigurationError(f"could not read policy file: {exc}") from exc
    if not isinstance(data, dict) or set(data) - {"policy"}:
        raise ConfigurationError("policy file must contain only a top-level 'policy' object")
    body = data.get("policy", {})
    if not isinstance(body, dict) or set(body) - {"default_scopes", "methods", "tools"}:
        raise ConfigurationError("policy may contain default_scopes, methods, and tools only")
    return Policy(
        global_scopes=_scopes(body.get("default_scopes", ["mcp:use"]), "default_scopes"),
        method_scopes=_rules(body.get("methods", {}), "methods"),
        tool_scopes=_rules(body.get("tools", {}), "tools"),
    )


def _scopes(value: Any, label: str) -> frozenset[str]:
    if not isinstance(value, list):
        raise ConfigurationError(f"{label} must be a list of non-empty scope strings")
    for scope in value:
        _validate_scope(scope, label)
    return frozenset(value)


def _validate_scope(scope: Any, label: str) -> None:
    try:
        validate_scope_token(scope)
    except (TypeError, ValueError) as exc:
        raise ConfigurationError(
            f"{label} entries must follow RFC 6749 scope-token syntax"
        ) from exc


def _rules(value: Any, label: str) -> dict[str, frozenset[str]]:
    if not isinstance(value, dict) or any(not isinstance(k, str) or not k for k in value):
        raise ConfigurationError(f"{label} must be a mapping of names to scope lists")
    result = {}
    for key, scopes in value.items():
        if isinstance(scopes, dict) and set(scopes) == {"require"}:
            scopes = scopes["require"]
        result[key] = _scopes(scopes, f"{label}.{key}")
    return result
