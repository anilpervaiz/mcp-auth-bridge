"""Pinned authorization-server discovery."""

from __future__ import annotations

from urllib.parse import urlsplit

from .config import BridgeSettings
from .egress import EgressError, SafeFetcher
from .strict_json import StrictJSONError, strict_loads


class DiscoveryError(RuntimeError):
    pass


def authorization_server_metadata_url(issuer: str) -> str:
    p = urlsplit(issuer)
    path = p.path or ""
    return f"{p.scheme}://{p.netloc}/.well-known/oauth-authorization-server{path}"


def oidc_metadata_url(issuer: str) -> str:
    return issuer.rstrip("/") + "/.well-known/openid-configuration"


class IssuerDiscovery:
    def __init__(self, settings: BridgeSettings) -> None:
        self.settings = settings
        self.fetcher = SafeFetcher(
            settings.max_metadata_bytes,
            settings.allow_insecure_loopback,
            settings.trust_fetch_timeout,
            settings.dns_timeout,
        )
        self.jwks_uri: str | None = None

    async def load(self) -> dict[str, object]:
        urls = [authorization_server_metadata_url(self.settings.issuer)]
        try:
            status, data = await self.fetcher.get_json(urls[0])
        except EgressError as exc:
            raise DiscoveryError("issuer metadata is unavailable") from exc
        if status in {404, 410}:
            urls.append(oidc_metadata_url(self.settings.issuer))
            try:
                status, data = await self.fetcher.get_json(urls[1])
            except EgressError as exc:
                raise DiscoveryError("issuer metadata is unavailable") from exc
        if status != 200:
            raise DiscoveryError("issuer metadata returned an unsuccessful status")
        try:
            metadata = strict_loads(data)
        except StrictJSONError as exc:
            raise DiscoveryError("issuer metadata is malformed JSON") from exc
        if not isinstance(metadata, dict) or metadata.get("issuer") != self.settings.issuer:
            raise DiscoveryError("metadata issuer does not exactly match configured issuer")
        jwks_uri = metadata.get("jwks_uri")
        if not isinstance(jwks_uri, str) or not jwks_uri:
            raise DiscoveryError("issuer metadata has no JWKS URI")
        self.jwks_uri = jwks_uri
        return metadata
