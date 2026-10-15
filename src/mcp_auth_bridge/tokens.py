"""JWT validation and immutable validated principal."""

from __future__ import annotations

import base64
import binascii
import math
import time
from dataclasses import dataclass
from typing import Any

from joserfc import jwk, jwt
from joserfc.errors import JoseError
from joserfc.jws import extract_compact

from .discovery import DiscoveryError
from .egress import EgressError
from .scopes import parse_scope_value
from .strict_json import StrictJSONError, strict_loads


class TokenError(ValueError):
    def __init__(self, reason: str = "invalid_token") -> None:
        self.reason = reason
        super().__init__(reason)


class TrustUnavailable(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class Principal:
    issuer: str
    subject: str | None
    client_id: str | None
    scopes: frozenset[str]


def parse_scopes(claims: dict[str, Any]) -> frozenset[str]:
    key = "scope" if "scope" in claims else "scp"
    raw = claims.get(key, "")
    if not isinstance(raw, str):
        raise TokenError()
    try:
        return parse_scope_value(raw)
    except ValueError as exc:
        raise TokenError() from exc


class JwksCache:
    """Bounded JWKS state with refresh coalescing and short unknown-kid cooldown."""

    FRESH_SECONDS = 3600.0
    STALE_SECONDS = 300.0
    REFRESH_COOLDOWN = 60.0
    NEGATIVE_SECONDS = 30.0
    NEGATIVE_MAX = 256

    def __init__(self, settings: Any, discovery: Any) -> None:
        self.settings = settings
        self.discovery = discovery
        self.keys: list[dict[str, Any]] = []
        self.loaded_at = 0.0
        self.last_attempt = 0.0
        self.negative: dict[tuple[str, str], float] = {}
        self._ready = False
        self._lock: Any = None

    @property
    def ready(self) -> bool:
        """Whether trusted keys remain inside the fresh-plus-stale validity window."""
        return (
            self._ready
            and bool(self.keys)
            and time.monotonic() - self.loaded_at < self.FRESH_SECONDS + self.STALE_SECONDS
        )

    async def start(self) -> None:
        import anyio

        self._lock = anyio.Lock()
        await self.refresh(force=True)

    async def refresh(self, force: bool = False) -> bool:
        if self._lock is None:
            import anyio

            self._lock = anyio.Lock()
        async with self._lock:
            now = time.monotonic()
            if not force and now - self.last_attempt < self.REFRESH_COOLDOWN:
                return self.ready
            self.last_attempt = now
            try:
                if self.discovery.jwks_uri is None or now - self.loaded_at >= self.FRESH_SECONDS:
                    await self.discovery.load()
                assert self.discovery.jwks_uri is not None
                status, body = await self.discovery.fetcher.get_json(self.discovery.jwks_uri)
                if status != 200:
                    raise TrustUnavailable()
                raw = strict_loads(body)
                candidates = raw.get("keys") if isinstance(raw, dict) else None
                if (
                    not isinstance(candidates, list)
                    or not 1 <= len(candidates) <= self.settings.max_jwks_keys
                ):
                    raise TrustUnavailable()
                clean: list[dict[str, Any]] = []
                for candidate in candidates:
                    key = _eligible_jwk(candidate, self.settings.algorithms)
                    if key is not None:
                        clean.append(key)
                if not clean:
                    raise TrustUnavailable()
                self.keys = clean
                self.loaded_at = time.monotonic()
                self.negative.clear()
                self._ready = True
                return True
            except (
                DiscoveryError,
                EgressError,
                TrustUnavailable,
                UnicodeDecodeError,
                TypeError,
                ValueError,
            ):
                self._ready = bool(self.keys)
                return self.ready

    async def key_for(self, kid: str | None, alg: str) -> dict[str, Any] | None:
        now = time.monotonic()
        if now - self.loaded_at > self.FRESH_SECONDS:
            await self.refresh()
        if not self.ready:
            return None
        eligible = [key for key in self.keys if _algorithm_matches(key, alg)]
        if kid is None:
            return eligible[0] if len(eligible) == 1 else None
        matches = [key for key in eligible if key.get("kid") == kid]
        if len(matches) == 1:
            return matches[0]
        if len(matches) > 1:
            return None
        negative_key = (kid, alg)
        if self.negative.get(negative_key, 0) > now:
            return None
        if len(self.negative) >= self.NEGATIVE_MAX:
            oldest = min(self.negative, key=lambda item: self.negative[item])
            self.negative.pop(oldest, None)
        self.negative[negative_key] = now + self.NEGATIVE_SECONDS
        await self.refresh()
        matches = [
            key for key in self.keys if key.get("kid") == kid and _algorithm_matches(key, alg)
        ]
        return matches[0] if len(matches) == 1 else None


def _decode_jwt_segment(segment: str) -> bytes:
    try:
        encoded = segment.encode("ascii")
        if not encoded or any(
            byte not in b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
            for byte in encoded
        ):
            raise ValueError("invalid base64url segment")
        return base64.b64decode(encoded + b"=" * (-len(encoded) % 4), altchars=b"-_", validate=True)
    except (UnicodeError, binascii.Error, ValueError) as exc:
        raise TokenError() from exc


def _eligible_jwk(item: Any, algorithms: frozenset[str]) -> dict[str, Any] | None:
    if not isinstance(item, dict):
        return None
    if any(name in item for name in ("d", "p", "q", "dp", "dq", "qi", "oth")):
        return None
    if item.get("use", "sig") != "sig" or item.get("key_ops", ["verify"]) != ["verify"]:
        return None
    declared_alg = item.get("alg")
    if declared_alg is not None and (
        not isinstance(declared_alg, str) or declared_alg not in algorithms
    ):
        return None
    try:
        key = jwk.import_key(item)
        if item.get("kty") == "RSA":
            if "RS256" not in algorithms or declared_alg not in {None, "RS256"}:
                return None
            public = key.as_dict()
            modulus = public.get("n")
            if not isinstance(modulus, str):
                return None
            decoded = base64.urlsafe_b64decode(modulus + "=" * (-len(modulus) % 4))
            if int.from_bytes(decoded, "big").bit_length() < 2048:
                return None
        elif item.get("kty") == "EC":
            if (
                "ES256" not in algorithms
                or declared_alg not in {None, "ES256"}
                or item.get("crv") != "P-256"
            ):
                return None
        else:
            return None
        return item
    except (JoseError, TypeError, ValueError, binascii.Error):
        return None


def _algorithm_matches(key: dict[str, Any], alg: str) -> bool:
    declared_alg = key.get("alg")
    return declared_alg in {None, alg} and (
        (alg == "RS256" and key.get("kty") == "RSA")
        or (alg == "ES256" and key.get("kty") == "EC" and key.get("crv") == "P-256")
    )


async def validate_token(token_text: str, settings: Any, cache: JwksCache) -> Principal:
    if len(token_text.encode("utf-8")) > settings.max_token_bytes:
        raise TokenError()
    try:
        parts = token_text.split(".")
        if len(parts) != 3:
            raise TokenError()
        header = strict_loads(_decode_jwt_segment(parts[0]))
        strict_claims = strict_loads(_decode_jwt_segment(parts[1]))
        if not isinstance(header, dict) or not isinstance(strict_claims, dict):
            raise TokenError()
        compact = extract_compact(token_text.encode("ascii"))
        if compact.headers() != header:
            raise TokenError()
    except (JoseError, StrictJSONError, ValueError, TypeError) as exc:
        raise TokenError() from exc
    alg = header.get("alg")
    if not isinstance(alg, str) or alg not in settings.algorithms or "crit" in header:
        raise TokenError()
    typ = header.get("typ")
    if typ is not None and (
        not isinstance(typ, str) or typ not in {"JWT", "at+jwt", "application/at+jwt"}
    ):
        raise TokenError()
    kid = header.get("kid")
    if kid is not None and (not isinstance(kid, str) or not kid):
        raise TokenError()
    key_data = await cache.key_for(kid, alg)
    if key_data is None:
        if not cache.ready:
            raise TrustUnavailable()
        raise TokenError()
    try:
        key = jwk.import_key(key_data)
        decoded = jwt.decode(token_text, key, algorithms=[alg])
    except (JoseError, ValueError, TypeError) as exc:
        raise TokenError() from exc
    claims = strict_claims
    if decoded.claims != claims:
        raise TokenError()
    if not cache.ready:
        raise TrustUnavailable()
    issuer = claims.get("iss")
    if not isinstance(issuer, str) or issuer != settings.issuer:
        raise TokenError()
    aud = claims.get("aud")
    if isinstance(aud, str):
        audience = aud
    elif isinstance(aud, list) and len(aud) == 1 and isinstance(aud[0], str):
        audience = aud[0]
    else:
        raise TokenError()
    if audience != settings.public_resource:
        raise TokenError()
    exp = _numeric_date(claims.get("exp"))
    now = time.time()
    leeway = 30.0
    if now > exp + leeway:
        raise TokenError()
    if "nbf" in claims and now + leeway < _numeric_date(claims["nbf"]):
        raise TokenError()
    if "iat" in claims and _numeric_date(claims["iat"]) > now + leeway:
        raise TokenError()
    sub = claims.get("sub")
    if sub is not None and (not isinstance(sub, str) or not sub):
        raise TokenError()
    client_id = claims.get("client_id")
    if client_id is not None and (not isinstance(client_id, str) or not client_id):
        client_id = None
    if not cache.ready:
        raise TrustUnavailable()
    return Principal(issuer=issuer, subject=sub, client_id=client_id, scopes=parse_scopes(claims))


def _numeric_date(value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TokenError()
    try:
        result = float(value)
    except OverflowError as exc:
        raise TokenError() from exc
    if not math.isfinite(result):
        raise TokenError()
    return result
