"""SSRF-resistant, bounded HTTP fetches for issuer metadata and JWKS."""

from __future__ import annotations

import asyncio
import concurrent.futures
import ipaddress
import socket
import threading
from collections.abc import AsyncIterable
from typing import cast
from urllib.parse import urlsplit

import anyio
import httpcore


class EgressError(RuntimeError):
    """A metadata/JWKS fetch failed or targeted an unsafe destination."""


_RESOLVER_EXECUTOR = concurrent.futures.ThreadPoolExecutor(
    max_workers=2, thread_name_prefix="mab-dns"
)
_RESOLVER_SLOTS = threading.BoundedSemaphore(2)


def _allowed_ip(text: str, allow_loopback: bool) -> bool:
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return False
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return addr.is_loopback if allow_loopback else addr.is_global


async def resolve_vetted(
    host: str, port: int, allow_loopback: bool, timeout: float = 2.0
) -> list[str]:
    if not _RESOLVER_SLOTS.acquire(blocking=False):
        raise EgressError("issuer DNS resolver capacity is exhausted")

    def lookup() -> list[str]:
        try:
            try:
                items = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
            except OSError as exc:
                raise EgressError("issuer host resolution failed") from exc
            addresses: list[str] = []
            for item in items:
                address = item[4][0]
                if isinstance(address, str) and address not in addresses:
                    addresses.append(address)
            if not addresses or any(
                not _allowed_ip(address, allow_loopback) for address in addresses
            ):
                raise EgressError("issuer resolved to a forbidden network address")
            return addresses
        finally:
            _RESOLVER_SLOTS.release()

    try:
        loop = asyncio.get_running_loop()
        future = loop.run_in_executor(_RESOLVER_EXECUTOR, lookup)
        future.add_done_callback(lambda task: task.exception() if not task.cancelled() else None)
        with anyio.fail_after(timeout):
            return await asyncio.shield(future)
    except TimeoutError as exc:
        raise EgressError("issuer host resolution timed out") from exc


class SafeFetcher:
    def __init__(
        self,
        max_bytes: int,
        allow_loopback: bool,
        fetch_timeout: float = 10.0,
        dns_timeout: float = 2.0,
    ) -> None:
        self.max_bytes = max_bytes
        self.allow_loopback = allow_loopback
        self.fetch_timeout = fetch_timeout
        self.dns_timeout = dns_timeout

    async def get_json(self, url: str) -> tuple[int, bytes]:
        try:
            with anyio.fail_after(self.fetch_timeout):
                return await self._get_json(url)
        except TimeoutError as exc:
            raise EgressError("metadata fetch exceeded its time limit") from exc

    async def _get_json(self, url: str) -> tuple[int, bytes]:
        try:
            parts = urlsplit(url)
            port = parts.port or (443 if parts.scheme == "https" else 80)
            host = parts.hostname
            if parts.scheme not in {"http", "https"} or host is None:
                raise EgressError("invalid metadata URL")
            if parts.username is not None or parts.password is not None or parts.fragment:
                raise EgressError("metadata URL contains forbidden components")
            if parts.scheme != "https" and not (
                self.allow_loopback
                and host.casefold() == "localhost"
                or self.allow_loopback
                and _allowed_ip(host, True)
            ):
                raise EgressError("metadata and JWKS URLs must use HTTPS")
            addresses = await resolve_vetted(host, port, self.allow_loopback, self.dns_timeout)
            address = addresses[0]
            ip = ipaddress.ip_address(address)
            netloc = f"[{address}]" if ip.version == 6 else address
            if port != (443 if parts.scheme == "https" else 80):
                netloc += f":{port}"
            target_url = f"{parts.scheme}://{netloc}{parts.path or '/'}"
            if parts.query:
                target_url += "?" + parts.query
            default_port = 443 if parts.scheme == "https" else 80
            host_text = f"[{host}]" if ":" in host else host.encode("idna").decode("ascii")
            host_header = host_text if port == default_port else f"{host_text}:{port}"
            headers = [(b"host", host_header.encode("ascii")), (b"accept", b"application/json")]
            extensions: dict[str, object] = {
                "timeout": {"connect": 5.0, "read": 5.0, "write": 5.0, "pool": 1.0}
            }
            if parts.scheme == "https":
                extensions["sni_hostname"] = host
            async with httpcore.AsyncConnectionPool(
                max_connections=1, max_keepalive_connections=0, retries=0
            ) as pool:
                response = await pool.handle_async_request(
                    httpcore.Request("GET", target_url, headers=headers, extensions=extensions)
                )
                chunks: list[bytes] = []
                total = 0
                async for chunk in cast(AsyncIterable[bytes], response.stream):
                    total += len(chunk)
                    if total > self.max_bytes:
                        await response.aclose()
                        raise EgressError("metadata response exceeded its size limit")
                    chunks.append(chunk)
                await response.aclose()
                return response.status, b"".join(chunks)
        except EgressError:
            raise
        except (
            httpcore.NetworkError,
            httpcore.ProtocolError,
            httpcore.TimeoutException,
            OSError,
            UnicodeError,
            ValueError,
        ) as exc:
            raise EgressError("metadata fetch failed") from exc
