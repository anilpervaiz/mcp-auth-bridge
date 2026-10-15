"""Command-line entry point."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import signal
from collections.abc import Generator, Sequence
from contextlib import contextmanager

import uvicorn

from .app import create_app, create_ops_app
from .config import BridgeSettings, ConfigurationError, load_policy


def _settings(args: argparse.Namespace) -> BridgeSettings:
    public = args.public_resource or os.getenv("MAB_PUBLIC_RESOURCE")
    issuer = args.issuer or os.getenv("MAB_ISSUER")
    upstream = args.upstream or os.getenv("MAB_UPSTREAM")
    missing = [
        name
        for name, value in (
            ("--public-resource", public),
            ("--issuer", issuer),
            ("--upstream", upstream),
        )
        if not value
    ]
    if missing:
        raise ConfigurationError("missing required settings: " + ", ".join(missing))
    assert public is not None and issuer is not None and upstream is not None
    policy_path = args.policy or os.getenv("MAB_POLICY")
    return BridgeSettings(
        public_resource=public,
        issuer=issuer,
        upstream=upstream,
        policy=load_policy(policy_path),
        allow_insecure_loopback=args.allow_insecure_loopback,
        bind_host=args.host,
        port=args.port,
        ops_host=args.ops_host,
        ops_port=args.ops_port,
    )


def _base_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="mcp-auth-bridge")
    parser.add_argument(
        "--public-resource", help="public MCP resource URI (or MAB_PUBLIC_RESOURCE)"
    )
    parser.add_argument("--issuer", help="pinned authorization-server issuer (or MAB_ISSUER)")
    parser.add_argument("--upstream", help="fixed private MCP upstream (or MAB_UPSTREAM)")
    parser.add_argument("--policy", help="optional YAML scope policy (or MAB_POLICY)")
    parser.add_argument(
        "--allow-insecure-loopback",
        action="store_true",
        help="allow HTTP only when the resource and issuer are literal loopback hosts",
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--ops-host", default="127.0.0.1")
    parser.add_argument("--ops-port", type=int, default=9090)
    return parser


async def _serve(settings: BridgeSettings) -> None:
    public = create_app(settings)
    ops = create_ops_app(public)
    servers = [
        _ManagedServer(
            uvicorn.Config(
                public,
                host=settings.bind_host,
                port=settings.port,
                log_level="info",
                access_log=False,
            )
        ),
        _ManagedServer(
            uvicorn.Config(
                ops,
                host=settings.ops_host,
                port=settings.ops_port,
                log_level="warning",
                access_log=False,
            )
        ),
    ]
    loop = asyncio.get_running_loop()

    def stop() -> None:
        for server in servers:
            server.should_exit = True

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop)
    try:
        await asyncio.gather(*(server.serve() for server in servers))
    finally:
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.remove_signal_handler(sig)


class _ManagedServer(uvicorn.Server):
    """Uvicorn server whose listeners share one process-level stop handler."""

    @contextmanager
    def capture_signals(self) -> Generator[None, None, None]:
        yield


def main(argv: Sequence[str] | None = None) -> int:
    parser = _base_parser()
    parser.add_argument(
        "command", choices=["serve", "check-config", "print-metadata"], nargs="?", default="serve"
    )
    args = parser.parse_args(argv)
    try:
        settings = _settings(args)
        if args.command == "check-config":
            print("configuration is valid")
        elif args.command == "print-metadata":
            print(json.dumps(settings.protected_resource_metadata(), indent=2))
        else:
            asyncio.run(_serve(settings))
        return 0
    except (ConfigurationError, OSError) as exc:
        parser.error(str(exc))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
