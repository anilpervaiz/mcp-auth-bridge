from __future__ import annotations

import asyncio
import time

import pytest

import scripts.run_oauth_demo as launcher
from scripts.run_oauth_demo import _race_stop


@pytest.mark.asyncio
async def test_launcher_stop_cancels_pending_startup_operation() -> None:
    stop_requested = asyncio.Event()
    cancelled = asyncio.Event()

    async def blocked_startup() -> None:
        try:
            await asyncio.Event().wait()
        finally:
            cancelled.set()

    startup = asyncio.create_task(_race_stop(blocked_startup(), stop_requested))
    await asyncio.sleep(0)
    stop_requested.set()

    with pytest.raises(RuntimeError, match="startup was interrupted"):
        await asyncio.wait_for(startup, timeout=1)

    assert cancelled.is_set()


@pytest.mark.asyncio
async def test_container_cleanup_force_removes_and_verifies_unique_container(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[list[str]] = []
    listings = [(0, b"owned-container-id\n", b""), (0, b"", b"")]

    async def fake_docker(
        args: list[str], *, timeout: float, env: dict[str, str] | None = None
    ) -> tuple[int, bytes, bytes]:
        del timeout, env
        calls.append(args)
        if args[0] == "ps":
            return listings.pop(0)
        return 0, b"", b""

    monkeypatch.setattr(launcher, "_docker", fake_docker)

    assert await launcher._remove_owned_container("mab-oauth-test", time.monotonic() + 2.0)
    assert ["rm", "--force", "owned-container-id"] in calls
    assert ["ps", "--all", "--quiet", "--no-trunc", "--filter", "name=mab-oauth-test"] in calls


def test_port_guard_rejects_an_active_listener() -> None:
    import socket

    with socket.socket() as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        with pytest.raises(RuntimeError, match="occupied"):
            launcher.require_free_ports((port,))


def test_port_guard_accepts_a_closed_listener_after_connections() -> None:
    import socket

    with socket.socket() as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        with socket.create_connection(("127.0.0.1", port), timeout=1) as client:
            connection, _ = listener.accept()
            connection.close()
            assert client.recv(1) == b""
    launcher.require_free_ports((port,))
