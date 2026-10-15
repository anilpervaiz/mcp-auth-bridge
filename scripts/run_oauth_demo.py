"""Run disposable Keycloak, the local MCP upstream, and the protected bridge."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import secrets
import signal
import socket
import subprocess
import sys
import time
import uuid
from collections.abc import Awaitable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TypeVar

import httpx2

from mcp_auth_bridge.strict_json import strict_loads

ROOT = Path(__file__).resolve().parents[1]
ISSUER = "http://127.0.0.1:8180/realms/mab-demo"
RESOURCE = "http://127.0.0.1:8080/mcp"
UPSTREAM = "http://127.0.0.1:8000/mcp"
CALLBACK = "http://127.0.0.1:8765/callback"
KEYCLOAK_IMAGE = (
    "quay.io/keycloak/keycloak:26.8.0@sha256:"
    "b0f60d489d51c5d113390bdf5461d4c06e6051be026c05549f2e1e10ec352bcc"
)
REALM_FILE = ROOT / "examples/oauth/keycloak/mab-demo-realm.json"
STARTUP_TIMEOUT = 600.0
CLEANUP_TIMEOUT = 30.0
_Result = TypeVar("_Result")


def require_free_ports(ports: tuple[int, ...] = (8000, 8080, 8180, 8765, 8766, 9090)) -> None:
    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.bind(("127.0.0.1", port))
                sock.listen(1)
            except OSError as exc:
                raise RuntimeError(f"required loopback port {port} is occupied") from exc


def _revision() -> str | None:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
            timeout=2,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    value = result.stdout.strip()
    return value if result.returncode == 0 and len(value) == 40 else None


async def _docker(
    args: list[str], *, timeout: float, env: dict[str, str] | None = None
) -> tuple[int, bytes, bytes]:
    """Run Docker without blocking the event loop and reap it on cancellation."""
    try:
        process = await asyncio.create_subprocess_exec(
            "docker",
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )
    except FileNotFoundError:
        raise RuntimeError("Docker is required; start Docker Desktop and retry") from None
    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
    except (asyncio.CancelledError, TimeoutError):
        if process.returncode is None:
            process.terminate()
            try:
                await asyncio.wait_for(process.wait(), timeout=2)
            except TimeoutError:
                process.kill()
                await process.wait()
        raise
    status = process.returncode
    return (status if status is not None else 1), stdout, stderr


async def ensure_docker() -> None:
    try:
        status, stdout, _stderr = await _docker(
            ["info", "--format", "{{.ServerVersion}}"], timeout=5
        )
    except (TimeoutError, OSError) as exc:
        raise RuntimeError("Docker is required; start Docker Desktop and retry") from exc
    if status or not stdout.strip():
        raise RuntimeError(
            "Docker is installed but its engine is unavailable; start Docker Desktop"
        )


async def wait_http(
    url: str,
    process: subprocess.Popen[bytes] | None,
    deadline: float,
    *,
    expected_status: int = 200,
) -> None:
    async with httpx2.AsyncClient(trust_env=False, timeout=1.0) as client:
        while time.monotonic() < deadline:
            if process is not None and process.poll() is not None:
                raise RuntimeError("a local demo process exited before it became ready")
            try:
                response = await client.get(url)
                if response.status_code == expected_status:
                    return
            except httpx2.HTTPError:
                pass
            await asyncio.sleep(0.25)
    raise TimeoutError("a local demo service did not become ready")


async def _race_stop(awaitable: Awaitable[_Result], stop_requested: asyncio.Event) -> _Result:
    """Cancel startup work promptly when the launcher receives a stop signal."""
    work = asyncio.ensure_future(awaitable)
    stopped = asyncio.create_task(stop_requested.wait())
    try:
        done, _pending = await asyncio.wait((work, stopped), return_when=asyncio.FIRST_COMPLETED)
        if stopped in done and not work.done():
            work.cancel()
            await asyncio.gather(work, return_exceptions=True)
            raise RuntimeError("OAuth demo startup was interrupted")
        return await work
    finally:
        for task in (work, stopped):
            if not task.done():
                task.cancel()
        await asyncio.gather(work, stopped, return_exceptions=True)


async def _remove_owned_container(name: str, deadline: float) -> bool:
    """Remove this launcher's uniquely named container and verify it is gone."""
    while time.monotonic() < deadline:
        remaining = deadline - time.monotonic()
        try:
            status, stdout, _stderr = await _docker(
                ["ps", "--all", "--quiet", "--no-trunc", "--filter", f"name={name}"],
                timeout=min(3.0, max(0.01, remaining)),
            )
        except (OSError, TimeoutError):
            await asyncio.sleep(min(0.25, max(0.0, deadline - time.monotonic())))
            continue
        if status != 0:
            await asyncio.sleep(min(0.25, max(0.0, deadline - time.monotonic())))
            continue
        ids = [
            line.strip()
            for line in stdout.decode("ascii", errors="ignore").splitlines()
            if line.strip()
        ]
        if not ids:
            return True

        remaining = deadline - time.monotonic()
        try:
            await _docker(["stop", "--time", "2", *ids], timeout=min(5.0, max(0.01, remaining)))
        except (OSError, TimeoutError):
            pass

        # A graceful stop should remove a container created with --rm. If it
        # remains (including after partial startup), force-remove its exact ID.
        remaining = deadline - time.monotonic()
        try:
            await _docker(["rm", "--force", *ids], timeout=min(5.0, max(0.01, remaining)))
        except (OSError, TimeoutError):
            pass

        await asyncio.sleep(min(0.25, max(0.0, deadline - time.monotonic())))
    return False


async def start_keycloak(admin_password: str, name: str, deadline: float) -> None:
    env = os.environ.copy()
    env["KC_BOOTSTRAP_ADMIN_PASSWORD"] = admin_password
    args = [
        "create",
        "--rm",
        "--name",
        name,
        "--pull=missing",
        "--publish",
        "127.0.0.1:8180:8080",
        "--env",
        "KC_BOOTSTRAP_ADMIN_USERNAME=mab-bootstrap",
        "--env",
        "KC_BOOTSTRAP_ADMIN_PASSWORD",
        "--volume",
        f"{REALM_FILE}:/opt/keycloak/data/import/mab-demo-realm.json:ro",
        KEYCLOAK_IMAGE,
        "start-dev",
        "--features=resource-indicators",
        "--import-realm",
        "--hostname=http://127.0.0.1:8180",
    ]
    try:
        status, stdout, _stderr = await _docker(
            args,
            timeout=max(0.01, deadline - time.monotonic()),
            env=env,
        )
    except (OSError, TimeoutError):
        raise RuntimeError("could not create pinned Keycloak container") from None
    if status:
        raise RuntimeError("could not create pinned Keycloak container")
    container_id = stdout.decode("ascii", errors="ignore").strip()
    if not container_id:
        raise RuntimeError("Docker did not return the Keycloak container ID")
    try:
        status, _stdout, _stderr = await _docker(
            ["start", container_id], timeout=min(30, max(0.01, deadline - time.monotonic()))
        )
    except (OSError, TimeoutError):
        raise RuntimeError("could not start the Keycloak container") from None
    if status:
        raise RuntimeError("could not start the Keycloak container")


async def run(report_path: Path | None = None) -> None:
    await ensure_docker()
    require_free_ports()
    admin_password = secrets.token_urlsafe(32)
    container_name = f"mab-oauth-{uuid.uuid4().hex[:10]}"
    processes: list[subprocess.Popen[bytes]] = []
    cleanup_state = {"owned_processes_reaped": False, "owned_container_removed": False}
    stop_requested = asyncio.Event()
    loop = asyncio.get_running_loop()
    for stop_signal in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(stop_signal, stop_requested.set)
    try:
        deadline = time.monotonic() + STARTUP_TIMEOUT
        await _race_stop(start_keycloak(admin_password, container_name, deadline), stop_requested)
        await _race_stop(
            wait_http(f"{ISSUER}/.well-known/openid-configuration", None, deadline),
            stop_requested,
        )

        from scripts.oauth_keycloak import configure_realm

        await _race_stop(
            asyncio.wait_for(
                configure_realm(admin_password),
                timeout=max(0.01, deadline - time.monotonic()),
            ),
            stop_requested,
        )

        async def read_metadata() -> dict[str, Any]:
            async with httpx2.AsyncClient(trust_env=False, timeout=5.0) as client:
                metadata_response = await client.get(f"{ISSUER}/.well-known/openid-configuration")
                metadata_response.raise_for_status()
                payload = strict_loads(metadata_response.content)
                if not isinstance(payload, dict):
                    raise TypeError("Keycloak returned malformed metadata")
                metadata: dict[str, Any] = {}
                for key, value in payload.items():
                    if not isinstance(key, str):
                        raise TypeError("Keycloak returned malformed metadata")
                    metadata[key] = value
                return metadata

        metadata = await _race_stop(read_metadata(), stop_requested)
        if metadata.get("issuer") != ISSUER:
            raise RuntimeError("Keycloak returned an unexpected issuer URL")
        if "offline_access" in metadata.get("scopes_supported", []):
            raise RuntimeError("Keycloak unexpectedly advertises offline_access")

        env = os.environ.copy()
        env["MAB_DEMO_CONFIRM_LOOPBACK"] = "yes"
        processes.append(
            subprocess.Popen(  # noqa: ASYNC220 - keep owned process handles for bounded cleanup
                [sys.executable, "-m", "examples.demo.server"],
                cwd=ROOT,
                env=env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        )
        await _race_stop(
            wait_http(UPSTREAM, processes[-1], deadline, expected_status=405),
            stop_requested,
        )
        processes.append(
            subprocess.Popen(  # noqa: ASYNC220 - keep owned process handles for bounded cleanup
                [
                    sys.executable,
                    "-m",
                    "mcp_auth_bridge.cli",
                    "serve",
                    "--public-resource",
                    RESOURCE,
                    "--issuer",
                    ISSUER,
                    "--upstream",
                    UPSTREAM,
                    "--policy",
                    "examples/demo/policy.yaml",
                    "--allow-insecure-loopback",
                ],
                cwd=ROOT,
                env=env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        )
        await _race_stop(
            wait_http("http://127.0.0.1:9090/readyz", processes[-1], deadline),
            stop_requested,
        )
        print(f"MCP resource: {RESOURCE}")
        print(f"Keycloak issuer: {ISSUER}")
        print(f"OAuth callback: {CALLBACK}")
        print("Demo users and passwords are documented in the local OAuth quickstart.")
        print("Run `uv run python -m scripts.oauth_client --scenario basic` in another terminal.")
        while all(process.poll() is None for process in processes):
            try:
                await asyncio.wait_for(stop_requested.wait(), timeout=0.4)
                break
            except TimeoutError:
                continue
        if not stop_requested.is_set():
            raise RuntimeError("a local demo process stopped unexpectedly")
    except KeyboardInterrupt:
        pass
    finally:

        async def cleanup() -> None:
            cleanup_deadline = time.monotonic() + CLEANUP_TIMEOUT
            for process in reversed(processes):
                if process.poll() is None:
                    process.send_signal(signal.SIGTERM)
            if processes:
                try:
                    await asyncio.wait_for(
                        asyncio.gather(*(asyncio.to_thread(process.wait) for process in processes)),
                        timeout=min(15, max(0.01, cleanup_deadline - time.monotonic() - 15)),
                    )
                except TimeoutError:
                    for process in processes:
                        if process.poll() is None:
                            process.kill()
                    await asyncio.gather(
                        *(asyncio.to_thread(process.wait) for process in processes),
                        return_exceptions=True,
                    )
            cleanup_state["owned_processes_reaped"] = all(
                process.poll() is not None for process in processes
            )
            cleanup_state["owned_container_removed"] = await _remove_owned_container(
                container_name, cleanup_deadline
            )
            if report_path is not None:
                report_path.parent.mkdir(parents=True, exist_ok=True)
                report_path.write_text(
                    json.dumps(
                        {
                            "schema": "mab-oauth-cleanup-v1",
                            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                            "revision": _revision(),
                            "versions": {
                                "python": sys.version.split()[0],
                                "keycloak": "26.8.0",
                                "keycloak_image_digest": KEYCLOAK_IMAGE.split("@", 1)[1],
                            },
                            "cleanup": cleanup_state,
                        },
                        sort_keys=True,
                    )
                    + "\n",
                    encoding="utf-8",
                )

        cleanup_task = asyncio.create_task(cleanup())
        try:
            await asyncio.shield(cleanup_task)
        except asyncio.CancelledError:
            await cleanup_task
            raise
        for stop_signal in (signal.SIGINT, signal.SIGTERM):
            loop.remove_signal_handler(stop_signal)
        if not all(cleanup_state.values()):
            raise RuntimeError("owned OAuth demo resources could not be fully cleaned up")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, help="write safe cleanup evidence to PATH")
    args = parser.parse_args()
    try:
        asyncio.run(run(args.report))
    except (RuntimeError, TimeoutError, OSError) as exc:
        raise SystemExit(str(exc)) from None


if __name__ == "__main__":
    main()
