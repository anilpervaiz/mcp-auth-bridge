"""Run isolated headless OAuth acceptance against the disposable Keycloak realm."""

from __future__ import annotations

import argparse
import asyncio
import importlib.metadata
import json
import logging
import os
import signal
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx2

from scripts.oauth_client import (
    run_scenario,
    verify_changed_resource_binding,
    verify_unknown_resource_rejected,
)
from scripts.run_oauth_demo import KEYCLOAK_IMAGE

ROOT = Path(__file__).resolve().parents[1]
STARTUP_TIMEOUT = 600.0
VERIFIER_SHUTDOWN_GRACE = 45.0


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


async def _wait_for_demo(process: subprocess.Popen[bytes]) -> None:
    deadline = time.monotonic() + STARTUP_TIMEOUT
    async with httpx2.AsyncClient(trust_env=False, timeout=1.0) as client:
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError("OAuth demo launcher stopped before readiness")
            try:
                metadata = await client.get(
                    "http://127.0.0.1:8180/realms/mab-demo/.well-known/openid-configuration"
                )
                ready = await client.get("http://127.0.0.1:9090/readyz")
                if metadata.status_code == 200 and ready.status_code == 200:
                    return
            except httpx2.HTTPError:
                pass
            await asyncio.sleep(0.5)
    raise TimeoutError("Keycloak or the bridge did not become ready")


async def _stop_launcher(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    process.send_signal(signal.SIGINT)
    try:
        await asyncio.wait_for(asyncio.to_thread(process.wait), timeout=VERIFIER_SHUTDOWN_GRACE)
    except TimeoutError:
        process.kill()
        await asyncio.to_thread(process.wait)


def _scenario_report(result: Any) -> dict[str, Any]:
    return {
        "tool_listing": result.list_tools_succeeded,
        "echo": result.echo_succeeded,
        "admin_allowed": result.admin_succeeded,
        "admin_denied": result.admin_denied,
        "admin_status_code": result.admin_status_code,
        "upstream_call_count_unchanged": result.upstream_call_count_unchanged,
        "refresh_count": result.refresh_count,
        "scope_step_up_preserved": result.scope_step_up_preserved,
        "resource_binding_valid": result.resource_binding_valid,
        "singleton_audience_valid": result.singleton_audience_valid,
        "issuance_claims_valid": result.issuance_claims_valid,
        "grant_counts": result.grant_counts,
        "token_response_status_codes": result.token_response_statuses,
        "upstream_response_status_codes": result.upstream_response_statuses,
        "refresh_replay_status_code": result.replay_status_code,
        "refresh_replay_error": result.replay_error_code,
        "replay_session_discarded": result.replay_session_discarded,
    }


def _exception_types(exc: BaseException) -> list[str]:
    """Return only exception class names, including grouped async failures."""
    found: set[str] = set()
    pending = [exc]
    while pending:
        current = pending.pop()
        found.add(type(current).__name__)
        nested = getattr(current, "exceptions", ())
        if isinstance(nested, tuple):
            pending.extend(item for item in nested if isinstance(item, BaseException))
    return sorted(found)


def _load_launcher_cleanup(path: Path | None, *, launcher_exit_code: int | None) -> dict[str, bool]:
    if path is None:
        clean_exit = launcher_exit_code == 0
        return {
            "owned_processes_reaped": clean_exit,
            "owned_container_removed": clean_exit,
        }
    if not path.exists():
        return {"owned_processes_reaped": False, "owned_container_removed": False}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        cleanup = payload.get("cleanup") if isinstance(payload, dict) else None
    except (OSError, json.JSONDecodeError):
        cleanup = None
    if not isinstance(cleanup, dict):
        return {"owned_processes_reaped": False, "owned_container_removed": False}
    return {
        "owned_processes_reaped": cleanup.get("owned_processes_reaped") is True,
        "owned_container_removed": cleanup.get("owned_container_removed") is True,
    }


async def run(report_path: Path | None = None) -> None:
    logging.getLogger("mcp.client.auth.oauth2").disabled = True
    outcomes: dict[str, Any] = {}
    stage = "readiness"
    cleanup_path = (
        report_path.with_name(f".{report_path.name}.launcher-{uuid.uuid4().hex}.json")
        if report_path is not None
        else None
    )
    env = os.environ.copy()
    launcher_args = [sys.executable, "-m", "scripts.run_oauth_demo"]
    if cleanup_path is not None:
        launcher_args.extend(["--report", str(cleanup_path)])
    launcher = subprocess.Popen(  # noqa: ASYNC220 - own process handle for bounded cleanup
        launcher_args,
        cwd=ROOT,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    successful = False
    cleanup: dict[str, bool] = {
        "verifier_launcher_exited": False,
        "owned_processes_reaped": False,
        "owned_container_removed": False,
    }
    try:
        await _wait_for_demo(launcher)
        stage = "basic"
        basic = await run_scenario("mcp-basic", headless=True, refreshes=0, callback_timeout=60.0)
        outcomes["basic"] = _scenario_report(basic)
        stage = "admin"
        administrator = await run_scenario(
            "mcp-admin", headless=True, refreshes=0, callback_timeout=60.0
        )
        outcomes["admin"] = _scenario_report(administrator)
        stage = "refresh"
        refresh = await run_scenario("mcp-basic", headless=True, refreshes=2, callback_timeout=60.0)
        outcomes["refresh"] = _scenario_report(refresh)
        stage = "refresh_replay"
        replay = await run_scenario(
            "mcp-basic",
            headless=True,
            refreshes=1,
            callback_timeout=60.0,
            replay_old_refresh=True,
        )
        outcomes["refresh_replay"] = _scenario_report(replay)

        stage = "resource_binding"
        resource_outcomes = await verify_changed_resource_binding(headless=True)
        outcomes["resource_binding"] = resource_outcomes
        stage = "unknown_resource"
        unknown_outcomes = await verify_unknown_resource_rejected(headless=True)
        outcomes["unknown_resource"] = unknown_outcomes

        if not basic.admin_denied or basic.admin_succeeded:
            raise RuntimeError("basic account did not remain blocked from the admin operation")
        if not administrator.admin_succeeded:
            raise RuntimeError("admin account did not reach the admin operation")
        if refresh.refresh_count != 2:
            raise RuntimeError("two successive rotating refreshes did not complete")
        if replay.replay_status_code != 400 or replay.replay_error_code != "invalid_grant":
            raise RuntimeError("old refresh token replay did not return invalid_grant")
        if not replay.replay_session_discarded:
            raise RuntimeError("refresh replay session was not discarded")
        if basic.upstream_call_count_unchanged is not True or basic.admin_status_code != 403:
            raise RuntimeError("basic admin denial did not preserve the upstream call count")
        successful = True
    except Exception as exc:
        outcomes["failure"] = {
            "stage": stage,
            "reason_code": type(exc).__name__,
            "cause_codes": _exception_types(exc),
        }
        raise
    finally:
        await _stop_launcher(launcher)
        cleanup["verifier_launcher_exited"] = launcher.poll() == 0
        launcher_cleanup = _load_launcher_cleanup(
            cleanup_path, launcher_exit_code=launcher.returncode
        )
        cleanup.update(launcher_cleanup)
        if cleanup_path is not None:
            cleanup_path.unlink(missing_ok=True)
        if report_path is not None:
            report_path.parent.mkdir(parents=True, exist_ok=True)
            try:
                sdk_version = importlib.metadata.version("mcp")
            except importlib.metadata.PackageNotFoundError:
                sdk_version = "unavailable"
            image, digest = KEYCLOAK_IMAGE.split("@", 1)
            report = {
                "schema": "mab-oauth-acceptance-v1",
                "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                "revision": _revision(),
                "versions": {
                    "python": sys.version.split()[0],
                    "mcp_sdk": sdk_version,
                    "keycloak_image": image,
                    "keycloak_image_digest": digest,
                },
                "headless": True,
                "passed": successful and all(cleanup.values()),
                "scenarios": outcomes,
                "cleanup": cleanup,
            }
            report_path.write_text(
                json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8"
            )
    if not all(cleanup.values()):
        raise RuntimeError("OAuth demo cleanup could not be verified")
    print(
        "OAuth browser acceptance passed: SDK discovery, basic/admin policy, resource binding, "
        "unknown-resource rejection, and two rotating refreshes."
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, help="write allow-listed JSON evidence to PATH")
    args = parser.parse_args()
    try:
        asyncio.run(run(args.report))
    except Exception as exc:  # noqa: BLE001 - suppress provider, browser, and remote details
        del exc
        raise SystemExit("OAuth browser acceptance failed safely") from None


if __name__ == "__main__":
    main()
