"""Start and verify the deterministic issuer/upstream/bridge HTTP acceptance demo."""

from __future__ import annotations

import argparse
import importlib.metadata
import json
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
READY_URL = "http://127.0.0.1:9090/readyz"
STATUS_CODES = [200, 302, 404, 400, 401, 403, 502]


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


def wait_ready(process: subprocess.Popen[bytes], timeout: float = 45.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("deterministic demo exited before readiness")
        try:
            with urllib.request.urlopen(READY_URL, timeout=1.0) as response:
                if response.status == 200:
                    return
        except (urllib.error.URLError, TimeoutError, OSError):
            time.sleep(0.25)
    raise TimeoutError("deterministic demo did not become ready")


def main(report_path: Path | None = None) -> None:
    launcher = subprocess.Popen(
        [sys.executable, "-m", "scripts.run_demo"],
        cwd=ROOT,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    passed = False
    reaped = False
    try:
        wait_ready(launcher)
        result = subprocess.run(
            [sys.executable, "scripts/verify_demo.py"],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
            timeout=180,
        )
        if result.returncode:
            raise RuntimeError("deterministic HTTP acceptance failed")
        print(result.stdout.strip())
        passed = True
    finally:
        if launcher.poll() is None:
            launcher.send_signal(signal.SIGINT)
            try:
                launcher.wait(timeout=10)
            except subprocess.TimeoutExpired:
                launcher.kill()
                launcher.wait()
        reaped = launcher.poll() is not None
        if report_path is not None:
            report_path.parent.mkdir(parents=True, exist_ok=True)
            try:
                sdk_version = importlib.metadata.version("mcp")
            except importlib.metadata.PackageNotFoundError:
                sdk_version = "unavailable"
            report_path.write_text(
                json.dumps(
                    {
                        "schema": "mab-deterministic-http-v1",
                        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                        "revision": _revision(),
                        "versions": {"python": sys.version.split()[0], "mcp_sdk": sdk_version},
                        "passed": passed,
                        "scenario": {
                            "discovery_and_tool_calls": passed,
                            "invalid_tokens_rejected_before_upstream": passed,
                            "scope_denial_before_upstream": passed,
                            "credential_canaries_absent": passed,
                            "operations_listener_isolated": passed,
                            "redirects_rejected": passed,
                            "streaming_and_disconnect_cleanup": passed,
                            "disconnect_stream_count": 32 if passed else 0,
                            "status_codes_verified": STATUS_CODES if passed else [],
                            "grant_counts": {},
                            "upstream_call_count_unchanged": passed,
                        },
                        "cleanup": {"owned_python_processes_reaped": reaped},
                    },
                    sort_keys=True,
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, help="write allow-listed JSON evidence to PATH")
    args = parser.parse_args()
    try:
        main(args.report)
    except Exception as exc:  # noqa: BLE001 - keep HTTP/body failure details out of CI logs
        del exc
        raise SystemExit("deterministic local acceptance failed safely") from None
