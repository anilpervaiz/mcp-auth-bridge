"""Start the loopback issuer, demo MCP server, and bridge; Ctrl+C stops all three."""

from __future__ import annotations

import os
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def wait_ready(url: str, process: subprocess.Popen[bytes]) -> None:
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"demo process exited before ready: {url}")
        try:
            with urllib.request.urlopen(url, timeout=0.5) as response:
                if response.status < 500:
                    return
        except urllib.error.HTTPError as response:
            if response.code < 500:
                return
        except (urllib.error.URLError, TimeoutError, OSError):
            time.sleep(0.2)
    raise TimeoutError(f"demo process did not become ready: {url}")


def _require_free_ports(ports: tuple[int, ...]) -> None:
    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
            connection.settimeout(0.2)
            if connection.connect_ex(("127.0.0.1", port)) == 0:
                raise RuntimeError(f"demo port {port} is already in use; stop its owner first")


def main() -> None:
    _require_free_ports((8000, 8080, 8180, 9090))
    env = os.environ.copy()
    env["MAB_DEMO_CONFIRM_LOOPBACK"] = "yes"
    processes: list[subprocess.Popen[bytes]] = []
    commands = [
        [sys.executable, "-m", "examples.demo.issuer"],
        [sys.executable, "-m", "examples.demo.server"],
    ]
    try:
        for command in commands:
            processes.append(subprocess.Popen(command, cwd=ROOT, env=env))
        wait_ready(
            "http://127.0.0.1:8180/.well-known/oauth-authorization-server/issuer", processes[0]
        )
        wait_ready("http://127.0.0.1:8000/mcp", processes[1])
        bridge = [
            sys.executable,
            "-m",
            "mcp_auth_bridge.cli",
            "serve",
            "--public-resource",
            "http://127.0.0.1:8080/mcp",
            "--issuer",
            "http://127.0.0.1:8180/issuer",
            "--upstream",
            "http://127.0.0.1:8000/mcp",
            "--policy",
            "examples/demo/policy.yaml",
            "--allow-insecure-loopback",
        ]
        processes.append(subprocess.Popen(bridge, cwd=ROOT, env=env))
        print("Bridge:   http://127.0.0.1:8080/mcp")
        print("Metadata: http://127.0.0.1:8080/.well-known/oauth-protected-resource/mcp")
        print("Ops:      http://127.0.0.1:9090/readyz (loopback only)")
        print(
            "Run `uv run python scripts/demo_token.py --scope mcp:use mcp:execute` in another terminal."
        )
        while all(process.poll() is None for process in processes):
            time.sleep(0.4)
        raise RuntimeError("a local demo service stopped unexpectedly")
    except KeyboardInterrupt:
        pass
    finally:
        for process in reversed(processes):
            if process.poll() is None:
                process.send_signal(signal.SIGTERM)
        for process in reversed(processes):
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


if __name__ == "__main__":
    main()
