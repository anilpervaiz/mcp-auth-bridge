"""Build and verify the self-hosted alpha without starting services."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from datetime import datetime, timezone
from email.parser import BytesParser
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]


def require(condition: bool, reason: str = "release_check_failed") -> None:
    if not condition:
        raise RuntimeError(reason)


def run(args: list[str], cwd: Path, step: str, *, env: dict[str, str] | None = None) -> str:
    result = subprocess.run(
        args, cwd=cwd, env=env, capture_output=True, text=True, timeout=300, check=False
    )
    if result.returncode:
        raise RuntimeError(step)
    return result.stdout


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def version() -> str:
    tree = ast.parse((ROOT / "src/mcp_auth_bridge/_version.py").read_text())
    for node in tree.body:
        if (
            isinstance(node, ast.Assign)
            and any(isinstance(t, ast.Name) and t.id == "__version__" for t in node.targets)
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        ):
            return node.value.value
    raise RuntimeError("version_missing")


def git_value(args: list[str]) -> str:
    result = subprocess.run(
        ["git", *args], cwd=ROOT, capture_output=True, text=True, check=False, timeout=5
    )
    return result.stdout.strip() if result.returncode == 0 else ""


RUNTIME_FILES = {
    "__init__.py",
    "_version.py",
    "app.py",
    "cli.py",
    "config.py",
    "discovery.py",
    "egress.py",
    "protocol.py",
    "proxy.py",
    "py.typed",
    "scopes.py",
    "strict_json.py",
    "tokens.py",
}
PUBLIC_DOCUMENTS = {
    "docs/architecture.md",
    "docs/threat-model.md",
    "docs/known-limitations.md",
    "docs/provenance.md",
}
ROOT_FILES = {
    ".gitignore",
    "pyproject.toml",
    "README.md",
    "LICENSE",
    "NOTICE",
    "SECURITY.md",
    "CONTRIBUTING.md",
    "SUPPORT.md",
    "CHANGELOG.md",
    "PRIVACY.md",
    "PKG-INFO",
}


def inspect_archives(wheel: Path, sdist: Path, expected: str) -> None:
    info = f"mcp_auth_bridge-{expected}.dist-info/"
    metadata_files = {
        info + name
        for name in (
            "METADATA",
            "WHEEL",
            "RECORD",
            "entry_points.txt",
            "licenses/LICENSE",
            "licenses/NOTICE",
        )
    }
    wheel_files = {"mcp_auth_bridge/" + name for name in RUNTIME_FILES} | metadata_files
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
        require(
            len(names) == len(set(names)) and set(names) == wheel_files, "unexpected_wheel_member"
        )
        require(
            all(not n.startswith("/") and ".." not in Path(n).parts for n in names),
            "release_check_failed",
        )
        require(
            all(item.external_attr >> 16 & 61440 != 40960 for item in archive.infolist()),
            "release_check_failed",
        )
        metadata = BytesParser().parsebytes(archive.read(info + "METADATA"))
        require(
            metadata["Name"] == "mcp-auth-bridge" and metadata["Version"] == expected,
            "release_check_failed",
        )
    allowed = (
        {"src/mcp_auth_bridge/" + name for name in RUNTIME_FILES} | PUBLIC_DOCUMENTS | ROOT_FILES
    )
    with tarfile.open(sdist) as archive:
        prefix = f"mcp_auth_bridge-{expected}/"
        seen: set[str] = set()
        for member in archive.getmembers():
            require(member.name.startswith(prefix) and member.isfile(), "release_check_failed")
            relative = member.name[len(prefix) :]
            require(relative in allowed and relative not in seen, "unexpected_sdist_member")
            seen.add(relative)
        require(seen == allowed, "missing_sdist_member")


def verify(python: str, output: Path, report_path: Path) -> None:
    expected = version()
    report: dict[str, Any] = {
        "schema": "mab-release-v1",
        "version": expected,
        "revision": git_value(["rev-parse", "HEAD"]) or None,
        "dirty_source": bool(git_value(["status", "--porcelain"])),
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "passed": False,
    }
    try:
        output.mkdir(parents=True, exist_ok=True)
        expected_outputs = {
            f"mcp_auth_bridge-{expected}-py3-none-any.whl",
            f"mcp_auth_bridge-{expected}.tar.gz",
            "runtime-requirements.txt",
            "runtime-sbom.cdx.json",
            "release-manifest.json",
            "SHA256SUMS",
        }
        require(
            all(
                p.is_file() and not p.is_symlink() and p.name in expected_outputs
                for p in output.iterdir()
            ),
            "unexpected_output_file",
        )
        for previous in output.iterdir():
            previous.unlink()
        build_env = dict(os.environ, SOURCE_DATE_EPOCH="315532800")
        build_env.pop("UV_PROJECT_ENVIRONMENT", None)
        run(
            [
                "uv",
                "build",
                "--sdist",
                "--wheel",
                "--no-create-gitignore",
                "--out-dir",
                str(output),
            ],
            ROOT,
            "initial_build",
            env=build_env,
        )
        wheel = output / f"mcp_auth_bridge-{expected}-py3-none-any.whl"
        sdist = output / f"mcp_auth_bridge-{expected}.tar.gz"
        inspect_archives(wheel, sdist, expected)
        with tempfile.TemporaryDirectory(prefix="mab-release-") as temporary:
            temp = Path(temporary)
            extracted = temp / "source"
            extracted.mkdir()
            with tarfile.open(sdist) as archive:
                archive.extractall(extracted)
            source = extracted / f"mcp_auth_bridge-{expected}"
            rebuilt = temp / "rebuilt"
            run(
                ["uv", "build", "--wheel", "--no-create-gitignore", "--out-dir", str(rebuilt)],
                source,
                "sdist_rebuild",
                env=build_env,
            )
            rebuilt_wheel = rebuilt / wheel.name
            require(digest(wheel) == digest(rebuilt_wheel), "non_reproducible_wheel")
            environment = temp / "runtime"
            run(["uv", "venv", "--python", python, str(environment)], temp, "runtime_environment")
            executable = environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
            cli = environment / (
                "Scripts/mcp-auth-bridge.exe" if os.name == "nt" else "bin/mcp-auth-bridge"
            )
            run(
                ["uv", "pip", "install", "--python", str(executable), str(rebuilt_wheel)],
                temp,
                "runtime_install",
            )
            smoke = "import importlib.metadata, pathlib, sys\nimport mcp_auth_bridge\nfrom mcp_auth_bridge import BridgeSettings, Principal, create_app\nif not pathlib.Path(mcp_auth_bridge.__file__).is_relative_to(pathlib.Path(sys.prefix)): raise RuntimeError('runtime_import_location')\nif mcp_auth_bridge.__version__ != importlib.metadata.version('mcp-auth-bridge'): raise RuntimeError('runtime_version')\ns = BridgeSettings(public_resource='https://bridge.example/mcp', issuer='https://issuer.example', upstream='https://upstream.example/mcp')\nif create_app(s) is None: raise RuntimeError('runtime_app')\nif Principal is None: raise RuntimeError('runtime_principal')\n"
            run([str(executable), "-I", "-c", smoke], temp, "runtime_api_smoke")
            flags = [
                "--public-resource",
                "https://bridge.example/mcp",
                "--issuer",
                "https://issuer.example",
                "--upstream",
                "https://upstream.example/mcp",
            ]
            run([str(cli), "check-config", *flags], temp, "runtime_config_smoke")
            metadata = json.loads(
                run([str(cli), "print-metadata", *flags], temp, "runtime_metadata_smoke")
            )
            require(metadata["resource"] == "https://bridge.example/mcp", "release_check_failed")
            installed = json.loads(
                run(
                    ["uv", "pip", "list", "--python", str(executable), "--format", "json"],
                    temp,
                    "runtime_inventory",
                )
            )
            packages = sorted(installed, key=lambda item: item["name"].lower())
            report["versions"] = json.loads(
                run(
                    [
                        str(executable),
                        "-I",
                        "-c",
                        "import json,platform; print(json.dumps({'python':platform.python_version(),'system':platform.system(),'machine':platform.machine()}))",
                    ],
                    temp,
                    "runtime_versions",
                )
            )
            report["versions"]["uv"] = run(["uv", "--version"], temp, "builder_version").strip()
            with zipfile.ZipFile(wheel) as built:
                report["versions"]["wheel_generator"] = BytesParser().parsebytes(
                    built.read(f"mcp_auth_bridge-{expected}.dist-info/WHEEL")
                )["Generator"]
            (output / "runtime-requirements.txt").write_text(
                "".join(
                    f"{p['name']}=={p['version']}\n"
                    for p in packages
                    if p["name"] != "mcp-auth-bridge"
                )
            )
            sbom = {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "version": 1,
                "components": [
                    {
                        "type": "library",
                        "name": p["name"],
                        "version": p["version"],
                        "purl": f"pkg:pypi/{p['name'].lower().replace('_', '-')}@{p['version']}",
                    }
                    for p in packages
                ],
            }
            (output / "runtime-sbom.cdx.json").write_text(json.dumps(sbom, indent=2) + "\n")
        report["checks"] = {
            "archive_allowlist": True,
            "typed_package": True,
            "sdist_rebuild": True,
            "reproducible_wheel": True,
            "runtime_only_install": True,
            "public_api": True,
            "check_config": True,
            "print_metadata": True,
        }
        artifacts = [
            wheel,
            sdist,
            output / "runtime-sbom.cdx.json",
            output / "runtime-requirements.txt",
        ]
        manifest = {
            **report,
            "passed": True,
            "artifacts": [
                {"filename": p.name, "sha256": digest(p), "bytes": p.stat().st_size}
                for p in artifacts
            ],
        }
        manifest_path = output / "release-manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
        artifacts.append(manifest_path)
        (output / "SHA256SUMS").write_text("".join(f"{digest(p)}  {p.name}\n" for p in artifacts))
        report["passed"] = True
    finally:
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(report, indent=2) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--python", default="3.12")
    parser.add_argument("--output-dir", type=Path, default=ROOT / "dist/release")
    parser.add_argument("--report", type=Path, default=ROOT / "artifacts/release.json")
    args = parser.parse_args()
    try:
        verify(args.python, args.output_dir.resolve(), args.report.resolve())
    except Exception:  # noqa: BLE001 - redact raw build/provider exceptions
        print("Release verification failed; see the safe report.", file=sys.stderr)
        return 1
    print("Release archives, reproducible rebuild, and isolated runtime checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
