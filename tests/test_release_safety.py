"""Distribution gates reject unreviewed members even under Python optimization."""

from __future__ import annotations

import io
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

from scripts.verify_release import (
    PUBLIC_DOCUMENTS,
    ROOT_FILES,
    RUNTIME_FILES,
    inspect_archives,
    verify,
)


def archives(
    directory: Path, extra_wheel: str | None = None, extra_sdist: str | None = None
) -> tuple[Path, Path]:
    version = "0.1.0a1"
    wheel = directory / "fixture.whl"
    info = f"mcp_auth_bridge-{version}.dist-info/"
    files = {"mcp_auth_bridge/" + name for name in RUNTIME_FILES}
    files |= {
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
    with zipfile.ZipFile(wheel, "w") as archive:
        for name in files:
            data = "Name: mcp-auth-bridge\nVersion: 0.1.0a1\n" if name == info + "METADATA" else ""
            archive.writestr(name, data)
        if extra_wheel:
            archive.writestr(extra_wheel, "synthetic")
    sdist = directory / "fixture.tar.gz"
    source = (
        {"src/mcp_auth_bridge/" + name for name in RUNTIME_FILES} | PUBLIC_DOCUMENTS | ROOT_FILES
    )
    if extra_sdist:
        source.add(extra_sdist)
    with tarfile.open(sdist, "w:gz") as archive:
        for name in source:
            member = tarfile.TarInfo(f"mcp_auth_bridge-{version}/" + name)
            member.size = 1
            archive.addfile(member, io.BytesIO(b"x"))
    return wheel, sdist


def test_exact_distribution_members_pass(tmp_path: Path) -> None:
    inspect_archives(*archives(tmp_path), "0.1.0a1")


@pytest.mark.parametrize(
    "name",
    [
        "mcp_auth_bridge/secrets.json",
        "mcp_auth_bridge/.env.local",
        "mcp_auth_bridge-0.1.0a1.dist-info/private-note.md",
    ],
)
def test_unapproved_wheel_files_fail(tmp_path: Path, name: str) -> None:
    with pytest.raises(RuntimeError, match="unexpected_wheel_member"):
        inspect_archives(*archives(tmp_path, extra_wheel=name), "0.1.0a1")


@pytest.mark.parametrize(
    "name", ["src/mcp_auth_bridge/secrets.json", "docs/private-note.md", "../outside"]
)
def test_unapproved_sdist_files_fail(tmp_path: Path, name: str) -> None:
    with pytest.raises(RuntimeError, match="unexpected_sdist_member"):
        inspect_archives(*archives(tmp_path, extra_sdist=name), "0.1.0a1")


def test_release_requirements_survive_python_optimization() -> None:
    result = subprocess.run(
        [
            sys.executable,
            "-O",
            "-c",
            "from scripts.verify_release import require; require(False, 'expected_failure')",
        ],
        capture_output=True,
        check=False,
    )
    assert result.returncode != 0


def test_stale_output_is_not_published_or_deleted(tmp_path: Path) -> None:
    output = tmp_path / "release"
    output.mkdir()
    unexpected = output / "unreviewed.txt"
    unexpected.write_text("preserved")
    with pytest.raises(RuntimeError, match="unexpected_output_file"):
        verify("3.12", output, tmp_path / "report.json")
    assert unexpected.read_text() == "preserved"
