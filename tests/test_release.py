from __future__ import annotations

import importlib.util
import io
import json
import stat
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location(
    "unasked_release_verifier",
    _ROOT / "scripts" / "verify_release.py",
)
assert _SPEC is not None and _SPEC.loader is not None
_RELEASE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_RELEASE)
ReleaseCheckError = _RELEASE.ReleaseCheckError
_require_exact_members = _RELEASE._require_exact_members
_require_matching_metadata = _RELEASE._require_matching_metadata
_validate_archive_name = _RELEASE._validate_archive_name
_validated_sdist_members = _RELEASE._validated_sdist_members
_validated_wheel_member_names = _RELEASE._validated_wheel_member_names
_expected_metadata_values = _RELEASE._expected_metadata_values
_expected_wheel_control_files = _RELEASE._expected_wheel_control_files
_verify_metadata = _RELEASE._verify_metadata
_verify_wheel_control_files = _RELEASE._verify_wheel_control_files


def test_release_source_bindings_are_consistent() -> None:
    root = Path(__file__).resolve().parents[1]

    completed = subprocess.run(
        [sys.executable, "scripts/verify_release.py", "--tag", "v0.2.0"],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    payload = json.loads(completed.stdout)
    report = payload["release"]

    assert completed.returncode == 0
    assert payload["ok"] is True
    assert report["name"] == "unasked-research"
    assert report["version"] == "0.2.0"
    assert (
        report["charter_sha256"]
        == "3c5b6e607f460581c7a85ecddbb695a54681a8d34b5bc2418896c3ab9dd0b86a"
    )
    assert report["source_file_count"] > 100


def test_release_rejects_a_version_mismatched_tag() -> None:
    root = Path(__file__).resolve().parents[1]

    completed = subprocess.run(
        [sys.executable, "scripts/verify_release.py", "--tag", "v9.9.9"],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    payload = json.loads(completed.stdout)

    assert completed.returncode == 1
    assert payload["ok"] is False
    assert "does not match" in payload["error"]


def test_release_member_allowlist_rejects_injected_wheel_payload() -> None:
    with pytest.raises(ReleaseCheckError, match="allowlist"):
        _require_exact_members(
            {"package.py", "payload.pth"},
            {"package.py"},
            kind="Wheel",
        )


@pytest.mark.parametrize("name", ["../payload", "/absolute", "a\\payload", "a//payload"])
def test_release_rejects_unsafe_archive_paths(name: str) -> None:
    with pytest.raises(ReleaseCheckError, match="unsafe archive path"):
        _validate_archive_name(name)


def test_release_rejects_duplicate_wheel_and_symlink_sdist_payloads(tmp_path: Path) -> None:
    wheel = tmp_path / "fixture.whl"
    with pytest.warns(UserWarning, match="Duplicate name"), zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("duplicate.py", b"first")
        archive.writestr("duplicate.py", b"second")
    with zipfile.ZipFile(wheel) as archive, pytest.raises(ReleaseCheckError, match="duplicate"):
        _validated_wheel_member_names(archive)

    sdist = tmp_path / "fixture.tar.gz"
    with tarfile.open(sdist, "w:gz") as archive:
        link = tarfile.TarInfo("package/link")
        link.type = tarfile.SYMTYPE
        link.linkname = "../../payload"
        link.mode = stat.S_IFLNK | 0o777
        archive.addfile(link)
    with (
        tarfile.open(sdist, "r:gz") as archive,
        pytest.raises(ReleaseCheckError, match="regular files"),
    ):
        _validated_sdist_members(archive)


def _render_expected_metadata() -> bytes:
    values = _expected_metadata_values(
        _ROOT,
        name="unasked-research",
        version="0.2.0",
    )
    header = "".join(
        f"{field}: {value}\n" for field, field_values in values.items() for value in field_values
    )
    return header.encode("utf-8") + b"\n" + (_ROOT / "README.md").read_bytes()


def test_release_metadata_is_exactly_bound_to_pyproject_and_readme() -> None:
    metadata = _render_expected_metadata()
    _verify_metadata(
        metadata,
        root=_ROOT,
        name="unasked-research",
        version="0.2.0",
    )

    injected = metadata.replace(b"\n\n", b"\nRequires-Dist: attacker-package\n\n", 1)
    with pytest.raises(ReleaseCheckError, match="Requires-Dist"):
        _verify_metadata(
            injected,
            root=_ROOT,
            name="unasked-research",
            version="0.2.0",
        )


@pytest.mark.parametrize("filename", ["WHEEL", "entry_points.txt"])
def test_release_rejects_modified_wheel_control_files(filename: str) -> None:
    expected = _expected_wheel_control_files(_ROOT)
    archive_bytes = io.BytesIO()
    with zipfile.ZipFile(archive_bytes, "w") as archive:
        for control_name, content in expected.items():
            archive.writestr(f"fixture.dist-info/{control_name}", content)
    with zipfile.ZipFile(archive_bytes) as archive:
        _verify_wheel_control_files(_ROOT, archive, dist_info="fixture.dist-info")

    modified_bytes = io.BytesIO()
    with zipfile.ZipFile(modified_bytes, "w") as archive:
        for control_name, content in expected.items():
            if control_name == filename:
                content += b"malicious = payload:main\n"
            archive.writestr(f"fixture.dist-info/{control_name}", content)
    with (
        zipfile.ZipFile(modified_bytes) as archive,
        pytest.raises(ReleaseCheckError, match="control file mismatch"),
    ):
        _verify_wheel_control_files(_ROOT, archive, dist_info="fixture.dist-info")


def test_release_requires_identical_wheel_and_sdist_metadata() -> None:
    _require_matching_metadata(b"same", b"same")
    with pytest.raises(ReleaseCheckError, match="not byte-identical"):
        _require_matching_metadata(b"wheel", b"sdist")
