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
_scan_public_resource = _RELEASE._scan_public_resource
_require_current_release_contract = _RELEASE._require_current_release_contract


def test_release_source_bindings_are_consistent() -> None:
    root = Path(__file__).resolve().parents[1]

    completed = subprocess.run(
        [sys.executable, "scripts/verify_release.py", "--tag", "v0.4.0"],
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
    assert report["version"] == "0.4.0"
    assert (
        report["charter_sha256"]
        == "3c5b6e607f460581c7a85ecddbb695a54681a8d34b5bc2418896c3ab9dd0b86a"
    )
    assert report["source_file_count"] > 100


def test_release_requires_current_claim_bounded_notes_and_v04_surface() -> None:
    note = (_ROOT / ".github" / "releases" / "0.4.0.md").read_text(encoding="utf-8")
    assert "SHADOW" in note
    assert "m0_demonstrated=false" in note
    assert "M0_NOT_DEMONSTRATED" in note
    assert (_ROOT / "src" / "unasked" / "trust.py").is_file()
    assert (_ROOT / "src" / "unasked" / "attestations.py").is_file()
    assert (_ROOT / "src" / "unasked" / "locking.py").is_file()


@pytest.mark.parametrize(
    ("name", "payload"),
    [
        ("examples/signing-key.json", b"{}"),
        ("examples/public.json", b'{"private_key_base64":"secret"}'),
        ("examples/public.json", b'{"kty":"OKP","crv":"Ed25519","x":"x","d":"d"}'),
        ("examples/public.pem", b"-----BEGIN " + b"PRIVATE KEY-----\nsecret\n"),
        ("examples/public.json", b'{"ground_truth":"secret"}'),
        ("src/unasked/bad.py", b"Ed25519PrivateKey.generate()"),
    ],
)
def test_release_rejects_private_keys_and_hidden_payloads(name: str, payload: bytes) -> None:
    with pytest.raises(ReleaseCheckError, match="forbidden|private"):
        _scan_public_resource(name, payload)


def test_release_allows_only_in_memory_test_key_code() -> None:
    _scan_public_resource("tests/test_fixture.py", b"Ed25519PrivateKey.generate()")
    with pytest.raises(ReleaseCheckError, match="private PEM"):
        _scan_public_resource(
            "tests/test_fixture.py", b"b'''-----BEGIN " + b"PRIVATE KEY-----\\nsecret\\n'''"
        )


def test_release_rejects_production_or_unbound_public_policy(tmp_path: Path) -> None:
    root = tmp_path
    note = root / ".github" / "releases" / "0.4.0.md"
    note.parent.mkdir(parents=True)
    note.write_text("SHADOW m0_demonstrated=false M0_NOT_DEMONSTRATED", encoding="utf-8")
    for relative in _RELEASE._V04_PACKAGE_FILES:
        path = root / "src" / Path(relative)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("", encoding="utf-8")
    schema_root = root / "src" / "unasked" / "schema_defs"
    schema_root.mkdir(parents=True, exist_ok=True)
    for filename in _RELEASE._V04_SCHEMA_FILES:
        (schema_root / filename).write_text("{}", encoding="utf-8")
    policy_path = root / "examples" / "trust-policy-shadow.json"
    policy_path.parent.mkdir(parents=True)
    policy_path.write_text('{"mode":"PRODUCTION"}', encoding="utf-8")
    (root / "README.md").write_text("", encoding="utf-8")

    with pytest.raises(ReleaseCheckError, match="SHADOW"):
        _require_current_release_contract(root, version="0.4.0")

    policy_path.write_text('{"mode":"SHADOW"}', encoding="utf-8")
    with pytest.raises(ReleaseCheckError, match="README"):
        _require_current_release_contract(root, version="0.4.0")


def test_release_workflow_binds_the_remote_tag_object_and_supports_recovery() -> None:
    workflow = (_ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")

    assert "workflow_dispatch:" in workflow
    assert "RELEASE_TAG: ${{ inputs.tag || github.ref_name }}" in workflow
    assert "ref: ${{ inputs.tag || github.ref }}" in workflow
    assert "git/ref/tags/$RELEASE_TAG" in workflow
    assert 'test "$(jq -r \'.object.type\' <<<"$tag_ref")" = tag' in workflow
    assert 'test "$(jq -r \'.tag\' <<<"$tag_record")" = "$RELEASE_TAG"' in workflow
    assert "compare/$EXPECTED_TAG_COMMIT...main" in workflow
    assert "group: release-${{ inputs.tag || github.ref_name }}" in workflow
    assert "cancel-in-progress: false" in workflow
    assert "existing_release_state=" in workflow
    assert 'gh release upload "$RELEASE_TAG"' in workflow
    assert workflow.count("require_release_binding") == 4
    assert "GITHUB_REF_NAME" not in workflow
    assert "uv run bandit -q -r src scripts" in workflow
    assert "uv run pip-audit" in workflow
    assert "Authenticated evidence verification" in workflow
    assert "unasked ${RELEASE_TAG#v}" in workflow
    assert "attestations verify --help" in workflow
    assert "schemas show trust-policy" in workflow
    assert "schemas show trial-run-matrix" in workflow
    assert "M0_NOT_DEMONSTRATED" in workflow


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
        version="0.4.0",
    )
    header = "".join(
        f"{field}: {value}\n" for field, field_values in values.items() for value in field_values
    )
    return header.encode("utf-8") + b"\n" + (_ROOT / "README.md").read_bytes()


def test_release_metadata_is_exactly_bound_to_pyproject_and_readme() -> None:
    metadata = _render_expected_metadata()
    expected = _expected_metadata_values(_ROOT, name="unasked-research", version="0.4.0")

    assert expected["License-Expression"] == ["LicenseRef-Proprietary"]
    assert expected["License-File"] == ["LICENSE"]
    _verify_metadata(
        metadata,
        root=_ROOT,
        name="unasked-research",
        version="0.4.0",
    )

    injected = metadata.replace(b"\n\n", b"\nRequires-Dist: attacker-package\n\n", 1)
    with pytest.raises(ReleaseCheckError, match="Requires-Dist"):
        _verify_metadata(
            injected,
            root=_ROOT,
            name="unasked-research",
            version="0.4.0",
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
