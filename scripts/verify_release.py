"""Fail-closed source and distribution checks used by CI and tagged releases."""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import io
import json
import os
import re
import stat
import tarfile
import tomllib
import zipfile
from email.parser import BytesParser
from email.policy import default
from pathlib import Path, PurePosixPath
from typing import Any

EXPECTED_CHARTER_SHA256 = "3c5b6e607f460581c7a85ecddbb695a54681a8d34b5bc2418896c3ab9dd0b86a"
_VERSION_RE = re.compile(r'^__version__\s*=\s*"(?P<version>[^"]+)"$', re.MULTILINE)
_REQUIREMENT_RE = re.compile(r"^(?P<name>[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)(?P<spec>.*)$")
_SPECIFIER_RE = re.compile(r"^(?:===|==|~=|!=|<=|>=|<|>)[^,;\s]+$")
_SOURCE_DIRECTORIES = (
    ".github",
    "constitution",
    "custody",
    "examples",
    "protocols",
    "scripts",
    "src",
    "templates",
    "tests",
)
_SOURCE_FILES = (
    ".gitattributes",
    ".gitignore",
    ".python-version",
    "CHANGELOG.md",
    "CODE_OF_CONDUCT.md",
    "CONTRIBUTING.md",
    "LICENSE",
    "README.md",
    "RELEASING.md",
    "SECURITY.md",
    "SUPPORT.md",
    "pyproject.toml",
    "unasked-threat-model.md",
    "uv.lock",
)


class ReleaseCheckError(RuntimeError):
    """A release input is incomplete, inconsistent, or not source-bound."""


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _project_metadata(root: Path) -> tuple[str, str]:
    pyproject = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    project = pyproject.get("project", {})
    name = project.get("name")
    version = project.get("version")
    if not isinstance(name, str) or not isinstance(version, str):
        raise ReleaseCheckError("pyproject.toml requires string project name and version.")
    match = _VERSION_RE.search((root / "src" / "unasked" / "__init__.py").read_text("utf-8"))
    if match is None or match.group("version") != version:
        raise ReleaseCheckError("Package and pyproject versions do not match.")
    return name, version


def _project_table(root: Path) -> dict[str, Any]:
    pyproject = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    project = pyproject.get("project")
    if not isinstance(project, dict):
        raise ReleaseCheckError("pyproject.toml requires a project table.")
    return project


def _string_list(value: Any, *, field: str) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ReleaseCheckError(f"pyproject.toml {field} must be a string array.")
    return value


def _normalize_specifier_set(value: str, *, field: str) -> str:
    parts = [part.strip() for part in value.split(",")]
    if not parts or any(not part or _SPECIFIER_RE.fullmatch(part) is None for part in parts):
        raise ReleaseCheckError(f"Unsupported {field} specifier syntax: {value!r}")
    return ",".join(sorted(parts))


def _normalize_requirement(value: str, *, extra: str | None = None) -> str:
    if ";" in value or "[" in value or "]" in value or "@" in value:
        raise ReleaseCheckError(f"Unsupported release requirement syntax: {value!r}")
    match = _REQUIREMENT_RE.fullmatch(value.strip())
    if match is None:
        raise ReleaseCheckError(f"Unsupported release requirement syntax: {value!r}")
    name = match.group("name")
    spec = match.group("spec").strip()
    normalized = name
    if spec:
        normalized += _normalize_specifier_set(spec, field=f"dependency {name}")
    if extra is not None:
        normalized += f"; extra == '{extra}'"
    return normalized


def _expected_metadata_values(root: Path, *, name: str, version: str) -> dict[str, list[str]]:
    project = _project_table(root)
    description = project.get("description")
    requires_python = project.get("requires-python")
    readme = project.get("readme")
    if not isinstance(description, str) or not isinstance(requires_python, str):
        raise ReleaseCheckError("Project description and requires-python must be strings.")
    if readme != "README.md":
        raise ReleaseCheckError("The release verifier requires README.md as the project readme.")

    urls = project.get("urls", {})
    if not isinstance(urls, dict) or any(
        not isinstance(label, str) or not isinstance(url, str) for label, url in urls.items()
    ):
        raise ReleaseCheckError("pyproject.toml project.urls must map strings to strings.")
    optional = project.get("optional-dependencies", {})
    if not isinstance(optional, dict) or any(not isinstance(extra, str) for extra in optional):
        raise ReleaseCheckError("pyproject.toml optional dependencies must be named tables.")

    dependencies = [
        _normalize_requirement(item)
        for item in _string_list(project.get("dependencies", []), field="dependencies")
    ]
    extra_requirements: list[str] = []
    for extra in sorted(optional):
        if not extra or any(character in extra for character in "\r\n'"):
            raise ReleaseCheckError(f"Unsafe optional dependency name: {extra!r}")
        extra_requirements.extend(
            _normalize_requirement(item, extra=extra)
            for item in _string_list(optional[extra], field=f"optional-dependencies.{extra}")
        )

    keywords = _string_list(project.get("keywords", []), field="keywords")
    classifiers = _string_list(project.get("classifiers", []), field="classifiers")
    license_expression = project.get("license")
    license_files = _string_list(project.get("license-files", []), field="license-files")
    if not isinstance(license_expression, str) or not license_expression:
        raise ReleaseCheckError("Project license must be a non-empty SPDX expression string.")
    if license_files != ["LICENSE"]:
        raise ReleaseCheckError("The release verifier requires LICENSE as the sole license file.")
    return {
        "Metadata-Version": ["2.4"],
        "Name": [name],
        "Version": [version],
        "Summary": [description],
        "Project-URL": [f"{label}, {url}" for label, url in urls.items()],
        "Keywords": [",".join(sorted(keywords))],
        "Classifier": classifiers,
        "Requires-Python": [_normalize_specifier_set(requires_python, field="requires-python")],
        "Requires-Dist": dependencies + extra_requirements,
        "Provides-Extra": sorted(optional),
        "Description-Content-Type": ["text/markdown"],
        "License-Expression": [license_expression],
        "License-File": license_files,
    }


def _expected_wheel_control_files(root: Path) -> dict[str, bytes]:
    pyproject = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    build_system = pyproject.get("build-system")
    if not isinstance(build_system, dict) or build_system.get("build-backend") != "hatchling.build":
        raise ReleaseCheckError("The release verifier requires the hatchling build backend.")
    requirements = _string_list(build_system.get("requires"), field="build-system.requires")
    hatchling_versions = [
        item.removeprefix("hatchling==") for item in requirements if item.startswith("hatchling==")
    ]
    if len(requirements) != 1 or len(hatchling_versions) != 1 or not hatchling_versions[0]:
        raise ReleaseCheckError(
            "The hatchling build backend must be the sole exact build requirement."
        )

    scripts = _project_table(root).get("scripts", {})
    if not isinstance(scripts, dict) or any(
        not isinstance(name, str) or not isinstance(target, str) for name, target in scripts.items()
    ):
        raise ReleaseCheckError("pyproject.toml project.scripts must map strings to strings.")
    if not scripts or any(
        not name or any(character in name + target for character in "\r\n=")
        for name, target in scripts.items()
    ):
        raise ReleaseCheckError("Project console scripts contain unsafe or unsupported values.")

    wheel = (
        "Wheel-Version: 1.0\n"
        f"Generator: hatchling {hatchling_versions[0]}\n"
        "Root-Is-Purelib: true\n"
        "Tag: py3-none-any\n"
    ).encode("ascii")
    entry_points = (
        "[console_scripts]\n" + "".join(f"{name} = {scripts[name]}\n" for name in sorted(scripts))
    ).encode("utf-8")
    return {"WHEEL": wheel, "entry_points.txt": entry_points}


def _source_paths(root: Path) -> list[Path]:
    paths: list[Path] = []
    for relative in _SOURCE_FILES:
        path = root / relative
        if not path.is_file():
            raise ReleaseCheckError(f"Required release source is missing: {relative}")
        paths.append(path)
    for relative in _SOURCE_DIRECTORIES:
        directory = root / relative
        if not directory.is_dir():
            raise ReleaseCheckError(f"Required release directory is missing: {relative}")
        paths.extend(
            path
            for path in directory.rglob("*")
            if path.is_file()
            and "__pycache__" not in path.parts
            and path.suffix not in {".pyc", ".pyo"}
        )
    return sorted(set(paths), key=lambda path: path.relative_to(root).as_posix())


def verify_source(root: Path, *, tag: str | None = None) -> dict[str, Any]:
    root = root.resolve()
    name, version = _project_metadata(root)
    if tag is not None and tag != f"v{version}":
        raise ReleaseCheckError(f"Tag {tag!r} does not match project version v{version}.")
    charter = root / "constitution" / "UNASKED_NORTH_STAR_v0.1.md"
    charter_hash = sha256_path(charter)
    if charter_hash != EXPECTED_CHARTER_SHA256:
        raise ReleaseCheckError("The exact-byte North Star charter hash changed.")
    for relative in ("protocols/p0-v0.1.json", "protocols/m0-development-v0.1.json"):
        protocol = json.loads((root / relative).read_text(encoding="utf-8"))
        if protocol.get("charter_source_sha256") != EXPECTED_CHARTER_SHA256:
            raise ReleaseCheckError(f"Protocol charter binding does not match: {relative}")
    source_paths = _source_paths(root)
    return {
        "name": name,
        "version": version,
        "tag": tag,
        "charter_sha256": charter_hash,
        "source_file_count": len(source_paths),
    }


def _wheel_record_is_valid(archive: zipfile.ZipFile) -> bool:
    record_names = [name for name in archive.namelist() if name.endswith(".dist-info/RECORD")]
    if len(record_names) != 1:
        return False
    rows = list(csv.reader(io.StringIO(archive.read(record_names[0]).decode("utf-8"))))
    by_path = {row[0]: row for row in rows if len(row) == 3}
    if set(by_path) != set(archive.namelist()):
        return False
    for path, (record_path, encoded_hash, rendered_size) in by_path.items():
        if record_path != path:
            return False
        if path == record_names[0]:
            if encoded_hash or rendered_size:
                return False
            continue
        data = archive.read(path)
        digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
        if encoded_hash != f"sha256={digest}" or rendered_size != str(len(data)):
            return False
    return True


def _verify_metadata(raw: bytes, *, root: Path, name: str, version: str) -> None:
    header, separator, body = raw.partition(b"\n\n")
    if not separator or b"\r" in header:
        raise ReleaseCheckError("Distribution metadata must use canonical LF framing.")
    metadata = BytesParser(policy=default).parsebytes(raw)
    if metadata.defects or metadata.is_multipart():
        raise ReleaseCheckError("Distribution metadata is malformed.")
    expected = _expected_metadata_values(root, name=name, version=version)
    actual_names = set(metadata.keys())
    if actual_names != set(expected):
        raise ReleaseCheckError("Distribution metadata header allowlist mismatch.")
    for field, expected_values in expected.items():
        actual_values = metadata.get_all(field, [])
        if sorted(actual_values) != sorted(expected_values):
            raise ReleaseCheckError(f"Distribution metadata field mismatch: {field}")
    if body != (root / "README.md").read_bytes():
        raise ReleaseCheckError("Distribution metadata description does not match README.md.")


def _verify_wheel_control_files(root: Path, archive: zipfile.ZipFile, *, dist_info: str) -> None:
    expected = _expected_wheel_control_files(root)
    for filename, expected_bytes in expected.items():
        archive_path = f"{dist_info}/{filename}"
        if archive.read(archive_path) != expected_bytes:
            raise ReleaseCheckError(f"Wheel control file mismatch: {filename}")


def _require_matching_metadata(wheel_metadata: bytes, sdist_metadata: bytes) -> None:
    if wheel_metadata != sdist_metadata:
        raise ReleaseCheckError("Wheel METADATA and source PKG-INFO are not byte-identical.")


def _validate_archive_name(name: str) -> None:
    pure = PurePosixPath(name)
    if (
        not name
        or "\x00" in name
        or "\\" in name
        or pure.is_absolute()
        or "." in pure.parts
        or ".." in pure.parts
        or pure.as_posix() != name
    ):
        raise ReleaseCheckError(f"Distribution contains an unsafe archive path: {name!r}")


def _require_exact_members(actual: set[str], expected: set[str], *, kind: str) -> None:
    if actual == expected:
        return
    extra = sorted(actual - expected)
    missing = sorted(expected - actual)
    details: list[str] = []
    if extra:
        details.append(f"extra={extra[:5]!r}")
    if missing:
        details.append(f"missing={missing[:5]!r}")
    raise ReleaseCheckError(f"{kind} member allowlist mismatch ({', '.join(details)}).")


def _wheel_expected_members(root: Path, *, name: str, version: str) -> set[str]:
    expected: set[str] = set()
    for source in (root / "src" / "unasked").rglob("*"):
        if not source.is_file() or "__pycache__" in source.parts or source.suffix == ".pyc":
            continue
        expected.add(source.relative_to(root / "src").as_posix())
    for source in _source_paths(root):
        relative = source.relative_to(root).as_posix()
        if (
            relative.startswith(
                ("constitution/", "custody/", "examples/", "protocols/", "templates/")
            )
            or relative == "unasked-threat-model.md"
        ):
            expected.add(f"unasked/bundled/{relative}")
    dist_info = f"{name.replace('-', '_')}-{version}.dist-info"
    expected.update(
        {
            f"{dist_info}/METADATA",
            f"{dist_info}/WHEEL",
            f"{dist_info}/entry_points.txt",
            f"{dist_info}/licenses/LICENSE",
            f"{dist_info}/RECORD",
        }
    )
    return expected


def _validated_wheel_member_names(archive: zipfile.ZipFile) -> list[str]:
    infos = archive.infolist()
    member_names = [info.filename for info in infos]
    if len(member_names) != len(set(member_names)):
        raise ReleaseCheckError("Wheel contains duplicate archive members.")
    for info in infos:
        _validate_archive_name(info.filename)
        mode = (info.external_attr >> 16) & 0xFFFF
        if info.is_dir() or stat.S_ISLNK(mode) or info.flag_bits & 0x1:
            raise ReleaseCheckError("Wheel members must be unencrypted regular files.")
    return member_names


def _validated_sdist_members(archive: tarfile.TarFile) -> dict[str, tarfile.TarInfo]:
    member_list = archive.getmembers()
    member_names = [member.name for member in member_list]
    if len(member_names) != len(set(member_names)):
        raise ReleaseCheckError("Source distribution contains duplicate archive members.")
    for member in member_list:
        _validate_archive_name(member.name)
        if not member.isfile():
            raise ReleaseCheckError("Source distribution members must all be regular files.")
    return {member.name: member for member in member_list}


def _verify_wheel(
    root: Path, wheel: Path, *, name: str, version: str
) -> tuple[dict[str, Any], bytes]:
    expected_filename = f"{name.replace('-', '_')}-{version}-py3-none-any.whl"
    if wheel.name != expected_filename:
        raise ReleaseCheckError(f"Wheel filename must be exactly {expected_filename}.")
    dist_info = f"{name.replace('-', '_')}-{version}.dist-info"
    with zipfile.ZipFile(wheel) as archive:
        member_names = _validated_wheel_member_names(archive)
        _require_exact_members(
            set(member_names),
            _wheel_expected_members(root, name=name, version=version),
            kind="Wheel",
        )
        if archive.testzip() is not None or not _wheel_record_is_valid(archive):
            raise ReleaseCheckError("Wheel CRC or RECORD verification failed.")
        metadata_bytes = archive.read(f"{dist_info}/METADATA")
        _verify_metadata(metadata_bytes, root=root, name=name, version=version)
        _verify_wheel_control_files(root, archive, dist_info=dist_info)
        names = set(archive.namelist())
        for source in (root / "src" / "unasked").rglob("*"):
            if not source.is_file() or "__pycache__" in source.parts or source.suffix == ".pyc":
                continue
            relative = source.relative_to(root / "src").as_posix()
            if relative not in names or archive.read(relative) != source.read_bytes():
                raise ReleaseCheckError(f"Wheel package content mismatch: {relative}")
        for source in _source_paths(root):
            relative = source.relative_to(root).as_posix()
            if (
                not relative.startswith(
                    ("constitution/", "custody/", "examples/", "protocols/", "templates/")
                )
                and relative != "unasked-threat-model.md"
            ):
                continue
            bundled = f"unasked/bundled/{relative}"
            if bundled not in names or archive.read(bundled) != source.read_bytes():
                raise ReleaseCheckError(f"Wheel bundled resource mismatch: {relative}")
    report = {"filename": wheel.name, "bytes": wheel.stat().st_size, "sha256": sha256_path(wheel)}
    return report, metadata_bytes


def _verify_sdist(
    root: Path, sdist: Path, *, name: str, version: str
) -> tuple[dict[str, Any], bytes]:
    distribution_root = f"{name.replace('-', '_')}-{version}"
    with tarfile.open(sdist, "r:gz") as archive:
        members = _validated_sdist_members(archive)
        member_names = list(members)
        source_paths = _source_paths(root)
        expected_members = {
            f"{distribution_root}/{source.relative_to(root).as_posix()}" for source in source_paths
        }
        expected_members.add(f"{distribution_root}/PKG-INFO")
        _require_exact_members(set(member_names), expected_members, kind="Source distribution")
        for source in source_paths:
            relative = source.relative_to(root).as_posix()
            archive_path = f"{distribution_root}/{relative}"
            member = members.get(archive_path)
            if member is None:
                raise ReleaseCheckError(f"Source distribution is missing: {relative}")
            stream = archive.extractfile(member)
            if stream is None or stream.read() != source.read_bytes():
                raise ReleaseCheckError(f"Source distribution content mismatch: {relative}")
        metadata_path = f"{distribution_root}/PKG-INFO"
        metadata_member = members.get(metadata_path)
        if metadata_member is None:
            raise ReleaseCheckError("Source distribution is missing PKG-INFO.")
        stream = archive.extractfile(metadata_member)
        if stream is None:
            raise ReleaseCheckError("Source distribution PKG-INFO is unreadable.")
        metadata_bytes = stream.read()
        _verify_metadata(metadata_bytes, root=root, name=name, version=version)
    report = {"filename": sdist.name, "bytes": sdist.stat().st_size, "sha256": sha256_path(sdist)}
    return report, metadata_bytes


def verify_dist(root: Path, dist: Path, *, tag: str | None = None) -> dict[str, Any]:
    source = verify_source(root, tag=tag)
    version = source["version"]
    normalized_name = source["name"].replace("-", "_")
    wheels = sorted(dist.glob(f"{normalized_name}-{version}-*.whl"))
    sdists = sorted(dist.glob(f"{normalized_name}-{version}.tar.gz"))
    if len(wheels) != 1 or len(sdists) != 1:
        raise ReleaseCheckError("Release directory requires exactly one matching wheel and sdist.")
    wheel_report, wheel_metadata = _verify_wheel(
        root, wheels[0], name=source["name"], version=version
    )
    sdist_report, sdist_metadata = _verify_sdist(
        root, sdists[0], name=source["name"], version=version
    )
    _require_matching_metadata(wheel_metadata, sdist_metadata)
    artifacts = [wheel_report, sdist_report]
    return {**source, "artifacts": sorted(artifacts, key=lambda item: item["filename"])}


def compare_dist(first: dict[str, Any], second: dict[str, Any]) -> None:
    first_hashes = {item["filename"]: item["sha256"] for item in first["artifacts"]}
    second_hashes = {item["filename"]: item["sha256"] for item in second["artifacts"]}
    if first_hashes != second_hashes:
        raise ReleaseCheckError("Repeated clean builds are not byte-for-byte reproducible.")


def write_checksums(dist: Path, report: dict[str, Any]) -> Path:
    destination = dist / "SHA256SUMS.txt"
    payload = "".join(
        f"{item['sha256']}  {item['filename']}\n" for item in report["artifacts"]
    ).encode("ascii")
    temporary = destination.with_name(f".{destination.name}.tmp")
    temporary.write_bytes(payload)
    os.replace(temporary, destination)
    return destination


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--dist", type=Path)
    parser.add_argument("--compare-dist", type=Path)
    parser.add_argument("--tag")
    parser.add_argument("--write-checksums", action="store_true")
    args = parser.parse_args()
    try:
        if args.dist is None:
            report = verify_source(args.root, tag=args.tag)
        else:
            report = verify_dist(args.root, args.dist, tag=args.tag)
            if args.compare_dist is not None:
                comparison = verify_dist(args.root, args.compare_dist, tag=args.tag)
                compare_dist(report, comparison)
                report["reproducible_build"] = True
            if args.write_checksums:
                report["checksums"] = str(write_checksums(args.dist, report))
    except (OSError, ReleaseCheckError, tarfile.TarError, zipfile.BadZipFile) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, sort_keys=True))
        return 1
    print(json.dumps({"ok": True, "release": report}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
