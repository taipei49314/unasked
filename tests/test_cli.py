from __future__ import annotations

import json
from pathlib import Path

from unasked.cli import main
from unasked.project import Project


def test_doctor_json_does_not_create_missing_workspace(tmp_path: Path, capsys) -> None:
    workspace = tmp_path / "missing"
    exit_code = main(["--json", "doctor", "--workspace", str(workspace)])
    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert payload["ok"] is True
    assert payload["data"]["workspace"]["initialized"] is False
    assert not workspace.exists()


def test_report_returns_explicit_silence(tmp_path: Path, capsys) -> None:
    workspace = tmp_path / "workspace"
    Project.create(workspace)
    exit_code = main(["--json", "report", "--workspace", str(workspace)])
    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert payload == {
        "command": "report",
        "data": {"certificates": [], "status": "NO_VERIFIED_DISCOVERY"},
        "ok": True,
    }


def test_json_errors_have_stable_shape(tmp_path: Path, capsys) -> None:
    exit_code = main(["--json", "runs", "list", "--workspace", str(tmp_path / "missing")])
    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 5
    assert payload["ok"] is False
    assert payload["error"]["code"] == "NOT_FOUND"
    assert payload["command"] == "runs list"


def test_missing_json_input_has_a_not_found_error(tmp_path: Path, capsys) -> None:
    exit_code = main(
        [
            "--json",
            "schemas",
            "validate",
            "knowledge-scan",
            "--file",
            str(tmp_path / "missing.json"),
        ]
    )
    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 5
    assert payload["error"]["code"] == "NOT_FOUND"
    assert payload["command"] == "schemas validate"


def test_resources_export_provides_a_wheel_safe_kit(tmp_path: Path, capsys) -> None:
    destination = tmp_path / "resource-kit"

    exit_code = main(["--json", "resources", "export", "--destination", str(destination)])
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert payload["ok"] is True
    assert payload["command"] == "resources export"
    assert payload["data"]["resource_count"] > 0
    assert (destination / "protocols" / "m0-development-v0.1.json").is_file()
    assert (destination / "examples" / "m0-budget.json").is_file()
