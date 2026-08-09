from __future__ import annotations

import copy
import json
import math
import os
import shutil
import subprocess
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from unasked.errors import ExecutionError, IntegrityError, NotFoundError, UsageError
from unasked.util import canonical_json, hash_json, sha256_bytes, sha256_file


@dataclass(frozen=True, slots=True)
class ProviderResponse:
    stdout: bytes
    stderr: bytes = b""
    exit_code: int = 0


class ProviderTimeoutError(ExecutionError):
    """The provider exceeded a named timeout boundary."""

    code = "PROVIDER_TIMEOUT"


class ExplorerProvider(Protocol):
    @property
    def metadata(self) -> dict[str, Any]: ...

    def invoke(
        self,
        request: dict[str, Any],
        *,
        max_output_bytes: int,
        timeout_seconds: float | None = None,
    ) -> ProviderResponse: ...


def parse_action(raw: bytes) -> dict[str, Any]:
    """Parse exactly one JSON object; model prose and trailing values are rejected."""

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise UsageError("Provider response is not UTF-8 JSON.") from exc
    decoder = json.JSONDecoder()
    try:
        value, end = decoder.raw_decode(text.lstrip())
    except json.JSONDecodeError as exc:
        raise UsageError(
            "Provider response is not valid JSON.",
            details={"line": exc.lineno, "column": exc.colno},
        ) from exc
    prefix = len(text) - len(text.lstrip())
    if text[prefix + end :].strip():
        raise UsageError("Provider response contains trailing non-whitespace data.")
    if not isinstance(value, dict):
        raise UsageError("Provider response must contain one JSON object.")
    return value


class ScriptedProvider:
    """Byte-deterministic development provider; never evidence of model capability."""

    def __init__(
        self,
        responses: list[bytes | dict[str, Any]],
        *,
        model_name: str = "scripted-development",
    ) -> None:
        self._responses = [
            canonical_json(item) if isinstance(item, dict) else bytes(item) for item in responses
        ]
        self._index = 0
        self._metadata = {
            "provider": "scripted",
            "model": model_name,
            "adapter": "offline_recorded_json",
            "response_count": len(self._responses),
            "transcript_hash": hash_json([sha256_bytes(item) for item in self._responses]),
            "network_isolation_enforced": True,
            "certifying": False,
        }

    @classmethod
    def from_jsonl(
        cls, path: str | Path, *, model_name: str = "scripted-development"
    ) -> ScriptedProvider:
        resolved = Path(path).expanduser().resolve()
        if not resolved.is_file():
            raise NotFoundError(
                "Scripted provider response file was not found.", details={"path": str(resolved)}
            )
        responses = [line for line in resolved.read_bytes().splitlines() if line.strip()]
        return cls(responses, model_name=model_name)

    @property
    def metadata(self) -> dict[str, Any]:
        return copy.deepcopy(self._metadata)

    def invoke(
        self,
        request: dict[str, Any],
        *,
        max_output_bytes: int,
        timeout_seconds: float | None = None,
    ) -> ProviderResponse:
        del request
        del timeout_seconds
        if self._index >= len(self._responses):
            raw = canonical_json({"action": "STOP", "reason": "SCRIPT_EXHAUSTED"})
        else:
            raw = self._responses[self._index]
            self._index += 1
        if len(raw) > max_output_bytes:
            return ProviderResponse(
                stdout=raw[:max_output_bytes],
                stderr=b"scripted response exceeded max_output_bytes",
                exit_code=75,
            )
        return ProviderResponse(stdout=raw)


class JsonSubprocessProvider:
    """One local argv-only provider bridge using canonical JSON stdin/stdout."""

    def __init__(
        self,
        argv: list[str],
        *,
        model_name: str,
        timeout_seconds: int = 60,
        bound_files: list[str | Path] | None = None,
    ) -> None:
        if (
            not isinstance(argv, list)
            or not argv
            or not all(isinstance(item, str) for item in argv)
        ):
            raise UsageError("Provider argv must be a non-empty array of strings.")
        if any(not item or "\x00" in item for item in argv):
            raise UsageError("Provider argv contains an empty or NUL-bearing argument.")
        if (
            not isinstance(timeout_seconds, int)
            or isinstance(timeout_seconds, bool)
            or timeout_seconds < 1
        ):
            raise UsageError("Provider timeout_seconds must be a positive integer.")
        executable = shutil.which(argv[0])
        if executable is None:
            candidate = Path(argv[0]).expanduser()
            if candidate.is_file():
                executable = str(candidate.resolve())
        if executable is None:
            raise NotFoundError(
                "Provider executable was not found.", details={"executable": argv[0]}
            )
        self.argv = [executable, *argv[1:]]
        self.timeout_seconds = timeout_seconds
        executable_path = Path(executable)
        executable_hash = sha256_file(executable_path) if executable_path.is_file() else None
        resolved_bound_files: dict[str, str] = {}
        for item in bound_files or []:
            path = Path(item).expanduser().resolve()
            if not path.is_file():
                raise NotFoundError(
                    "A provider bound file was not found.", details={"path": str(path)}
                )
            resolved_bound_files[str(path)] = sha256_file(path)
        self._executable_hash = executable_hash
        self._bound_file_hashes = resolved_bound_files
        bundle_identity = {
            "model": model_name,
            "executable": executable,
            "executable_sha256": executable_hash,
            "argv_hash": hash_json(self.argv),
            "bound_files": [
                {"path": path, "sha256": digest}
                for path, digest in sorted(resolved_bound_files.items())
            ],
        }
        self._metadata = {
            "provider": "json-subprocess",
            "model": model_name,
            "adapter": "canonical_json_stdio",
            "executable": executable,
            "executable_sha256": executable_hash,
            "argv_hash": hash_json(self.argv),
            "bound_files": bundle_identity["bound_files"],
            "provider_bundle_hash": hash_json(bundle_identity),
            "timeout_seconds": timeout_seconds,
            "network_isolation_enforced": False,
            "certifying": False,
        }

    @property
    def metadata(self) -> dict[str, Any]:
        return copy.deepcopy(self._metadata)

    def _verify_integrity(self) -> None:
        executable = Path(self.argv[0])
        actual_executable_hash = sha256_file(executable) if executable.is_file() else None
        if actual_executable_hash != self._executable_hash:
            raise IntegrityError("Provider executable changed after its identity was frozen.")
        for raw_path, expected in self._bound_file_hashes.items():
            path = Path(raw_path)
            if not path.is_file() or sha256_file(path) != expected:
                raise IntegrityError(
                    "Provider bound file changed after its identity was frozen.",
                    details={"path": raw_path},
                )

    @staticmethod
    def _environment() -> dict[str, str]:
        allowed = (
            "PATH",
            "SYSTEMROOT",
            "WINDIR",
            "COMSPEC",
            "PATHEXT",
            "TEMP",
            "TMP",
            "LANG",
            "LC_ALL",
        )
        return {name: os.environ[name] for name in allowed if name in os.environ}

    def invoke(
        self,
        request: dict[str, Any],
        *,
        max_output_bytes: int,
        timeout_seconds: float | None = None,
    ) -> ProviderResponse:
        if (
            not isinstance(max_output_bytes, int)
            or isinstance(max_output_bytes, bool)
            or max_output_bytes < 1
        ):
            raise UsageError("Provider max_output_bytes must be a positive integer.")
        effective_timeout = float(self.timeout_seconds)
        timeout_source = "provider"
        if timeout_seconds is not None:
            if (
                isinstance(timeout_seconds, bool)
                or not isinstance(timeout_seconds, (int, float))
                or not math.isfinite(timeout_seconds)
                or timeout_seconds <= 0
            ):
                raise UsageError("Provider timeout override must be a positive finite number.")
            effective_timeout = min(effective_timeout, float(timeout_seconds))
            if float(timeout_seconds) <= self.timeout_seconds:
                timeout_source = "investigation_budget"
        self._verify_integrity()
        payload = canonical_json(request) + b"\n"
        try:
            process = subprocess.Popen(
                self.argv,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                env=self._environment(),
            )
        except OSError as exc:
            raise ExecutionError(
                "Explorer provider could not be started.",
                details={"type": type(exc).__name__},
            ) from exc

        stdout = bytearray()
        stderr = bytearray()
        overflow = threading.Event()
        output_lock = threading.Lock()

        def drain(stream: Any, destination: bytearray) -> None:
            try:
                while chunk := stream.read(8192):
                    with output_lock:
                        remaining = max_output_bytes - len(stdout) - len(stderr)
                        if remaining > 0:
                            destination.extend(chunk[:remaining])
                        exceeded = len(chunk) > remaining
                    if exceeded:
                        overflow.set()
                        process.kill()
                        break
            except (OSError, ValueError):
                return

        def write_request() -> None:
            try:
                if process.stdin is not None:
                    process.stdin.write(payload)
                    process.stdin.close()
            except (BrokenPipeError, OSError, ValueError):
                return

        readers = [
            threading.Thread(target=drain, args=(process.stdout, stdout), daemon=True),
            threading.Thread(target=drain, args=(process.stderr, stderr), daemon=True),
        ]
        writer = threading.Thread(target=write_request, daemon=True)
        for thread in readers:
            thread.start()
        writer.start()
        try:
            process.wait(timeout=effective_timeout)
        except subprocess.TimeoutExpired as exc:
            process.kill()
            process.wait()
            writer.join(timeout=1)
            for thread in readers:
                thread.join(timeout=1)
            raise ProviderTimeoutError(
                "Explorer provider timed out.",
                details={
                    "timeout_seconds": effective_timeout,
                    "timeout_source": timeout_source,
                },
            ) from exc
        writer.join(timeout=1)
        for thread in readers:
            thread.join(timeout=1)
        self._verify_integrity()
        if overflow.is_set():
            return ProviderResponse(
                stdout=bytes(stdout),
                stderr=bytes(stderr),
                exit_code=75,
            )
        return ProviderResponse(
            stdout=bytes(stdout),
            stderr=bytes(stderr),
            exit_code=process.returncode,
        )


def provider_from_config(config: dict[str, Any], *, base: Path | None = None) -> ExplorerProvider:
    if not isinstance(config, dict):
        raise UsageError("Provider configuration must be a JSON object.")
    kind = config.get("kind")
    if kind == "scripted":
        allowed = {"kind", "responses_file", "model"}
        if set(config) - allowed or not isinstance(config.get("responses_file"), str):
            raise UsageError("Scripted provider configuration fields are invalid.")
        responses_path = Path(config["responses_file"])
        if base is not None and not responses_path.is_absolute():
            responses_path = base / responses_path
        return ScriptedProvider.from_jsonl(
            responses_path,
            model_name=str(config.get("model", "scripted-development")),
        )
    if kind == "json-subprocess":
        allowed = {"kind", "argv", "model", "timeout_seconds", "bound_files"}
        if set(config) - allowed:
            raise UsageError("Subprocess provider configuration has unknown fields.")
        model = config.get("model")
        if not isinstance(model, str) or not model:
            raise UsageError("Subprocess provider model must be a non-empty string.")
        bound_files = config.get("bound_files", [])
        if not isinstance(bound_files, list) or not all(
            isinstance(item, str) and item for item in bound_files
        ):
            raise UsageError("Subprocess provider bound_files must be an array of paths.")
        if base is not None:
            bound_files = [
                str((base / item).resolve()) if not Path(item).is_absolute() else item
                for item in bound_files
            ]
        return JsonSubprocessProvider(
            config.get("argv"),
            model_name=model,
            timeout_seconds=config.get("timeout_seconds", 60),
            bound_files=bound_files,
        )
    raise UsageError(
        "Provider kind must select exactly one supported provider.",
        details={"supported": ["json-subprocess", "scripted"]},
    )


__all__ = [
    "ExplorerProvider",
    "JsonSubprocessProvider",
    "ProviderResponse",
    "ProviderTimeoutError",
    "ScriptedProvider",
    "parse_action",
    "provider_from_config",
]
