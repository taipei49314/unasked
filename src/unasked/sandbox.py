"""A deny-by-default local command policy and recorder.

``local_restricted`` means argv, executable, cwd, timeout, and environment rules
are enforced in the current host process environment.  It is **not** network
isolation, a container, or an operating-system filesystem sandbox.
"""

from __future__ import annotations

import math
import os
import re
import subprocess  # nosec B404
import time
from collections.abc import Collection, Mapping
from pathlib import Path
from typing import Any

from unasked.errors import ExecutionError, NotFoundError, PolicyError, UsageError
from unasked.executables import find_executable
from unasked.util import ensure_within

ISOLATION_MODE = "local_restricted"
NETWORK_ISOLATED = False
ISOLATION_NOTICE = (
    "local_restricted enforces local process policy only; it is not network-isolated "
    "or an operating-system filesystem sandbox."
)

_SAFE_INHERITED_ENV = {
    "COMSPEC",
    "LANG",
    "LC_ALL",
    "PATH",
    "PATHEXT",
    "SYSTEMDRIVE",
    "SYSTEMROOT",
    "TEMP",
    "TMP",
    "TZ",
    "WINDIR",
}
_LAUNCH_ENV = {"COMSPEC", "PATH", "PATHEXT", "SYSTEMROOT", "WINDIR"}
_SECRET_NAME_RE = re.compile(
    r"(?:^|_)(?:API_?KEY|AUTH|COOKIE|CREDENTIALS?|PASS(?:WORD|WD)?|PRIVATE_?KEY|"
    r"SECRET|SESSION|TOKEN)(?:$|_)|^(?:ANTHROPIC|AWS|AZURE|GITHUB|GITLAB|GOOGLE|"
    r"OPENAI)_|^(?:NPM_TOKEN|PIP_INDEX_URL|PIP_EXTRA_INDEX_URL)$",
    re.IGNORECASE,
)
_WINDOWS_SCRIPT_SUFFIXES = {".bat", ".cmd"}


def _display_decode(value: bytes | str | None) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return value.decode("utf-8", errors="replace")


def _normalized_executable_name(value: str) -> str:
    name = Path(value).name.casefold()
    if os.name == "nt" and name.endswith(".exe"):
        return name[:-4]
    return name


def _contains_path_separator(value: str) -> bool:
    return "/" in value or "\\" in value


def _validated_timeout(value: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise UsageError("timeout must be a positive finite number of seconds.")
    rendered = float(value)
    if rendered <= 0 or not math.isfinite(rendered):
        raise UsageError("timeout must be a positive finite number of seconds.")
    return rendered


class RestrictedExecutor:
    """Execute explicitly allowed programs from a cwd confined to one worktree.

    The default executable allowlist is empty.  Allowing an interpreter grants
    that interpreter its normal host capabilities; this class records and limits
    process invocation but must not be represented as a security boundary.
    """

    def __init__(
        self,
        worktree: str | os.PathLike[str],
        *,
        allowed_executables: Collection[str | os.PathLike[str]] | None = None,
        timeout_seconds: float = 30.0,
    ) -> None:
        root = Path(worktree).expanduser().resolve()
        if not root.exists() or not root.is_dir():
            raise NotFoundError("Worktree directory does not exist.", details={"path": str(root)})
        self.worktree = root
        self.timeout_seconds = _validated_timeout(timeout_seconds)
        self._allowed_names: set[str] = set()
        self._allowed_paths: set[Path] = set()

        if isinstance(allowed_executables, (str, bytes, os.PathLike)):
            raise UsageError("allowed_executables must be a collection, not a string.")
        for item in allowed_executables or ():
            rendered = os.fspath(item)
            if not rendered or "\x00" in rendered:
                raise UsageError("Executable allowlist entries must be non-empty paths or names.")
            candidate = Path(rendered).expanduser()
            if candidate.is_absolute():
                self._allowed_paths.add(candidate.resolve())
            elif _contains_path_separator(rendered):
                raise UsageError("Relative executable paths are not accepted in the allowlist.")
            else:
                self._allowed_names.add(_normalized_executable_name(rendered))

    def _environment(
        self,
        overrides: Mapping[str, str] | None,
    ) -> tuple[dict[str, str], list[str]]:
        inherited = {
            key: value
            for key, value in os.environ.items()
            if key.upper() in _SAFE_INHERITED_ENV and not _SECRET_NAME_RE.search(key)
        }
        stripped = {key for key in os.environ if _SECRET_NAME_RE.search(key)}

        if overrides is not None and not isinstance(overrides, Mapping):
            raise UsageError("env must be a mapping of strings.")
        for key, value in (overrides or {}).items():
            if not isinstance(key, str) or not isinstance(value, str):
                raise UsageError("env keys and values must be strings.")
            if not key or "\x00" in key or "\x00" in value or "=" in key:
                raise UsageError("env contains an invalid key or value.")
            if _SECRET_NAME_RE.search(key):
                stripped.add(key)
                continue
            existing_key = next((name for name in inherited if name.upper() == key.upper()), None)
            if key.upper() in _LAUNCH_ENV and (
                existing_key is None or inherited[existing_key] != value
            ):
                raise PolicyError(
                    "Launch environment variables may not be overridden.",
                    details={"key": key},
                )
            inherited[key] = value

        inherited["GIT_TERMINAL_PROMPT"] = "0"
        inherited["PIP_NO_INPUT"] = "1"
        inherited["PYTHONIOENCODING"] = "utf-8"
        inherited["PYTHONUTF8"] = "1"
        return inherited, sorted(stripped, key=str.casefold)

    def _resolve_executable(self, executable: str, environment: Mapping[str, str]) -> Path:
        if not executable or "\x00" in executable:
            raise UsageError("argv[0] must be a non-empty executable name or path.")
        candidate = Path(executable).expanduser()
        normalized_name = _normalized_executable_name(executable)

        if candidate.is_absolute() or _contains_path_separator(executable):
            try:
                resolved = candidate.resolve(strict=True)
            except FileNotFoundError as exc:
                raise NotFoundError(
                    "Allowed executable was not found.", details={"executable": executable}
                ) from exc
            directly_allowed = resolved in self._allowed_paths
            trusted_name_match = False
            if normalized_name in self._allowed_names:
                discovered = find_executable(
                    resolved.name,
                    path=environment.get("PATH"),
                    excluded_roots=(self.worktree,),
                )
                trusted_name_match = (
                    discovered is not None and Path(discovered).resolve() == resolved
                )
            if not directly_allowed and not trusted_name_match:
                raise PolicyError(
                    "Executable is not allowlisted.", details={"executable": executable}
                )
        else:
            if normalized_name not in self._allowed_names:
                raise PolicyError(
                    "Executable is not allowlisted.", details={"executable": executable}
                )
            discovered = find_executable(
                executable,
                path=environment.get("PATH"),
                excluded_roots=(self.worktree,),
            )
            if discovered is None:
                raise NotFoundError(
                    "Allowed executable was not found.", details={"executable": executable}
                )
            resolved = Path(discovered).resolve()

        if os.name == "nt" and resolved.suffix.casefold() in _WINDOWS_SCRIPT_SUFFIXES:
            raise PolicyError(
                "Windows command scripts are not accepted because they may invoke a shell.",
                details={"executable": str(resolved)},
            )
        if not resolved.is_file():
            raise NotFoundError(
                "Allowed executable is not a file.", details={"executable": str(resolved)}
            )
        return resolved

    def resolve_executable(self, executable: str) -> Path:
        """Resolve one allowlisted executable through the executor's launch policy.

        Callers that enforce an executable-identity policy can inspect this path
        immediately before execution.  The command is still resolved again by
        :meth:`execute`, so this method does not weaken the allowlist.
        """

        environment, _ = self._environment(None)
        return self._resolve_executable(executable, environment)

    def _cwd(self, cwd: str | os.PathLike[str] | None) -> Path:
        if cwd is None:
            candidate = self.worktree
        else:
            candidate_path = Path(cwd).expanduser()
            candidate = (
                candidate_path if candidate_path.is_absolute() else self.worktree / candidate_path
            )
        resolved = ensure_within(candidate, self.worktree)
        if not resolved.exists() or not resolved.is_dir():
            raise NotFoundError("Command cwd does not exist.", details={"cwd": str(resolved)})
        return resolved

    def execute(
        self,
        argv: list[str],
        *,
        cwd: str | os.PathLike[str] | None = None,
        timeout: float | None = None,
        env: Mapping[str, str] | None = None,
        shell: bool = False,
    ) -> dict[str, Any]:
        """Execute an argv list and return a complete JSON-serializable record."""

        if shell:
            raise PolicyError("Shell execution is disabled.")
        if not isinstance(argv, list):
            raise UsageError("Command must be supplied as an argv list, never a command string.")
        if not argv:
            raise UsageError("argv must contain at least an executable.")
        if any(not isinstance(argument, str) for argument in argv):
            raise UsageError("Every argv element must be a string.")
        if any("\x00" in argument for argument in argv):
            raise UsageError("argv elements may not contain NUL bytes.")

        effective_timeout = self.timeout_seconds if timeout is None else _validated_timeout(timeout)
        command_cwd = self._cwd(cwd)
        environment, stripped_env_keys = self._environment(env)
        executable = self._resolve_executable(argv[0], environment)
        executed_argv = [str(executable), *argv[1:]]

        started = time.monotonic()
        timed_out = False
        exit_code: int | None
        stdout: str
        stderr: str
        try:
            # The executable is resolved and allowlisted; shell execution is disabled.
            completed = subprocess.run(  # nosec B603
                executed_argv,
                cwd=command_cwd,
                env=environment,
                shell=False,
                check=False,
                capture_output=True,
                timeout=effective_timeout,
            )
            exit_code = completed.returncode
            stdout = _display_decode(completed.stdout)
            stderr = _display_decode(completed.stderr)
        except subprocess.TimeoutExpired as exc:
            timed_out = True
            exit_code = None
            stdout = _display_decode(exc.stdout)
            stderr = _display_decode(exc.stderr)
        except OSError as exc:
            raise ExecutionError(
                "Unable to start allowed executable.",
                details={"argv": list(argv), "cwd": str(command_cwd), "error": str(exc)},
            ) from exc
        duration_seconds = time.monotonic() - started

        return {
            "argv": list(argv),
            "resolved_executable": str(executable),
            "cwd": str(command_cwd),
            "stdout": stdout,
            "stderr": stderr,
            "exit_code": exit_code,
            "duration_seconds": duration_seconds,
            "duration_ms": round(duration_seconds * 1000, 3),
            "timeout_seconds": effective_timeout,
            "timed_out": timed_out,
            "shell": False,
            "environment_policy": "secret_stripped",
            "stripped_env_keys": stripped_env_keys,
            "isolation": ISOLATION_MODE,
            "network_isolated": NETWORK_ISOLATED,
            "isolation_notice": ISOLATION_NOTICE,
        }


RestrictedCommandExecutor = RestrictedExecutor


def execute_command(
    worktree: str | os.PathLike[str],
    argv: list[str],
    *,
    allowed_executables: Collection[str | os.PathLike[str]],
    cwd: str | os.PathLike[str] | None = None,
    timeout: float = 30.0,
    env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """One-shot convenience wrapper with the same deny-by-default policy."""

    executor = RestrictedExecutor(
        worktree,
        allowed_executables=allowed_executables,
        timeout_seconds=timeout,
    )
    return executor.execute(argv, cwd=cwd, timeout=timeout, env=env)


__all__ = [
    "ISOLATION_MODE",
    "ISOLATION_NOTICE",
    "NETWORK_ISOLATED",
    "RestrictedCommandExecutor",
    "RestrictedExecutor",
    "execute_command",
]
