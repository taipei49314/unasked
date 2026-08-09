"""Load and validate the versioned UNASKED artifact schemas.

The functions in this module deliberately validate artifact shape only.  Passing
schema validation does not authorize a verdict or establish a discovery claim.
"""

from __future__ import annotations

import copy
import json
import re
from dataclasses import dataclass
from functools import cache, lru_cache
from importlib.resources import files
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import ValidationError
from referencing import Registry, Resource

SCHEMA_DRAFT = "https://json-schema.org/draft/2020-12/schema"
SCHEMA_VERSION = "0.1.0"

_SCHEMA_FILES = {
    "baseline-result": "baseline-result.schema.json",
    "budget-policy": "budget-policy.schema.json",
    "candidate": "candidate.schema.json",
    "discovery-certificate": "discovery-certificate.schema.json",
    "event": "event.schema.json",
    "evidence-reference": "evidence-reference.schema.json",
    "expectation": "expectation.schema.json",
    "experiment-plan": "experiment-plan.schema.json",
    "experiment-result": "experiment-result.schema.json",
    "explorer-action": "explorer-action.schema.json",
    "hypothesis": "hypothesis.schema.json",
    "investigation-result": "investigation-result.schema.json",
    "knowledge-scan": "knowledge-scan.schema.json",
    "observation": "observation.schema.json",
    "replay-result": "replay-result.schema.json",
    "review": "review.schema.json",
    "run": "run.schema.json",
    "trial-manifest": "trial-manifest.schema.json",
    "trial-report": "trial-report.schema.json",
    "verdict": "verdict.schema.json",
}
_INTERNAL_FILES = ("common.schema.json",)
_REQUIRED_RE = re.compile(r"^'(?P<name>[^']+)' is a required property$")


@dataclass(frozen=True, slots=True)
class ValidationIssue:
    """A deterministic, machine-readable schema validation failure."""

    path: str
    code: str
    message: str
    schema_path: str

    def to_dict(self) -> dict[str, str]:
        return {
            "path": self.path,
            "code": self.code,
            "message": self.message,
            "schema_path": self.schema_path,
        }


class SchemaNotFoundError(KeyError):
    """Raised when an unknown public schema name is requested."""

    code = "SCHEMA_NOT_FOUND"

    def __init__(self, schema_name: str) -> None:
        self.schema_name = schema_name
        self.available = list_schemas()
        super().__init__(
            f"Unknown schema {schema_name!r}. Available schemas: {', '.join(self.available)}"
        )


class SchemaValidationError(ValueError):
    """Raised by :func:`validate_or_raise` for an invalid artifact."""

    code = "SCHEMA_VALIDATION_FAILED"

    def __init__(self, schema_name: str, errors: tuple[ValidationIssue, ...]) -> None:
        self.schema_name = schema_name
        self.errors = errors
        super().__init__(
            f"Artifact failed {schema_name!r} schema validation ({len(errors)} errors)."
        )


def list_schemas() -> tuple[str, ...]:
    """Return canonical public schema names in stable lexical order."""

    return tuple(sorted(_SCHEMA_FILES))


def _canonical_name(schema_name: str) -> str:
    name = schema_name.strip().lower().replace("_", "-")
    for suffix in (".schema.json", ".json"):
        if name.endswith(suffix):
            name = name[: -len(suffix)]
            break
    if name not in _SCHEMA_FILES:
        raise SchemaNotFoundError(schema_name)
    return name


@lru_cache(maxsize=1)
def _schema_documents() -> dict[str, dict[str, Any]]:
    schema_root = files("unasked.schema_defs")
    documents: dict[str, dict[str, Any]] = {}
    for filename in (*_INTERNAL_FILES, *_SCHEMA_FILES.values()):
        document = json.loads(schema_root.joinpath(filename).read_text(encoding="utf-8"))
        if document.get("$schema") != SCHEMA_DRAFT:
            raise RuntimeError(f"Packaged schema {filename!r} is not Draft 2020-12.")
        Draft202012Validator.check_schema(document)
        documents[filename] = document
    return documents


@lru_cache(maxsize=1)
def _registry() -> Registry:
    resources = []
    for document in _schema_documents().values():
        resources.append((document["$id"], Resource.from_contents(document)))
    return Registry().with_resources(resources)


@cache
def _validator(schema_name: str) -> Draft202012Validator:
    canonical_name = _canonical_name(schema_name)
    document = _schema_documents()[_SCHEMA_FILES[canonical_name]]
    return Draft202012Validator(
        document,
        registry=_registry(),
        format_checker=FormatChecker(),
    )


def show_schema(schema_name: str) -> dict[str, Any]:
    """Return a defensive copy of a named JSON Schema document."""

    canonical_name = _canonical_name(schema_name)
    return copy.deepcopy(_schema_documents()[_SCHEMA_FILES[canonical_name]])


get_schema = show_schema


def _pointer(parts: Any) -> str:
    encoded = [str(part).replace("~", "~0").replace("/", "~1") for part in parts]
    return "" if not encoded else "/" + "/".join(encoded)


def _stable_error(error: ValidationError) -> ValidationIssue:
    path_parts = list(error.absolute_path)
    code = str(error.validator or "validation")
    message = error.message

    if code == "required":
        match = _REQUIRED_RE.fullmatch(error.message)
        missing = match.group("name") if match else "<unknown>"
        path_parts.append(missing)
        message = f"Required property is missing: {missing}."
    elif code == "enum":
        allowed = json.dumps(error.validator_value, ensure_ascii=False, separators=(",", ":"))
        actual = json.dumps(
            error.instance,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        message = f"Expected one of {allowed}; received {actual}."
    elif code == "const":
        expected = json.dumps(error.validator_value, ensure_ascii=False, sort_keys=True)
        actual = json.dumps(error.instance, ensure_ascii=False, sort_keys=True)
        message = f"Expected constant {expected}; received {actual}."
    elif code == "type":
        expected = json.dumps(error.validator_value, ensure_ascii=False, separators=(",", ":"))
        message = f"Expected JSON type {expected}."
    elif code == "format":
        message = f"Value does not match format {error.validator_value!r}."
    elif code == "pattern":
        message = f"Value does not match required pattern {error.validator_value!r}."

    return ValidationIssue(
        path=_pointer(path_parts),
        code=code,
        message=message,
        schema_path=_pointer(error.absolute_schema_path),
    )


def validate_schema(schema_name: str, instance: Any) -> tuple[ValidationIssue, ...]:
    """Validate *instance* and return stable, deterministically ordered issues."""

    errors = (_stable_error(error) for error in _validator(schema_name).iter_errors(instance))
    return tuple(
        sorted(errors, key=lambda item: (item.path, item.code, item.schema_path, item.message))
    )


validate = validate_schema


def validate_or_raise(schema_name: str, instance: Any) -> None:
    """Validate *instance* and raise :class:`SchemaValidationError` on failure."""

    canonical_name = _canonical_name(schema_name)
    errors = validate_schema(canonical_name, instance)
    if errors:
        raise SchemaValidationError(canonical_name, errors)


def is_valid(schema_name: str, instance: Any) -> bool:
    """Return whether *instance* conforms to the named schema."""

    return not validate_schema(schema_name, instance)


__all__ = [
    "SCHEMA_DRAFT",
    "SCHEMA_VERSION",
    "SchemaNotFoundError",
    "SchemaValidationError",
    "ValidationIssue",
    "get_schema",
    "is_valid",
    "list_schemas",
    "show_schema",
    "validate",
    "validate_or_raise",
    "validate_schema",
]
