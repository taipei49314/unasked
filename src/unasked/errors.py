from __future__ import annotations


class UnaskedError(Exception):
    """Base error with a stable machine-readable code."""

    code = "UNASKED_ERROR"

    def __init__(self, message: str, *, details: dict | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}


class UsageError(UnaskedError):
    code = "INVALID_INPUT"


class IntegrityError(UnaskedError):
    code = "INTEGRITY_ERROR"


class PolicyError(UnaskedError):
    code = "POLICY_DENIED"


class NotFoundError(UnaskedError):
    code = "NOT_FOUND"


class ExecutionError(UnaskedError):
    code = "EXECUTION_FAILED"


class ConcurrentModificationError(UnaskedError):
    """A prepared evidence graph changed before its atomic commit."""

    code = "CONCURRENT_MODIFICATION"
