"""One result envelope shared by native tools and external engines.

The envelope makes evidence discipline machine-checkable: every operation reports what was
observed (`findings`), how complete the observation was (`coverage`), what could not be
resolved (`unknowns`), and whether a failure was caller error, environment error, or a
partial result. See `docs/static-analysis-backends.md` and `reverselab_mcp/registry.py`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

ENVELOPE_SCHEMA = "reverselab.envelope.v1"


@dataclass(frozen=True)
class Coverage:
    """How much of the requested scope was actually examined."""

    scope: str = "operation"
    complete: bool = False
    reason: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {"scope": self.scope, "complete": self.complete, "reason": self.reason}


@dataclass(frozen=True)
class OperationError:
    """A structured failure.

    `kind` is one of: `invalid_argument`, `missing_engine`, `unsupported`, `not_found`,
    `timeout`, `partial`, `internal`.
    """

    kind: str
    message: str
    remedy: str = ""
    retryable: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "message": self.message,
            "remedy": self.remedy,
            "retryable": self.retryable,
        }


def _coverage(
    value: Coverage | dict[str, Any] | None,
    engine: str,
    *,
    default_complete: bool = True,
    default_reason: str = "",
) -> dict[str, Any]:
    if value is None:
        return Coverage(scope=engine, complete=default_complete, reason=default_reason).as_dict()
    if isinstance(value, Coverage):
        return value.as_dict()
    return {
        "scope": str(value.get("scope", engine)),
        "complete": bool(value.get("complete", False)),
        "reason": str(value.get("reason", "")),
    }


def _unknowns(value: list[Any] | None) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for item in value or []:
        if isinstance(item, dict):
            rows.append(dict(item))
        else:
            rows.append({"detail": str(item)})
    return rows


def ok(
    operation: str,
    *,
    engine: str = "native",
    target: dict[str, Any] | None = None,
    findings: Any = None,
    evidence_ref: str = "",
    coverage: Coverage | dict[str, Any] | None = None,
    unknowns: list[Any] | None = None,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a successful envelope."""

    return {
        "schema": ENVELOPE_SCHEMA,
        "ok": True,
        "operation": operation,
        "engine": engine,
        "target": dict(target or {}),
        "findings": findings if findings is not None else {},
        "evidence_ref": evidence_ref,
        "coverage": _coverage(coverage, engine),
        "unknowns": _unknowns(unknowns),
        "error": None,
        "metadata": dict(metadata or {}),
    }


def fail(
    operation: str,
    *,
    kind: str,
    message: str,
    remedy: str = "",
    retryable: bool = False,
    engine: str = "native",
    target: dict[str, Any] | None = None,
    findings: Any = None,
    evidence_ref: str = "",
    coverage: Coverage | dict[str, Any] | None = None,
    unknowns: list[Any] | None = None,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a failure envelope. Partial findings may still be attached."""

    return {
        "schema": ENVELOPE_SCHEMA,
        "ok": False,
        "operation": operation,
        "engine": engine,
        "target": dict(target or {}),
        "findings": findings if findings is not None else {},
        "evidence_ref": evidence_ref,
        "coverage": _coverage(coverage, engine, default_complete=False, default_reason=message[:200]),
        "unknowns": _unknowns(unknowns),
        "error": OperationError(kind, message, remedy, retryable).as_dict(),
        "metadata": dict(metadata or {}),
    }


def component_failure(
    operation: str, target: dict[str, Any], findings: dict[str, Any], components: list[str]
) -> dict[str, Any] | None:
    """Keep successful outputs when some of the requested components failed."""
    failed = [name for name in components if "error" in findings[name]]
    if not failed:
        return None
    kinds = {findings[name]["kind"] for name in failed}
    if len(failed) < len(components):
        kind = "partial"
    elif len(kinds) == 1:
        kind = next(iter(kinds))
    else:
        kind = "internal"
    message = "; ".join(f"{name}: {findings[name]['error']}" for name in failed)
    return fail(operation, kind=kind, message=message, target=target, findings=findings,
                retryable=all(findings[name]["kind"] == "timeout" for name in failed))
