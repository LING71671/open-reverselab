"""Shared result contracts for ReverseLab MCP operations."""

from .envelope import ENVELOPE_SCHEMA, Coverage, OperationError, fail, ok
from .operations import OperationSpec

__all__ = [
    "ENVELOPE_SCHEMA",
    "Coverage",
    "OperationError",
    "OperationSpec",
    "fail",
    "ok",
]
