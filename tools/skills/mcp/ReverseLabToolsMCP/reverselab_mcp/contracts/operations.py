"""Declarative operation metadata.

An operation is the unit the registry, the profiles, and the generated capability matrix all
agree on. It is deliberately backend-neutral: `engine` says who implements it today, not who
must implement it forever.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class OperationSpec:
    name: str
    family: str
    profiles: tuple[str, ...] = ("legacy",)
    target_formats: tuple[str, ...] = ()
    engine: str = "native"
    fallback: tuple[str, ...] = ()
    authority: str = "shipped-artifact"
    cost: str = "low"
    description: str = ""
    tags: tuple[str, ...] = field(default_factory=tuple)

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "family": self.family,
            "profiles": list(self.profiles),
            "target_formats": list(self.target_formats),
            "engine": self.engine,
            "fallback": list(self.fallback),
            "authority": self.authority,
            "cost": self.cost,
            "description": self.description,
            "tags": list(self.tags),
        }
