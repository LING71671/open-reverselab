from __future__ import annotations

from pathlib import Path

from .config import ALLOWED_ROOTS, GENERATED_ROOTS, GHIDRA_EXPORTS_DIR, PATCHES_DIR
from .errors import ToolError
from .static_config import IDA_EXPORTS_DIR


def is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def resolve_file(path: str) -> Path:
    if not path:
        raise ToolError("file path is required")

    resolved = Path(path).expanduser().resolve(strict=True)
    if not resolved.is_file():
        raise ToolError(f"not a file: {resolved}")

    allowed = any(is_relative_to(resolved, root.resolve()) for root in ALLOWED_ROOTS)
    if not allowed:
        allowed_text = ", ".join(str(root) for root in ALLOWED_ROOTS)
        raise ToolError(f"path is outside allowed roots: {resolved}; allowed roots: {allowed_text}")

    return resolved


def check_tool(path: Path, name: str) -> None:
    if not path.exists():
        raise ToolError(f"{name} not found: {path}")


def ensure_under(path: Path, roots: list[Path], label: str) -> Path:
    resolved = path.expanduser().resolve()
    allowed = any(is_relative_to(resolved, root.resolve()) for root in roots)
    if not allowed:
        allowed_text = ", ".join(str(root) for root in roots)
        raise ToolError(f"{label} is outside allowed roots: {resolved}; allowed roots: {allowed_text}")
    return resolved


def resolve_patch_output(path: str) -> Path:
    if not path:
        raise ToolError("output path is required")
    resolved = Path(path).expanduser().resolve()
    if not is_relative_to(resolved, PATCHES_DIR.resolve()):
        raise ToolError(f"patch output path is outside patches directory: {resolved}")
    return resolved


def resolve_generated_artifact(path: str) -> Path:
    if not path:
        raise ToolError("artifact path is required")
    resolved = Path(path).expanduser().resolve(strict=True)
    ensure_under(resolved, GENERATED_ROOTS, "artifact path")
    for root in GENERATED_ROOTS:
        if resolved == root.resolve():
            raise ToolError(f"refusing to operate on generated root itself: {resolved}")
    return resolved


def summary_candidates(*, include_ida: bool = False) -> list[Path]:
    paths = list(GHIDRA_EXPORTS_DIR.glob("*-ghidra-summary.json"))
    if include_ida:
        paths.extend(IDA_EXPORTS_DIR.glob("*-ida-summary.json"))
    return sorted(paths, key=lambda path: (path.stat().st_mtime_ns, path.name), reverse=True)


def resolve_summary(summary_path: str = "", *, include_ida: bool = False) -> Path:
    if summary_path:
        resolved = Path(summary_path).expanduser().resolve(strict=True)
    else:
        candidates = summary_candidates(include_ida=include_ida)
        if not candidates:
            roots = f"{GHIDRA_EXPORTS_DIR} or {IDA_EXPORTS_DIR}" if include_ida else str(GHIDRA_EXPORTS_DIR)
            raise ToolError(f"no summary found under: {roots}")
        resolved = candidates[0].resolve(strict=True)

    if not resolved.is_file():
        raise ToolError(f"not a file: {resolved}")
    if resolved.suffix.lower() != ".json":
        raise ToolError(f"not a JSON summary: {resolved}")
    if not any(is_relative_to(resolved, root.resolve()) for root in [GHIDRA_EXPORTS_DIR, IDA_EXPORTS_DIR]):
        raise ToolError(f"summary path is outside configured Ghidra/IDA export roots: {resolved}")
    return resolved
