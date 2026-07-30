#!/usr/bin/env sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$SCRIPT_DIR"

if command -v python3 >/dev/null 2>&1; then
  PYTHON_BIN=${PYTHON:-python3}
else
  PYTHON_BIN=${PYTHON:-python}
fi

echo "ReverseLab first-run check"
"$PYTHON_BIN" scripts/misc/first_run_check.py --write-report

if command -v uv >/dev/null 2>&1; then
  echo ""
  echo "ReverseLab MCP smoke check"
  uv run --project tools/skills/mcp/ReverseLabToolsMCP python scripts/misc/mcp_smoke_check.py --write-report || {
    echo "MCP smoke check reported warnings or failures; see reports/misc/ for details." >&2
  }
else
  echo ""
  echo "uv not found; skipping MCP smoke check. Install uv or run mcp_smoke_check.py with your preferred Python environment."
fi
