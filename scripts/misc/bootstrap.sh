#!/usr/bin/env sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
BIN_DIR="$ROOT/tools/bin"

mkdir -p "$BIN_DIR"

write_wrapper() {
  name=$1
  target=$2
  cat > "$BIN_DIR/$name" <<EOF
#!/usr/bin/env sh
set -eu
SCRIPT_DIR=\$(CDPATH= cd -- "\$(dirname -- "\$0")" && pwd)
ROOT=\$(CDPATH= cd -- "\$SCRIPT_DIR/../.." && pwd)
if command -v python3 >/dev/null 2>&1; then
  PYTHON_BIN=\${PYTHON:-python3}
else
  PYTHON_BIN=\${PYTHON:-python}
fi
exec "\$PYTHON_BIN" "\$ROOT/$target" "\$@"
EOF
  chmod +x "$BIN_DIR/$name"
}

write_wrapper ai_context scripts/misc/ai_context.py
write_wrapper ai_tool scripts/misc/ai_tool.py
write_wrapper ai_finding scripts/misc/ai_finding.py
write_wrapper ai_toolcheck scripts/misc/ai_toolcheck.py

echo "ReverseLab POSIX wrappers ready under tools/bin"
echo "Add to PATH for this shell:"
echo "  export PATH=\"\$ROOT/tools/bin:\$ROOT/tools/ctf-website/bin:\$PATH\""
