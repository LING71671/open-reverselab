#!/usr/bin/env python3
"""Compatibility entrypoint for the independent knowledge repository's builder."""
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]


def main() -> int:
    builder = ROOT / 'kb' / 'scripts' / 'build.py'
    if not builder.is_file():
        print('Initialize the knowledge repository: git submodule update --init --recursive', file=sys.stderr)
        return 1
    return subprocess.call([sys.executable, str(builder), *sys.argv[1:]])


if __name__ == '__main__':
    raise SystemExit(main())
