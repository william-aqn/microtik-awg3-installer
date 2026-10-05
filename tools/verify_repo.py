#!/usr/bin/env python3
"""Check ASCII-only executable sources and synchronized bootstrap checksums."""
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
SOURCE_SUFFIXES = {'.py', '.ps1', '.sh', '.rsc', '.yml', '.yaml'}
IGNORED_DIRS = {'.git', '.venv', '__pycache__', '.ruff_cache'}


def main():
    failures = []
    checked = 0
    for path in ROOT.rglob('*'):
        relative = path.relative_to(ROOT)
        if any(part in IGNORED_DIRS or part.startswith('awg-run-') for part in relative.parts):
            continue
        if not path.is_file() or path.suffix not in SOURCE_SUFFIXES:
            continue
        checked += 1
        if not path.read_bytes().isascii():
            failures.append(str(relative))
    if failures:
        print('Non-ASCII executable sources: ' + ', '.join(failures), file=sys.stderr)
        return 1
    print(f'ASCII source check passed: {checked} files.')
    return subprocess.run([sys.executable, str(ROOT / 'tools/update-checksums.py'), '--check']).returncode


if __name__ == '__main__':
    sys.exit(main())
