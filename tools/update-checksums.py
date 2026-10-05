#!/usr/bin/env python3
"""Synchronize bootstrap SHA256 values; --check only validates them."""
import argparse
import hashlib
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
PATTERNS = {
    'install.sh': r'(PYTHON_SHA256=")[0-9a-f]{64}',
    'install.ps1': r"(\$pythonSha256 = ')[0-9a-f]{64}",
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    digest = hashlib.sha256((ROOT / 'awg-mikrotik.py').read_bytes()).hexdigest()
    valid = True
    for filename, pattern in PATTERNS.items():
        path = ROOT / filename
        source = path.read_text(encoding='ascii')
        updated, matches = re.subn(pattern, lambda match: match[1] + digest, source)
        if matches != 1:
            raise RuntimeError(f'Expected one checksum declaration in {filename}')
        if source != updated:
            valid = False
            if args.check:
                print(f'Stale checksum: {filename}', file=sys.stderr)
            else:
                path.write_text(updated, encoding='ascii', newline='\n')
                print(f'Updated checksum: {filename}')
    if args.check and not valid:
        return 1
    print('Bootstrap checksums match the installer.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
