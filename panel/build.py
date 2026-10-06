#!/usr/bin/env python3
"""Build and export an ARMv7 unified AWG Control image using Docker."""
import argparse
import hashlib
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=Path('awg-control.tar'))
    args = parser.parse_args()
    if args.output.exists():
        parser.error('Output already exists; choose a new filename.')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    root = Path(__file__).resolve().parent
    image = 'awg-control:0.2.3'
    subprocess.run(['docker', 'build', '--platform', 'linux/arm/v7', '--provenance=false',
                    '-t', image, '-f', str(root / 'Dockerfile'), str(root)], check=True)
    subprocess.run(['docker', 'save', '--platform', 'linux/arm/v7',
                    '--output', str(args.output.resolve()), image], check=True)
    digest = hashlib.sha256()
    with args.output.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    checksum = digest.hexdigest() + '  ' + args.output.name + '\n'
    args.output.with_suffix(args.output.suffix + '.sha256').write_text(checksum, encoding='ascii')
    print(checksum.strip())
    print('Image exported. No registry push and no router changes were made.')


if __name__ == '__main__':
    main()
