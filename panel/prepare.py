#!/usr/bin/env python3
"""Prepare an offline AWG Control installation or migration bundle."""
import argparse
import getpass
import importlib.util
import json
import os
from pathlib import Path

_SPEC = importlib.util.spec_from_file_location('awg_deploy', Path(__file__).with_name('deploy.py'))
_DEPLOY = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_DEPLOY)
build_bundle = _DEPLOY.build_bundle


def write_private(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w', encoding='ascii', newline='\n') as stream:
        stream.write(text)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--lan', default='192.168.3.0/24')
    p.add_argument('--bridge', default='bridge')
    p.add_argument('--disk', default='usb1-part1')
    p.add_argument('--upstream')
    p.add_argument('--wan-address')
    p.add_argument('--migrate-from', type=Path, help='Previous private panel settings.json')
    p.add_argument('--buttons-only', action='store_true', help='Generate Mode/Reset update for an existing unified installation')
    p.add_argument('--output', type=Path, default=Path('awg-control-private'))
    args = p.parse_args()
    if args.output.exists():
        p.error('Output directory exists. Choose a new path.')
    if args.buttons_only:
        write_private(args.output / 'buttons.rsc', _DEPLOY.button_setup(args.lan))
        print('Button update prepared. Import buttons.rsc on the existing AWG Control router.')
        print('Mode toggles the connection; short Reset stops the container. No router settings changed.')
        return
    prior = None
    password = ''
    if args.migrate_from:
        prior = json.loads(args.migrate_from.read_text(encoding='utf-8-sig'))
    else:
        password = getpass.getpass('New panel password (16+ characters): ')
        if password != getpass.getpass('Repeat panel password: '):
            p.error('Passwords do not match.')
    settings, setup, rollback = build_bundle(args.lan, args.bridge, args.disk, args.upstream,
        args.wan_address, password, migration=bool(prior), prior_settings=prior)
    write_private(args.output / 'settings.json', json.dumps(settings, indent=2))
    write_private(args.output / 'setup.rsc', setup)
    write_private(args.output / 'rollback.rsc', rollback)
    print('Private bundle prepared. Keep this directory out of Git.')
    print('Upload settings.json to USB/awg-control-data. Upload image and scripts to USB.')
    if prior:
        print('Also migrate state.json and import the native VPN profile before cutover; see README.')
    print('No router settings were changed.')


if __name__ == '__main__':
    main()
