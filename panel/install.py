#!/usr/bin/env python3
"""Interactive installer for the unified AWG Control container (SSH/SFTP)."""
import argparse
import getpass
import hashlib
import importlib.util
import json
from pathlib import Path
import secrets
import subprocess
import sys
import time

from prepare import build_bundle, write_private

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('awg_legacy_transport', ROOT / 'awg-mikrotik.py')
legacy = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = legacy
SPEC.loader.exec_module(legacy)


def diagnostics(router, output):
    commands = (
        '/system/resource/print', '/container/print', '/disk/print',
        '/system/routerboard/mode-button/print',
        '/system/routerboard/reset-button/print',
        '/system/leds/print detail where leds="user-led"',
        '/ip/firewall/mangle/print stats where comment~"^AWG"',
        '/ip/firewall/filter/print stats where comment~"^AWGC"',
        '/routing/rule/print where comment~"^AWG"',
        '/ip/route/print where routing-table=to-awg',
    )
    parts = ['AWG Control 0.2.1 diagnostics (no configuration contents)']
    for cmd in commands:
        try:
            parts.append(cmd + '\n' + router.run(cmd))
        except Exception:
            parts.append(cmd + '\nCHECK FAILED')
    try:
        if router.count('/container', 'name="awg-control" and running=yes'):
            parts.append(router.run('/container/shell [/container/find where name="awg-control"] cmd="/awg-control --control diag" no-sh', timeout=45))
    except Exception:
        parts.append('Controller diagnostics unavailable; inspect container state above.')
    text = legacy.scrub('\n\n'.join(parts))
    legacy.secure_write(output / 'diagnostics.txt', text)
    print(text)


def download_private(router, remote, path):
    with router.client.open_sftp() as sftp:
        with sftp.open('/' + remote.lstrip('/'), 'rb') as stream:
            data = stream.read(256 * 1024 + 1)
    if len(data) > 256 * 1024:
        raise ValueError('Private migration file exceeds 256 KiB.')
    text = data.decode('utf-8-sig')
    write_private(path, text.encode('ascii', 'backslashreplace').decode('ascii'))
    return text


def image_checksum(path):
    expected = path.with_suffix(path.suffix + '.sha256').read_text(encoding='ascii').split()[0]
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    if digest.hexdigest() != expected:
        raise ValueError('Image checksum mismatch.')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    mode = p.add_mutually_exclusive_group()
    mode.add_argument('--diag', action='store_true', help='Read-only diagnostics')
    mode.add_argument('--migrate', action='store_true', help='Migrate the existing two-container 0.1.1 installation')
    mode.add_argument('--rollback', type=Path, help='Private run directory containing rollback.rsc and target.json')
    p.add_argument('--host')
    p.add_argument('--user', default='admin')
    p.add_argument('--port', type=int, default=22)
    p.add_argument('--lan')
    p.add_argument('--bridge')
    p.add_argument('--wan', default='ether1')
    p.add_argument('--disk')
    p.add_argument('--image', type=Path, help='Locally built ARMv7 tar plus .sha256')
    p.add_argument('--output', type=Path)
    args = p.parse_args()
    output = args.output or Path('awg-control-run-' + time.strftime('%Y%m%d-%H%M%S'))
    router = None
    try:
        if output.exists():
            raise ValueError('Choose a new output directory; existing private data is never overwritten.')
        output.mkdir(parents=True)
        args.host = args.host or legacy.ask('MikroTik IP', '192.168.3.1')
        router = legacy.Router(args)
        if args.diag:
            diagnostics(router, output)
            return 0
        if args.rollback:
            target = json.loads((args.rollback / 'target.json').read_text())
            if target['host'] != args.host:
                raise ValueError('Rollback belongs to another router.')
            disk = legacy.name(target['disk'])
            router.upload(args.rollback / 'rollback.rsc', disk + '/awg-control-rollback.rsc')
            router.run('/import file-name=' + disk + '/awg-control-rollback.rsc', timeout=180)
            diagnostics(router, output)
            return 0
        lan = args.lan or legacy.ask('LAN subnet', '192.168.3.0/24')
        bridge = args.bridge or legacy.ask('LAN bridge', 'bridge')
        disk = args.disk or legacy.ask('Ext4 USB partition', 'usb1-part1')
        legacy.name(disk)
        if not args.migrate:
            legacy.preflight(router, legacy.Settings(lan, bridge, args.wan, disk, True, True).validate())
        if router.get('/disk', 'fs', 'slot=' + legacy.ros_quote(disk)) != 'ext4':
            raise ValueError('Prepare and back up the ext4 USB partition first. This installer never formats disks.')
        if router.count('/file', 'name=' + legacy.ros_quote(disk + '/awg-control-data')):
            raise ValueError('Unified data already exists; inspect diagnostics or use the previous rollback bundle.')
        prior, profile, state = None, None, None
        password = ''
        if args.migrate:
            prior = json.loads(download_private(router, disk + '/awg-panel-data/settings.json', output / 'legacy-settings.json'))
            state = json.loads(download_private(router, disk + '/awg-panel-data/state.json', output / 'legacy-state.json'))
            config = download_private(router, disk + '/wg/awg0.conf', output / 'legacy-profile.conf')
            profile = {'id': secrets.token_hex(8), 'revision': secrets.token_hex(8), 'name': 'Main VPN',
                       'updated': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), 'config': config}
        else:
            password = getpass.getpass('New panel password (16+ characters): ')
            if password != getpass.getpass('Repeat panel password: '):
                raise ValueError('Passwords do not match.')
        settings, setup, rollback = build_bundle(lan, bridge, disk, None, None, password,
                                                 migration=args.migrate, prior_settings=prior)
        data = {'settings.json': settings, 'profiles.json': [profile] if profile else [],
                'tunnel.json': {'active': profile or {}, 'previous': {}, 'enabled': bool(profile)}}
        if state is not None:
            data['state.json'] = state
        for name, value in data.items():
            write_private(output / name, json.dumps(value, ensure_ascii=True, indent=2))
        write_private(output / 'setup.rsc', setup)
        write_private(output / 'rollback.rsc', rollback)
        write_private(output / 'target.json', json.dumps({'host': args.host, 'disk': disk}))
        image = args.image or output / 'awg-control.tar'
        if not args.image:
            print('Building the ARMv7 image using Docker. This can take several minutes.')
            subprocess.run([sys.executable, str(ROOT / 'panel/build.py'), '--output', str(image.resolve())], check=True)
        image_checksum(image)
        print('Prepared one container, LAN-only panel, Mode and USR integration. Private rollback bundle: ' + str(output))
        legacy.confirm('Apply the prepared installation? VPN traffic will pause during migration.')
        router.run('/file/add name=' + legacy.ros_quote(disk + '/awg-control-data') + ' type=directory')
        for name in data:
            router.upload(output / name, disk + '/awg-control-data/' + name)
        router.upload(image, disk + '/awg-control.tar')
        router.upload(output / 'setup.rsc', disk + '/awg-control-setup.rsc')
        router.upload(output / 'rollback.rsc', disk + '/awg-control-rollback.rsc')
        router.run('/import file-name=' + disk + '/awg-control-setup.rsc', timeout=240)
        diagnostics(router, output)
        print('Open your LAN gateway on port 8088. Fresh installation: import a profile and select Connect.')
        print('If migration did not connect, inspect Diagnostics and use --rollback with this private run directory.')
        return 0
    except (Exception, KeyboardInterrupt) as exc:
        message = 'Stopped by user.' if isinstance(exc, KeyboardInterrupt) else legacy.scrub(exc)
        print('ERROR: ' + message, file=sys.stderr)
        if output.is_dir():
            legacy.secure_write(output / 'error.txt', message)
            if router:
                diagnostics(router, output)
        return 1
    finally:
        if router:
            router.close()


if __name__ == '__main__':
    sys.exit(main())
