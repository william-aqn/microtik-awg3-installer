"""Failure-injection tests for updates, rollback and post-commit garbage collection."""
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import re
import tarfile
import tempfile
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location('panel_update', Path(__file__).resolve().parents[1] / 'panel/update.py')
u = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(u)
DISK = 'usb1-part1'
DATA = DISK + '/awg-control-data'


class Transport:
    @staticmethod
    def secure_write(file, text):
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(text, encoding='utf-8')

    @staticmethod
    def name(value):
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,48}', value):
            raise ValueError('Unsafe name')
        return value

    scrub = staticmethod(str)
    confirm = staticmethod(lambda _: None)


def container(name='awg-control', root='awg-control-026-root', interface=u.UPLINK, image='a' * 64, running=True):
    return {'name': name, 'root-dir': DISK + '/' + root, 'interface': interface,
            'image-id': image, 'mountlists': u.MOUNT, 'running': running, 'stopped': not running,
            'start-on-boot': running, 'layer-dir': ''}


def old_backup():
    return container('awg-control-previous-025i', 'awg-control-025i-root', 'awg-previous-025i', 'b' * 64, False)


def healthy(expected, version='0.2.7'):
    return {'panel_version': version, 'busy': False, 'error': '', 'geo_error': '', 'revision': expected['revision'],
            'resource': [{'version': '7.23.8'}], 'routes': [], 'routing': [], 'dns': {'error': ''},
            'ready': [{'list': 'AWG3UI-ready', 'address': '192.168.3.0/24'}],
            'mangle': [{'comment': 'AWG3UI entry ' + expected['revision'], 'disabled': not expected['enabled']}],
            'tunnel': {'enabled': expected['enabled'], 'connected': expected['enabled'],
                       'phase': 'connected' if expected['enabled'] else 'off', 'error': '',
                       'active_id': expected['active_id'], 'active_revision': expected['active_revision'],
                       'route': {'ready': expected['enabled']}}}


class FakeRouter:
    def __init__(self, device):
        self.d = device

    def get(self, menu, prop, where=None):
        return {'serial-number': 'router-one', 'architecture-name': 'arm', 'board-name': 'hAP ac^2', 'version': '7.23.8 (long-term)',
                'free-hdd-space': str(512 * 1024), 'free-memory': str(32 * 1024 * 1024),
                'fs': 'ext4', 'free': str(1024 ** 3)}[prop]

    def run(self, command, timeout=30):
        # Exercise the real deletion guard, with RouterOS's native root removal.
        if '/container/remove $c' not in command:
            raise AssertionError('Unexpected command: ' + command)
        name = json.loads(re.search(r'where name=("[^"]+")', command)[1])
        self.d.event('remove:' + name)
        row = next(r for r in self.d.items if r['name'] == name)
        self.d.items.remove(row)
        self.d.dirs.discard(u.path(row['root-dir']))
        return ''


class FakeDevice(u.Device):
    def __init__(self):
        self.router, self.transport, self.q = FakeRouter(self), Transport, json.dumps
        self.items = [container(), old_backup()]
        self.mount_rows = [{'list': u.MOUNT, 'src': DATA, 'dst': '/data'}]
        self.files = {DATA + '/' + n: json.dumps(v).encode() for n, v in {
            'settings.json': {'password_hash': 'keep-me'}, 'profiles.json': [{'config': 'private-key'}],
            'state.json': {'revision': 'policy-one', 'policy': {'default': 'geo'}},
            'tunnel.json': {'enabled': True, 'active': {'id': 'profile-one', 'revision': 'profile-rev'}}}.items()}
        self.dirs = {DATA, *(r['root-dir'] for r in self.items)}
        self.veth = {u.UPLINK, 'awg-previous-025i'}
        self.button_flags = {'mode': True, 'reset': True}
        self.events, self.faults, self.journal_value = [], set(), None
        self.locked = None

    def event(self, name):
        self.events.append(name)
        if name in self.faults:
            self.faults.remove(name)
            raise ValueError('Simulated failure: ' + name)

    def identity(self):
        return 'router-one'

    def lock(self, token, recovery=False):
        if self.locked and not (recovery and token == self.locked):
            raise ValueError('Locked')
        self.locked = token

    def unlock(self, token):
        if self.locked == token:
            self.locked = None

    def containers(self):
        return copy.deepcopy(self.items)

    def mounts(self):
        return copy.deepcopy(self.mount_rows)

    def read(self, remote, limit=u.MAX_JSON):
        raw = self.files.get(remote)
        if raw is not None and len(raw) > limit:
            raise ValueError('Oversized')
        return raw

    def json_files(self, directory):
        return sorted(p[len(directory) + 1:] for p in self.files if p.startswith(directory + '/') and '/' not in p[len(directory) + 1:] and p.endswith('.json'))

    def mkdir(self, directory):
        self.dirs.add(directory)

    def exists(self, remote):
        return remote in self.files or remote in self.dirs

    def upload(self, local, remote):
        self.files[remote] = local.read_bytes()

    def journal(self, tx, output):
        self.event('journal:' + tx['phase'])
        self.journal_value = copy.deepcopy(tx)
        Transport.secure_write(output / 'update.json', json.dumps(tx))

    def load_journal(self, disk):
        return copy.deepcopy(self.journal_value)

    def buttons(self):
        return self.button_flags.copy()

    def set_buttons(self, buttons):
        self.button_flags = buttons.copy()

    def set_container(self, row, **values):
        self.event('set:' + row['name'])
        item = next(r for r in self.items if r['name'] == row['name'])
        if 'name' in values:
            if any(r is not item and r['name'] == values['name'] for r in self.items):
                raise ValueError('Duplicate name')
        item.update({k.replace('_', '-'): v for k, v in values.items()})

    def stop(self, row):
        self.event('stop:' + row['name'])
        self.set_container(row, running=False, stopped=True, start_on_boot='no')

    def start(self, name):
        self.event('start:' + name)
        self.set_container({'name': name}, running=True, stopped=False)

    def wait_memory(self):
        self.event('memory')

    def add_veth(self, name, token):
        self.veth.add(name)

    def ensure_stage_veth(self, tx):
        self.veth.add(tx['stage_veth'])

    def add_container(self, tx):
        self.event('extract')
        row = {**tx['new'], 'name': tx['stage_name'], 'interface': tx['stage_veth'],
               'running': False, 'stopped': True, 'start-on-boot': False}
        self.items.append(row)
        self.dirs.update((row['root-dir'], row['layer-dir']))

    def diagnostic(self):
        return {'tunnel': {}}

    def wait_healthy(self, tx, output, *, rollback=False):
        self.event('rollback-health' if rollback else 'health')
        message = u.health_error(healthy(tx['expected']), tx['expected'])
        if message:
            raise ValueError(message)

    def remove_file(self, remote):
        self.event('unlink:' + remote)
        self.files.pop(remote, None)

    def remove_empty_dir(self, directory):
        if directory not in self.dirs:
            return
        if any(p.startswith(directory + '/') for p in self.files.keys() | self.dirs):
            raise ValueError('Nonempty directory')
        self.dirs.remove(directory)

    def remove_veth(self, name):
        if any(r['interface'] == name for r in self.items):
            raise ValueError('Interface used')
        if name == u.UPLINK:
            raise AssertionError('Must never remove live uplink')
        self.veth.discard(name)


class UpdateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.image = self.root / 'image.tar'
        self.image.write_bytes(b'image for orchestration test')
        self.d = FakeDevice()
        self.n = 0

    def perform(self):
        self.n += 1
        output = self.root / ('run' + str(self.n))
        output.mkdir()
        with patch.object(u, 'inspect_image', return_value=(str(self.n) * 64, '0.2.7')), patch.object(u.secrets, 'token_hex', return_value=f'{self.n:08x}'):
            u.update(self.d, DISK, self.image, output, Transport)
        return output

    def test_three_updates_keep_only_current_previous_and_one_usb_snapshot(self):
        original = copy.deepcopy(self.d.files)
        for _ in range(3):
            self.perform()
            self.assertEqual(len(self.d.items), 2)
            self.assertEqual(len(self.d.veth), 2)
            self.assertEqual(sum(u.yes(c['running']) for c in self.d.items), 1)
            self.assertIsNone(self.d.locked)
            self.assertEqual(self.d.button_flags, {'mode': True, 'reset': True})
            self.assertFalse(any(p.endswith('.tar') for p in self.d.files))
            self.assertEqual(sum(p.endswith('/owner.json') for p in self.d.files), 1)
        for p, raw in original.items():
            self.assertEqual(self.d.files[p], raw)
        self.assertTrue(self.d.events.index('health') < self.d.events.index('remove:awg-control-previous-025i'))
        self.assertEqual({r['image-id'] for r in self.d.items}, {'2' * 64, '3' * 64})

    def test_vpn_off_stays_off(self):
        self.d.files[DATA + '/tunnel.json'] = json.dumps({'enabled': False, 'active': {}}).encode()
        self.perform()
        self.assertFalse(self.d.journal_value['expected']['enabled'])

    def test_health_failure_rolls_back_without_retiring_any_backup(self):
        before = copy.deepcopy(self.d.files)
        self.d.faults.add('health')
        with self.assertRaisesRegex(ValueError, 'Simulated failure'):
            self.perform()
        self.assertFalse(any(e.startswith('remove:') for e in self.d.events))
        active = next(r for r in self.d.items if r['name'] == u.ACTIVE)
        self.assertEqual(active['image-id'], 'a' * 64)
        self.assertTrue(u.yes(active['running']))
        self.assertEqual(self.d.journal_value['phase'], 'rolled-back')
        for p, raw in before.items():
            self.assertEqual(self.d.files[p], raw)

    def test_extraction_failure_keeps_both_originals_and_restores_buttons(self):
        self.d.faults.add('extract')
        with self.assertRaises(ValueError):
            self.perform()
        self.assertEqual(len(self.d.items), 2)
        self.assertTrue(u.yes(self.d.items[0]['running']))
        self.assertEqual(self.d.button_flags, {'mode': True, 'reset': True})
        self.assertFalse(any(e.startswith('remove:') for e in self.d.events))

    def test_cleanup_failure_does_not_rollback_healthy_new_and_can_be_retried(self):
        self.d.faults.add('remove:awg-control-previous-025i')
        with self.assertRaises(ValueError):
            self.perform()
        self.assertEqual(self.d.journal_value['phase'], 'verified')
        self.assertEqual(next(r for r in self.d.items if r['name'] == u.ACTIVE)['image-id'], '1' * 64)
        self.assertNotIn('rollback-health', self.d.events)
        u.retry_cleanup(self.d, DISK, self.root / 'retry')
        self.assertEqual(len(self.d.items), 2)
        u.retry_cleanup(self.d, DISK, self.root / 'retry-again')
        self.assertEqual(len(self.d.items), 2)

    def test_disconnect_after_container_removal_retries_remaining_tails(self):
        self.perform()
        old_tx = copy.deepcopy(self.d.journal_value)
        self.d.faults.add('unlink:' + old_tx['directory'] + '/data/profiles.json')
        with self.assertRaises(ValueError):
            self.perform()
        self.assertEqual(len(self.d.items), 2)
        self.assertTrue(any(p.startswith(old_tx['directory'] + '/') for p in self.d.files))
        u.retry_cleanup(self.d, DISK, self.root / 'retry')
        self.assertFalse(any(p.startswith(old_tx['directory'] + '/') for p in self.d.files))

    def test_committed_update_can_restore_snapshot_and_recreate_staging_interface(self):
        output = self.perform()
        tx = self.d.load_journal(DISK)
        self.d.files[DATA + '/settings.json'] = b'{"changed":true}'
        self.d.files[DATA + '/new-format.json'] = b'{}'
        u.rollback_update(self.d, tx, output, Transport)
        self.assertEqual(json.loads(self.d.files[DATA + '/settings.json']), {'password_hash': 'keep-me'})
        self.assertNotIn(DATA + '/new-format.json', self.d.files)
        self.assertEqual(next(r for r in self.d.items if r['name'] == u.ACTIVE)['image-id'], 'a' * 64)

    def test_corrupt_snapshot_never_overwrites_shared_data(self):
        output = self.perform()
        tx = self.d.load_journal(DISK)
        self.d.files[tx['directory'] + '/data/profiles.json'] = b'corrupt'
        before = copy.deepcopy({p: v for p, v in self.d.files.items() if p.startswith(DATA + '/')})
        with self.assertRaisesRegex(ValueError, 'corrupt'):
            u.restore_data(self.d, tx, output, Transport)
        self.assertEqual(before, {p: v for p, v in self.d.files.items() if p.startswith(DATA + '/')})

    def test_unknown_copy_is_not_deleted_or_silently_counted_as_backup(self):
        self.d.items.append(container('awg-control-custom', 'custom-root', 'custom-veth', 'c' * 64, False))
        with self.assertRaisesRegex(ValueError, 'Unrecognized'):
            self.perform()
        self.assertFalse(self.d.events)

    def test_foreign_containers_are_untouched(self):
        extra = container('unrelated', 'other-app', 'other-veth', 'c' * 64, False)
        extra['mountlists'] = 'unrelated_mount'
        self.d.items.append(extra)
        self.perform()
        self.assertIn(extra, self.d.items)

    def test_shared_root_or_mount_prevents_retired_container_deletion(self):
        r = old_backup()
        self.d.mount_rows.append({'list': 'custom', 'src': r['root-dir'] + '/shared', 'dst': '/other'})
        with self.assertRaisesRegex(ValueError, 'mount'):
            self.d.remove_retired(r, DISK, [container()])
        self.assertEqual(len(self.d.items), 2)
        self.d.mount_rows.pop()
        shared = container('other', 'awg-control-025i-root/child', 'other', 'c' * 64, False)
        self.d.items.append(shared)
        with self.assertRaisesRegex(ValueError, 'shared'):
            self.d.remove_retired(r, DISK, [container()])

    def test_active_or_boot_enabled_candidate_cannot_be_removed(self):
        record = old_backup()
        for field in ('running', 'start-on-boot'):
            with self.subTest(field=field):
                self.d.items[1][field] = True
                with self.assertRaises(ValueError):
                    self.d.remove_retired(record, DISK, [container()])
                self.d.items[1][field] = False
        with self.assertRaisesRegex(ValueError, 'retained'):
            self.d.remove_retired(container(), DISK, [container()])

    def test_stale_or_unverified_journal_cannot_cleanup(self):
        self.perform()
        tx = self.d.load_journal(DISK)
        tx['phase'] = 'switching'
        with self.assertRaisesRegex(ValueError, 'verified'):
            u.cleanup(self.d, tx, self.root)
        tx['phase'] = 'verified'
        self.d.journal_value['token'] = '20000101-aaaaaaaa'
        with self.assertRaisesRegex(ValueError, 'later'):
            u.cleanup(self.d, tx, self.root)

    def test_usb_path_traversal_and_foreign_snapshot_are_rejected(self):
        for p in ('../flash', '/usb1-part1/../flash', 'usb1-part1//awg-control-root', 'usb1-part1/awg-control-root;remove'):
            with self.subTest(path=p), self.assertRaises(ValueError):
                u.root_on_usb(p, DISK)
        with self.assertRaises(ValueError):
            u.remove_snapshot(self.d, {**old_backup(), 'snapshot_dir': DATA}, DISK, ())

    def test_health_rejects_busy_route_error_wrong_profile_and_missing_api(self):
        e = {'enabled': True, 'active_id': 'p', 'active_revision': 'r', 'revision': 's'}
        good = healthy(e)
        self.assertEqual(u.health_error(good, e), '')
        for change in (
            lambda d: d.update(busy=True), lambda d: d.update(geo_error='failed'),
            lambda d: d.update(resource='API down'), lambda d: d.update(revision='other'),
            lambda d: d['tunnel'].update(connected=False), lambda d: d['tunnel']['route'].update(ready=False),
            lambda d: d['tunnel'].update(active_id='other'), lambda d: d['mangle'][0].update(disabled=True),
        ):
            d = copy.deepcopy(good)
            change(d)
            self.assertTrue(u.health_error(d, e), d)

    def test_single_platform_image_metadata_and_no_tar_extraction(self):
        raw = json.dumps({'os': 'linux', 'architecture': 'arm', 'variant': 'v7', 'config': {
            'Entrypoint': ['/awg-control'], 'Labels': {'org.opencontainers.image.version': '0.2.7'}}}).encode()
        with tarfile.open(self.image, 'w') as tar:
            for name, value in [('manifest.json', json.dumps([{'Config': 'config.json'}]).encode()), ('config.json', raw)]:
                info = tarfile.TarInfo(name)
                info.size = len(value)
                tar.addfile(info, io.BytesIO(value))
        self.assertEqual(u.inspect_image(self.image), (hashlib.sha256(raw).hexdigest(), '0.2.7'))

    def test_real_adapter_checks_interface_references_including_negation(self):
        for menu, field, value in (
            ('/ip/address', 'interface', 'awg-previous-example'),
            ('/ipv6/firewall/filter', 'in-interface', '!awg-previous-example'),
            ('/ip/route', 'gateway', '192.0.2.1%awg-previous-example'),
        ):
            with self.subTest(menu=menu), patch.object(self.d, 'rows', create=True,
                    side_effect=lambda m, f: [{'name': 'awg-previous-example', 'comment': 'old rollback'}] if m == '/interface/veth' else ([{field: value}] if m == menu else [])):
                with self.assertRaisesRegex(ValueError, 'referenced'):
                    u.Device.remove_veth(self.d, 'awg-previous-example')

    def test_readiness_requires_two_samples_and_does_not_accept_listening_alone(self):
        expected = {'enabled': True, 'active_id': 'p', 'active_revision': 'r', 'revision': 's'}
        samples = [healthy(expected) for _ in range(3)]
        samples[0]['busy'] = True
        with patch.object(self.d, 'diagnostic', side_effect=samples), \
                patch.object(self.d, 'panel_check') as http, patch.object(u.time, 'sleep'):
            u.Device.wait_healthy(self.d, {'version': '0.2.7', 'expected': expected}, self.root)
        self.assertEqual(http.call_count, 2)

    def test_snapshot_larger_than_old_migration_limit_and_empty_flag_values(self):
        self.d.files[DATA + '/state.json'] = json.dumps({'revision': 'policy-one', 'bundle': {'ips': ['203.0.113.0/24'] * 22000}}).encode()
        self.d.items[0]['stopped'] = ''
        self.d.items[1]['running'] = ''
        self.assertGreater(len(self.d.files[DATA + '/state.json']), 256 * 1024)
        self.perform()
        self.assertEqual(len(self.d.items), 2)

    def test_other_running_mount_alias_blocks_update_before_stop(self):
        other = container('other-app', 'other-root', 'other-interface', 'c' * 64, True)
        other['mountlists'] = 'custom,alias'
        self.d.items.append(other)
        self.d.mount_rows.append({'list': 'alias', 'src': DATA, 'dst': '/shared'})
        with self.assertRaisesRegex(ValueError, 'shares'):
            self.perform()
        self.assertFalse(self.d.events)


if __name__ == '__main__':
    unittest.main()
