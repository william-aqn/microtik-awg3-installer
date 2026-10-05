import argparse
import base64
import importlib.util
import io
import ipaddress
import json
from pathlib import Path
import re
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / 'awg-mikrotik.py'
spec = importlib.util.spec_from_file_location('awg_installer', SCRIPT)
awg = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = awg
spec.loader.exec_module(awg)
KEY = base64.b64encode(bytes(32)).decode()
SAMPLE = f'''[Interface]
Address = 10.8.1.8/32
PrivateKey = {KEY}
DNS = 1.1.1.1, 1.0.0.1
MTU = 1280
I1 = <r2><b0x00 aa FF 12>
RandomTrailers = on
DisableCookies = on

[Peer]
PublicKey = {KEY}
PresharedKey = {KEY}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 9.9.9.9:39423
PersistentKeepalive = 25-35
'''


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.config = self.root / 'fixture.conf'
        self.config.write_text(SAMPLE, encoding='utf-8')
        self.settings = awg.Settings().validate()
        self.parsed = awg.parse_config(self.config, resolve=False)

    def tearDown(self):
        self.tmp.cleanup()

    def test_config_preserves_keys_and_new_protocol_fields(self):
        self.assertIn('PrivateKey = ' + KEY, self.parsed.text)
        self.assertIn('RandomTrailers = on', self.parsed.text)
        self.assertIn('DisableCookies = on', self.parsed.text)
        self.assertIn('<b0x00aaFF12>', self.parsed.text)
        self.assertIn('AllowedIPs = 0.0.0.0/1, 128.0.0.0/1', self.parsed.text)
        self.assertIn('ip route replace 9.9.9.9/32 via 172.18.20.1', self.parsed.text)

    def test_invalid_config_rejections_do_not_echo_secrets(self):
        replacements = [('Address = 10.8.1.8/32', 'Address = 10.8.1.8/24'),
                        ('MTU = 1280', 'MTU = 9000'), ('<b0x00 aa FF 12>', '<b0x00 aa F>'),
                        ('AllowedIPs = 0.0.0.0/0, ::/0', 'AllowedIPs = 10.0.0.0/8'),
                        ('Endpoint = 9.9.9.9:39423', 'Endpoint = 127.0.0.1:39423'),
                        ('[Peer]', '[Peer]\nPostUp = touch /tmp/unwanted'),
                        ('DNS = 1.1.1.1, 1.0.0.1', 'DNS = 192.168.3.1, 1.0.0.1')]
        for before, after in replacements:
            with self.subTest(after=after):
                self.config.write_text(SAMPLE.replace(before, after), encoding='utf-8')
                with self.assertRaises(awg.InstallError) as caught:
                    awg.parse_config(self.config, resolve=False)
                self.assertNotIn(KEY, str(caught.exception))

    def test_settings_reject_injection_and_transit_overlap(self):
        for field, value in [('wan', 'ether1; /system/reset-configuration'), ('disk', '../flash'),
                             ('bridge', 'bridge$bad'), ('lan', '172.18.20.0/24'), ('lan', '8.8.8.0/24')]:
            with self.subTest(field=field):
                data = dict(lan='192.168.3.0/24', bridge='bridge', wan='ether1', disk='usb1-part1')
                data[field] = value
                with self.assertRaises((awg.InstallError, ValueError)):
                    awg.Settings(**data).validate()

    def test_prepend_firewall_results_allow_before_guard(self):
        forward = []
        for command, _ in awg.make_plan(self.settings, self.parsed):
            if command.startswith('/ip/firewall/filter/add') and 'chain=forward' in command:
                forward.insert(0, command)
        allow = next(i for i, line in enumerate(forward) if 'encrypted transport' in line)
        guard = next(i for i, line in enumerate(forward) if 'prevent unencrypted' in line)
        self.assertLess(allow, guard)
        self.assertIn('dst-address=9.9.9.9', forward[allow])
        self.assertIn('dst-port=39423', forward[allow])

    def test_no_fallback_policy_and_dns_not_open_to_wan(self):
        commands = '\n'.join(cmd for cmd, _ in awg.make_plan(self.settings, self.parsed))
        self.assertIn('src-address=192.168.3.0/24 action=lookup-only-in-table table=to-awg disabled=yes', commands)
        self.assertIn('chain=input action=drop in-interface=ether1 protocol=udp dst-port=53', commands)
        self.assertIn('new-mss=1240', commands)
        self.assertNotIn(KEY, commands)
        self.assertNotIn('PrivateKey', commands)
        self.assertNotIn('/ip/route/set', commands)

    def test_connection_cleanup_matches_exact_lan(self):
        for cidr in ('192.168.3.0/24', '10.20.0.0/16', '192.168.3.128/25', '192.168.3.64/26', '10.10.16.0/20'):
            settings = awg.Settings(lan=cidr).validate()
            script = awg.toggle_rsc(settings, self.parsed)
            quoted = re.search(r'src-address~("(?:\\.|[^"\\])*")', script)[1]
            regex = json.loads(quoted.replace('\\$', '$'))
            net = ipaddress.ip_network(cidr)
            self.assertRegex(str(net.network_address) + ':1234', regex)
            self.assertRegex(str(net.broadcast_address) + ':1234', regex)
            self.assertNotRegex(str(ipaddress.ip_address(int(net.broadcast_address) + 1)) + ':1234', regex)
            self.assertNotRegex('192x168x3x100:1234', regex)

    def test_toggle_boot_flag_only_after_stop_and_failure_restores_main(self):
        script = awg.toggle_rsc(self.settings, self.parsed)
        self.assertLess(script.index('/container/stop'), script.index('start-on-boot=no'))
        self.assertLess(script.index('/container/stop'), script.index('start-on-boot=yes'))
        self.assertIn('/routing/rule/disable [find where comment~"^AWG3 switch"]', script)
        self.assertIn('/system/script/run awg-diag', script)
        self.assertIn(':set awgBusy false', script)

    def test_scrub_removes_keys_and_passwords(self):
        result = awg.scrub('PrivateKey = ' + KEY + '\nPresharedKey=' + KEY + '\npassword=secret\nI1=<b0x012345>\nkey: ' + KEY)
        self.assertNotIn(KEY, result)
        self.assertNotIn('secret', result)
        self.assertNotIn('012345', result)

    def test_hash_rejects_modified_blob(self):
        digest = 'sha256:' + awg.hashlib.sha256(b'original').hexdigest()
        self.assertEqual(awg.checked_blob(b'original', digest), b'original')
        with self.assertRaises(awg.InstallError):
            awg.checked_blob(b'changed', digest)

    def test_routeros_zero_exit_failure_without_marker_rejected(self):
        class Output(io.BytesIO):
            channel = type('Channel', (), {'recv_exit_status': lambda self: 0})()
        router = awg.Router.__new__(awg.Router)
        class Client:
            def exec_command(self, command, timeout):
                return io.BytesIO(), Output(b'failure: no such item\n__AWG_ERROR__'), io.BytesIO()
        router.client = Client()
        with self.assertRaises(awg.InstallError):
            router.run('/container/start bad')

    def test_diagnostic_continues_when_menu_unavailable(self):
        class Broken:
            def run(self, command):
                if '/container' in command:
                    raise RuntimeError('missing package')
                return 'OK'
            def get(self, *args):
                raise RuntimeError('not running')
        with patch('sys.stdout', io.StringIO()):
            result = awg.diagnostics(Broken(), self.root / 'diag.txt')
        self.assertIn('missing package', result)
        self.assertIn('AWG rules', result)
        self.assertTrue((self.root / 'diag.txt').exists())

    def test_rollback_reverse_order_and_all_failures_reported(self):
        calls = []
        class Fake:
            def run(self, command, timeout=30):
                calls.append(command)
                if command == 'undo2':
                    raise RuntimeError('failed undo2')
                return ''
            def count(self, *args):
                return 0
        with patch('sys.stdout', io.StringIO()):
            failed = awg.rollback(Fake(), ['undo1', 'undo2', 'undo3'], self.root / 'report')
        self.assertEqual(calls[-3:], ['undo3', 'undo2', 'undo1'])
        self.assertEqual(len(failed), 1)
        self.assertTrue((self.root / 'report.rollback.txt').exists())

    def test_dry_run_no_connection_and_no_config_saved(self):
        argv = ['--dry-run', '--config', str(self.config), '--lan', '192.168.3.0/24', '--bridge', 'bridge', '--wan', 'ether1', '--disk', 'usb1-part1', '--output', str(self.root / 'generated')]
        with patch.object(awg, 'Router', side_effect=AssertionError('network used')), patch('sys.stdout', io.StringIO()):
            self.assertEqual(awg.main(argv), 0)
        self.assertTrue((self.root / 'generated/prepare.rsc').exists())
        self.assertFalse((self.root / 'generated/awg0.conf').exists())

    def test_diag_does_not_ask_for_config(self):
        class Fake:
            def run(self, command):
                return ''
            def get(self, *args):
                return 'false'
            def close(self):
                pass
        with patch.object(awg, 'Router', return_value=Fake()), patch.object(awg, 'parse_config', side_effect=AssertionError('config accessed')), patch('sys.stdout', io.StringIO()):
            self.assertEqual(awg.main(['--diag', '--host', '192.168.3.1', '--output', str(self.root / 'diagnostic')]), 0)

    def test_connection_failure_has_report_and_nonzero_exit(self):
        with patch.object(awg, 'Router', side_effect=OSError('connection refused')), patch('sys.stderr', io.StringIO()):
            code = awg.main(['--diag', '--host', '192.168.3.1', '--output', str(self.root / 'failed')])
        self.assertEqual(code, 1)
        self.assertIn('connection refused', (self.root / 'failed/diagnostics.txt').read_text(encoding='utf-8'))

    def test_oci_archive_download_verifies_platform_and_every_layer(self):
        config_bytes = json.dumps({'architecture': 'arm', 'os': 'linux', 'variant': 'v7'}).encode()
        layer = b'simulated layer'
        config_digest = 'sha256:' + awg.hashlib.sha256(config_bytes).hexdigest()
        layer_digest = 'sha256:' + awg.hashlib.sha256(layer).hexdigest()
        manifest = json.dumps({'schemaVersion': 2, 'mediaType': 'application/vnd.oci.image.manifest.v1+json', 'config': {'digest': config_digest, 'size': len(config_bytes)}, 'layers': [{'digest': layer_digest, 'size': len(layer)}]}).encode()
        digest = 'sha256:' + awg.hashlib.sha256(manifest).hexdigest()
        def get(url, token=None):
            if 'auth.docker.io' in url:
                return b'{"token":"test"}'
            if '/manifests/' in url:
                return manifest
            return config_bytes if url.endswith(config_digest) else layer
        target = self.root / 'image.tar'
        with patch.object(awg, 'IMAGE_DIGEST', digest), patch.object(awg, 'download', side_effect=get), patch('sys.stdout', io.StringIO()):
            awg.build_image(target)
        with tarfile.open(target) as archive:
            index = json.load(archive.extractfile('index.json'))
            self.assertEqual(index['manifests'][0]['digest'], digest)
            self.assertEqual(archive.extractfile('blobs/sha256/' + layer_digest[7:]).read(), layer)

    def test_failed_install_keeps_diagnostic_and_dns_undo_before_rollback(self):
        calls = []
        class SFTP:
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def get(self, remote, local): Path(local).write_bytes(b'fixture backup')
        class Fake:
            client = type('Client', (), {'open_sftp': lambda self: SFTP()})()
            def run(self, command, timeout=30):
                calls.append(command)
                if command.startswith('/ip/dns/set servers=1.1.1.1'):
                    raise awg.InstallError('Simulated DNS failure after request')
                return ''
            def get(self, menu, prop, where=None):
                return {'servers': '192.168.1.1', 'allow-remote-requests': 'false', 'use-peer-dns': 'true'}[prop]
            def upload(self, local, remote): pass
        args = argparse.Namespace(host='192.168.3.1')
        image = self.root / 'image.tar'
        image.write_bytes(b'image fixture')
        events = []
        def diag(router, report):
            events.append('diag')
            report.write_text('Failed state saved', encoding='utf-8')
        def undo(router, commands, report):
            events.append('rollback')
            self.assertIn('/ip/dns/set servers="192.168.1.1" allow-remote-requests=no', commands)
            self.assertTrue((self.root / 'rollback.json').exists())
        with patch.object(awg, 'preflight'), patch.object(awg, 'prepare_disk'), patch.object(awg, 'confirm'), patch.object(awg, 'build_image', return_value=image), patch.object(awg, 'diagnostics', side_effect=diag), patch.object(awg, 'rollback', side_effect=undo), patch('sys.stdout', io.StringIO()):
            with self.assertRaises(awg.InstallError):
                awg.install(Fake(), args, self.settings, self.parsed, self.root)
        self.assertEqual(events, ['diag', 'rollback'])
        self.assertFalse((self.root / 'awg0.conf').exists())
        self.assertNotIn(KEY, (self.root / 'rollback.json').read_text(encoding='utf-8'))

    def test_shell_handles_echo_and_waits_for_complete_marker(self):
        class Channel:
            chunks = [b'/ # ', b"echo something; printf '__AWG_SHELL_%s__' DONE\n1234567890\n__AWG_SHELL_DONE__\n"]
            def get_pty(self, **kwargs): pass
            def exec_command(self, command): pass
            def recv_ready(self): return bool(self.chunks)
            def recv(self, size): return self.chunks.pop(0)
            def send(self, command): self.sent = command
            def exit_status_ready(self): return False
            def close(self): pass
        channel = Channel()
        transport = type('Transport', (), {'open_session': lambda self, timeout: channel})()
        router = awg.Router.__new__(awg.Router)
        router.client = type('Client', (), {'get_transport': lambda self: transport})()
        with patch.object(awg.time, 'sleep'):
            output = router.shell('echo something')
        self.assertIn('1234567890', output)
        self.assertIn('exit', channel.sent)


if __name__ == '__main__':
    unittest.main(verbosity=2)
