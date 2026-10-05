import importlib.util
from pathlib import Path
import unittest


PATH = Path(__file__).resolve().parents[1] / 'panel' / 'prepare.py'
SPEC = importlib.util.spec_from_file_location('panel_prepare', PATH)
prepare = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(prepare)


class PanelPrepareTests(unittest.TestCase):
    def test_private_bundle_does_not_open_public_wan(self):
        settings, setup, rollback = prepare.build_bundle(
            '192.168.3.0/24', 'bridge', 'usb1-part1', None, None, 'a sufficiently long test password')
        self.assertNotIn('temporary upstream', setup)
        self.assertIn('src-address=192.168.3.0/24', setup)
        self.assertIn('address=172.18.20.2/32', setup)
        self.assertIn('policy=read,write,test,api,rest-api', setup)
        self.assertNotIn('password', rollback.lower())
        self.assertNotIn('a sufficiently long test password', setup)
        self.assertEqual(len(settings['password_hash']), 64)
        self.assertIn('name=awg-control interface=docker-awg-veth', setup)
        self.assertNotIn('awg-toggle-base', setup)
        self.assertIn('name="awg-mode"', rollback)
        self.assertTrue(setup.isascii())

    def test_upstream_is_one_private_host_only(self):
        settings, setup, _ = prepare.build_bundle(
            '192.168.3.0/24', 'bridge', 'usb1-part1', '192.168.1.50', '192.168.1.135', 'a sufficiently long test password')
        upstream = [line for line in setup.splitlines() if 'temporary upstream' in line]
        self.assertEqual(len(upstream), 2)
        self.assertTrue(all('src-address=192.168.1.50 ' in line for line in upstream))
        self.assertIn('192.168.1.135:8088', settings['hosts'])

    def test_refuses_overlap_and_public_management(self):
        for lan, bridge, upstream, wan in [
            ('172.18.21.0/24', 'bridge', None, None),
            ('192.168.3.0/24', 'bridge; reset', None, None),
            ('192.168.3.0/24', 'bridge', '8.8.8.8', '192.168.1.135'),
            ('192.168.3.0/24', 'bridge', '192.168.1.50', None),
        ]:
            with self.assertRaises(ValueError):
                prepare.build_bundle(lan, bridge, 'usb1-part1', upstream, wan, 'a sufficiently long test password')

    def test_access_exceptions_precede_guards_during_import(self):
        _, setup, _ = prepare.build_bundle(
            '192.168.3.0/24', 'bridge', 'usb1-part1', '192.168.1.50', '192.168.1.135', 'a sufficiently long test password')
        rules = ['existing-rule-zero']
        import re
        for line in setup.splitlines():
            if not line.startswith('/ip/firewall/filter/add '):
                continue
            name = re.search(r'comment="([^"]+)"', line).group(1)
            anchor = re.search(r'place-before=\[find where comment="([^"]+)"\]', line)
            before = anchor.group(1) if anchor else 'existing-rule-zero'
            rules.insert(rules.index(before), name)
        for allow in ('AWGC API and DNS', 'AWGC DNS'):
            self.assertLess(rules.index(allow), rules.index('AWGC input guard'))
        for allow in ('AWGC transport replies', 'AWGC LAN traffic', 'AWGC temporary upstream'):
            self.assertLess(rules.index(allow), rules.index('AWGC access guard'))

    def test_mode_double_press_acknowledges_before_full_stop(self):
        _, setup, _ = prepare.build_bundle('192.168.3.0/24', 'bridge', 'usb1-part1', None, None, 'a sufficiently long test password')
        self.assertIn(':delay 1500ms', setup)
        self.assertIn(':for pulse from=1 to=2', setup)
        self.assertLess(setup.index('full stop accepted'), setup.index('for pulse'))
        self.assertLess(setup.index('for pulse'), setup.index('/container/stop $c'))
        self.assertIn('--control toggle', setup)
        self.assertIn('--control connect', setup)
        self.assertNotIn('reset-button', setup)

    def test_migration_parks_legacy_engine_and_has_restore(self):
        prior = {'router_user': 'awg-panel', 'router_password': 'a' * 48, 'password_salt': 'b' * 32, 'password_hash': 'c' * 64}
        settings, setup, rollback = prepare.build_bundle('192.168.3.0/24', 'bridge', 'usb1-part1', None, None, '', migration=True, prior_settings=prior)
        self.assertIn('interface=awg-retired-veth', setup)
        self.assertIn('AWGC legacy ', setup)
        self.assertNotIn('/container/remove', setup)
        self.assertIn('interface=docker-awg-veth start-on-boot=yes', rollback)
        self.assertEqual(settings['router_password'], prior['router_password'])
        self.assertEqual(settings['router_user'], 'awg-panel')
        self.assertNotIn('name=awg-control address=', setup)
        self.assertNotIn(prior['router_password'], setup)
        self.assertNotIn(prior['router_password'], rollback)

    def test_only_vpn_transport_can_leave_container_for_wan(self):
        _, setup, _ = prepare.build_bundle('192.168.3.0/24', 'bridge', 'usb1-part1', None, None, 'a sufficiently long test password')
        egress = [s for s in setup.splitlines() if 'chain=forward in-interface=docker-awg-veth' in s and 'action=accept' in s and 'out-interface-list=WAN' in s]
        self.assertEqual(len(egress), 1)
        self.assertIn('protocol=udp dst-port=9', egress[0])
        self.assertNotIn('dst-port=443', setup)

    def test_preflight_is_before_backup_or_network_mutations(self):
        _, setup, _ = prepare.build_bundle('192.168.3.0/24', 'bridge', 'usb1-part1', None, None, 'a sufficiently long test password')
        self.assertLess(setup.index('Existing Mode binding'), setup.index('/system/backup/save'))
        self.assertIn('name="www" and dynamic=no', setup)


if __name__ == '__main__':
    unittest.main()
