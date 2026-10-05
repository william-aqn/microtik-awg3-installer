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
        self.assertIn('address=172.18.21.2/32', setup)
        self.assertIn('policy=read,write,test,api,rest-api', setup)
        self.assertNotIn('password', rollback.lower())
        self.assertNotIn('a sufficiently long test password', setup)
        self.assertEqual(len(settings['password_hash']), 64)
        self.assertIn('name=awg-toggle-base', setup)
        self.assertIn('name=awg-toggle', rollback)
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
        for allow in ('AWG3UI API and DNS', 'AWG3UI DNS'):
            self.assertLess(rules.index(allow), rules.index('AWG3UI input guard'))
        for allow in ('AWG3UI replies', 'AWG3UI LAN panel', 'AWG3UI temporary upstream'):
            self.assertLess(rules.index(allow), rules.index('AWG3UI access guard'))


if __name__ == '__main__':
    unittest.main()
