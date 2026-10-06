import hashlib
import importlib.util
import io
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location('password_reset', Path(__file__).resolve().parents[1] / 'panel/reset-password.py')
reset = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(reset)


class PasswordResetTests(unittest.TestCase):
    def test_hash_matches_panel_and_uses_fresh_salt(self):
        password = 'a new private panel password'
        salt, digest = reset.password_fields(password)
        self.assertEqual(digest, hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt), 100000).hex())
        self.assertNotEqual(salt, reset.password_fields(password)[0])

    def test_script_never_contains_plaintext_and_preserves_network(self):
        password = 'not for RouterOS history $ " ;'
        script, restore = reset.build_scripts(password)
        self.assertTrue(script.isascii())
        self.assertNotIn(password, script + restore)
        for forbidden in ('/user/', '/ip/firewall/', '/routing/', 'tunnel.json', 'profiles.json', 'start-on-boot=', '/file/set'):
            self.assertNotIn(forbidden, script + restore)
        self.assertLess(script.index('Unexpected panel settings format'), script.index('/container/shell'))
        self.assertLess(script.index('Password write was not verified'), script.index('/container/stop'))
        self.assertIn('settings-password-', restore)
        self.assertIn('Restore not verified', restore)

    def test_invalid_password_and_names(self):
        for password in ('short', ' '*16, 'x'*257, 'password-with-newline\n'):
            with self.assertRaises(ValueError):
                reset.build_scripts(password)
        for name in ('../usb', 'usb;reset', 'disk"', 'x'*49):
            with self.assertRaises(ValueError):
                reset.build_scripts('valid private password', disk=name)

    def test_cli_requires_matching_passwords_and_does_not_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp)/'private'
            with patch.object(reset.getpass,'getpass',side_effect=['valid password one','valid password two']), patch('sys.stderr',io.StringIO()):
                self.assertEqual(reset.main(['--output',str(output)]),1)
            self.assertFalse(output.exists())
            password = 'new panel password private'
            with patch.object(reset.getpass,'getpass',return_value=password), patch('sys.stdout',io.StringIO()) as stdout:
                self.assertEqual(reset.main(['--output',str(output)]),0)
            self.assertNotIn(password,stdout.getvalue())
            self.assertEqual(sorted(p.name for p in output.iterdir()),['reset-password.rsc','restore-password.rsc'])
            with patch.object(reset.getpass,'getpass') as prompt, patch('sys.stderr',io.StringIO()):
                self.assertEqual(reset.main(['--output',str(output)]),1)
                prompt.assert_not_called()

    def test_shell_uses_atomic_replace_after_verified_backup(self):
        salt,digest=reset.password_fields('valid panel password')
        script=reset.reset_shell(salt,digest,'a'*16)
        self.assertLess(script.index('cmp -s'),script.index('sed -E'))
        self.assertLess(script.index('grep -qF'),script.index('mv "$tmp" "$cfg"'))
        self.assertIn('umask 077',script)
        self.assertIn('chmod 600',script)
        self.assertTrue(re.fullmatch('[a-f0-9]{32}',salt))


if __name__ == '__main__':
    unittest.main()
