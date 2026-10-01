"""Protocol vectors captured from the ZJU portal's own JavaScript implementation."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import campus_login as app


DEFAULTS = {
    'campus_dns': ['10.10.0.21', '10.10.0.17'],
    'local_socks_port': 7897,
    'bootstrap_ipv4': ['10.50.254.11'],
    'ac_id': '80',
}


class IsolatedTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name) / 'source'
        self.data = Path(temporary.name) / 'data'
        self.root.mkdir()
        self.data.mkdir()
        (self.root / 'config.example.json').write_text(json.dumps(DEFAULTS), encoding='utf-8')
        for name, value in [('ROOT', self.root), ('DATA_DIR', self.data)]:
            patcher = patch.object(app, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)


class ProtocolTests(IsolatedTests):
    def test_official_encoding_vectors(self):
        token = '0123456789abcdef0123456789abcdef'
        for text, expected in [('abc', 'dad1d07f6292b0ec'),
                               ('校园密码😀', 'f30d81b47982a551b9e0a420'), ('', '')]:
            with self.subTest(text=text):
                self.assertEqual(app.xencode(text, token).hex(), expected)

    def test_complete_login_signature_matches_portal(self):
        result = app.login_params('sample', 'p@ss', '10.1.2.3', '80', '0123456789abcdef0123456789abcdef')
        self.assertEqual(result['info'], '{SRBX1}JFYQi8lo/ygmcQAkuqgUiofkHpQAW0v3Y+eN0T8Z3PFnBj0VDlBtaX1R9/WAJBelZTu7oZiFrIL7tv34i8s290SWnJLBBdNCAlISBZVQwXUz87KwxtYoKk0vQuZ=')
        self.assertEqual(result['password'], '{MD5}d91eb0e1ec8bc96a920fb37e9f1d7ab9')
        self.assertEqual(result['chksum'], 'f9a1df69ecf78dae3fad9339eea0aa8a8b8aaa19')

    def test_unknown_state_does_not_mean_offline(self):
        portal = app.Portal('127.0.0.1')
        with patch.object(portal, 'get', return_value={'error': 'server_error'}):
            with self.assertRaises(app.CampusError):
                portal.status()

    def test_confirmed_offline_state(self):
        portal = app.Portal('127.0.0.1')
        with patch.object(portal, 'get', return_value={'error': 'not_online_error'}):
            self.assertFalse(portal.status()[0])

    def test_online_does_not_decrypt_password_or_send_login(self):
        with patch.object(app, 'select_portal', return_value=(None, True, {})), \
             patch.object(app, 'load_credentials', side_effect=AssertionError('Must not read credentials')):
            self.assertEqual(app.run(), 0)


    def test_check_only_never_reads_credentials_or_authenticates(self):
        with patch.object(app, 'select_portal', return_value=(None, False, {})), \
             patch.object(app, 'load_credentials', side_effect=AssertionError('Must not read credentials')):
            self.assertEqual(app.run(check_only=True), 2)

    @unittest.skipUnless(os.name == 'nt', 'DPAPI requires Windows')
    def test_dpapi_roundtrip_and_tamper_rejection(self):
        data = 'throwaway-test-秘密'.encode('utf-8')
        encrypted = app.protect(data)
        self.assertNotIn(data, encrypted)
        self.assertEqual(app.protect(encrypted, decrypt=True), data)
        damaged = encrypted[:-1] + bytes([encrypted[-1] ^ 1])
        with self.assertRaises(app.CampusError):
            app.protect(damaged, decrypt=True)


class ConfigurationTests(IsolatedTests):
    def test_defaults_do_not_create_runtime_data_or_read_source_override(self):
        (self.root / 'config.json').write_text('{"ac_id":"999"}', encoding='utf-8')
        self.data.rmdir()
        self.assertEqual(app.load_config(), DEFAULTS)
        self.assertFalse(self.data.exists())

    def test_runtime_override_merges_and_supports_disabled_socks(self):
        (self.data / 'config.json').write_text(
            '{"local_socks_port":null,"ac_id":"81"}', encoding='utf-8')
        result = app.load_config()
        self.assertEqual(result, dict(DEFAULTS, local_socks_port=None, ac_id='81'))
        self.assertEqual(
            json.loads((self.root / 'config.example.json').read_text(encoding='utf-8')), DEFAULTS)

    def test_invalid_runtime_boundaries_are_rejected(self):
        overrides = [
            [], {'campus_dns': []}, {'campus_dns': ['::1']},
            {'campus_dns': ['portal.example']}, {'bootstrap_ipv4': [1]},
            {'bootstrap_ipv4': '10.50.254.11'},
            {'local_socks_port': True}, {'local_socks_port': 0},
            {'local_socks_port': 65536}, {'local_socks_port': '7897'},
            {'ac_id': 80}, {'ac_id': '80&action=logout'},
        ]
        for override in overrides:
            with self.subTest(override=override):
                (self.data / 'config.json').write_text(json.dumps(override), encoding='utf-8')
                with self.assertRaises(app.CampusError):
                    app.load_config()

    def test_invalid_configuration_does_not_echo_contents_or_contact_portal(self):
        secret = 'private-config-value'
        (self.data / 'config.json').write_text(secret, encoding='utf-8')
        with patch.object(app, 'select_portal', side_effect=AssertionError('Must not contact portal')):
            with self.assertRaises(app.CampusError) as caught:
                app.run()
        self.assertNotIn(secret, str(caught.exception))


class CredentialTests(IsolatedTests):
    def test_source_credentials_are_not_used(self):
        (self.root / 'credentials.dat').write_bytes(b'not-runtime-credentials')
        with self.assertRaises(app.CampusError):
            app.load_credentials()

    def test_corrupt_credential_payload_has_safe_error(self):
        (self.data / 'credentials.dat').write_bytes(b'encrypted-placeholder')
        for payload in [b'private-password', b'[]',
                        b'{"username":42,"password":"private-password"}',
                        b'{"username":"sample","password":""}']:
            with self.subTest(payload=payload):
                with patch.object(app, 'protect', return_value=payload):
                    with self.assertRaises(app.CampusError) as caught:
                        app.load_credentials()
                self.assertNotIn('private-password', str(caught.exception))

    @unittest.skipUnless(os.name == 'nt', 'Credential storage requires Windows DPAPI')
    def test_credentials_are_encrypted_and_isolated_from_source(self):
        password = 'throwaway-storage-秘密'
        app.save_credentials(' sample ', password)
        self.assertEqual(app.load_credentials(), {'username': 'sample', 'password': password})
        self.assertNotIn(password.encode('utf-8'), (self.data / 'credentials.dat').read_bytes())
        self.assertFalse((self.root / 'credentials.dat').exists())
        self.assertFalse((self.data / 'credentials.tmp').exists())

    def test_protection_failure_leaves_no_credentials(self):
        with patch.object(app, 'ensure_data_dir', side_effect=app.CampusError('Protection failed')):
            with self.assertRaises(app.CampusError):
                app.save_credentials('sample', 'throwaway-password')
        self.assertFalse((self.data / 'credentials.dat').exists())
        self.assertFalse((self.data / 'credentials.tmp').exists())
        self.assertFalse((self.root / 'credentials.dat').exists())


if __name__ == '__main__':
    unittest.main()
