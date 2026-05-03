import os
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from modules import export
from modules import elgamal
from modules import vault
from modules import signatures


class TestDHPrimitives(unittest.TestCase):
    def test_load_dh_params(self):
        q, alpha = export.load_dh_params()
        self.assertIsInstance(q, int)
        self.assertIsInstance(alpha, int)
        self.assertGreater(q, 0)
        self.assertGreater(alpha, 0)

    def test_generate_dh_keypair(self):
        q, alpha = export.load_dh_params()
        pub, priv = export.generate_dh_keypair(q, alpha)
        self.assertIsInstance(pub, int)
        self.assertIsInstance(priv, int)
        self.assertTrue(1 < priv < q - 1)
        self.assertEqual(pub, pow(alpha, priv, q))

    def test_shared_secret_agreement(self):
        q, alpha = export.load_dh_params()
        pub_a, priv_a = export.generate_dh_keypair(q, alpha)
        pub_b, priv_b = export.generate_dh_keypair(q, alpha)

        secret_a = export.compute_shared_secret(pub_b, priv_a, q)
        secret_b = export.compute_shared_secret(pub_a, priv_b, q)
        self.assertEqual(secret_a, secret_b)

    def test_different_sessions_different_secrets(self):
        q, alpha = export.load_dh_params()
        pub_a1, priv_a1 = export.generate_dh_keypair(q, alpha)
        pub_b1, priv_b1 = export.generate_dh_keypair(q, alpha)
        secret1 = export.compute_shared_secret(pub_b1, priv_a1, q)

        pub_a2, priv_a2 = export.generate_dh_keypair(q, alpha)
        pub_b2, priv_b2 = export.generate_dh_keypair(q, alpha)
        secret2 = export.compute_shared_secret(pub_b2, priv_a2, q)

        self.assertNotEqual(secret1, secret2)

    def test_derive_session_key(self):
        q, alpha = export.load_dh_params()
        pub_a, priv_a = export.generate_dh_keypair(q, alpha)
        pub_b, priv_b = export.generate_dh_keypair(q, alpha)

        secret = export.compute_shared_secret(pub_b, priv_a, q)
        key = export.derive_session_key(secret)
        self.assertIsInstance(key, bytes)
        self.assertEqual(len(key), 32)  # AES-256

    def test_session_key_deterministic(self):
        q, alpha = export.load_dh_params()
        pub_a, priv_a = export.generate_dh_keypair(q, alpha)
        pub_b, priv_b = export.generate_dh_keypair(q, alpha)

        secret_a = export.compute_shared_secret(pub_b, priv_a, q)
        secret_b = export.compute_shared_secret(pub_a, priv_b, q)

        key_a = export.derive_session_key(secret_a)
        key_b = export.derive_session_key(secret_b)
        self.assertEqual(key_a, key_b)


class TestSessionEncryption(unittest.TestCase):
    def test_encrypt_decrypt_roundtrip(self):
        import hashlib
        key = hashlib.sha256(b"test-session-key").digest()
        plaintext = b'{"creds": [{"site": "google.com"}]}'

        ct, nonce, tag = export._encrypt_with_key(plaintext, key)
        result = export._decrypt_with_key(ct, nonce, tag, key)
        self.assertEqual(result, plaintext)

    def test_wrong_key_fails(self):
        import hashlib
        key1 = hashlib.sha256(b"key1").digest()
        key2 = hashlib.sha256(b"key2").digest()
        plaintext = b"secret data"

        ct, nonce, tag = export._encrypt_with_key(plaintext, key1)
        with self.assertRaises(ValueError):
            export._decrypt_with_key(ct, nonce, tag, key2)


class TestExportVault(unittest.TestCase):
    def setUp(self):
        self.temp_keys = tempfile.TemporaryDirectory()
        self.temp_vaults = tempfile.TemporaryDirectory()

        self.key_patcher = patch('modules.elgamal.KEYS_DIR', self.temp_keys.name)
        self.vault_patcher = patch('modules.vault.VAULTS_DIR', self.temp_vaults.name)
        self.key_patcher.start()
        self.vault_patcher.start()

        self.sender = "alice"
        self.receiver = "bob"
        self.sender_pw = "alice_master_pw"
        self.receiver_pw = "bob_master_pw"
        elgamal.initialize_user(self.sender)
        elgamal.initialize_user(self.receiver)
        vault.create_vault(self.sender, self.sender_pw)
        vault.add_credential(self.sender, self.sender_pw,
                             "google.com", "alice@gmail.com", "gpass123")
        vault.add_credential(self.sender, self.sender_pw,
                             "github.com", "alice", "ghpass456")

    def tearDown(self):
        self.key_patcher.stop()
        self.vault_patcher.stop()
        self.temp_keys.cleanup()
        self.temp_vaults.cleanup()

    def test_full_export_import(self):
        result = export.export_vault(
            self.sender, self.sender_pw,
            self.receiver, self.receiver_pw
        )
        self.assertEqual(len(result), 2)
        receiver_creds = vault.load_vault(self.receiver, self.receiver_pw)
        self.assertEqual(len(receiver_creds), 2)

        sites = [c["website"] for c in receiver_creds]
        self.assertIn("google.com", sites)
        self.assertIn("github.com", sites)

    def test_receiver_vault_uses_own_signature(self):
        export.export_vault(
            self.sender, self.sender_pw,
            self.receiver, self.receiver_pw
        )

        creds = vault.load_vault(self.receiver, self.receiver_pw)
        self.assertIsNotNone(creds)

    def test_receiver_different_password(self):
        export.export_vault(
            self.sender, self.sender_pw,
            self.receiver, "totally_different_pw"
        )
        with self.assertRaises(ValueError):
            vault.load_vault(self.receiver, self.sender_pw)
        creds = vault.load_vault(self.receiver, "totally_different_pw")
        self.assertEqual(len(creds), 2)

    def test_sender_vault_unchanged(self):
        original = vault.load_vault(self.sender, self.sender_pw)

        export.export_vault(
            self.sender, self.sender_pw,
            self.receiver, self.receiver_pw
        )

        after = vault.load_vault(self.sender, self.sender_pw)
        self.assertEqual(original, after)

    def test_wrong_sender_password_fails(self):
        with self.assertRaises(ValueError):
            export.export_vault(
                self.sender, "wrong_password",
                self.receiver, self.receiver_pw
            )

    def test_missing_sender_keys_fails(self):
        with self.assertRaises(FileNotFoundError):
            export.export_vault(
                "nonexistent_user", "pw",
                self.receiver, self.receiver_pw
            )

    def test_empty_vault_export(self):
        empty_sender = "charlie"
        elgamal.initialize_user(empty_sender)
        vault.create_vault(empty_sender, "charlie_pw")

        result = export.export_vault(
            empty_sender, "charlie_pw",
            self.receiver, self.receiver_pw
        )
        self.assertEqual(result, [])
        creds = vault.load_vault(self.receiver, self.receiver_pw)
        self.assertEqual(creds, [])


if __name__ == '__main__':
    unittest.main()
