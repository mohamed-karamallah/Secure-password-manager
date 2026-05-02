import os
import sys
import json
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from modules import vault
from modules import elgamal
import modules.elgamal


class TestVault(unittest.TestCase):

    def setUp(self):
        self.temp_keys = tempfile.TemporaryDirectory()
        self.temp_vaults = tempfile.TemporaryDirectory()

        self.key_patcher = patch('modules.elgamal.KEYS_DIR', self.temp_keys.name)
        self.vault_patcher = patch('modules.vault.VAULTS_DIR', self.temp_vaults.name)
        self.key_patcher.start()
        self.vault_patcher.start()

        self.username = "testvault"
        self.master_pw = "supersecret123"
        elgamal.initialize_user(self.username)

    def tearDown(self):
        self.key_patcher.stop()
        self.vault_patcher.stop()
        self.temp_keys.cleanup()
        self.temp_vaults.cleanup()

    def test_create_and_load_empty(self):
        vault.create_vault(self.username, self.master_pw)
        creds = vault.load_vault(self.username, self.master_pw)
        self.assertEqual(creds, [])

    def test_add_and_get(self):
        vault.create_vault(self.username, self.master_pw)

        vault.add_credential(self.username, self.master_pw,
                             "google.com", "myemail@gmail.com", "gpass123")

        result = vault.get_credential(self.username, self.master_pw, "google.com")
        self.assertIsNotNone(result)
        self.assertEqual(result["website"], "google.com")
        self.assertEqual(result["username"], "myemail@gmail.com")
        self.assertEqual(result["password"], "gpass123")

    def test_add_duplicate_fails(self):
        vault.create_vault(self.username, self.master_pw)
        vault.add_credential(self.username, self.master_pw,
                             "github.com", "user1", "pw1")

        with self.assertRaises(ValueError):
            vault.add_credential(self.username, self.master_pw,
                                 "github.com", "user2", "pw2")

    def test_get_nonexistent(self):
        vault.create_vault(self.username, self.master_pw)
        result = vault.get_credential(self.username, self.master_pw, "doesntexist.com")
        self.assertIsNone(result)

    def test_update_credential(self):
        vault.create_vault(self.username, self.master_pw)
        vault.add_credential(self.username, self.master_pw,
                             "twitter.com", "tweeter", "oldpw")

        vault.update_credential(self.username, self.master_pw,
                                "twitter.com", "newpw999")

        result = vault.get_credential(self.username, self.master_pw, "twitter.com")
        self.assertEqual(result["password"], "newpw999")

    def test_delete_credential(self):
        vault.create_vault(self.username, self.master_pw)
        vault.add_credential(self.username, self.master_pw,
                             "reddit.com", "redditor", "rpass")

        vault.delete_credential(self.username, self.master_pw, "reddit.com")

        result = vault.get_credential(self.username, self.master_pw, "reddit.com")
        self.assertIsNone(result)

    def test_list_credentials(self):
        vault.create_vault(self.username, self.master_pw)
        vault.add_credential(self.username, self.master_pw,
                             "site1.com", "u1", "p1")
        vault.add_credential(self.username, self.master_pw,
                             "site2.com", "u2", "p2")

        sites = vault.list_credentials(self.username, self.master_pw)
        self.assertIn("site1.com", sites)
        self.assertIn("site2.com", sites)
        self.assertEqual(len(sites), 2)

    def test_wrong_password(self):
        vault.create_vault(self.username, self.master_pw)
        vault.add_credential(self.username, self.master_pw,
                             "test.com", "user", "pass")

        with self.assertRaises(ValueError):
            vault.load_vault(self.username, "wrongpassword")

    def test_tampered_vault_detected(self):
        vault.create_vault(self.username, self.master_pw)
        vault.add_credential(self.username, self.master_pw,
                             "bank.com", "bankuser", "bankpw")

        vault_path = vault._vault_path(self.username)
        with open(vault_path, 'r') as f:
            data = json.load(f)

        enc = data["encrypted_data"]
        if enc[0] == 'A':
            data["encrypted_data"] = 'B' + enc[1:]
        else:
            data["encrypted_data"] = 'A' + enc[1:]

        with open(vault_path, 'w') as f:
            json.dump(data, f)

        with self.assertRaises(ValueError):
            vault.load_vault(self.username, self.master_pw)


if __name__ == '__main__':
    unittest.main()
