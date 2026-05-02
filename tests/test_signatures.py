import os
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from modules import signatures
from modules import elgamal

class TestSignatures(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.patcher = patch('modules.elgamal.KEYS_DIR', self.temp_dir.name)
        self.patcher.start()

    def tearDown(self):
        self.patcher.stop()
        self.temp_dir.cleanup()

    def test_sign_and_verify_vault(self):
        username = "test_signer"
        vault_data = '{"vault": "data", "passwords": [{"service": "google", "pwd": "123"}]}'
        
        # Initialize user to get keys
        elgamal.initialize_user(username)
        
        # Sign vault
        signature = signatures.sign_vault(vault_data, username)
        self.assertIn('r', signature)
        self.assertIn('s', signature)
        
        # Verify vault
        is_valid = signatures.verify_vault(vault_data, signature, username)
        self.assertTrue(is_valid)

    def test_verify_vault_tampered_data(self):
        username = "test_signer2"
        vault_data = '{"vault": "data"}'
        
        elgamal.initialize_user(username)
        
        signature = signatures.sign_vault(vault_data, username)
        
        # Tampered data
        tampered_data = '{"vault": "hacked"}'
        with self.assertRaises(ValueError):
            signatures.verify_vault(tampered_data, signature, username)

    def test_verify_vault_tampered_signature(self):
        username = "test_signer3"
        vault_data = '{"vault": "data"}'
        
        elgamal.initialize_user(username)
        
        signature = signatures.sign_vault(vault_data, username)
        
        # Tampered signature
        tampered_signature = {'r': signature['r'], 's': signature['s'] + 1}
        with self.assertRaises(ValueError):
            signatures.verify_vault(vault_data, tampered_signature, username)

    def test_verify_invalid_signature_format(self):
        username = "test_signer4"
        vault_data = '{"vault": "data"}'
        
        elgamal.initialize_user(username)
        
        # Invalid signature format
        with self.assertRaises(ValueError):
            signatures.verify_vault(vault_data, {'r': 123}, username)
        with self.assertRaises(ValueError):
            signatures.verify_vault(vault_data, {'s': 456}, username)
        with self.assertRaises(ValueError):
            signatures.verify_vault(vault_data, {}, username)

if __name__ == "__main__":
    unittest.main()
