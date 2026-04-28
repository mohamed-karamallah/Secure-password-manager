import os
import sys
import tempfile
import hashlib

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from modules.elgamal import (
    load_params, generate_keypair, sign, verify, 
    save_keys, load_public_key, load_private_key, KEYS_DIR
)
import modules.elgamal

def test_load_params():
    p, alpha = load_params()
    assert isinstance(p, int)
    assert isinstance(alpha, int)
    assert p > 0
    assert alpha > 0

def test_generate_keypair():
    p, alpha = load_params()
    public_key, private_key = generate_keypair(p, alpha)
    
    assert isinstance(public_key, int)
    assert isinstance(private_key, int)
    assert 1 < private_key < p - 1
    assert 0 < public_key < p
    
    # Verify mathematically
    expected_y = pow(alpha, private_key, p)
    assert public_key == expected_y

def test_sign_and_verify():
    p, alpha = load_params()
    public_key, private_key = generate_keypair(p, alpha)
    
    # Hash a dummy vault content
    vault_content = b'{"vault": "secret"}'
    message_hash = hashlib.sha256(vault_content).hexdigest()
    message_hash_int = int(message_hash, 16)
    
    # Sign
    r, s = sign(message_hash_int, private_key, p, alpha)
    
    assert isinstance(r, int)
    assert isinstance(s, int)
    assert 0 < r < p
    assert 0 < s < p - 1
    
    # Verify
    is_valid = verify(message_hash_int, r, s, public_key, p, alpha)
    assert is_valid == True

def test_verify_fails_on_tampering():
    p, alpha = load_params()
    public_key, private_key = generate_keypair(p, alpha)
    
    vault_content = b'{"vault": "secret"}'
    message_hash = hashlib.sha256(vault_content).hexdigest()
    message_hash_int = int(message_hash, 16)
    
    r, s = sign(message_hash_int, private_key, p, alpha)
    
    # Tamper with the message
    tampered_vault = b'{"vault": "hacked"}'
    tampered_hash = hashlib.sha256(tampered_vault).hexdigest()
    tampered_hash_int = int(tampered_hash, 16)
    
    is_valid = verify(tampered_hash_int, r, s, public_key, p, alpha)
    assert is_valid == False
    
    # Tamper with the signature
    tampered_r = (r + 1) % p
    if tampered_r == 0:
        tampered_r = 1
    is_valid_sig = verify(message_hash_int, tampered_r, s, public_key, p, alpha)
    assert is_valid_sig == False

def test_key_storage(monkeypatch):
    p, alpha = load_params()
    public_key, private_key = generate_keypair(p, alpha)
    username = "testuser"
    
    with tempfile.TemporaryDirectory() as temp_dir:
        # Mock the KEYS_DIR for testing to avoid cluttering actual project structure
        monkeypatch.setattr(modules.elgamal, "KEYS_DIR", temp_dir)
        
        # Save keys
        save_keys(username, public_key, private_key)
        
        # Ensure files were created
        assert os.path.exists(os.path.join(temp_dir, f"{username}_private.key"))
        assert os.path.exists(os.path.join(temp_dir, f"{username}_public.key"))
        
        # Load keys and verify they match
        loaded_private = load_private_key(username)
        loaded_public = load_public_key(username)
        
        assert loaded_private == private_key
        assert loaded_public == public_key

if __name__ == "__main__":
    import pytest
    pytest.main([__file__])

