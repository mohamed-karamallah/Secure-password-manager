#mod4
import json
import os
import secrets
import hashlib
import base64
from Crypto.Cipher import AES
from modules import elgamal
from modules import signatures
from modules import vault

MODULES_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(MODULES_DIR)
CONFIG_PATH = os.path.join(PROJECT_ROOT, "config", "params.json")

def load_dh_params():
    with open(CONFIG_PATH, 'r') as f:
        data = json.load(f)
        q = int(data['dh']['q'], 16)
        alpha = int(data['dh']['alpha'], 16)
        return q, alpha


def generate_dh_keypair(q, alpha):
    private_key = 2 + secrets.randbelow(q - 3)
    public_key = pow(alpha, private_key, q)
    return public_key, private_key


def compute_shared_secret(other_public_key, my_private_key, q):
    return pow(other_public_key, my_private_key, q)


def derive_session_key(shared_secret):
    secret_bytes = shared_secret.to_bytes(
        (shared_secret.bit_length() + 7) // 8, byteorder='big'
    )
    return hashlib.sha256(secret_bytes).digest()

def _encrypt_with_key(plaintext_bytes, key):
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext_bytes)
    return ciphertext, cipher.nonce, tag


def _decrypt_with_key(ciphertext, nonce, tag, key):
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

def export_vault(sender_username, sender_master_pw,
                 receiver_username, receiver_master_pw):
    elgamal.load_private_key(sender_username)
    elgamal.load_private_key(receiver_username)
    elgamal_q, elgamal_alpha = elgamal.load_params()
    print("\n[Phase 1] Diffie-Hellman Key Exchange")
    q, alpha = load_dh_params()
    sender_dh_pub, sender_dh_priv = generate_dh_keypair(q, alpha)
    receiver_dh_pub, receiver_dh_priv = generate_dh_keypair(q, alpha)
    print("  Both devices generated ephemeral DH key pairs.")
    sender_dh_hash = signatures.hash_content(str(sender_dh_pub))
    sender_elgamal_priv = elgamal.load_private_key(sender_username)
    sig1_r, sig1_s = elgamal.sign(
        sender_dh_hash, sender_elgamal_priv, elgamal_q, elgamal_alpha
    )
    print(f"  Device 1 ({sender_username}) signed and sent DH public key.")
    sender_elgamal_pub = elgamal.load_public_key(sender_username)
    if not elgamal.verify(sender_dh_hash, sig1_r, sig1_s,
                          sender_elgamal_pub, elgamal_q, elgamal_alpha):
        raise ValueError(
            "ABORT: Device 1's DH public key signature is INVALID. "
            "Possible man-in-the-middle attack."
        )
    print("  Device 2 verified Device 1's DH public key signature. ✓")
    receiver_dh_hash = signatures.hash_content(str(receiver_dh_pub))
    receiver_elgamal_priv = elgamal.load_private_key(receiver_username)
    sig2_r, sig2_s = elgamal.sign(
        receiver_dh_hash, receiver_elgamal_priv, elgamal_q, elgamal_alpha
    )
    print(f"  Device 2 ({receiver_username}) signed and sent DH public key.")
    receiver_elgamal_pub = elgamal.load_public_key(receiver_username)
    if not elgamal.verify(receiver_dh_hash, sig2_r, sig2_s,
                          receiver_elgamal_pub, elgamal_q, elgamal_alpha):
        raise ValueError(
            "ABORT: Device 2's DH public key signature is INVALID. "
            "Possible man-in-the-middle attack."
        )
    print("  Device 1 verified Device 2's DH public key signature. ✓")

    # 7. Both devices compute the shared secret
    sender_shared = compute_shared_secret(receiver_dh_pub, sender_dh_priv, q)
    receiver_shared = compute_shared_secret(sender_dh_pub, receiver_dh_priv, q)
    assert sender_shared == receiver_shared, "Shared secrets do not match!"
    print("  Shared secret computed on both devices. ✓")

    # 8. Derive session AES-256 key from the shared secret
    session_key = derive_session_key(sender_shared)
    print("  Session AES-256 key derived via SHA-256. ✓")
    print("\n[Phase 2] Vault Transfer")

    # 1. Device 1 decrypts the vault with the master password
    creds = vault.load_vault(sender_username, sender_master_pw)
    print(f"  Device 1 decrypted vault ({len(creds)} credential(s)).")

    # 2-3. Re-encrypt the plaintext credentials with the session key
    plain_json = json.dumps(creds).encode('utf-8')
    session_ct, session_nonce, session_tag = _encrypt_with_key(
        plain_json, session_key
    )
    session_ct_b64 = base64.b64encode(session_ct).decode()
    session_nonce_b64 = base64.b64encode(session_nonce).decode()
    session_tag_b64 = base64.b64encode(session_tag).decode()
    print("  Vault re-encrypted with DH session key.")

    # 4. Sign the session-encrypted data with Device 1's ElGamal key
    transfer_hash = signatures.hash_content(session_ct_b64)
    transfer_sig_r, transfer_sig_s = elgamal.sign(
        transfer_hash, sender_elgamal_priv, elgamal_q, elgamal_alpha
    )
    print("  Session-encrypted data signed by Device 1. ✓")

    # 5. "Transmit" — data passed in memory for CLI simulation
    transfer_package = {
        "encrypted_data": session_ct_b64,
        "nonce": session_nonce_b64,
        "tag": session_tag_b64,
        "signature": {"r": transfer_sig_r, "s": transfer_sig_s},
        "sender": sender_username,
    }

    #  PHASE 3
    print("\n[Phase 3] Vault Import")

    received_hash = signatures.hash_content(transfer_package["encrypted_data"])
    if not elgamal.verify(received_hash,
                          transfer_package["signature"]["r"],
                          transfer_package["signature"]["s"],
                          sender_elgamal_pub, elgamal_q, elgamal_alpha):
        raise ValueError(
            "ABORT: Transfer data signature is INVALID. "
            "Data may have been tampered with in transit."
        )
    print("  Device 2 verified transfer signature. ✓")

    received_ct = base64.b64decode(transfer_package["encrypted_data"])
    received_nonce = base64.b64decode(transfer_package["nonce"])
    received_tag = base64.b64decode(transfer_package["tag"])

    try:
        decrypted_json = _decrypt_with_key(
            received_ct, received_nonce, received_tag, session_key
        )
    except (ValueError, KeyError):
        raise ValueError("Failed to decrypt transfer data with session key.")

    imported_creds = json.loads(decrypted_json.decode('utf-8'))
    print(f"  Decrypted {len(imported_creds)} credential(s) with session key.")
    vault.save_vault(receiver_username, receiver_master_pw, imported_creds)
    print(f"  Vault saved for '{receiver_username}' with new master password.")

    print(f"\n✓ Export complete! {len(imported_creds)} credential(s) "
          f"transferred from '{sender_username}' to '{receiver_username}'.")
    return imported_creds
