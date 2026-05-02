import json
import os
import hashlib
import base64
from Crypto.Cipher import AES
from modules import signatures

MODULES_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(MODULES_DIR)
VAULTS_DIR = os.path.join(PROJECT_ROOT, "vaults")


def derive_key(master_pw):
    return hashlib.sha256(master_pw.encode('utf-8')).digest()


def _vault_path(username):
    return os.path.join(VAULTS_DIR, f"{username}_vault.json")


def create_vault(username, master_pw):
    """Sets up an empty vault for a new user."""
    path = _vault_path(username)
    if os.path.exists(path):
        raise FileExistsError(f"Vault already exists for '{username}'")

    if not os.path.exists(VAULTS_DIR):
        os.makedirs(VAULTS_DIR)

    save_vault(username, master_pw, [])
    print(f"Vault created for {username}.")


def _encrypt(data_bytes, key):
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data_bytes)
    return ciphertext, cipher.nonce, tag


def _decrypt(ciphertext, nonce, tag, key):
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext


def save_vault(username, master_pw, creds):
    """Encrypt credentials and write to disk, then sign the result."""
    key = derive_key(master_pw)

    raw = json.dumps(creds).encode('utf-8')
    ct, nonce, tag = _encrypt(raw, key)

    enc_b64 = base64.b64encode(ct).decode()
    nonce_b64 = base64.b64encode(nonce).decode()
    tag_b64 = base64.b64encode(tag).decode()

    sig = signatures.sign_vault(enc_b64, username)

    vault_data = {
        "encrypted_data": enc_b64,
        "nonce": nonce_b64,
        "tag": tag_b64,
        "signature": {"r": sig['r'], "s": sig['s']}
    }

    if not os.path.exists(VAULTS_DIR):
        os.makedirs(VAULTS_DIR)

    with open(_vault_path(username), 'w') as f:
        json.dump(vault_data, f, indent=2)


def load_vault(username, master_pw):
    """
    Opens the vault: verifies signature first, then decrypts.
    Returns the credentials list.
    """
    path = _vault_path(username)
    if not os.path.exists(path):
        raise FileNotFoundError(f"No vault found for '{username}'")

    with open(path, 'r') as f:
        vault_data = json.load(f)

    enc_b64 = vault_data["encrypted_data"]
    sig = vault_data["signature"]

    signatures.verify_vault(enc_b64, sig, username)

    key = derive_key(master_pw)
    ct = base64.b64decode(enc_b64)
    nonce = base64.b64decode(vault_data["nonce"])
    tag = base64.b64decode(vault_data["tag"])

    try:
        plain = _decrypt(ct, nonce, tag, key)
    except (ValueError, KeyError):
        raise ValueError("Wrong master password or corrupted vault data.")

    creds = json.loads(plain.decode('utf-8'))
    return creds


def add_credential(username, master_pw, website, user, pw):
    creds = load_vault(username, master_pw)

    for entry in creds:
        if entry["website"].lower() == website.lower():
            raise ValueError(f"Credential for '{website}' already exists. Use update instead.")

    creds.append({
        "website": website,
        "username": user,
        "password": pw
    })
    save_vault(username, master_pw, creds)
    print(f"Added credential for {website}.")


def get_credential(username, master_pw, website):
    creds = load_vault(username, master_pw)

    for entry in creds:
        if entry["website"].lower() == website.lower():
            return entry

    return None


def list_credentials(username, master_pw):
    """Returns all stored credentials (just website names, not passwords)."""
    creds = load_vault(username, master_pw)
    return [c["website"] for c in creds]


def update_credential(username, master_pw, website, new_pw):
    creds = load_vault(username, master_pw)

    found = False
    for entry in creds:
        if entry["website"].lower() == website.lower():
            entry["password"] = new_pw
            found = True
            break

    if not found:
        raise ValueError(f"No credential found for '{website}'")

    save_vault(username, master_pw, creds)
    print(f"Updated password for {website}.")


def delete_credential(username, master_pw, website):
    creds = load_vault(username, master_pw)
    original_len = len(creds)

    creds = [c for c in creds if c["website"].lower() != website.lower()]

    if len(creds) == original_len:
        raise ValueError(f"No credential found for '{website}'")

    save_vault(username, master_pw, creds)
    print(f"Deleted credential for {website}.")
