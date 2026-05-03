import json
import os
import secrets

MODULES_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(MODULES_DIR)
CONFIG_PATH = os.path.join(PROJECT_ROOT, "config", "params.json")
KEYS_DIR = os.path.join(PROJECT_ROOT, "keys")


def load_params():
    with open(CONFIG_PATH, 'r') as f:
        data = json.load(f)
    q     = int(data['elgamal']['q'],     16)
    alpha = int(data['elgamal']['alpha'], 16)
    return q, alpha


def generate_keypair(q, alpha):
    # Private key x is random integer in (1, q-1)
    # Public  key y is alpha^x mod q
    x = 2 + secrets.randbelow(q - 3)
    y = pow(alpha, x, q)
    return y, x


def initialize_user(username):

    private_path = os.path.join(KEYS_DIR, f"{username}_private.key")
    if os.path.exists(private_path):
        raise Exception(f"Keys already exist for '{username}'. Use load_private_key() instead.")

    q, alpha = load_params()
    public_key, private_key = generate_keypair(q, alpha)
    save_keys(username, public_key, private_key)
    return public_key, private_key


def save_keys(username, public_key, private_key):
    os.makedirs(KEYS_DIR, exist_ok=True)
    with open(os.path.join(KEYS_DIR, f"{username}_private.key"), 'w') as f:
        f.write(hex(private_key))
    with open(os.path.join(KEYS_DIR, f"{username}_public.key"), 'w') as f:
        f.write(hex(public_key))


def load_private_key(username):
    path = os.path.join(KEYS_DIR, f"{username}_private.key")
    if not os.path.exists(path):
        raise FileNotFoundError(f"Private key not found for user '{username}'")
    with open(path) as f:
        return int(f.read().strip(), 16)


def load_public_key(username):
    path = os.path.join(KEYS_DIR, f"{username}_public.key")
    if not os.path.exists(path):
        raise FileNotFoundError(f"Public key not found for user '{username}'")
    with open(path) as f:
        return int(f.read().strip(), 16)