import json
import os
import secrets
import math

MODULES_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(MODULES_DIR)
CONFIG_PATH = os.path.join(PROJECT_ROOT, "config", "params.json")
KEYS_DIR = os.path.join(PROJECT_ROOT, "keys")


def load_params():
    """
    Loads ElGamal shared parameters (p, alpha) from config/params.json.
    Returns:
        tuple: (p, alpha) as integers.
    """
    with open(CONFIG_PATH, 'r') as f:
        data = json.load(f)
        p = int(data['elgamal']['p'], 16)
        alpha = int(data['elgamal']['alpha'], 16)
        return p, alpha


def extended_gcd(a, b):
    """
    Extended Euclidean Algorithm (iterative).
    Returns (gcd, x, y) such that a*x + b*y = gcd(a, b).
    Iterative to avoid Python recursion limit (~1000 calls),
    which would be exceeded by a 1536-bit prime (~2200 steps worst case).
    """
    old_r, r = a, b
    old_s, s = 1, 0
    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
    # old_r = gcd, old_s = x, compute y from (gcd - old_s * a) // b
    y = (old_r - old_s * a) // b if b != 0 else 0
    return old_r, old_s, y


def mod_inverse(a, m):
    """
    Computes the modular inverse of a modulo m.
    Returns x such that (a * x) % m == 1.
    """
    gcd, x, _ = extended_gcd(a, m)
    if gcd != 1:
        raise Exception(f"Modular inverse does not exist for {a} mod {m}")
    return x % m


def generate_keypair(p, alpha):
    """
    Generates an ElGamal public/private key pair.
    Args:
        p (int): The large prime.
        alpha (int): The primitive root.
    Returns:
        tuple: (public_key, private_key)
    """
    # Private key: random integer x such that 1 < x < p - 1
    x = 2 + secrets.randbelow(p - 3)

    # Public key: y = alpha^x mod p
    y = pow(alpha, x, p)

    return y, x


def sign(message_hash_int, private_key, p, alpha):
    """
    Signs a message hash using the ElGamal Signature Algorithm.
    Args:
        message_hash_int (int): The SHA-256 hash of the message, as an integer.
        private_key (int): The signer's private key (x).
        p (int): The large prime.
        alpha (int): The primitive root.
    Returns:
        tuple: (r, s) representing the signature.
    """
    x = private_key
    while True:
        # Choose a random k such that 1 < k < p - 1 and gcd(k, p-1) == 1
        k = 2 + secrets.randbelow(p - 3)
        if math.gcd(k, p - 1) != 1:
            continue

        # r = alpha^k mod p
        r = pow(alpha, k, p)

        # Per ElGamal spec both r and s must be non-zero
        if r == 0:
            continue

        # k_inv = k^-1 mod (p-1)
        k_inv = mod_inverse(k, p - 1)

        # s = (m - x * r) * k^-1 mod (p-1)
        s = ((message_hash_int - x * r) * k_inv) % (p - 1)

        if s == 0:
            continue

        return r, s


def verify(message_hash_int, r, s, public_key, p, alpha):
    """
    Verifies an ElGamal signature.
    Args:
        message_hash_int (int): The SHA-256 hash of the message, as an integer.
        r (int): Signature part r.
        s (int): Signature part s.
        public_key (int): The signer's public key (y).
        p (int): The large prime.
        alpha (int): The primitive root.
    Returns:
        bool: True if signature is valid, False otherwise.
    """
    # Check boundaries
    if not (0 < r < p and 0 < s < p - 1):
        return False

    # v1 = (y^r * r^s) mod p
    v1 = (pow(public_key, r, p) * pow(r, s, p)) % p

    # v2 = alpha^m mod p
    v2 = pow(alpha, message_hash_int, p)

    return v1 == v2


def initialize_user(username):
    """
    Generates keys for a new user and saves them locally.
    Raises an exception if keys already exist for this username
    to prevent silent overwriting of existing keys.
    """
    private_path = os.path.join(KEYS_DIR, f"{username}_private.key")
    if os.path.exists(private_path):
        raise Exception(
            f"User '{username}' already has keys. "
            f"Use load_private_key() instead."
        )

    p, alpha = load_params()
    public_key, private_key = generate_keypair(p, alpha)
    save_keys(username, public_key, private_key)
    return public_key, private_key


def save_keys(username, public_key, private_key):
    """
    Saves the user's private and public keys to the filesystem.
    Note: private key is stored as plaintext hex — known limitation,
    acceptable for project scope. Documented in design_decisions.md.
    """
    if not os.path.exists(KEYS_DIR):
        os.makedirs(KEYS_DIR)

    private_path = os.path.join(KEYS_DIR, f"{username}_private.key")
    public_path = os.path.join(KEYS_DIR, f"{username}_public.key")

    with open(private_path, 'w') as f:
        f.write(hex(private_key))

    with open(public_path, 'w') as f:
        f.write(hex(public_key))


def load_private_key(username):
    """
    Loads the user's private key.
    """
    private_path = os.path.join(KEYS_DIR, f"{username}_private.key")
    if not os.path.exists(private_path):
        raise FileNotFoundError(f"Private key not found for user '{username}'")

    with open(private_path, 'r') as f:
        return int(f.read().strip(), 16)


def load_public_key(username):
    """
    Loads a public key (either local user or another user's exported key).
    """
    public_path = os.path.join(KEYS_DIR, f"{username}_public.key")
    if not os.path.exists(public_path):
        raise FileNotFoundError(f"Public key not found for user '{username}'")

    with open(public_path, 'r') as f:
        return int(f.read().strip(), 16)