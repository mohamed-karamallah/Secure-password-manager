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
    Loads ElGamal shared parameters (q, alpha) from config/params.json.
    Returns:
        tuple: (q, alpha) as integers.
    """
    with open(CONFIG_PATH, 'r') as f:
        data = json.load(f)
        q = int(data['elgamal']['q'], 16)
        alpha = int(data['elgamal']['alpha'], 16)
        return q, alpha


def extended_gcd(a, b):
    """
    Extended Euclidean Algorithm (iterative).
    Returns (gcd, x, y) such that a*x + b*y = gcd(a, b).
    Iterative to avoid Python recursion limit (~1000 calls),
    which would be exceeded by a 1536-bit prime (~2200 steps worst case).
    """
    old_r = a
    r = b
    
    old_s = 1
    s = 0
    
    while r != 0:
        quotient = old_r // r
        
        # Linearize r updates
        temp_r = r
        r = old_r - quotient * r
        old_r = temp_r
        
        # Linearize s updates
        temp_s = s
        s = old_s - quotient * s
        old_s = temp_s
        
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


def generate_keypair(q, alpha):
    """
    Generates an ElGamal public/private key pair.
    Args:
        q (int): The large prime.
        alpha (int): The primitive root.
    Returns:
        tuple: (public_key, private_key)
    """
    # Private key: random integer x such that 1 < x < q - 1
    x = 2 + secrets.randbelow(q - 3)

    # Public key: y = alpha^x mod q
    y = pow(alpha, x, q)

    return y, x


def sign(message_hash_int, private_key, q, alpha):
    """
    Signs a message hash using the ElGamal Signature Algorithm.
    Args:
        message_hash_int (int): The SHA-256 hash of the message, as an integer.
        private_key (int): The signer's private key (x).
        q (int): The large prime.
        alpha (int): The primitive root.
    Returns:
        tuple: (r, s) representing the signature.
    """
    x = private_key
    while True:
        # Choose a random k such that 1 < k < q - 1 and gcd(k, q-1) == 1
        k = 2 + secrets.randbelow(q - 3)
        if math.gcd(k, q - 1) != 1:
            continue

        # r = alpha^k mod q
        r = pow(alpha, k, q)

        # Per ElGamal spec both r and s must be non-zero
        if r == 0:
            continue

        # k_inv = k^-1 mod (q-1)
        k_inv = mod_inverse(k, q - 1)

        # s = (m - x * r) * k^-1 mod (q-1)
        s = ((message_hash_int - x * r) * k_inv) % (q - 1)

        if s == 0:
            continue

        return r, s


def verify(message_hash_int, r, s, public_key, q, alpha):
    """
    Verifies an ElGamal signature.
    Args:
        message_hash_int (int): The SHA-256 hash of the message, as an integer.
        r (int): Signature part r.
        s (int): Signature part s.
        public_key (int): The signer's public key (y).
        q (int): The large prime.
        alpha (int): The primitive root.
    Returns:
        bool: True if signature is valid, False otherwise.
    """
    # Check boundaries
    if not (0 < r < q and 0 < s < q - 1):
        return False

    # v1 = (y^r * r^s) mod q
    v1 = (pow(public_key, r, q) * pow(r, s, q)) % q

    # v2 = alpha^m mod q
    v2 = pow(alpha, message_hash_int, q)

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

    q, alpha = load_params()
    public_key, private_key = generate_keypair(q, alpha)
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