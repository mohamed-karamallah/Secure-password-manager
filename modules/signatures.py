import hashlib
import math
import secrets
from modules import elgamal


def hash_content(content) -> int:
    """
    Computes the SHA-256 hash of the content (str or bytes)
    and returns it as an integer.
    """
    if isinstance(content, str):
        content = content.encode('utf-8')
    h = hashlib.sha256(content).hexdigest()
    return int(h, 16)


def sign_vault(vault_content, username: str) -> dict:
    """
    Signs the vault content for the given username using ElGamal.

    Args:
        vault_content: The vault data (str or bytes) to be signed.
        username: The username whose private key will be used to sign.

    Returns:
        dict: The signature containing 'r' and 's' as integers.
    """
    message_hash_int = hash_content(vault_content)
    q, alpha = elgamal.load_params()
    x = elgamal.load_private_key(username)

    while True:
        # Pick random k in (1, q-1) with gcd(k, q-1) == 1
        k = 2 + secrets.randbelow(q - 3)
        if math.gcd(k, q - 1) != 1:
            continue

        # r = alpha^k mod q
        r = pow(alpha, k, q)
        if r == 0:
            continue

        # k_inv = k^-1 mod (q-1)
        k_inv = pow(k, -1, q - 1)

        # s = (m - x * r) * k^-1 mod (q-1)
        s = ((message_hash_int - x * r) * k_inv) % (q - 1)
        if s == 0:
            continue

        return {'r': r, 's': s}


def verify_vault(vault_content, signature: dict, username: str) -> bool:
    """
    Verifies the signature of the vault content using the user's public key.

    Args:
        vault_content: The vault data (str or bytes) that was signed.
        signature: A dict containing 'r' and 's' signature components.
        username: The username whose public key will be used for verification.

    Returns:
        bool: True if the signature is valid, False otherwise.
    """
    if not isinstance(signature, dict) or 'r' not in signature or 's' not in signature:
        print("ALERT: Invalid signature format. The vault refuses to open.")
        raise ValueError("Invalid signature format.")

    message_hash_int = hash_content(vault_content)
    q, alpha = elgamal.load_params()
    y = elgamal.load_public_key(username)
    r = signature['r']
    s = signature['s']

    # Boundary check
    if not (0 < r < q and 0 < s < q - 1):
        print("ALERT: Signature is invalid! Vault has been tampered with and refuses to open.")
        raise ValueError("Signature verification failed.")

    # v1 = (y^r * r^s) mod q
    v1 = (pow(y, r, q) * pow(r, s, q)) % q

    # v2 = alpha^m mod q
    v2 = pow(alpha, message_hash_int, q)

    if v1 != v2:
        print("ALERT: Signature is invalid! Vault has been tampered with and refuses to open.")
        raise ValueError("Signature verification failed.")

    return True




