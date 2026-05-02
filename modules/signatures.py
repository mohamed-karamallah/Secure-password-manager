import hashlib
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
    p, alpha = elgamal.load_params()
    private_key = elgamal.load_private_key(username)
    r, s = elgamal.sign(message_hash_int, private_key, p, alpha)
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
    p, alpha = elgamal.load_params()
    public_key = elgamal.load_public_key(username)
    r = signature['r']
    s = signature['s']
    is_valid = elgamal.verify(message_hash_int, r, s, public_key, p, alpha)
    if not is_valid:
        print("ALERT: Signature is invalid! Vault has been tampered with and refuses to open.")
        raise ValueError("Signature verification failed.")
        
    return True
