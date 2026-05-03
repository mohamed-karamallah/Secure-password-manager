# Design Decisions

## Cryptographic Primitives
- **ElGamal**: Used for digital signatures and asymmetric encryption.
- **AES-GCM**: Used for symmetric encryption of the vault data.
- **Diffie-Hellman**: Used for secure key exchange during vault export/import.

## Vault Structure
The vault is stored as a JSON file, encrypted using AES-GCM with a master key derived from the user's password.

## Module 3: Digital Signatures
- **Hashing**: Vault contents are hashed using SHA-256 before signing. `hashlib.sha256` is used to compute the hash, which is then converted to an integer for the ElGamal signature algorithm.
- **Signature format**: Signatures are represented and stored as a dictionary containing the `r` and `s` components (`{'r': int, 's': int}`) which allows for easy JSON serialization.

## Module 2: Vault Encryption & Credential Management
- **Key Derivation**: The master password is hashed with `SHA-256` to produce a 32-byte key for AES-256. This is a direct hash, not PBKDF2/scrypt — acceptable for project scope since the focus is on demonstrating AES-GCM and signature integration, not production-grade KDF.
- **AES-GCM Mode**: Used `AES.MODE_GCM` from PyCryptodome as required by the spec. GCM provides both confidentiality and authenticity — the authentication tag catches any corruption at the AES level before we even get to the ElGamal signature check.
- **Vault Format**: Stored as a JSON file containing base64-encoded ciphertext, nonce, GCM tag, and the ElGamal signature. Base64 encoding keeps the file human-readable and avoids binary blob issues.
- **Signature Scope**: The signature is computed over the encrypted data (the base64 string), not the plaintext credentials. This matches the spec: "Compute a SHA-256 hash of the vault contents (encrypted content)."
- **CRUD Flow**: Every write operation (add, update, delete) follows the same pattern: decrypt → modify → re-encrypt → re-sign. This ensures the signature always reflects the current vault state.
