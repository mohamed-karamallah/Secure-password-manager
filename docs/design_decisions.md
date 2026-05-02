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
