# Design Decisions

## Cryptographic Primitives
- **ElGamal**: Used for digital signatures and asymmetric encryption.
- **AES-GCM**: Used for symmetric encryption of the vault data.
- **Diffie-Hellman**: Used for secure key exchange during vault export/import.

## Vault Structure
The vault is stored as a JSON file, encrypted using AES-GCM with a master key derived from the user's password.
