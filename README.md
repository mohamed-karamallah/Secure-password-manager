# Secure Password Manager — CMPS426

## Team 25

| Name | ID |
|------|----|
| Yousef Elessawy | 1220300 |
| Mohamed Ashraf | 4230167 |
| Ahmed Sameh | 4230138 |
| Youssef Afify | 1220299 |

---

## Requirements

```
pip install pycryptodome
```

---

## How to Run

```
python cli.py
```

---

## Full Workflow

### Step 1 — Initialize Users

Pick option `1` and enter a username and master password. Do this for both users if you plan to test the export feature.

```
--- Password Manager ---
1) Initialize new user
...
Username: alice
Set master password: ****
Confirm master password: ****
```

This generates an ElGamal key pair for the user and creates an empty encrypted vault.

---

### Step 2 — Store Credentials

Pick option `2`.

```
Username: alice
Master password: ****
Website: github.com
Site username/email: alice@example.com
Site password: ****
```

The vault is encrypted with AES-GCM using a key derived from the master password (SHA-256), then signed with Alice's ElGamal private key.

---

### Step 3 — Retrieve a Credential

Pick option `3`.

```
Username: alice
Master password: ****
Website to search: github.com
```

Before decrypting, the vault signature is verified. If the vault file was tampered with, it refuses to open.

---

### Step 4 — Export Vault to Another User

Pick option `7`. Both users must already be initialized.

```
Username: alice
Master password: ****
Receiver username: bob
Receiver's new master password: ****
Confirm receiver's master password: ****
```

This runs the full Diffie-Hellman key exchange + transfer + import sequence automatically.

---

## Menu Options

| Option | Action |
|--------|--------|
| 1 | Initialize a new user (generates keys + empty vault) |
| 2 | Add a credential |
| 3 | Get a credential by website |
| 4 | List all stored websites |
| 5 | Update a credential's password |
| 6 | Delete a credential |
| 7 | Export vault to another user (DH key exchange) |
| 8 | Exit |

---

## File Structure

```
project/
├── cli.py               # Entry point — run this
├── config/
│   └── params.json      # Shared ElGamal and DH parameters (q, alpha)
├── keys/
│   ├── alice_private.key
│   └── alice_public.key
├── vaults/
│   └── alice_vault.json  # Encrypted + signed vault
└── modules/
    ├── elgamal.py        # Module 1: Key generation
    ├── vault.py          # Module 2: Encryption & credential management
    ├── signatures.py     # Module 3: ElGamal digital signatures
    └── export.py         # Module 4: DH vault export
```

---

## CTF Challenges

This repository also contains solutions and writeups for the 6 security CTF challenges included in the course project. They are located in the `ctf/` directory:

- **CTF 1 — Packet Analysis**: Extracting flags from captured network traffic using packet analyzers.
- **CTF 2 — Image Manipulation**: Recovering hidden flags by manipulating image properties.
- **CTF 3 — Bit Shifting**: Reversing bit-level transformations to decode a hidden message.
- **CTF 4 — Steganography**: Extracting concealed data from steganographic images.
- **CTF 5 — Padding Oracle**: Exploiting cryptographic padding vulnerabilities to decrypt ciphertext.
- **CTF 6 — RSA**: Solving RSA-based cryptographic challenges to recover the plaintext.

Each CTF subdirectory contains the necessary scripts, data files, and documentation (writeups) detailing the solution methodology.
