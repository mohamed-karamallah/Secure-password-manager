# Secure Password Manager — Full Workflow

## Overview

The system has 4 modules that chain together:

| Module | File | Responsibility |
|--------|------|----------------|
| 1 | `elgamal.py` | Key generation & storage |
| 2 | `vault.py` | Credential encryption & management |
| 3 | `signatures.py` | ElGamal digital signatures |
| 4 | `export.py` | Secure vault export via Diffie-Hellman |

---

## Shared Parameters (`config/params.json`)

Both ElGamal and Diffie-Hellman use the same shared domain parameters loaded from `config/params.json`:

| Parameter | Value | Source |
|-----------|-------|--------|
| **`q`** (prime) | RFC 3526 — 1536-bit MODP Group 5 | [RFC 3526, Section 2](https://www.rfc-editor.org/rfc/rfc3526#section-2) |
| **`alpha`** (generator) | `31` — verified primitive root of `q` | Computed locally |

### Why this prime?
The prime `q` is the **RFC 3526 1536-bit MODP Group 5** — a well-known, publicly vetted safe prime used in TLS, IKE, and SSH. It is a **safe prime** (`q = 2p + 1` where `p` is also prime), which eliminates small-subgroup attacks.

### Why `alpha = 31`?
The RFC standard uses generator `2`, but `2` only generates a subgroup of order `(q-1)/2` — it is not a true primitive root. We use `alpha = 31`, which is the **smallest verified primitive root** of this prime (order exactly `q-1`), matching the strict textbook definition.

**Verification (two checks sufficient for a safe prime):**
```
pow(31, 2,         q) ≠ 1   ✓   (order is not 2)
pow(31, (q-1)//2,  q) ≠ 1   ✓   (order is not (q-1)/2)
→ order must be q-1  →  31 is a primitive root
```

---

## Step 1 — Setup (Module 1)

**CLI option: `1) Initialize new user`**

1. User enters a username and master password.
2. `elgamal.initialize_user(username)` is called:
   - Loads shared prime `q` and primitive root `alpha` from `config/params.json`.
   - Generates a random private key `x` in range `(1, q-1)`.
   - Computes public key `y = alpha^x mod q`.
   - Saves both to `keys/` directory as hex files.
3. `vault.create_vault(username, master_pw)` creates an empty encrypted vault in `vaults/`.

---

## Step 2 — Store Credentials (Module 2)

**CLI option: `2) Add credential`**

1. User enters username, master password, website, site username, and site password.
2. `vault.add_credential(...)` is called:
   - Loads and decrypts the existing vault (which also verifies the signature first).
   - Appends the new credential entry.
   - Re-encrypts the entire vault with AES-GCM using `SHA-256(master_password)` as the key.
   - Re-signs the encrypted data and saves back to disk.

**Vault file structure (`vaults/alice_vault.json`):**
```json
{
  "encrypted_data": "<base64 AES-GCM ciphertext>",
  "nonce": "<base64>",
  "tag": "<base64>",
  "signature": { "r": 123456, "s": 789012 }
}
```

---

## Step 3 — Sign & Verify (Module 3)

**Triggered automatically on every vault read/write.**

### Signing (happens on every save):
1. Compute `m = SHA-256(encrypted_data)` as an integer.
2. Pick random `k` where `gcd(k, q-1) = 1`.
3. Compute `r = alpha^k mod q`.
4. Compute `k_inv = k^-1 mod (q-1)`.
5. Compute `s = (m - x*r) * k_inv mod (q-1)`.
6. Store `(r, s)` in the vault file.

### Verification (happens on every open):
1. Compute `m = SHA-256(encrypted_data)`.
2. Compute `v1 = (y^r * r^s) mod q`.
3. Compute `v2 = alpha^m mod q`.
4. If `v1 == v2` → valid. Otherwise → **vault refuses to open**.

Any manual edit to the vault file (even a single character) causes verification to fail.

---

## Step 4 — Retrieve a Credential (Module 2)

**CLI option: `3) Get credential`**

1. Signature is verified first — if tampered, raises an error and stops.
2. Vault is decrypted in memory using `SHA-256(master_password)`.
3. The matching credential is displayed. Nothing is written back to disk.

---

## Step 5 — Export Vault to Another User (Module 4)

**CLI option: `7) Export vault to another user`**

Both users must already be initialized. The export runs 3 phases:

### Phase 1 — Diffie-Hellman Key Exchange
1. Both devices generate ephemeral DH key pairs: private `a`, public `alpha^a mod q`.
2. Device 1 signs its DH public key with its ElGamal private key → sends to Device 2.
3. Device 2 verifies the signature. If invalid → **aborts**.
4. Device 2 signs its DH public key → sends to Device 1.
5. Device 1 verifies. If invalid → **aborts**.
6. Both compute the shared secret: `S = other_dh_pub^my_dh_priv mod q`.
7. Session AES-256 key = `SHA-256(S)`.

### Phase 2 — Vault Transfer
1. Device 1 decrypts its vault with the master password.
2. Re-encrypts the plaintext credentials using the session key (AES-GCM).
3. Signs the session-encrypted data with its ElGamal private key.
4. Sends the encrypted package to Device 2.

### Phase 3 — Vault Import
1. Device 2 verifies the transfer signature using Device 1's public key.
2. Decrypts the package using the same session key.
3. Re-encrypts the credentials with Device 2's master password.
4. Signs and saves the new vault under Device 2's username.

---
