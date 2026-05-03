# Module 1: ElGamal Key Management — Design & Implementation Writeup

## Overview

This module is the cryptographic foundation of the Secure Password Manager. It is responsible for one task: **generating and securely storing an ElGamal public/private key pair for each user**. These keys are then used by Module 3 (Digital Signatures) and Module 4 (Secure Vault Export) to sign and verify data.

The implementation lives in `modules/elgamal.py`. The shared domain parameters (`q` and `alpha`) are loaded from `config/params.json`.

---

## Implementation: `modules/elgamal.py`

### Function Breakdown

#### `load_params()`
```python
def load_params():
    with open(CONFIG_PATH, 'r') as f:
        data = json.load(f)
    return int(data['elgamal']['q'], 16), int(data['elgamal']['alpha'], 16)
```
Reads the shared prime `q` and primitive root `alpha` from the central config file. Both values are stored as hex strings and parsed into Python integers. Using a shared config file (rather than generating per-user parameters) means all users operate in the same mathematical group, which is required for signature verification in Module 3 and DH key exchange in Module 4.

---

#### `generate_keypair(q, alpha)`
```python
def generate_keypair(q, alpha):
    x = 2 + secrets.randbelow(q - 3)   # private key: x in (1, q-1)
    y = pow(alpha, x, q)                # public key:  y = alpha^x mod q
    return y, x
```
This is the core of the ElGamal key generation algorithm:

- **Private key `x`**: A randomly chosen integer strictly in the range `(1, q-1)`. The `secrets` module is used instead of `random` because it reads from the OS cryptographic random source, making `x` unpredictable.
- **Public key `y`**: Computed as `y = alpha^x mod q`. This is a one-way operation — given `y`, `alpha`, and `q`, recovering `x` is the **Discrete Logarithm Problem (DLP)**, which is computationally infeasible for our 1536-bit prime.
- **`pow(alpha, x, q)`**: Python's built-in three-argument `pow` uses fast modular exponentiation (square-and-multiply), making this efficient even for 1536-bit numbers.

---

#### `initialize_user(username)`
```python
def initialize_user(username):
    private_path = os.path.join(KEYS_DIR, f"{username}_private.key")
    if os.path.exists(private_path):
        raise Exception(...)
    q, alpha = load_params()
    public_key, private_key = generate_keypair(q, alpha)
    save_keys(username, public_key, private_key)
    return public_key, private_key
```
The single entry point for setting up a new user. It guards against accidentally overwriting existing keys by checking for the private key file first. Keys are generated once during setup and reused across all modules — never regenerated.

---

#### `save_keys(username, public_key, private_key)`
```python
def save_keys(username, public_key, private_key):
    os.makedirs(KEYS_DIR, exist_ok=True)
    with open(os.path.join(KEYS_DIR, f"{username}_private.key"), 'w') as f:
        f.write(hex(private_key))
    with open(os.path.join(KEYS_DIR, f"{username}_public.key"), 'w') as f:
        f.write(hex(public_key))
```
Both keys are serialized as hex strings and saved to the `keys/` directory. The public key file (`{username}_public.key`) is designed to be shared with other users for signature verification. The private key stays local and is never transmitted.

---

#### `load_private_key(username)` / `load_public_key(username)`
Simple loaders that read the hex file and return a Python integer. They raise a `FileNotFoundError` with a clear message if the key doesn't exist, rather than failing silently.

---

## Parameter Choice: `config/params.json`

```json
{
  "elgamal": {
    "q":     "0xFFFF...FFFF",
    "alpha": "0x1f"
  }
}
```

### The Prime `q` — RFC 3526 Group 5 (1536-bit MODP)

The prime `q` was taken directly from **RFC 3526** ("More Modular Exponential (MODP) Diffie-Hellman Groups for IKE"), a published IETF standard. This specific prime is known as the **1536-bit MODP Group** and has been publicly vetted by the cryptographic community.

**Why use a published prime rather than generating one?**
- Generating a cryptographically sound large prime is error-prone and time-consuming.
- The RFC 3526 prime has been reviewed and trusted for use in TLS, IKE, and SSH for decades.
- It is a **safe prime**: `q = 2p + 1` where `p = (q-1)/2` is also prime. This structure means the prime factorization of `q-1` is simply `2 × p`, which:
  1. Eliminates the Pohlig-Hellman attack (which exploits small prime factors of `q-1`).
  2. Makes verifying a primitive root trivial — only two modular exponentiations are needed.

At **1536 bits**, this prime provides approximately **80+ bits of security** against discrete logarithm attacks, which is well beyond the requirements of a course project.

---

### The Generator `alpha` — Verified Primitive Root `31`

`alpha = 31` (`0x1f`) was chosen to be a **true primitive root** of `q` — meaning its multiplicative order modulo `q` is exactly `q-1`. This is the strict textbook definition: `alpha` generates the entire multiplicative group `Z_q*`, cycling through all `q-1` non-zero residues.

#### Why Not `alpha = 2`?

The RFC 3526 standard uses generator `g = 2`, but `2` is **not** a primitive root of this prime — it generates only a subgroup of order `(q-1)/2`. While this is sufficient for Diffie-Hellman (subgroup order is still astronomically large), it does not satisfy the textbook definition of a primitive root.

#### How `alpha = 31` Was Verified

Because `q` is a safe prime (`q = 2p + 1`), the only possible orders for any element are `{1, 2, p, 2p}`. An element is a primitive root if and only if its order is `2p = q-1`. This requires ruling out the three smaller orders:

| Condition | Check | Result for `alpha = 31` |
|---|---|---|
| Order ≠ 1 | `alpha > 1` | ✅ |
| Order ≠ 2 | `pow(31, 2, q) ≠ 1` | ✅ `False` |
| Order ≠ p | `pow(31, (q-1)//2, q) ≠ 1` | ✅ `False` |

Since all three smaller orders are ruled out, the order of `31` must be `q-1` — confirming it is a primitive root.

This was verified programmatically:

```python
p = 0xFFFF...FFFF   # RFC 3526 prime
q = (p - 1) // 2
a = 31

assert pow(a, 2, p) != 1          # not order 2
assert pow(a, q, p) != 1          # not order (p-1)/2
assert pow(a, 2 * q, p) == 1      # order divides p-1
# → order is exactly p-1 → primitive root ✅
```

`31` is the **smallest integer ≥ 2** that passes both checks for this prime.

---

## Design Decisions Summary

| Decision | Choice | Reason |
|---|---|---|
| Prime source | RFC 3526 (published standard) | Vetted, safe prime, avoids error-prone generation |
| Prime size | 1536 bits | Well above minimum for course security requirements |
| Generator `alpha` | `31` (primitive root) | Satisfies strict textbook definition (order = q-1) |
| Private key range | `x ∈ (1, q-1)` | Standard ElGamal specification |
| Random source | `secrets.randbelow()` | Cryptographically secure OS random source |
| Key storage format | Hex string in `.key` file | Simple, human-readable, portable |
| Shared params | Single `config/params.json` | All modules and users share the same group |
