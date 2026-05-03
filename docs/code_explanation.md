# Code Explanation — Member B

Detailed line-by-line breakdown of all code written for Module 2, CTF 2, and CTF 6.

---

## Module 2: `modules/vault.py`

This file is the heart of the password manager. It handles encrypting credentials and writing them to disk, and decrypting them when the user wants to read.

### Imports and Setup

```python
import json       # for serializing/deserializing credential data
import os         # for file path operations
import hashlib    # for SHA-256 key derivation
import base64     # for encoding binary data as text so it can go into a JSON file
from Crypto.Cipher import AES   # AES encryption from pycryptodome
from modules import signatures  # Module 3: ElGamal signing/verification
```

```python
MODULES_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(MODULES_DIR)
VAULTS_DIR = os.path.join(PROJECT_ROOT, "vaults")
```
These three lines figure out where on disk to save vault files.
- `__file__` is the path of this script itself (vault.py)
- `abspath` converts it to a full absolute path
- `dirname` strips the filename off to get just the folder
- So `MODULES_DIR` = the `modules/` folder
- `PROJECT_ROOT` = one level up = the project root
- `VAULTS_DIR` = `project_root/vaults/` — where all user vault files are saved

---

### `derive_key(master_pw)`

```python
def derive_key(master_pw):
    return hashlib.sha256(master_pw.encode('utf-8')).digest()
```

**Algorithm: SHA-256 (key derivation)**

This turns the user's master password string into a 32-byte key for AES-256.
- `.encode('utf-8')` converts the string to bytes (required by hashlib)
- `hashlib.sha256(...)` runs the SHA-256 hash function on those bytes
- `.digest()` returns the raw 32 bytes of the hash (not hex, actual bytes)
- SHA-256 always produces exactly 32 bytes — which is exactly what AES-256 needs

So if the password is `"hello"`, the AES key will be the SHA-256 hash of `"hello"`.
A different password = a completely different key = the ciphertext becomes unreadable.

---

### `_vault_path(username)`

```python
def _vault_path(username):
    return os.path.join(VAULTS_DIR, f"{username}_vault.json")
```

Simple helper. Returns the full file path where a user's vault is stored.
For username `"afify21"` this returns something like `/project/vaults/afify21_vault.json`.

---

### `create_vault(username, master_pw)`

```python
def create_vault(username, master_pw):
    path = _vault_path(username)
    if os.path.exists(path):
        raise FileExistsError(f"Vault already exists for '{username}'")

    if not os.path.exists(VAULTS_DIR):
        os.makedirs(VAULTS_DIR)

    save_vault(username, master_pw, [])
    print(f"Vault created for {username}.")
```

Creates a new empty vault for a brand new user.
1. First checks if a vault file already exists — if so, refuse (don't overwrite someone's data)
2. Creates the `vaults/` directory if it doesn't exist yet
3. Calls `save_vault` with an empty list `[]` — this writes an empty encrypted vault to disk

---

### `_encrypt(data_bytes, key)`

```python
def _encrypt(data_bytes, key):
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data_bytes)
    return ciphertext, cipher.nonce, tag
```

**Algorithm: AES-GCM (Galois/Counter Mode)**

AES-GCM is an authenticated encryption algorithm. It does two things at once:
- **Encrypts** the data so no one can read it without the key
- **Produces an authentication tag** — a checksum that proves the data hasn't been tampered with

How it works:
1. `AES.new(key, AES.MODE_GCM)` creates a new AES cipher in GCM mode. A random **nonce** (a one-time 16-byte random number) is automatically generated — this ensures that even if you encrypt the same data twice, the ciphertext will be different each time
2. `encrypt_and_digest(data_bytes)` encrypts the data and simultaneously produces a 16-byte **tag**
3. We return all three: the ciphertext, the nonce (needed for decryption), and the tag (needed for integrity verification)

---

### `_decrypt(ciphertext, nonce, tag, key)`

```python
def _decrypt(ciphertext, nonce, tag, key):
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext
```

The reverse of `_encrypt`.
1. Creates an AES-GCM cipher using the same key and the **same nonce** that was used during encryption — without the nonce you cannot decrypt
2. `decrypt_and_verify` first verifies that the authentication tag is correct (meaning the ciphertext wasn't modified), then decrypts
3. If the key is wrong OR the ciphertext was tampered with, this raises a `ValueError` and decryption fails

---

### `save_vault(username, master_pw, creds)`

```python
def save_vault(username, master_pw, creds):
    key = derive_key(master_pw)

    raw = json.dumps(creds).encode('utf-8')
    ct, nonce, tag = _encrypt(raw, key)

    enc_b64 = base64.b64encode(ct).decode()
    nonce_b64 = base64.b64encode(nonce).decode()
    tag_b64 = base64.b64encode(tag).decode()

    sig = signatures.sign_vault(enc_b64, username)

    vault_data = {
        "encrypted_data": enc_b64,
        "nonce": nonce_b64,
        "tag": tag_b64,
        "signature": {"r": sig['r'], "s": sig['s']}
    }

    if not os.path.exists(VAULTS_DIR):
        os.makedirs(VAULTS_DIR)

    with open(_vault_path(username), 'w') as f:
        json.dump(vault_data, f, indent=2)
```

This is the main write function. Called every time data changes.

Step by step:
1. Derive the AES key from the master password using SHA-256
2. Convert credentials list to a JSON string, then encode as bytes
3. Encrypt those bytes with AES-GCM — get back ciphertext, nonce, and auth tag
4. The ciphertext, nonce, and tag are raw binary — JSON can't store binary, so we base64-encode each one into a text string
5. Sign the encrypted data using Module 3's `sign_vault`. **We sign the encrypted data, not the plaintext** — this matches the project spec which says "hash of the vault contents (encrypted content)"
6. The signature has two parts `r` and `s` — these come from ElGamal (Module 1)
7. Build a dictionary with all 4 fields and write to a JSON file

The resulting vault file on disk looks like:
```json
{
  "encrypted_data": "Ab3xK...",
  "nonce": "Tz9pQ...",
  "tag": "mN4rL...",
  "signature": { "r": 123456789, "s": 987654321 }
}
```

---

### `load_vault(username, master_pw)`

```python
def load_vault(username, master_pw):
    path = _vault_path(username)
    if not os.path.exists(path):
        raise FileNotFoundError(f"No vault found for '{username}'")

    with open(path, 'r') as f:
        vault_data = json.load(f)

    enc_b64 = vault_data["encrypted_data"]
    sig = vault_data["signature"]

    signatures.verify_vault(enc_b64, sig, username)

    key = derive_key(master_pw)
    ct = base64.b64decode(enc_b64)
    nonce = base64.b64decode(vault_data["nonce"])
    tag = base64.b64decode(vault_data["tag"])

    try:
        plain = _decrypt(ct, nonce, tag, key)
    except (ValueError, KeyError):
        raise ValueError("Wrong master password or corrupted vault data.")

    creds = json.loads(plain.decode('utf-8'))
    return creds
```

The main read function.

Step by step:
1. Check vault file exists
2. Load the JSON file from disk
3. **Verify the ElGamal signature BEFORE doing anything else** — if someone manually edited the vault file, this fails and we refuse to continue. This is the tamper detection mechanism from Module 3
4. Derive AES key from master password
5. Base64-decode the ciphertext, nonce, and tag back to raw bytes
6. Decrypt with AES-GCM — if the password is wrong, the key is wrong, so decryption fails and we raise a `ValueError`
7. Convert the decrypted bytes back to a Python list of credentials and return it

---

### CRUD Functions

**`add_credential`**: Loads the vault, checks there's no duplicate for that website, appends the new entry, saves back.

**`get_credential`**: Loads the vault, loops through to find a matching website (case-insensitive), returns the entry dict or `None`.

**`list_credentials`**: Loads the vault, returns just the website names — not the passwords.

**`update_credential`**: Loads the vault, finds the entry, replaces its password, saves back.

**`delete_credential`**: Loads the vault, rebuilds the list excluding the target website, saves back. If nothing was removed, raises an error.

---

---

## CLI: `cli.py`

```python
import sys, os, getpass
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
```
`sys.path.insert` adds the project root to Python's module search path so that `from modules import vault` works correctly regardless of where you run the script from.

```python
from modules import elgamal
from modules import vault
```
Imports Module 1 (for key generation during user initialization) and Module 2 (for all vault operations).

### `print_menu()`
Prints the numbered menu to the terminal.

### `ask_master_pw()`
Uses `getpass.getpass()` — this is a special function that reads the password from the keyboard without displaying it on screen (like when you type a password in a terminal and see `*` or nothing).

### `main()` loop

Runs in an infinite loop:
- Prints the menu
- Reads the user's choice
- Dispatches to the correct action based on the number typed
- Each action is wrapped in `try/except` so an error in one action doesn't crash the whole program

**Option 1 (Initialize):** Calls `elgamal.initialize_user()` first (generates the ElGamal key pair from Module 1), then `vault.create_vault()` (creates the empty encrypted vault).

**Options 2–6:** All follow the same pattern — ask for username + master password + whatever extra info is needed, then call the corresponding function from `vault.py`.

**Option 7 (Export):** Calls `export.export_vault()` from Module 4 (written by Member D).

---

---

## CTF 2: `ctf/ctf2_image_manipulation/solve.py`

### The Challenge
Two PNG images are given (`Layer1.png`, `Layer2.png`). Each looks like random noise. Together they hide a message.

### Thought Process
This is a classic technique called **Visual Cryptography**. The idea is:
- Take a message image (the flag text)
- XOR each pixel with a random value to create Layer 1 (looks like noise)
- Layer 2 IS that random value (also looks like noise)
- To recover the original: XOR the two layers together — the random values cancel out, leaving the original

`A XOR B XOR B = A` — XOR-ing with something twice undoes itself.

### The Code

```python
from PIL import Image   # Pillow: for loading/saving images
import numpy as np      # NumPy: for doing math on entire pixel arrays at once
import os
```

```python
script_dir = os.path.dirname(os.path.abspath(__file__))
data_dir = os.path.join(script_dir, "..", "CTF_DATA", "CTF2")
img1_path = os.path.join(data_dir, "Layer1.png")
img2_path = os.path.join(data_dir, "Layer2.png")
```
Figures out the paths to the image files relative to the script's location.

```python
layer1 = Image.open(img1_path)
layer2 = Image.open(img2_path)
```
Opens both PNG images using Pillow.

```python
arr1 = np.array(layer1)
arr2 = np.array(layer2)
```
Converts each image into a NumPy array. Each pixel becomes a number (or three numbers for RGB). For example a white pixel is `[255, 255, 255]` and black is `[0, 0, 0]`.

```python
result = np.bitwise_xor(arr1, arr2)
```
**Algorithm: XOR (bitwise exclusive OR)**

XOR works on individual bits:
- `0 XOR 0 = 0`
- `1 XOR 1 = 0`
- `0 XOR 1 = 1`
- `1 XOR 0 = 1`

`np.bitwise_xor` applies XOR to every corresponding pixel in both arrays simultaneously. This is what reveals the hidden image — the random noise in both layers cancels out.

```python
out_path = os.path.join(script_dir, "result.png")
result_img = Image.fromarray(result)
result_img.save(out_path)
```
Converts the NumPy array back into a Pillow image and saves it as `result.png`.

**Result:** Opening `result.png` shows the flag `CMPN{im4g3s-4s_k3y$}` as clear black text on a white background.

---

---

## CTF 6: `ctf/ctf6_rsa/solve.py`

### The Challenge
Given an RSA public key `(n, e)` and ciphertext `c`. The hint says the primes are "too close together."

RSA values:
- `n = 143991606075158483660871570161405209117`
- `e = 65537`
- `c = 34130411904650996210426832018051041635`

### Background: How RSA Works

RSA encryption is based on the difficulty of factoring a large number `n = p * q` where `p` and `q` are large prime numbers.

- **Public key:** `(n, e)` — anyone can see this
- **Private key:** `d` — computed from knowing `p` and `q`
- **Encryption:** `c = m^e mod n`
- **Decryption:** `m = c^d mod n`

The security of RSA relies on no one being able to factor `n`. If someone factors it (finds `p` and `q`), they can compute `d` and decrypt everything.

### Why This Key is Weak

1. **`n` is only ~128 bits** — modern RSA uses 2048 or 4096 bits. This is tiny and can be factored on a laptop
2. **The primes are close together** — Fermat's factorization algorithm is specifically fast when `p` and `q` are close to each other

### The Code

```python
import math
import os
from sympy import factorint
```
`sympy` is a mathematics library. `factorint` is its integer factorization function — it uses multiple algorithms internally to find prime factors efficiently.

```python
script_dir = os.path.dirname(os.path.abspath(__file__))
data_dir = os.path.join(script_dir, "..", "CTF_DATA", "CTF6")
challenge_path = os.path.join(data_dir, "challenge.txt")
```
Builds the path to the challenge file.

```python
n = None
e = None
c = None

with open(challenge_path, 'r') as f:
    for line in f:
        line = line.strip()
        if line.startswith("n ="):
            n = int(line.split("=")[1].strip())
        elif line.startswith("e ="):
            e = int(line.split("=")[1].strip())
        elif line.startswith("ciphertext ="):
            c = int(line.split("=")[1].strip())
```
Reads the challenge file line by line and parses the three values out of it. `line.split("=")[1]` takes everything after the `=` sign, `.strip()` removes whitespace, `int(...)` converts it to a Python integer.

```python
factors = factorint(n)
primes = list(factors.keys())
p = primes[0]
q = primes[1]
if p > q:
    p, q = q, p
```
`factorint(n)` returns a dictionary like `{prime1: exponent1, prime2: exponent2}`. For a semiprime (product of two primes), both exponents are 1. We take the keys (the prime numbers themselves) and store them as `p` and `q`. Then we sort them so `p` is always the smaller one.

Result: `p = 11607228028223627369`, `q = 12405339649142310293`

```python
assert p * q == n
```
Sanity check — confirm the two factors actually multiply back to `n`. If not, something went wrong.

```python
phi = (p - 1) * (q - 1)
```
**Algorithm: Euler's Totient Function**

`phi(n)` counts how many integers from 1 to n are coprime with n. For `n = p * q`:
`phi(n) = (p-1) * (q-1)`

This is needed to compute the private key.

```python
d = pow(e, -1, phi)
```
**Algorithm: Modular Inverse**

The private exponent `d` is the modular inverse of `e` modulo `phi`. This means:
`d * e ≡ 1 (mod phi)`

Python's built-in `pow(e, -1, phi)` computes this directly using the Extended Euclidean Algorithm internally.

```python
m = pow(c, d, n)
```
**Algorithm: RSA Decryption**

This is the actual decryption step. It computes `c^d mod n` using Python's fast built-in modular exponentiation. This recovers `m`, the original plaintext as an integer.

```python
flag_bytes = m.to_bytes((m.bit_length() + 7) // 8, 'big')
flag = flag_bytes.decode('utf-8')
print(f"\nFlag: {flag}")
```
Converts the integer `m` back into bytes:
- `m.bit_length()` = number of bits in `m`
- `(bits + 7) // 8` = number of bytes needed (rounding up)
- `'big'` = big-endian byte order (most significant byte first)
- `.decode('utf-8')` = interpret those bytes as a UTF-8 text string

**Result:** `CMPN{f4c70r_m3}`

---

---

## Test Suite: `tests/test_vault.py`

The test file uses Python's `unittest` framework to automatically verify that all vault functions work correctly.

### `setUp` — runs before every single test

```python
def setUp(self):
    self.temp_keys = tempfile.TemporaryDirectory()
    self.temp_vaults = tempfile.TemporaryDirectory()
    self.key_patcher = patch('modules.elgamal.KEYS_DIR', self.temp_keys.name)
    self.vault_patcher = patch('modules.vault.VAULTS_DIR', self.temp_vaults.name)
    self.key_patcher.start()
    self.vault_patcher.start()
    self.username = "testvault"
    self.master_pw = "supersecret123"
    elgamal.initialize_user(self.username)
```
Creates temporary directories for keys and vaults so tests don't touch real data. `patch` replaces the actual directory paths inside the modules with the temp ones during the test. Creates a fresh user with ElGamal keys.

### `tearDown` — runs after every single test

Stops the patches and deletes the temporary directories — full cleanup between tests.

### The 9 Tests

| Test | What it checks |
|---|---|
| `test_create_and_load_empty` | A brand new vault has zero credentials |
| `test_add_and_get` | Adding a credential, then retrieving it returns the exact same data |
| `test_add_duplicate_fails` | Adding the same website twice raises a `ValueError` |
| `test_get_nonexistent` | Searching for a website that doesn't exist returns `None` |
| `test_update_credential` | Updating a password changes it correctly |
| `test_delete_credential` | Deleting an entry makes it unretrievable |
| `test_list_credentials` | Lists the correct number and names of websites |
| `test_wrong_password` | Loading with the wrong master password raises `ValueError` |
| `test_tampered_vault_detected` | Manually flipping a character in the vault file causes signature verification to fail |
