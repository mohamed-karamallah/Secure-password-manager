# Thought Process & Implementation Details (Member B)

This document details my implementation process for Module 2, CTF 2, and CTF 6.

## Module 2: Vault Encryption & Credential Management
My role was to implement the core CRUD (Create, Read, Update, Delete) functionality for the password vault, ensuring it's properly encrypted with AES-GCM and integrated with the ElGamal signature system from Module 1 & 3.

**Implementation Steps:**
1. **Key Derivation:** I used `hashlib.sha256` to derive a 32-byte AES key directly from the master password.
2. **Encryption:** For AES, I utilized `AES.MODE_GCM` from the `pycryptodome` library. GCM was chosen because it provides authenticated encryption, meaning it generates an authentication tag that allows us to detect tampering at the decryption layer even before checking the ElGamal signature.
3. **Data Storage:** The vault is stored as a JSON file. To ensure binary data (ciphertext, nonce, tag) is properly stored, I base64-encoded these components.
4. **Signature Integration:** I integrated the `signatures` module to sign the base64-encoded encrypted data during any write operation (`create`, `add`, `update`, `delete`). Before decrypting the vault, the signature is first verified. If verification fails, the vault loading is aborted.
5. **CLI Application:** I built `cli.py` to provide an interactive menu for users to manage their vault intuitively. The `getpass` module was used to hide password input from the terminal.

## CTF 2: Image Manipulation
**Challenge:** We were given two noise images (`Layer1.png` and `Layer2.png`).
**Thought Process:** 
When two images appear as random noise but contain a secret together, this is typically an instance of Visual Cryptography. The most common operation to combine such layers and reveal the hidden information is a pixel-by-pixel XOR.
**Solution:**
I used the `Pillow` library to load the PNG images and converted them into `numpy` arrays. I then applied a bitwise XOR (`np.bitwise_xor`) across the two arrays and saved the result. The output image clearly showed the hidden flag text.

## CTF 6: RSA Key Recovery
**Challenge:** Given an RSA public key and ciphertext where the primes used are "too close together."
**Thought Process:**
The modulus `n` was remarkably small (~128 bits), which is already insecure. The hint about primes being "close together" suggested that Fermat's factorization method could work. Fermat's method looks for a representation of `n` as the difference of two squares.
Initially, I considered writing a manual implementation of Fermat's factorization or Pollard's rho, but given the small size of `n`, I decided to use the `sympy` library's `factorint` function. It is highly optimized and handles semiprimes of this size almost instantly.
**Solution:**
After obtaining `p` and `q` from `factorint`, I confirmed they were indeed quite close in value. With the prime factors known, I calculated Euler's totient `phi = (p-1)*(q-1)`, found the modular inverse `d` of the public exponent `e`, and decrypted the ciphertext using `pow(c, d, n)`. The resulting integer was converted to bytes to reveal the flag.
