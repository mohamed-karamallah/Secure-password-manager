# Member B — README

**Member B owns:** Module 2 (Vault Encryption & Credential Management), CTF 2 (Image Manipulation), CTF 6 (RSA Key Recovery)

---

## Requirements

Install dependencies with:

```bash
pip3.10 install pycryptodome Pillow numpy sympy pytest
```

> Make sure you are using Python 3.10. Python 3.14 has a known broken install on this machine.

---

## How to Run the Password Manager (Module 2)

### Step 1 — Navigate to the project root

```bash
cd "/Users/youssefafify/Documents/Uni/spring 2026/security/project/Security_PasswordManager_CTFs"
```

### Step 2 — Start the CLI

```bash
python3.10 cli.py
```

You will see this menu:

```
--- Password Manager ---
1) Initialize new user
2) Add credential
3) Get credential
4) List all sites
5) Update credential
6) Delete credential
7) Export vault to another user
8) Exit
```

### Workflow

**First time? Always start with option 1:**
- This generates your ElGamal key pair and creates an empty encrypted vault.
- You will set a master password — remember it, there is no recovery.

**Adding a password (option 2):**
- Provide your username, master password, and then the website/username/password you want to store.

**Looking up a password (option 3):**
- Provide your username, master password, and the website name.
- The vault is decrypted in memory and only that one entry is shown.

**Updating a password (option 5):**
- Finds the entry by website name and replaces the stored password.

**Deleting an entry (option 6):**
- Asks for confirmation before removing the entry.

---

## How to Run the Tests

```bash
python3.10 -m pytest tests/ -v
```

Expected output: **19 passed**

---

## How to Run CTF 2 (Image Manipulation)

```bash
python3.10 ctf/ctf2_image_manipulation/solve.py
```

This will create a file called `result.png` inside `ctf/ctf2_image_manipulation/`.
Open that image to see the flag.

**Flag: `CMPN{im4g3s-4s_k3y$}`**

---

## How to Run CTF 6 (RSA Key Recovery)

```bash
python3.10 ctf/ctf6_rsa/solve.py
```

The flag is printed directly to the terminal.

**Flag: `CMPN{f4c70r_m3}`**

---

## File Structure (Member B's files)

```
modules/
  vault.py              ← Module 2: all encryption and CRUD logic

cli.py                  ← Main entry point, interactive menu

tests/
  test_vault.py         ← 9 unit tests for Module 2

ctf/
  ctf2_image_manipulation/
    solve.py            ← XOR the two noise images
    writeup.md          ← Explanation of how we solved it
    result.png          ← The XOR output showing the flag

  ctf6_rsa/
    solve.py            ← Factor n and decrypt the ciphertext
    writeup.md          ← Explanation of how we solved it

docs/
  thought_process.md    ← Detailed thought process for all 3 deliverables
  design_decisions.md   ← Technical design rationale
```
