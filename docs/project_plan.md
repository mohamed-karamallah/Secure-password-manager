# Cryptography & Computer Systems Project — Planning Document

---

## 1. Project Overview

The project has two fully independent parts that can be worked on in parallel from day one.

**Part 1 — Secure Password Manager (Python CLI)**
A command-line password manager built across 4 modules. ElGamal and Diffie-Hellman must be implemented from scratch. AES and SHA-256 may be imported.

**Part 2 — 6 CTF Challenges**
Six standalone puzzle challenges across different cryptography and security domains. Each is independent of the others and of the password manager.

---

## 2. Part 1 — Password Manager Modules

### What Each Module Does

| Module | Name | Description |
|--------|------|-------------|
| 1 | ElGamal Key Management | Generates long-lived public/private key pairs from shared parameters (p, α). The foundational module — every other module depends on it. |
| 2 | Vault Encryption & Credential Management | Core CRUD system. Uses `SHA-256(master_password)` as an AES-GCM key to encrypt/decrypt a JSON vault. Calls Module 3 to re-sign on every write. |
| 3 | Digital Signatures | Signs the vault (SHA-256 hash → ElGamal sign) and verifies on every open. Borrows ElGamal algorithm and keys from Module 1 entirely. |
| 4 | Secure Vault Export via Diffie-Hellman | Orchestrates a full DH ephemeral key exchange (signed with ElGamal), re-encrypts the vault under the session key, transfers, and re-imports. Depends on all three prior modules. |

### Module Dependency Map

```
Module 1 (ElGamal)
    ├──► Module 3 (Signatures)   ← needs ElGamal keys + algorithm
    │         ▲
    ├──► Module 2 (Vault)   ─────── calls Module 3 on every write
    │
    └──► Module 4 (DH Export) ──── needs Module 1 (keys), Module 2 (vault data), Module 3 (signing)
```

**Critical implication:** Module 1 must define its interface first. Module 4 cannot be meaningfully built until Modules 1, 2, and 3 are functional.

---

## 3. Part 2 — CTF Challenges

| CTF | Domain | Challenge File | Notes |
|-----|--------|----------------|-------|
| 1 | Packet Analysis | `traffic.pcapng` | Needs tshark/scapy/wireshark installed |
| 2 | Image Manipulation | `Layer1.png`, `Layer2.png` | XOR of two noise images |
| 3 | Bit Shifting | `shifted.txt` | Decimal values, bitwise operation |
| 4 | Steganography | `stego.png` | Determine which tool was used to hide data first (steghide, OpenStego, etc.) — may require a passphrase |
| 5 | CBC Padding Oracle | Live server: `http://cbc-ctf.westeurope.azurecontainer.io:5000/` | ⚠️ Time-sensitive — server is not under your control |
| 6 | RSA Key Recovery | `challenge.txt` | Math-heavy, weak key factorization |

### CTF Planning Flags

- **CTF 5 must be started first** — it depends on an external live server that could go down or become unreachable. Whoever takes it should verify the link is active before doing anything else.
- **CTF 4 requires a tool decision upfront** — different steganography tools produce different LSB patterns and are not interchangeable. The first step is identifying which tool was used to hide the data.
- **CTF 1 requires external tooling** — `tshark`, `scapy`, or Wireshark must be installed. Note this in `requirements.txt` and the README.
- **CTFs 2, 3, 6 are self-contained** — only need standard Python libraries (PIL, numpy, sympy/math).
- **Document as you go** — the project rules state that solutions without a documented thought process will be discarded. Each member should maintain their `writeup.md` alongside their code as they work, not reconstruct it at the end.

---

## 4. Team Split (4 Members)

| Member | Module | Suggested CTFs | Notes |
|--------|--------|----------------|-------|
| A | Module 1 — ElGamal (from scratch) | CTF 3 (Bit Shifting), CTF 6 (RSA) | Must start immediately — unblocks everyone. Also owns `params.json`. |
| B | Module 2 — Vault + CLI entry point | CTF 1 (Packet Analysis), CTF 4 (Steganography) | Can develop in parallel once Module 1 interface is agreed on. Owns `cli.py`. |
| C | Module 3 — Digital Signatures | CTF 2 (Image Manipulation) | Closely coupled to Module 1. Can develop against a stub initially. |
| D | Module 4 — DH Export (from scratch) | CTF 5 (CBC Padding Oracle) | Most complex integration work. Starts after Modules 1–3 interfaces are settled. **CTF 5 must be first priority.** |

---

## 5. Two Things That Must Happen on Day One

These are the only two items that can block teammates from writing code.

### 5.1 — Create `params.json` (Member A)

Both ElGamal and Diffie-Hellman require shared public parameters: a large prime `p` and a primitive root `α`. These are not secret — they are the agreed-upon "rules of the game" that all parties use.

**The risk:** If Member A generates ElGamal assuming one prime and Member D generates DH assuming a different one, Module 4's integration (which signs DH keys using ElGamal) will break at a math level.

**How to define it — two options:**

- **Option A (recommended):** Use a well-known pre-vetted safe prime from RFC 3526. Look one up, put it in `params.json`, commit it. Done.
- **Option B:** Write a one-time script using Python's `sympy` to generate a suitable prime, run it once, save output to `params.json`, and commit. Never run again.

The file format:
```json
{
  "p": "<very large prime>",
  "alpha": "2"
}
```

It gets created once on day one and never touched again. Everyone imports from it on startup.

### 5.2 — Publish `elgamal.py` stub interface (Member A)

Members B, C, and D all call into `elgamal.py`. Without even the function signatures, they're blocked or will make assumptions that cause integration bugs.

A stub is just function names, parameters, return types, and docstrings — no real implementation needed yet. This should be one of the first commits to the repo.

---

## 6. Parallel vs. Sequential Work

**CTFs and Modules share zero dependencies.** Different files, different libraries, different logic entirely. Both tracks run simultaneously from day one.

Within the module track:
- Members A, B, C can work in parallel once `params.json` and the `elgamal.py` stub exist.
- Member D must wait until Modules 1, 2, and 3 interfaces are settled.

Within the CTF track:
- All 6 CTFs are fully independent of each other.
- CTF 5 should be the first thing Member D touches.

---

## 7. File Structure

```
project/
│
├── README.md
├── requirements.txt               ← include tshark/scapy note for CTF 1
│
├── config/
│   └── params.json                ← shared p, α for ElGamal + DH (created day one, never modified)
│
├── modules/
│   ├── __init__.py
│   ├── elgamal.py                 ← Module 1: key gen, sign, verify primitives (from scratch)
│   ├── vault.py                   ← Module 2: AES-GCM CRUD on vault JSON
│   ├── signatures.py              ← Module 3: sign/verify vault using Module 1
│   └── export.py                  ← Module 4: DH exchange + export/import flow (from scratch)
│
├── cli.py                         ← Main entry point (owned by Member B)
│
├── tests/
│   ├── test_elgamal.py            ← most important: 3 modules depend on this
│   ├── test_vault.py
│   ├── test_signatures.py
│   └── test_export.py
│
├── ctf/
│   ├── ctf1_packet_analysis/
│   │   ├── solve.py
│   │   └── writeup.md
│   ├── ctf2_image_manipulation/
│   │   ├── solve.py
│   │   └── writeup.md
│   ├── ctf3_bit_shifting/
│   │   ├── solve.py
│   │   └── writeup.md
│   ├── ctf4_steganography/
│   │   ├── solve.py
│   │   └── writeup.md
│   ├── ctf5_padding_oracle/
│   │   ├── solve.py
│   │   └── writeup.md
│   └── ctf6_rsa/
│       ├── solve.py
│       └── writeup.md
│
└── docs/
    └── design_decisions.md        ← required project deliverable
```

### Note on `tests/`

Unit tests are not a submission requirement but are strongly recommended for `elgamal.py` specifically. Since 3 modules call into it, having even basic tests (does key generation return a valid pair? does sign → verify roundtrip correctly?) makes integration debugging significantly easier. Whether to write tests for the other modules is a team call.

---

*Document generated during planning phase — update as decisions are made.*
