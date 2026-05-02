import math
import os
from sympy import factorint

# read the challenge file
script_dir = os.path.dirname(os.path.abspath(__file__))
data_dir = os.path.join(script_dir, "..", "..", "CTF_DATA", "CTF_DATA", "CTF6")
challenge_path = os.path.join(data_dir, "challenge.txt")

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

print(f"n = {n}")
print(f"e = {e}")
print(f"c = {c}")
print()

# the hint says the primes are "too close together" which means
# the key is weak and we can factor n
# n is small enough (~128 bits) that standard factoring algorithms
# handle it quickly

factors = factorint(n)
primes = list(factors.keys())

p = primes[0]
q = primes[1]

# make sure p < q for consistency
if p > q:
    p, q = q, p

print(f"Factored n!")
print(f"p = {p}")
print(f"q = {q}")
print(f"Difference between primes: {q - p}")
assert p * q == n

# now we can compute the private key
phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)

# decrypt: m = c^d mod n
m = pow(c, d, n)

# convert the integer back to the flag string
flag_bytes = m.to_bytes((m.bit_length() + 7) // 8, 'big')
flag = flag_bytes.decode('utf-8')

print(f"\nFlag: {flag}")
