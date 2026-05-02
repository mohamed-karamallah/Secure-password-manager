# CTF 6: RSA Key Recovery — Writeup

## Challenge

We're given an RSA public key and a ciphertext:
- `n = 143991606075158483660871570161405209117`
- `e = 65537`
- `c = 34130411904650996210426832018051041635`

The hint says the key was "generated poorly — the primes used are too close together."

## Thought Process

The public modulus `n` is the product of two primes `p` and `q`. Normally `n` is hundreds of digits long and impossible to factor. But this one is only about 39 digits (~128 bits), which is absurdly small for RSA. On top of that, the primes are supposedly close together.

When primes are close together, Fermat's factorization is the textbook attack: start from `√n` and search upward for an `a` where `a² - n` is a perfect square. That gives you `p = a + b` and `q = a - b`.

I initially tried Fermat's method but it was still slow because the primes differ by ~800 quadrillion (close in ratio but far in absolute terms). So I used `sympy.factorint()` which internally uses optimized algorithms like Pollard's p-1, Williams' p+1, and ECM (Elliptic Curve Method) to factor numbers of this size almost instantly.

## Solution

```python
from sympy import factorint

n = 143991606075158483660871570161405209117
e = 65537
c = 34130411904650996210426832018051041635

factors = factorint(n)
p, q = list(factors.keys())

# compute private key
phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)

# decrypt
m = pow(c, d, n)
flag = m.to_bytes((m.bit_length() + 7) // 8, 'big').decode()
print(flag)
```

## Factorization Result

```
p = 11607228028223627369
q = 12405339649142310293
```

These two primes differ by only about 6.4%, confirming the "too close together" hint.

## Flag

**`CMPN{f4c70r_m3}`**

## Tools Used
- Python 3
- `sympy` for integer factorization
- Built-in `pow()` for modular exponentiation and modular inverse
