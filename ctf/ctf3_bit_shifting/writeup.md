# CTF 3 — Bit Shifting Writeup

## Challenge Description

> given a text file `shifted.txt` containing a sequence of decimal numbers.
> Each number represents a character that has been bit-shifted. Find the right
> operation to recover the original ASCII characters and reveal the flag.

---

## Tools Used

| Tool | Purpose |
|------|---------|
| **Python 3** | Scripting the decode logic |

---

## Thought Process

### Step 1 — Examine the Data

The file `shifted.txt` contains 26 decimal numbers on a single line:

```
134 154 160 156 246 196 210 110 190 230 208 210 204 110 210 220 206 190 210 230 190 238 102 104 214 250
```

Since the challenge says each number "represents a character that has been bit-shifted," the goal is to find which bit operation reverses the shift.

### Step 2 — Identify the Shift

The flag format starts with `CMPN{`. The ASCII values for these characters are:

| Character | ASCII | Binary |
|-----------|-------|--------|
| C | 67 | `01000011` |
| M | 77 | `01001101` |
| P | 80 | `01010000` |
| N | 78 | `01001110` |
| { | 123 | `01111011` |

Now look at the first five numbers in the file:

| Number | Binary | Number ÷ 2 | Result Char |
|--------|--------|------------|-------------|
| 134 | `10000110` | 67 | C ✓ |
| 154 | `10011010` | 77 | M ✓ |
| 160 | `10100000` | 80 | P ✓ |
| 156 | `10011100` | 78 | N ✓ |
| 246 | `11110110` | 123 | { ✓ |

Every number is exactly **twice** the expected ASCII value. Dividing by 2 is the same as a **right bit-shift by 1** (`>> 1`). This confirms the encoding was a **left bit-shift by 1** (`<< 1`).

### Step 3 — Decode All Characters

Applying `n >> 1` (right-shift by 1) to every number:

```python
with open('shifted.txt', 'r') as file:
    raw_content = file.read().strip()

shifted_numbers = [int(num_str) for num_str in raw_content.split()]

recovered_characters = []
for number in shifted_numbers:
    original_ascii_value = number >> 1
    character = chr(original_ascii_value)
    recovered_characters.append(character)

flag = "".join(recovered_characters)
print(flag)
```

Output:
```
CMPN{bi7_shif7ing_is_w34k}
```

---

## Flag

```
CMPN{bi7_shif7ing_is_w34k}
```

Translation from leetspeak: **"bit shifting is weak"** — a reference to the fact that a simple bit-shift is not a real encryption scheme and is trivially reversible.

---

## Summary

The encoding was a single left bit-shift (`<< 1`) applied to each ASCII character, which is equivalent to multiplying each value by 2. Reversing it required a right bit-shift (`>> 1`) on each number. The pattern was immediately identifiable by comparing the first few numbers to the expected flag prefix `CMPN{`.
