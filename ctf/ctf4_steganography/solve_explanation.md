# CTF 4 `solve.py` — Line-by-Line Explanation

This document breaks down the `solve.py` script for CTF 4, explaining the Python syntax and the logic used to extract the hidden LSB (Least Significant Bit) data.

---

## 1. Imports and Boilerplate

```python
import os
import sys
import io

# Force UTF-8 output on Windows so terminal doesn't crash on hidden binary bytes
if hasattr(sys, "stdout") and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
```
* Extracting binary data from an image often yields random, non-printable characters. If the script tries to print these characters to a Windows console running older encodings (like `cp1252`), it will crash. `sys.stdout.reconfigure(...)` forces the terminal to use UTF-8 and replace invalid characters with a `?`.

```python
try:
    from PIL import Image
except ImportError:
    print("[!] Pillow library is required. Please run: pip install pillow")
    sys.exit(1)
```
* **`from PIL import Image`**: We import the Image module from the `Pillow` library, which allows us to load and manipulate images. Since `Pillow` is an external library, we wrap it in a `try/except` block to give the user a helpful error message if it's not installed.

---

## 2. Configuration Variables

```python
DEFAULT_IMAGE_PATH = os.path.join(
    os.path.dirname(__file__),          # ctf/ctf4_steganography/
    "..", "..",                         # project root
    "CTF_DATA", "CTF_DATA", "CTF4", "stego.png",
)

FLAG_PREFIXES = ["CMPN{", "FLAG{"]
```
* **`os.path.join`**: Dynamically builds the file path to `stego.png` using relative directories so the script works regardless of where the user runs it from.
* **`FLAG_PREFIXES`**: A list of strings that represent the start of the flag. We will search our extracted text for these specific strings.

---

## 3. The Extraction Logic

```python
def extract_lsb_string(image_path: str) -> str:
    img = Image.open(image_path)
    
    # Do NOT convert the image. Keep it in its original mode.
    pixels = img.load()
    width, height = img.size
```
* **`Image.open(...)`**: Opens the PNG image from the disk.
* **`img.load()`**: Returns a 2D array-like object that lets us quickly access individual pixels using `[x, y]` coordinates.
* **`img.size`**: Returns a tuple containing the `(width, height)` of the image in pixels.

```python
    bits = []
    
    for y in range(height):
        for x in range(width):
            p = pixels[x, y]
```
* We initialize an empty list `bits` to store our extracted `0`s and `1`s.
* The nested `for` loops iterate over every single pixel in the image. By looping `y` (rows) first, then `x` (columns), we read the image left-to-right, top-to-bottom.

```python
            # If grayscale (mode 'L'), p is an int
            if isinstance(p, int):
                bits.append(str(p & 1))
            else:
                # If RGB/RGBA, p is a tuple. Extract LSB from the first 3 channels
                for c in range(min(3, len(p))):
                    bits.append(str(p[c] & 1))
```
* **`isinstance(p, int)`**: Images can be in different color modes. In `RGB` mode, a pixel `p` is a tuple like `(255, 0, 0)`. In Grayscale (`L`) mode, `p` is just a single integer like `128`. We check if it's an integer to handle it properly.
* **`p & 1`**: This is a bitwise AND operation. It isolates the Least Significant Bit. If `p` is even, `p & 1` is `0`. If `p` is odd, `p & 1` is `1`.
* **`bits.append(str(...))`**: We convert the resulting integer (`0` or `1`) into a string character and add it to our list.

```python
    chars = []
    for i in range(0, len(bits), 8):
        byte_chunk = "".join(bits[i:i+8])
        if len(byte_chunk) == 8:
            chars.append(chr(int(byte_chunk, 2)))
            
    return "".join(chars)
```
* **`range(0, len(bits), 8)`**: We loop through our list of bits, jumping forward by 8 bits each time.
* **`"".join(bits[i:i+8])`**: Slices exactly 8 bits from the list and glues them into a single string like `"01000011"`.
* **`int(byte_chunk, 2)`**: Converts the binary string (base 2) into a standard base-10 integer. For example, `"01000011"` becomes `67`.
* **`chr(...)`**: Converts the integer into its ASCII character equivalent (`67` becomes `"C"`). We append this to the `chars` list.
* Finally, we join all the ASCII characters into one massive string and return it.

---

## 4. Main Execution and Search

```python
    extracted_text = extract_lsb_string(img_path)

    flag = None
    for prefix in FLAG_PREFIXES:
        if prefix in extracted_text:
            start_idx = extracted_text.find(prefix)
            end_idx = extracted_text.find("}", start_idx)
            
            if end_idx != -1:
                flag = extracted_text[start_idx:end_idx + 1]
                break
```
* The script calls our extractor function and saves the massive result into `extracted_text`.
* **`prefix in extracted_text`**: A quick check to see if `"CMPN{"` exists anywhere in the string.
* **`extracted_text.find(prefix)`**: Gets the exact index location where the flag starts.
* **`extracted_text.find("}", start_idx)`**: Searches for the closing brace `}`, but only looks *after* the `start_idx`.
* **`flag = extracted_text[start_idx:end_idx + 1]`**: We slice out exactly the characters that make up the flag and save it to the `flag` variable.

```python
    if flag:
        print(f"  FLAG FOUND: {flag}")
    else:
        print("[!] No flag found in the LSB stream.")
```
* If the search was successful, it prints the discovered flag. Otherwise, it warns the user.
