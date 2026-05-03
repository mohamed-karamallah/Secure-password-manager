# CTF 4: Steganography — Solution Process

## Objective
The goal of this challenge was to extract a hidden flag from an image file named `stego.png`. The challenge hinted that data was hiding inside the image, potentially using a specific steganography tool that might require a passphrase.

## Thought Process
Before falling down the rabbit hole of brute-forcing passwords or trying dozens of different steganography tools (like steghide or OpenStego), I decided to check for the most fundamental steganography technique first: **Least Significant Bit (LSB) encoding without encryption.**

If the data was hidden in plain text within the LSBs, I could extract it manually without needing to guess passwords or identify the exact tool used by the challenge creator.

## Implementation: The Custom Python Extractor
To test this hypothesis, I wrote a lightweight, custom Python script (`solvectf4_simple.py`) to manually extract the data. 

The logic of my script was straightforward:
1. **Load the Image:** Use the `Pillow` library to open `stego.png` and load its pixel map.
2. **Extract Bits:** Loop through every single pixel in the image. Since the image was grayscale, I could isolate the lowest bit of each pixel's color value by performing a bitwise AND operation (`pixel_value & 1`).
3. **Reconstruct Bytes:** Group the continuous stream of extracted bits into chunks of 8 (since 8 bits = 1 byte = 1 ASCII character).
4. **Convert and Search:** Convert those binary chunks into text and search the resulting string for the known flag format `CMPN{`.

Running my script successfully dumped the hidden text, and the flag was found instantly without needing any passwords.

## Alternative Verification
To double-check my work and ensure my script's logic was sound, I also uploaded the image to **StegOnline** (a standard web-based CTF tool). By selecting the "Extract Files/Data" feature and isolating **Bit 0** (the LSB), the tool instantly returned the exact same text stream. 

## Conclusion and Flag
My initial hypothesis was correct. The data was not encrypted or password-protected; it was simply embedded as raw plaintext bits in the image's LSB stream. 

**Flag Found:**
```text
CMPN{Hidd3n_in_pl4in_sigh7}
```
The text translates to "Hidden in plain sight," which perfectly confirms why the basic LSB extraction worked without any advanced tools.
