# CTF 4: Steganography — Solution Process


## Implementation: The Custom Python Extractor
To test this hypothesis, I wrote a lightweight, custom Python script (`solvectf4_simple.py`) to manually extract the data. 

The logic of my script was straightforward:
1. **Load the Image:** Use the `Pillow` library to open `stego.png` and load its pixel map.
2. **Extract Bits:** Loop through every single pixel in the image. Since the image was grayscale, I could isolate the lowest bit of each pixel's color value by performing a bitwise AND operation (`pixel_value & 1`).
3. **Reconstruct Bytes:** Group the continuous stream of extracted bits into chunks of 8 (since 8 bits = 1 byte = 1 ASCII character).
4. **Convert and Search:** Convert those binary chunks into text and search the resulting string for the known flag format `CMPN{`.

Running my script successfully dumped the hidden text, and the flag was found instantly without needing any passwords.


**Flag Found:**
```text
CMPN{Hidd3n_in_pl4in_sigh7}
```
The text translates to "Hidden in plain sight," which perfectly confirms why the basic LSB extraction worked without any advanced tools.
