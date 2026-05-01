# CTF 4 — Steganography Writeup

## Challenge Description

> Steganography is the practice of hiding data inside another file. You are given
> an image file `stego.png` that looks like an ordinary photograph. Something is
> HIDING inside this image using LSB (Least Significant Bit) steganography.
> 
> **Hint:** Determine which tool was used to hide data first (steghide, OpenStego,
> etc.) — may require a passphrase.

---

## Tools Used

| Tool | Purpose |
|------|---------|
| **Python 3** | Scripting language for analysis |
| **Pillow (PIL)** | Reading pixel data from the PNG file |

---

## Thought Process

### Step 1 — Initial Image Analysis
We were provided an image file named `stego.png`. The challenge prompt hinted that a specific steganography tool (like `steghide` or `OpenStego`) might have been used and might require a passphrase. 

However, before making assumptions or trying to brute-force passwords with various tools, the first rule of steganography is to check the basics: **Plain Least Significant Bit (LSB) encoding**.

### Step 2 — Developing an LSB Extractor
Rather than guessing the tool, we wrote a small Python script to inspect the lowest bit (the `& 1` bit) of every pixel in the image. The image was identified as having a Grayscale mode (`L`), meaning each pixel is represented by a single integer rather than an `(R, G, B)` tuple.

The extraction logic:
1. Iterate over the image width and height (row by row).
2. Extract the lowest bit from each pixel using bitwise AND (`pixel & 1`).
3. Collect all these bits into a continuous stream.
4. Group the stream into chunks of 8 bits (1 byte).
5. Convert each byte into its corresponding ASCII character.

### Step 3 — Flag Discovery
Once the bits were converted to a string of ASCII text, we performed a simple search for the known flag format `CMPN{`. 

Surprisingly, the data was not encrypted, compressed, or disguised behind a complex tool like `steghide` (which doesn't natively support PNGs anyway) or `OpenStego`. It was simply embedded as raw plaintext bits in the image's LSB stream. 

The flag was located near the very beginning of the extracted text:

```
CMPN{Hidd3n_in_pl4in_sigh7}
```

---

## Flag

```
CMPN{Hidd3n_in_pl4in_sigh7}
```

Translation: **"Hidden in plain sight"** — perfectly matching the fact that the data wasn't encrypted with a complex tool but was literally sitting in the raw LSBs.

---

## Summary

Despite the prompt hinting at advanced tools and passphrases, the solution required a back-to-basics approach. By writing a custom Python script using the `Pillow` library, we iterated through the pixels of the grayscale image, extracted the least significant bit of each, and grouped them into ASCII characters. This immediately revealed the unencrypted flag.
