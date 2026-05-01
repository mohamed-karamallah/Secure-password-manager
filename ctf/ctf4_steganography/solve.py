# -*- coding: utf-8 -*-
"""
CTF 4 — Steganography
======================
This script extracts a hidden flag from `stego.png`.
It reads the Least Significant Bit (LSB) of each RGB channel
across the image's pixels and groups them into 8-bit characters
to recover the embedded ASCII text.
"""

import os
import sys
import io

# Force UTF-8 output on Windows so terminal doesn't crash on hidden binary bytes
if hasattr(sys, "stdout") and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

try:
    from PIL import Image
except ImportError:
    print("[!] Pillow library is required. Please run: pip install pillow")
    sys.exit(1)


# ── Configuration ────────────────────────────────────────────────────────────

DEFAULT_IMAGE_PATH = os.path.join(
    os.path.dirname(__file__),          # ctf/ctf4_steganography/
    "..", "..",                         # project root
    "CTF_DATA", "CTF_DATA", "CTF4", "stego.png",
)

FLAG_PREFIXES = ["CMPN{", "FLAG{"]


# ── Helpers ───────────────────────────────────────────────────────────────────

def extract_lsb_string(image_path: str) -> str:
    """
    Reads the LSB of every color channel of every pixel in the image.
    Reconstructs 8-bit bytes and decodes them to ASCII characters.
    """
    img = Image.open(image_path)
    
    # Do NOT convert the image. Keep it in its original mode.
    pixels = img.load()
    width, height = img.size

    bits = []
    
    # Iterate over all pixels: row by row, from left to right
    for y in range(height):
        for x in range(width):
            p = pixels[x, y]
            
            # If grayscale (mode 'L'), p is an int
            if isinstance(p, int):
                bits.append(str(p & 1))
            else:
                # If RGB/RGBA, p is a tuple. Extract LSB from the first 3 channels
                for c in range(min(3, len(p))):
                    bits.append(str(p[c] & 1))

    # Group extracted bits into 8-bit chunks (bytes)
    chars = []
    for i in range(0, len(bits), 8):
        byte_chunk = "".join(bits[i:i+8])
        if len(byte_chunk) == 8:
            chars.append(chr(int(byte_chunk, 2)))
            
    return "".join(chars)


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    img_path = os.path.normpath(sys.argv[1] if len(sys.argv) > 1 else DEFAULT_IMAGE_PATH)

    print("=" * 60)
    print("CTF 4 — Steganography Solver (LSB Extractor)")
    print("=" * 60)

    if not os.path.isfile(img_path):
        print(f"[!] Image file not found: {img_path}")
        sys.exit(1)
        
    print(f"[*] Analyzing image: {img_path}")
    print(f"[*] Extracting LSB from RGB channels...")

    extracted_text = extract_lsb_string(img_path)

    # Search for known flag formats
    flag = None
    for prefix in FLAG_PREFIXES:
        if prefix in extracted_text:
            start_idx = extracted_text.find(prefix)
            end_idx = extracted_text.find("}", start_idx)
            
            if end_idx != -1:
                flag = extracted_text[start_idx:end_idx + 1]
                break

    print()
    if flag:
        print("=" * 60)
        print(f"  FLAG FOUND: {flag}")
        print("=" * 60)
    else:
        print("[!] No flag found in the LSB stream.")
        print("First 100 extracted characters:")
        # Print a sanitized version of the start of the string for debugging
        print(repr(extracted_text[:100]))


if __name__ == "__main__":
    main()
