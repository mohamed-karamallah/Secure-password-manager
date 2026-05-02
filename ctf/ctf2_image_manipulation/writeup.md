# CTF 2: Image Manipulation — Writeup

## Challenge

We got two PNG images (`Layer1.png` and `Layer2.png`). Each one looks like random noise by itself — no visible pattern at all. The challenge says they "reveal a secret" when combined.

## Thought Process

When I opened both images they were just static/noise, same dimensions. The classic way to hide something across two noise images is **visual cryptography** using XOR. The idea is: if you XOR each pixel of image A with a random mask, you get noise. If someone has the same mask (image B), they XOR again and the randomness cancels out, leaving the original content.

So the approach was straightforward:
1. Load both images as pixel arrays
2. XOR them together pixel-by-pixel
3. Save the output and look at it

## Solution

Used Pillow to load the images and numpy for the XOR:

```python
from PIL import Image
import numpy as np

layer1 = Image.open("Layer1.png")
layer2 = Image.open("Layer2.png")

arr1 = np.array(layer1)
arr2 = np.array(layer2)

result = np.bitwise_xor(arr1, arr2)
Image.fromarray(result).save("result.png")
```

## Result

The XOR output shows the flag in clear text on a white background:

**`CMPN{im4g3s-4s_k3y$}`**

## Tools Used
- Python 3
- Pillow (PIL) for loading/saving PNGs
- NumPy for pixel-level XOR
