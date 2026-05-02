from PIL import Image
import numpy as np
import os

# paths to the two layer images
script_dir = os.path.dirname(os.path.abspath(__file__))
data_dir = os.path.join(script_dir, "..", "..", "CTF_DATA", "CTF_DATA", "CTF2")

img1_path = os.path.join(data_dir, "Layer1.png")
img2_path = os.path.join(data_dir, "Layer2.png")

# load both images
layer1 = Image.open(img1_path)
layer2 = Image.open(img2_path)

# convert to numpy arrays so we can do pixel math
arr1 = np.array(layer1)
arr2 = np.array(layer2)

# XOR the two — each looks like random noise alone,
# but XOR should cancel out the noise and reveal the hidden message
result = np.bitwise_xor(arr1, arr2)

# save the result
out_path = os.path.join(script_dir, "result.png")
result_img = Image.fromarray(result)
result_img.save(out_path)

print(f"XOR result saved to {out_path}")
print("Open result.png to see the flag.")
