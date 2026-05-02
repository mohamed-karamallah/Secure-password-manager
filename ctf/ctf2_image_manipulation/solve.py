from PIL import Image
import numpy as np
import os

script_dir = os.path.dirname(os.path.abspath(__file__))
data_dir = os.path.join(script_dir, "..", "..", "CTF_DATA", "CTF_DATA", "CTF2")

img1_path = os.path.join(data_dir, "Layer1.png")
img2_path = os.path.join(data_dir, "Layer2.png")

layer1 = Image.open(img1_path)
layer2 = Image.open(img2_path)

arr1 = np.array(layer1)
arr2 = np.array(layer2)

result = np.bitwise_xor(arr1, arr2)

out_path = os.path.join(script_dir, "result.png")
result_img = Image.fromarray(result)
result_img.save(out_path)

print(f"XOR result saved to {out_path}")
print("Open result.png to see the flag.")
