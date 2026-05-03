import os
from PIL import Image

def main():
    img_path = os.path.join(os.path.dirname(__file__), "..", "CTF_DATA", "CTF4", "stego.png")
    img = Image.open(img_path)
    pixels = img.load()

    bits = ""
    for y in range(img.height):
        for x in range(img.width):
            pixel_value = pixels[x, y]
            bits += str(pixel_value & 1)

    chars = []
    for i in range(0, len(bits), 8):
        byte = bits[i:i+8]
        if len(byte) == 8:
            chars.append(chr(int(byte, 2)))
            
    text = "".join(chars)

    # 4. Search for the flag format in the extracted text
    flag_start = text.find("CMPN{")
    flag_end = text.find("}", flag_start)
    
    print("Flag Found:", text[flag_start:flag_end+1])


if __name__ == "__main__":
    main()
