import os
DATA_PATH = os.path.join(
    os.path.dirname(__file__), "..", "..", "CTF_DATA", "CTF_DATA", "CTF3", "shifted.txt"
)

def solve():
    with open(DATA_PATH, "r") as file:
        raw_content = file.read().strip()
        
    number_strings = raw_content.split()    
    shifted_numbers = [int(num_str) for num_str in number_strings]
    recovered_characters = []
    for number in shifted_numbers:
        original_ascii_value = number >> 1
        character = chr(original_ascii_value)
        recovered_characters.append(character)        
    flag = "".join(recovered_characters)
    return flag


if __name__ == "__main__":
    flag = solve()
    print(f"Flag: {flag}")
