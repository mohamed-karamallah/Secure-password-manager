import requests

URL = "http://cbc-ctf.westeurope.azurecontainer.io:5000/oracle"
s = requests.Session()

def check_pad(ct_hex):
    try:
        r = s.post(URL, json={"ciphertext_hex": ct_hex})
        return r.json()["valid_padding"]
    except:
        return False

def solve():
    raw_hex = "b248f0e8f4e3548b995d2215f54b72bd5d3b211b522b7a5ea25c5763e7425447e440e4d85933807e1385d11cd1959975"
    ct = bytes.fromhex(raw_hex)
    
    blocks = []
    for i in range(0, len(ct), 16):
        blocks.append(ct[i:i+16])
        
    full_pt = b""
    
    for i in range(1, len(blocks)):
        prev_block = blocks[i-1]
        curr_block = blocks[i]
        
        intermediate = [0] * 16
        print(f"[*] Decrypting block {i}")
        
        for p in range(1, 17):
            found_ans = -1
            
            for guess in range(256):
                fake = [0] * 16
                # set the bytes we already know
                for k in range(1, p):
                    fake[16-k] = intermediate[16-k] ^ p
                    
                fake[16-p] = guess
                
                test_ct = bytes(fake) + curr_block
                if check_pad(test_ct.hex()):
                    # check false positive
                    if p == 1:
                        fake[-2] ^= 1
                        if not check_pad((bytes(fake) + curr_block).hex()):
                            continue
                    
                    found_ans = guess
                    break

            if found_ans == -1:
                print("error finding byte")
                return
                
            val = found_ans ^ p
            intermediate[16-p] = val
            print(f"  [+] byte {16-p} is {hex(val)}")

        pt_block = b""
        for j in range(16):
            pt_block += bytes([intermediate[j] ^ prev_block[j]])
            
        full_pt += pt_block

    # remove padding
    pad = full_pt[-1]
    full_pt = full_pt[:-pad]
    print("\nPlaintext:", full_pt.decode())

solve()