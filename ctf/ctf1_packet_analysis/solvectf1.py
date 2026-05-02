import base64

def main():
        
    encoded_string = "Q01QTntwYzRwX2hpZGQzbl9pbl9sM2dpN183cjRmZmljfQ=="
    
    print("CTF 1 — Manual Base64 Decoder")
    print(f"[*] Base64 Encoded String: {encoded_string}")
    
    decoded_bytes = base64.b64decode(encoded_string)
    decoded_flag = decoded_bytes.decode('utf-8')
    
    print(f"[+] Decoded Flag: {decoded_flag}")

if __name__ == "__main__":
    main()
