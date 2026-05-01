# CTF 5: CBC Padding Oracle Writeup

## 1. Tools Used
- **Python 3**: For writing the custom decryption script (`solve.py`).
- **Requests Library**: To send POST requests to the server's oracle endpoint efficiently using `requests.Session()`.
- **Web Browser (Inspector)**: To initially analyze the web page, locate the target ciphertext, and find the `/oracle` API endpoint.

## 2. Thought Process
When I first loaded the target server (`http://cbc-ctf.westeurope.azurecontainer.io:5000/`), I immediately looked for the data we needed to decrypt. I found the target ciphertext string (`b248f0e8f4e3548b995d2215f54b72bd5d3b211b522b7a5ea25c5763e7425447e440e4d85933807e1385d11cd1959975`). I also noticed an endpoint `/oracle` that accepts JSON data `{"ciphertext_hex": "..."}` and returns a boolean value `valid_padding`. 

Seeing an endpoint that literally tells you if the padding is valid immediately signaled that this was a classic **CBC Padding Oracle Attack**. My thought process was to exploit the way CBC mode decrypts blocks. In CBC mode, a block is decrypted using the AES key and then XORed with the previous block to produce the final plaintext:
`Plaintext[N] = Decrypt(Ciphertext[N]) XOR Ciphertext[N-1]`

Because we control the ciphertext being sent to the server, we can send a single target block along with a completely fabricated "previous block". By brute-forcing the last byte of this fake previous block from `0x00` to `0xFF`, we can observe the server's response. When the server returns `valid_padding: true`, it means our guessed byte successfully forced the last byte of the plaintext to become `0x01` (valid PKCS#7 padding). From there, basic XOR math reveals the intermediate decryption state, which we can then XOR with the real previous ciphertext block to uncover the actual plaintext.

## 3. Steps Followed
1. **Analyze the Ciphertext:** The ciphertext is 96 hex characters (48 bytes). Since AES blocks are 16 bytes, this gives us exactly 3 blocks (Block 0 is the IV, Block 1 is the first ciphertext block, Block 2 is the second).
2. **Develop the Script:** I wrote a Python script (`solve.py`) to automate the attack.
3. **Iterate Blocks:** The script is designed to iterate through Block 1 and Block 2. 
4. **Brute Force Padding:** For each block, it loops through padding values from 1 to 16.
5. **Guess Bytes:** For each padding value, it guesses all 256 possible bytes for the fake previous block. It constructs the fake block by filling in the previously discovered intermediate bytes to ensure the padding remains valid.
6. **Query the Oracle:** It sends the payload (`fake_prev_block + target_block`) to the server using `requests.Session()` to keep the connection fast. 
7. **Handle False Positives:** When guessing the very first byte (padding value `0x01`), the script flips the second-to-last byte and sends a second request to ensure the valid response wasn't a false positive (e.g., accidental `0x02 0x02` padding).
8. **Calculate Plaintext:** Once the full intermediate state is recovered for a block, it is XORed against the real previous block to get the plaintext.

## 4. How I Arrived at the Flag
I ran my `solve.py` script, and it sequentially brute-forced the intermediate bytes by hitting the server's oracle endpoint. Once the attack finished, it successfully recovered the decrypted blocks:
- **Block 1 Plaintext:** `CMPN{cbc_p4dding`
- **Block 2 Plaintext:** `_0r4cl3}\x08\x08\x08\x08\x08\x08\x08\x08` 

The last block contained 8 bytes of valid PKCS#7 padding (`\x08`). My script automatically stripped these padding bytes off the end of the combined string.

This revealed the final flag:
**Flag:** `CMPN{cbc_p4dding_0r4cl3}`
