# CTF 1 `solve.py` — Line-by-Line Explanation

This document breaks down the `solve.py` script for CTF 1 line by line, explaining both the Python syntax used and the logical flow of the program. 

---

## 1. File Header & Imports

```python
# -*- coding: utf-8 -*-
"""
CTF 1 — Packet Analysis
========================
... docstring ...
"""
```
* **`# -*- coding: utf-8 -*-`**: A special comment telling Python that this file uses UTF-8 character encoding. This ensures any special characters (like the `—` dash or arrows) in the file are read correctly.
* **`""" ... """`**: A multi-line string used here as a "docstring" (documentation string). It explains what the script does and how to use it. 

```python
import subprocess
import base64
import sys
import os
import io
```
These are built-in Python modules (libraries) imported to give the script specific capabilities:
* **`subprocess`**: Allows the script to run external terminal commands (specifically, to run the `tshark` program).
* **`base64`**: Provides functions to encode and decode base64 data.
* **`sys`**: Provides access to system-specific parameters and functions, like reading command-line arguments (`sys.argv`) and exiting the script (`sys.exit`).
* **`os`**: Provides operating system interfaces, like building file paths (`os.path.join`) and checking if files exist (`os.path.isfile`).
* **`io`**: Core tools for working with input/output streams (imported but mostly handled behind the scenes here).

```python
# Force UTF-8 output on Windows so Unicode symbols print correctly
if hasattr(sys, "stdout") and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
```
* **`sys.stdout`**: This represents the standard output stream (usually your terminal/console).
* **`hasattr(...)`**: Checks if an object has a specific attribute. Here, it checks if `sys.stdout` exists and has the `reconfigure` method (which was added in newer Python 3 versions).
* **`.reconfigure(...)`**: Forces the terminal output to use UTF-8 encoding. Windows terminals sometimes default to older encodings (like `cp1252`), which crash if the script tries to print a special Unicode character.

---

## 2. Configuration Variables

```python
TSHARK_PATHS = [
    "tshark",                           # if already on PATH
    r"C:\Program Files\Wireshark\tshark.exe",
]
```
* **`TSHARK_PATHS`**: A list of strings representing possible locations for the `tshark` command. 
* **`"tshark"`**: The command as it would run if Wireshark is correctly added to your system's `PATH` environment variable.
* **`r"C:\..."`**: The `r` before the string stands for "raw string". It tells Python to treat backslashes `\` as literal backslashes, rather than escape characters (like `\n` for newline).

```python
DEFAULT_PCAP = os.path.join(
    os.path.dirname(__file__),          # ctf/ctf1_packet_analysis/
    "..", "..",                         # project root
    "CTF_DATA", "CTF_DATA", "CTF1", "traffic.pcapng",
)
```
* **`__file__`**: A special Python variable that holds the path of the current script (`solve.py`).
* **`os.path.dirname(__file__)`**: Gets the folder containing `solve.py`.
* **`os.path.join(...)`**: Intelligently joins folder names together using the correct slashes for the current operating system (`\` on Windows, `/` on Mac/Linux). `".."` means "go up one folder level".

```python
MSG_START = "MSG:"
MSG_END   = ":EOF"
```
Constants defining the markers we observed in the packet payloads surrounding our base64 data.

---

## 3. Helper Functions

### Finding Tshark
```python
def find_tshark() -> str:
    """Return the first usable tshark executable path."""
    for path in TSHARK_PATHS:
        try:
            subprocess.run([path, "--version"], capture_output=True, check=True)
            return path
        except (FileNotFoundError, subprocess.CalledProcessError):
            continue
    raise EnvironmentError(
        "tshark not found. Install Wireshark and ensure tshark is on PATH."
    )
```
* **`def find_tshark() -> str:`**: Defines a function. `-> str` is a "type hint" indicating this function returns a string.
* **`for path in TSHARK_PATHS:`**: Loops through the list of potential `tshark` locations.
* **`try: ... except: ...`**: An error-handling block. It "tries" to run the code inside. If an error occurs, instead of crashing, it jumps to the `except` block.
* **`subprocess.run(...)`**: Runs a terminal command. We pass it `[path, "--version"]` which translates to running `tshark --version` in the terminal. 
  * `capture_output=True`: Hides the output from printing to the screen.
  * `check=True`: Forces Python to raise an error (`CalledProcessError`) if the command fails.
* **`return path`**: If the command succeeds, it immediately exits the function and returns the working path.
* **`continue`**: If it fails (hits the `except` block), `continue` tells the loop to move on to the next path in the list.
* **`raise EnvironmentError(...)`**: If the loop finishes without returning, it means no path worked. We purposefully crash the script with a custom error message.

### Converting Hex to ASCII
```python
def hex_to_ascii(hex_str: str) -> str:
    """Convert a hex string (e.g. '4d5347') to its ASCII representation."""
    raw = bytes.fromhex(hex_str)
    return raw.decode("ascii", errors="replace")
```
* **`bytes.fromhex(hex_str)`**: Converts a string of hexadecimal characters (like `"414243"`) into raw computer bytes (like `b"ABC"`).
* **`.decode("ascii")`**: Converts those raw bytes into a readable Python string using the ASCII standard. `errors="replace"` ensures that if an invalid byte is found, it is replaced with a `?` instead of crashing.

### Extracting Payloads via Tshark
```python
def extract_payloads(tshark: str, pcap: str) -> list[str]:
    ...
    cmd = [
        tshark,
        "-r", pcap,
        "-Y", "tcp.port==4444 && tcp.srcport!=4444 && data",
        "-T", "fields",
        "-e", "data",
        "-E", "separator=|",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
```
* This builds the command line arguments as a list.
* **`-r`**: Read a capture file.
* **`-Y`**: Apply a display filter. We filter for:
  1. `tcp.port==4444` (Traffic on port 4444)
  2. `tcp.srcport!=4444` (Sent by the client, not the server)
  3. `data` (The packet actually contains an application payload, not just TCP acknowledgements).
* **`-T fields -e data`**: Tell tshark to format the output as raw fields, and we only want the `data` field (the raw hex payload).
* **`result = subprocess.run(...)`**: Executes the command. `text=True` means we want the output returned as a regular string, not raw bytes.

```python
    if result.returncode != 0:
        raise RuntimeError(f"tshark error:\n{result.stderr.strip()}")
```
* **`result.returncode`**: A program returns `0` if it succeeds. Anything else means an error occurred. We check this and raise an error if `tshark` failed.

```python
    payloads = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if line:
            payloads.append(hex_to_ascii(line))
    return payloads
```
* **`result.stdout.splitlines()`**: Takes the output of the tshark command (a big block of text) and splits it into a list of individual lines.
* **`line.strip()`**: Removes any leading or trailing whitespace/newlines from the line.
* **`if line:`**: Checks if the line is not empty.
* **`payloads.append(...)`**: Calls our `hex_to_ascii` helper function and adds the resulting string to our `payloads` list.

### Reassembling the Flag
```python
def reassemble_flag(payloads: list[str]) -> str:
    raw = "".join(payloads)
```
* **`"".join(payloads)`**: Takes the list of payload strings and glues them all together into one single long string.

```python
    start_idx = raw.find(MSG_START)
    end_idx   = raw.find(MSG_END)

    if start_idx == -1 or end_idx == -1:
        raise ValueError("Could not locate MSG:/EOF markers in stream.")
```
* **`.find(...)`**: Searches the string for the marker and returns the index (the character position number) where it starts. If it can't find it, it returns `-1`.
* We check to make sure both markers were found.

```python
    b64_data = raw[start_idx + len(MSG_START) : end_idx]
```
* **`raw[ start : end ]`**: This is Python "string slicing". It extracts a chunk of the string.
* Start position: `start_idx + len(MSG_START)`. We don't want the word `MSG:` itself, so we add the length of the marker to start capturing *after* it.
* End position: `end_idx`. We stop capturing right when `:EOF` begins.

```python
    flag_bytes = base64.b64decode(b64_data)
    return flag_bytes.decode("utf-8")
```
* **`base64.b64decode(...)`**: Takes the base64 string and decodes it back into raw bytes.
* **`.decode("utf-8")`**: Converts those raw bytes into a normal Python string.

---

## 4. Main Execution Flow

```python
def main():
    pcap = os.path.normpath(sys.argv[1] if len(sys.argv) > 1 else DEFAULT_PCAP)
```
* **`sys.argv`**: A list containing command-line arguments passed to the script. `sys.argv[0]` is the script name itself (`solve.py`). `sys.argv[1]` would be the first argument provided by the user.
* **`... if ... else ...`**: An inline `if` statement (ternary operator). If the user provided a command line argument (`len > 1`), use it. Otherwise, use our `DEFAULT_PCAP` path.
* **`os.path.normpath(...)`**: Cleans up the path, resolving any `..` (up one folder) references to create a clean, absolute path.

```python
    # ... (Print statements omitted for brevity) ...
    
    tshark = find_tshark()
    
    if not os.path.isfile(pcap):
        print(f"[!] pcap file not found: {pcap}")
        sys.exit(1)
```
* Calls `find_tshark()` to get the executable path.
* **`os.path.isfile(pcap)`**: Checks if the capture file actually exists on the hard drive before trying to process it. If not, it gracefully exits the script with `sys.exit(1)`.

```python
    payloads = extract_payloads(tshark, pcap)
    for i, p in enumerate(payloads, 1):
        print(f"    Packet {i:>2}: {p!r}")
```
* Calls `extract_payloads()` to get the list of ASCII strings.
* **`enumerate(payloads, 1)`**: Loops through the list, but also gives us an index counter `i` that starts at `1` (instead of the default `0`).
* **`f"..."`**: An f-string (formatted string). It evaluates variables inside `{}` and inserts them into the string.
* **`{i:>2}`**: Formats the integer `i` to be right-aligned with a width of 2 spaces.
* **`{p!r}`**: The `!r` tells Python to use the "repr()" representation of the string. This puts quote marks around the string and makes hidden characters (like newlines) visible, making debugging easier.

```python
    flag = reassemble_flag(payloads)
    print(f"  FLAG FOUND: {flag}")
```
* Passes the payloads to `reassemble_flag()` and prints the final result!

---

## 5. Script Entry Point

```python
if __name__ == "__main__":
    main()
```
* This is standard Python boilerplate. 
* **`__name__`** is a special variable. If you run this script directly (e.g., `python solve.py`), `__name__` is set to `"__main__"`. 
* If you were to `import` this script into another Python file, `__name__` would be `"solve"`. 
* This block ensures that `main()` is only executed when the script is run directly, not when it is imported as a library by another script.
