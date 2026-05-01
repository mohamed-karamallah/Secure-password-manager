# -*- coding: utf-8 -*-
"""
CTF 1 — Packet Analysis
========================
A secret flag was transmitted over a TCP session on port 4444.
The flag was split across multiple packets and base64-encoded.
We reassemble the payload chunks, strip the MSG:/EOF markers, and decode.

Usage:
    python solve.py [path_to_pcapng]

Default pcapng path (relative to project root):
    CTF_DATA/CTF_DATA/CTF1/traffic.pcapng
"""

import subprocess
import base64
import sys
import os
import io

# Force UTF-8 output on Windows so Unicode symbols print correctly
if hasattr(sys, "stdout") and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")


# ── Configuration ────────────────────────────────────────────────────────────

TSHARK_PATHS = [
    "tshark",                           # if already on PATH
    r"C:\Program Files\Wireshark\tshark.exe",
]

DEFAULT_PCAP = os.path.join(
    os.path.dirname(__file__),          # ctf/ctf1_packet_analysis/
    "..", "..",                         # project root
    "CTF_DATA", "CTF_DATA", "CTF1", "traffic.pcapng",
)

MSG_START = "MSG:"
MSG_END   = ":EOF"


# ── Helpers ───────────────────────────────────────────────────────────────────

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


def hex_to_ascii(hex_str: str) -> str:
    """Convert a hex string (e.g. '4d5347') to its ASCII representation."""
    raw = bytes.fromhex(hex_str)
    return raw.decode("ascii", errors="replace")


def extract_payloads(tshark: str, pcap: str) -> list[str]:
    """
    Use tshark to pull the raw hex payload of every TCP packet on port 4444
    that originates from the CLIENT (srcport != 4444) and carries data.
    Returns a list of ASCII-decoded payload strings in frame order.
    """
    cmd = [
        tshark,
        "-r", pcap,
        # client packets with a data layer
        "-Y", "tcp.port==4444 && tcp.srcport!=4444 && data",
        "-T", "fields",
        "-e", "data",          # raw hex payload
        "-E", "separator=|",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"tshark error:\n{result.stderr.strip()}")

    payloads = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if line:
            payloads.append(hex_to_ascii(line))
    return payloads


def reassemble_flag(payloads: list[str]) -> str:
    """
    Concatenate all ASCII payloads, strip MSG: / :EOF markers,
    and base64-decode the remainder to obtain the flag.
    """
    raw = "".join(payloads)

    # Locate and remove protocol markers
    start_idx = raw.find(MSG_START)
    end_idx   = raw.find(MSG_END)

    if start_idx == -1 or end_idx == -1:
        raise ValueError(
            f"Could not locate MSG:/EOF markers in stream.\nRaw data: {raw!r}"
        )

    b64_data = raw[start_idx + len(MSG_START) : end_idx]

    # base64 decode → flag
    flag_bytes = base64.b64decode(b64_data)
    return flag_bytes.decode("utf-8")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    pcap = os.path.normpath(sys.argv[1] if len(sys.argv) > 1 else DEFAULT_PCAP)

    print("=" * 60)
    print("CTF 1 — Packet Analysis Solver")
    print("=" * 60)

    # 1. Locate tshark
    print(f"\n[*] Locating tshark ...", end=" ")
    tshark = find_tshark()
    print(f"found -> {tshark}")

    # 2. Verify pcap exists
    if not os.path.isfile(pcap):
        print(f"[!] pcap file not found: {pcap}")
        sys.exit(1)
    print(f"[*] Capture file       : {pcap}")

    # 3. Extract payloads
    print(f"[*] Filtering TCP port 4444 client packets ...")
    payloads = extract_payloads(tshark, pcap)
    print(f"    -> {len(payloads)} data-bearing packets found")
    for i, p in enumerate(payloads, 1):
        print(f"    Packet {i:>2}: {p!r}")

    # 4. Reassemble & decode
    print(f"\n[*] Reassembling base64 stream ...")
    full_stream = "".join(payloads)
    b64_start   = full_stream.find(MSG_START) + len(MSG_START)
    b64_end     = full_stream.find(MSG_END)
    b64_payload = full_stream[b64_start:b64_end]
    print(f"    Base64 payload : {b64_payload}")

    flag = reassemble_flag(payloads)

    print()
    print("=" * 60)
    print(f"  FLAG FOUND: {flag}")
    print("=" * 60)


if __name__ == "__main__":
    main()
