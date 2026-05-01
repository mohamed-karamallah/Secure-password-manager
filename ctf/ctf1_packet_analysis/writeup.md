# CTF 1 — Packet Analysis Writeup

## Challenge Description

> You have been given a network capture file `traffic.pcapng`. A secret flag was
> transmitted during a suspicious TCP session. The flag has been split across
> multiple TCP packets and base64-encoded before transmission. Reassemble the data
> from the TCP stream and decode it to find the original flag.
>
> **Hint:** Filter for TCP traffic on port 4444. Extract the payload data from
> each packet in order and concatenate before decoding.

---

## Tools Used

| Tool | Purpose |
|------|---------|
| **Wireshark / tshark 4.6.4** | Opening and querying the `.pcapng` capture file |
| **Python 3** (`base64`, `subprocess`) | Automating extraction and decoding |

---

## Thought Process

### Step 1 — Understand the file format

A `.pcapng` file is a **network packet capture** — a recording of every packet
transmitted on a network interface during a session. Each record stores the
timestamp, source/destination addresses, protocol, and raw payload bytes.

The challenge hint immediately pointed to **TCP port 4444**, which is not a
standard service port, making it stand out as suspicious in normal traffic.

### Step 2 — Filter for suspicious traffic

Using `tshark` (the command-line version of Wireshark) we filtered the capture
to show only TCP packets involving port 4444:

```bash
tshark -r traffic.pcapng -Y "tcp.port==4444" -T fields -e frame.number -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e data
```

This revealed a short exchange between two sockets on the same host
(`192.168.146.137`), with the client using ephemeral port `40328` and the
server listening on port `4444`.

### Step 3 — Identify which side carries the flag

In a TCP exchange, **ACK-only packets** carry no application data. After
filtering those out we focused on packets where:
- `tcp.srcport != 4444` (i.e. sent by the **client**, not the server)
- The `data` field is non-empty

This left exactly **14 meaningful packets**.

### Step 4 — Extract and inspect the payloads

Each payload was stored as a raw hex string by tshark. Converting hex → ASCII
for each packet revealed:

| Packet | Hex Payload | ASCII |
|--------|------------|-------|
| 1 | `4d53473a` | `MSG:` |
| 2 | `5130315154` | `Q01QT` |
| 3 | `6e7477597a` | `ntwYz` |
| 4 | `527758` | `RwX` |
| 5 | `3268705a` | `2hpZ` |
| 6 | `47517a626c3970` | `GQzbl9p` |
| 7 | `626c3973` | `bl9s` |
| 8 | `4d3264` | `M2d` |
| 9 | `704e3138` | `pN18` |
| 10 | `33636a` | `3cj` |
| 11 | `526d5a6d6c6a` | `RmZmlj` |
| 12 | `66513d` | `fQ=` |
| 13 | `3d` | `=` |
| 14 | `3a454f46` | `:EOF` |

Two markers were immediately obvious:
- Packet 1 starts with **`MSG:`** — a start-of-message delimiter.
- Packet 14 ends with **`:EOF`** — an end-of-message delimiter.

Everything in between is the actual data payload.

### Step 5 — Reassemble the base64 string

Concatenating the ASCII content of packets 2–13 (between the markers) gave:

```
Q01QTntwYzRwX2hpZGQzbl9pbl9sM2dpN183cjRmZmljfQ==
```

The trailing `==` padding is a classic sign of **base64 encoding**.

### Step 6 — Decode the base64

```python
import base64
base64.b64decode("Q01QTntwYzRwX2hpZGQzbl9pbl9sM2dpN183cjRmZmljfQ==").decode()
```

Output:

```
CMPN{pc4p_hidd3n_in_l3gi7_7r4ffic}
```

---

## Flag

```
CMPN{pc4p_hidd3n_in_l3gi7_7r4ffic}
```

Decoded from leetspeak: **"pcap hidden in legit traffic"** — a reference to
the technique of hiding covert data inside what appears to be normal network
traffic.

---

## Summary

The flag was exfiltrated over a non-standard port (4444) by splitting a
base64-encoded string across multiple TCP packets, using `MSG:` and `:EOF`
as delimiters. The solve strategy was:

1. Filter the capture to port 4444
2. Extract only client-side data-bearing packets
3. Hex-decode each payload to ASCII
4. Strip the protocol markers and concatenate the base64 chunks
5. Base64-decode the result to get the plaintext flag

The entire process was automated in `solve.py`, which uses `tshark` for packet
extraction and Python's `base64` module for decoding.
