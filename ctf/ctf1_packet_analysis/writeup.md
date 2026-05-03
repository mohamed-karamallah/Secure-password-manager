# CTF 1: Manual Wireshark Solution Guide


## Step 1: Filter the Suspicious Traffic

1. Open the capture file `traffic.pcapng` in Wireshark.
2. In the display filter bar at the top of the screen, type `tcp.port == 4444` and hit **Enter**.
3. You will now see only the packets involved in this specific exchange.

![Filtering Traffic](Screenshot%20(40).png)

## Step 2: Follow the TCP Stream



1. Right-click on **any** of the packets currently displayed.
2. From the context menu, select **Follow > TCP Stream**.

![Following TCP Stream](Screenshot%20(41).png)

## Step 3: Extract and Decode the Flag

 "Show data as" to ASCII .

```text
MSG:Q01QTntwYzRwX2hpZGQzbl9pbl9sM2dpN183cjRmZmljfQ==:EOF
```

The data is wrapped between `MSG:` and `:EOF`. The string in the middle is base64 encoded (we can tell by the alphanumeric character set and the telltale `==` padding at the end).

1. Select and copy the base64 string: `Q01QTntwYzRwX2hpZGQzbl9pbl9sM2dpN183cjRmZmljfQ==`
2. Run the `solvectf1.py` script provided in this directory to decode it, or use an online tool like CyberChef.

**Decoded Flag:**
```text
CMPN{pc4p_hidd3n_in_l3gi7_7r4ffic}
```
