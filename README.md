# Packet Sniffer

Packet Sniffer is a beginner-friendly cybersecurity project built with Python and Scapy. It captures live network packets, displays important packet details, logs activity to a file, supports simple protocol filters, and includes basic suspicious activity detection.

This project is designed to look and feel like a real internship portfolio project while still being understandable for beginners moving toward intermediate cybersecurity topics.

## Project Structure

```text
packet-sniffer/
|
+-- sniffer.py
+-- logs.txt
+-- requirements.txt
+-- README.md
+-- screenshots/
```

## Features

- Capture live network packets
- Display source IP address
- Display destination IP address
- Detect TCP, UDP, and ICMP packets
- Show packet count
- Show timestamp for each packet
- Save packet logs into `logs.txt`
- Filter traffic by `tcp`, `udp`, or `icmp`
- Detect simple suspicious activity when one IP sends many packets quickly
- Colorful terminal output using Colorama
- Organized functions and beginner-friendly comments
- Compatible with Windows and Linux

## Installation

### 1. Clone or Open the Project

```bash
cd packet-sniffer
```

### 2. Create a Virtual Environment

Windows:

```bash
python -m venv .venv
.venv\Scripts\activate
```

Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Install Packet Capture Support

Windows users should install Npcap:

[https://npcap.com/](https://npcap.com/)

Linux users may need packet capture libraries:

```bash
sudo apt install tcpdump
```

## How to Run

Packet sniffing usually requires elevated permissions.

Windows PowerShell as Administrator:

```powershell
python sniffer.py
```

Linux:

```bash
sudo python3 sniffer.py
```

Capture only TCP packets:

```bash
sudo python3 sniffer.py --filter tcp
```

Capture only UDP packets:

```bash
sudo python3 sniffer.py --filter udp
```

Capture only ICMP packets:

```bash
sudo python3 sniffer.py --filter icmp
```

Capture 25 packets and stop:

```bash
sudo python3 sniffer.py --count 25
```

Use a specific interface:

```bash
sudo python3 sniffer.py --interface eth0
```

Try running without the permission pre-check:

```bash
python sniffer.py --skip-admin-check
```

## Example Output

```text
========================================================================
                    Packet Sniffer - Python + Scapy
========================================================================
Interface       : Default
Protocol filter : ALL
Packet limit    : Unlimited
Log file        : /path/to/packet-sniffer/logs.txt
------------------------------------------------------------------------
Press Ctrl+C to stop capturing packets.

[00001] 2026-05-15 10:30:41 | SRC: 192.168.1.10    -> DST: 142.250.190.14  | PROTOCOL: TCP
[00002] 2026-05-15 10:30:42 | SRC: 192.168.1.10    -> DST: 8.8.8.8         | PROTOCOL: UDP
[00003] 2026-05-15 10:30:43 | SRC: 192.168.1.1     -> DST: 192.168.1.10    | PROTOCOL: ICMP
[WARNING] Suspicious activity: 192.168.1.20 sent 20 packets in 10 seconds
```

## Screenshots

Add screenshots of the tool running here.

Suggested screenshots:

- Main terminal banner
- TCP filter example
- UDP filter example
- ICMP filter example
- Suspicious activity warning
- `logs.txt` output

Save screenshots in the `screenshots/` folder.

```text
screenshots/
|
+-- terminal-output.png
+-- suspicious-warning.png
```

## Code Explanation

### Imports

`sniffer.py` imports standard Python modules for command-line arguments, timestamps, operating system checks, file paths, and data structures. It also imports Scapy layers such as `IP`, `TCP`, `UDP`, and `ICMP`.

Colorama is used for colorful terminal output. If Colorama is missing, the program still works without colors.

### `PacketSniffer` Class

The `PacketSniffer` class stores the state of the running sniffer:

- selected protocol filter
- packet count
- network interface
- suspicious activity settings
- recent packet timestamps per source IP

Keeping this state inside a class makes the code easier to organize and expand.

### `identify_protocol()`

This function checks which protocol layer exists inside a packet.

```python
if packet.haslayer(TCP):
    return "TCP"
```

Scapy represents packets as layered objects. If a packet contains the TCP layer, the program labels it as TCP. The same idea is used for UDP and ICMP.

### `process_packet()`

This is the most important callback function in the project. Scapy calls it once for every captured packet.

It does four main things:

1. Skips packets that do not contain an IP layer
2. Extracts source IP and destination IP
3. Detects the protocol type
4. Prints and logs the formatted packet details

### `check_suspicious_activity()`

This function performs basic rate-based detection.

If the same source IP sends too many packets inside a short time window, the program prints a warning. This is a simplified example of how intrusion detection systems can look for unusual traffic patterns.

Example:

```text
[WARNING] Suspicious activity: 192.168.1.20 sent 20 packets in 10 seconds
```

### `start()`

The `start()` method begins live packet capture by calling Scapy's `sniff()` function.

```python
sniff(
    iface=self.interface,
    filter=bpf_filter,
    prn=self.process_packet,
    store=False,
    count=self.packet_limit,
)
```

`store=False` is important because it prevents Scapy from keeping every captured packet in memory. That makes the sniffer safer to run for longer periods.

## How Packet Sniffing Works

Packet sniffing is the process of capturing network packets as they move through a network interface. A packet is a small unit of network data. When you visit a website, send a message, or ping a server, your computer sends and receives packets.

A packet sniffer listens on a network interface and inspects packets that the operating system allows it to see. This can help security learners understand how devices communicate, how protocols behave, and how unusual traffic may appear.

## Why Administrator or Root Permissions Are Needed

Operating systems protect raw network access because packets can contain sensitive information. Without protection, any normal program could inspect network traffic.

For that reason, packet sniffing usually requires elevated privileges:

- Windows: run the terminal as Administrator
- Linux: run with `sudo`

On Linux, advanced users can also configure network capabilities such as `CAP_NET_RAW`, but `sudo` is the simplest option for beginners.

## How Scapy's `sniff()` Function Works

Scapy's `sniff()` function captures packets from a network interface.

Important parameters used in this project:

- `iface`: chooses the network interface, such as `eth0` or `Wi-Fi`
- `filter`: applies a packet filter before packets reach Python
- `prn`: tells Scapy which function to call for each packet
- `store`: decides whether Scapy keeps captured packets in memory
- `count`: stops after a certain number of packets

## What `prn` Does in Scapy

`prn` stands for the function that should process each packet.

In this project:

```python
prn=self.process_packet
```

That means every captured packet is passed into `process_packet(packet)`.

## What `filter` Does in Scapy

`filter` tells Scapy to capture only packets that match a rule. This project supports:

- `tcp`
- `udp`
- `icmp`

Example:

```python
filter="tcp"
```

This captures TCP packets only. Scapy uses BPF-style filters, similar to tools like tcpdump and Wireshark.

## Ethical Usage Disclaimer

This project is for education, portfolio building, and authorized security learning only.

Use it only on:

- your own computer
- your own lab network
- networks where you have clear written permission

Do not use this tool to monitor other people's traffic without permission. Unauthorized packet sniffing may violate privacy laws, workplace policies, school policies, or computer misuse laws.

## Portfolio Notes

This project demonstrates practical beginner-to-intermediate cybersecurity skills:

- Python scripting
- packet analysis
- protocol identification
- logging
- command-line tooling
- basic detection logic
- ethical security documentation

Possible future improvements:

- export logs to CSV or JSON
- add DNS detection
- add HTTP host extraction
- create a dashboard
- add unit tests for protocol detection logic
- integrate with Wireshark-compatible packet capture files
