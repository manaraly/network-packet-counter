# network-packet-counter
Key Goals:
Capture packets on a specified interface using libpcap

Classify each packet as TCP, UDP, ICMP, or Other

Display packet counts every 5 seconds

Allow filtering via BPF (optional -f)

Support duration of capture via -t or terminate with Ctrl+C
# Packet Counter

A simple C-based tool that captures and analyzes network packets, classifies them by protocol, and provides basic statistics.

## 📁 File Structure

File Structure:
```bash

packet_counter/
├── main.c               # Entry point, handles CLI args and capture loop
├── packet_parser.c      # Contains logic to parse packets and update stats
├── packet_parser.h      # Declarations of parsing/statistics functions
├── test_parser.c        # Unit tests for protocol classification
├── Makefile             # Build configuration
└── README.md            # How to build and run
