# Packet Counter

A simple network packet analyzer for Linux that captures packets, classifies them by protocol type (TCP, UDP, ICMP, Other), and displays statistics.

## Features

- Captures packets on a specified network interface using libpcap
- Counts packets by protocol type (TCP, UDP, ICMP, Other)
- Displays updated statistics every 5 seconds
- Runs for a specified duration or until terminated by CTRL+C
- Supports BPF filtering for targeted packet capture
- Memory efficient with proper memory management
- Includes comprehensive test suite

## Requirements

- Linux operating system
- libpcap development package
- gcc compiler

## Installation

### Install Dependencies

For Debian/Ubuntu-based systems:
```bash
sudo apt-get install libpcap-dev gcc make
```

For Red Hat/Fedora-based systems:
```bash
sudo dnf install libpcap-devel gcc make
```

### Building the Project

1. Clone or download this repository
2. Navigate to the project directory
3. Build the project:

```bash
make
```

This will create the `packet_counter` and `test_parser` executables.

## Usage

```bash
sudo ./packet_counter -i <interface> [-f <filter>] [-t <seconds>]
```

Where:
- `-i <interface>`: Network interface to capture from (required)
- `-f <filter>`: BPF filter expression (optional)
- `-t <seconds>`: Duration to run in seconds (optional, default: run until CTRL+C)

Example:
```bash
sudo ./packet_counter -i wlp3s0 -f "tcp port 80 or tcp port 443" -t 30
```

Note: Root privileges (sudo) are required to capture packets on network interfaces.

## Testing

Run the test suite with:
```bash
make test
```

This will run the provided test cases to verify the packet parser functionality.

## Output

The program displays real-time statistics about captured packets:
- Total number of packets captured
- Count and percentage of TCP packets
- Count and percentage of UDP packets
- Count and percentage of ICMP packets
- Count and percentage of other packet types
- Memory usage statistics

## License

This project is open-source software.
