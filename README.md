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
![WhatsApp Image 2025-05-20 at 22 05 37_aaf906b1](https://github.com/user-attachments/assets/0b1fa4e7-6af8-4b3a-8b21-7bab10478072)

![WhatsApp Image 2025-05-20 at 22 06 04_1af6aab8](https://github.com/user-attachments/assets/42a4bc4c-a881-4ec8-91f7-1e0ec3bd221e)

![WhatsApp Image 2025-05-20 at 22 06 49_5c9240d0](https://github.com/user-attachments/assets/be6c4046-eb9e-4b3f-bbd8-2cb7bcf471ff)

![WhatsApp Image 2025-05-20 at 22 07 18_4ba78a66](https://github.com/user-attachments/assets/7dea7025-71bd-4a67-9e76-6af671948af7)

![WhatsApp Image 2025-05-20 at 22 07 56_a97c5e29](https://github.com/user-attachments/assets/384a77c7-8d69-4ce2-8f7c-aa37ec9fe474)

![WhatsApp Image 2025-05-20 at 22 08 19_8a370c24](https://github.com/user-attachments/assets/ed23dd9f-e4f0-40e9-b595-1b0a3751b9c0)

![WhatsApp Image 2025-05-20 at 22 08 40_684fc639](https://github.com/user-attachments/assets/2d17ae60-3e50-42fa-ad63-0997a8020718)


## License

This project is open-source software.
