#PRODIGY_CY_05
# Network Packet Analyzer

This project is a network packet analyzer implemented in Python. It captures and analyzes network packets, providing detailed information about Ethernet frames, IPv4 packets, ICMP packets, TCP segments, and UDP segments.

## Features

- Capture network packets from various interfaces.
- Display detailed information about Ethernet frames, including MAC addresses and protocol types.
- Decode and print information about IPv4 packets, including source and destination IPs, TTL, and protocols.
- Analyze and display ICMP packet details such as type, code, and checksum.
- Decode TCP segments, including source and destination ports, flags, and sequence numbers.
- Display UDP segment details, including source and destination ports and length.

## Requirements

- Python 3.x

## Installation

1. **Clone the Repository:**

    ```sh
    git clone https://github.com/yourusername/prajit07-PRODIGY_CY_05.git
    cd prajit07-PRODIGY_CY_05
    ```

2. **Install Dependencies:**

    This project does not require any external dependencies. It uses Python's built-in libraries.

## Usage

1. **Run the Script:**

    ```sh
    sudo python3 network_analyser.py
    ```

    Note: Ensure you run the script with administrative privileges to capture packets.

2. **Enter the Number of Packets to Capture:**

    The script will prompt you to enter the number of packets to capture. Enter `0` to capture packets indefinitely.

3. **Stop the Capture:**

    Press `Ctrl+C` to stop the packet capture.
