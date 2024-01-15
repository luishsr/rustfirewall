# Simple Firewall in Rust

## Overview
This project is a step-by-step guide to building a simple, command-line firewall application in Rust. It allows users to define rules for accepting or dropping incoming network packets based on specified criteria.

## Prerequisites
Before you begin, ensure you have Rust installed on your system. Follow the [Rust Installation Guide](https://www.rust-lang.org/tools/install) for guidance.

## Getting Started
Clone this repository and navigate into the project directory:

    git clone [URL to your repository]
    cd rust_firewall

## Features
- **Rule Definition**: Define rules based on source IP, destination port, and other criteria.
- **Rule Management**: Add, remove, and list firewall rules.
- **Iptables Integration**: Update iptables based on defined rules.
- **Command-Line Interface**: Easy-to-use CLI for managing the firewall.
- **Packet Processing**: Process incoming packets and apply rules.
- **Logging**: Log accepted and dropped packets for monitoring.
- **Error Handling**: Gracefully handle errors and provide informative messages.

## Contributing
Contributions to this project are welcome. Please submit a pull request or open an issue to suggest improvements.

## License
This project is licensed under the MIT License.
