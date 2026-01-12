# 🐱 Advanced Network Packet Analyzer - Cat Edition

<div align="center">

```
    /\_/\  
   ( o.o ) 
    > ^ <   
   /|   |\   
  (_|   |_)  
```
Advanced Network Packet Analyzer

Professional Network Analysis Tool

[![Python Version](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![PyShark](https://img.shields.io/badge/pyshark-required-orange.svg)](https://github.com/KimiNewt/pyshark)

**A professional network packet analysis tool with a cute cat twist! 🐱**

</div>

---

## 📋 Overview

Advanced Network Packet Analyzer is a powerful Python-based tool for capturing and analyzing network traffic. Built for cybersecurity professionals, students, and network enthusiasts, it combines robust functionality with a user-friendly interface (and adorable cat animations).

### ✨ Key Features

- **🎯 Multi-Protocol Support**: TCP, UDP, ICMP, HTTP, HTTPS, DNS
- **🔍 Advanced Filtering**: Capture specific traffic types with BPF filters
- **📊 Detailed Statistics**: Protocol distribution, top source/destination IPs
- **💾 Multiple Export Formats**: JSON, CSV, and TXT
- **🔎 Smart Search**: Search by IP, protocol, or port
- **🎨 Colorful CLI**: Beautiful colored output for better readability
- **🐱 Cat Animations**: Because packet analysis is better with cats!

---

## 🚀 Installation

### Prerequisites

1. **Python 3.7+**
2. **Wireshark/TShark** (required by PyShark)
3. **Administrator/Root privileges** (for packet capture)

### Install Wireshark/TShark

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install tshark
```

**macOS:**
```bash
brew install wireshark
```

**Windows:**
Download and install from [Wireshark Official Website](https://www.wireshark.org/download.html)

### Install Python Dependencies

```bash
pip install pyshark
```

---

## 📖 Usage

### Basic Usage

Run the analyzer with administrator privileges:

```bash
sudo python3 packet_analyzer.py
```

### Step-by-Step Guide

1. **Select Network Interface**
   - The tool will detect available interfaces
   - Choose the interface you want to monitor (e.g., eth0, wlan0)

2. **Choose Filter**
   - Select from predefined filters (TCP, UDP, HTTP, etc.)
   - Or capture all packets

3. **Set Packet Count**
   - Specify how many packets to capture
   - Default: 50 packets

4. **Analyze Results**
   - View packets in table format
   - Check detailed statistics
   - Search specific packets
   - Export data in your preferred format

---

## 🎮 Features Walkthrough

### 1️⃣ Packet Capture with Cat Animation

```
=^._.^= ∫ [🐱🐱🐱🐱·········] 20/50 (40.0%)
```

Real-time progress bar with animated cat watching your packets!

### 2️⃣ Beautiful Packet Table

View captured packets in a clean, organized table:
- Sequence number
- Source/Destination IP and MAC
- Port numbers
- Protocol
- Additional info

### 3️⃣ Comprehensive Statistics

- **Protocol Distribution**: See percentage breakdown of traffic types
- **Top 5 Source IPs**: Identify most active sources
- **Top 5 Destination IPs**: Find popular destinations

### 4️⃣ Advanced Search

Search packets by:
- Source IP address
- Destination IP address
- Protocol type
- Port number

### 5️⃣ Multiple Export Formats

Save your analysis in:
- **JSON**: For programmatic processing
- **CSV**: For spreadsheet analysis
- **TXT**: Human-readable reports

---

## 🎨 Filter Options

| Filter | Description | BPF Expression |
|--------|-------------|----------------|
| TCP | Transmission Control Protocol | `tcp` |
| UDP | User Datagram Protocol | `udp` |
| ICMP | Internet Control Message Protocol | `icmp` |
| HTTP | Web traffic (port 80) | `tcp port 80` |
| HTTPS | Secure web traffic (port 443) | `tcp port 443` |
| DNS | Domain Name System (port 53) | `udp port 53` |
| All | No filter applied | None |

---

## 📊 Example Output

### Statistics View
```
Protocol Distribution:
  TCP       :   35 packets ( 70.0%)
  UDP       :   10 packets ( 20.0%)
  ICMP      :    5 packets ( 10.0%)

Top 5 Source IPs:
  192.168.1.100   :   15 packets
  192.168.1.101   :   10 packets
```

---

## 🛠️ Troubleshooting

### Common Issues

**"Permission denied" error**
```bash
# Solution: Run with sudo/administrator privileges
sudo python3 packet_analyzer.py
```

**"No module named 'pyshark'"**
```bash
# Solution: Install pyshark
pip install pyshark
```

**"TShark not found"**
```bash
# Solution: Install Wireshark/TShark
# Ubuntu/Debian:
sudo apt-get install tshark

# macOS:
brew install wireshark
```

---

## 🔒 Security & Ethics

⚠️ **Important Notice**:
- Only capture traffic on networks you own or have explicit permission to monitor
- This tool is for educational and authorized security testing purposes only
- Unauthorized packet capture may be illegal in your jurisdiction
- Always respect privacy and follow applicable laws

---

## 🎓 Educational Use

This tool was developed for the **Topics in Cyber Security Programming** course and is perfect for:
- Learning network protocols
- Understanding packet structure
- Network troubleshooting
- Security analysis and penetration testing (authorized only)
- Cyber security research

---

## 🤝 Contributing

Contributions are welcome! Feel free to:
- Report bugs
- Suggest new features
- Submit pull requests
- Improve documentation

---

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

---

## 👨‍💻 Author

Created with ❤️ and 🐱 for cyber security education

---

## 🐾 Fun Facts

- The cat animation changes every few packets to keep you entertained
- Cat-themed progress bar because network analysis doesn't have to be boring
- The tool captures packets while a virtual cat "watches" them
- Over 9 different cat emoji variations used in the UI!

---

<div align="center">

### Made with 💙 for Packet Analysis and 🐱 for Cats

**If you found this tool helpful, give it a ⭐!**

</div>


















