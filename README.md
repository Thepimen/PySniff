# 🕵️ PySniff v3: Intelligent Network Analyzer

> *"A cross-platform packet sniffer that translates raw binary network traffic into human-readable data using Raw Sockets and Struct Unpacking."*

[![Language](https://img.shields.io/badge/Python-3.x-blue?style=for-the-badge&logo=python)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey?style=for-the-badge&logo=linux)](https://github.com/Thepimen)
[![Type](https://img.shields.io/badge/Category-Network_Forensics-red?style=for-the-badge&logo=wireshark)]()

---

## 📖 Overview

**PySniff v3** is a CLI-based network analysis tool designed to bridge the gap between low-level packet capture and high-level protocol understanding. Unlike standard sniffers that dump hex code, PySniff includes an **internal translation engine** that maps protocol numbers and ports to known services (e.g., Identifying Port 443 as HTTPS).

It operates at **Layer 3 (Network)** and **Layer 4 (Transport)** of the OSI model, with basic **Layer 7 (Application)** inspection to detect HTTP traffic.

---

## ⚙️ Technical Features

### 1. 🧠 Intelligent Translation Engine
Instead of displaying raw integers, the tool utilizes dictionary mapping to identify:
* **Protocols:** TCP, UDP, ICMP.
* **Common Services:** FTP, SSH, DNS, HTTP/HTTPS, MySQL, RDP, etc.
* **TCP Flags:** Translates bitwise flags into status messages (e.g., `SYN` -> "INITIATING CONNECTION").

### 2. 📦 Deep Packet Inspection (DPI)
* **Payload Analysis:** The tool attempts to decode the data payload from ASCII/UTF-8.
* **HTTP Detection:** Automatically identifies web traffic keywords (`GET`, `POST`, `HTTP/`) and formats the output for readability.

### 3. 🛡️ Security Alerts
* **SYN Scanning Detection:** Flags packets that attempt to initiate connections without completing the handshake.
* **RST Flag Monitoring:** Alerts on abrupt connection resets, which can indicate firewall blocking or service crashes.

---

## 🛠️ Architecture

The tool bypasses the Operating System's network stack using **Raw Sockets**:

```python
# Windows Implementation (Promiscuous Mode via IOCTL)
conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

# Linux Implementation (AF_PACKET)
conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
