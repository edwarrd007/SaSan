<div align="center">

<img src="assets/logo.png" alt="Windows Admin & Security Tool" width="180">

# Windows Admin & Security Tool

### A Modular Windows Administration & Cybersecurity Toolkit

A modern desktop application built with **Python** and **PySide6**, combining Windows administration, network monitoring, security analysis, encoding/decoding, payload management, and utility tools in a single interface.

<br>

![Python](https://img.shields.io/badge/Python-3.x-3776AB?style=for-the-badge\&logo=python\&logoColor=white)
![PySide6](https://img.shields.io/badge/PySide6-GUI-41CD52?style=for-the-badge\&logo=qt\&logoColor=white)
![Windows](https://img.shields.io/badge/Platform-Windows-0078D6?style=for-the-badge\&logo=windows\&logoColor=white)
![Cybersecurity](https://img.shields.io/badge/Focus-Cybersecurity-red?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)

</div>

---

## Overview

**Windows Admin & Security Tool** is a modular Windows desktop toolkit designed to bring commonly used administration, networking, and security utilities into one centralized interface.

The application provides tools for:

* System administration
* Network monitoring
* Nmap scanning
* Command execution
* DNS investigation
* Security data extraction
* JavaScript / JSFuck encoding
* Data encoding and decoding
* Payload management
* Music scanning and playback
* Time-zone monitoring

The application uses a dark **Cyber/Security-inspired interface** and executes resource-intensive operations through background workers to keep the GUI responsive.

---

## Features

### 🖥️ System Tools

Manage and inspect common Windows system settings and information.

* Proxy management
* Local IP information
* Port inspection
* System utilities

---

### 🌐 Network Monitor

Monitor active network listeners and identify the processes responsible for them.

* TCP listening ports
* UDP listening ports
* Process ID (PID)
* Process name
* Network endpoint information

---

### 🔎 Nmap Scanner

Perform fast network reconnaissance against authorized targets.

Default scan command:

```bash
nmap -T4 -F -n --open
```

Features:

* Host/IP scanning
* Fast scanning profile
* Open-port filtering
* Background execution
* Scan output display

> Only scan systems and networks that you own or have explicit authorization to test.

---

### ⚙️ Command Runner

Execute Windows commands directly from the application.

Features:

* Command execution
* Configurable timeout
* `stdout` capture
* `stderr` capture
* Background execution
* Output visualization

Example:

```powershell
ipconfig
```

```powershell
netstat -ano
```

---

### 🧬 DNS Tools

Run DNS utilities directly from the interface.

Supported tools include:

```text
nslookup
dig
```

Useful for DNS troubleshooting, investigation, and security analysis.

---

### 🔐 Security Text Extractor

Extract security-relevant indicators from arbitrary text.

Supported patterns include:

```text
URL
Domain
IPv4
Email
Hash
JWT
Path
```

Useful for analyzing:

* Logs
* HTTP responses
* Security reports
* Configuration files
* Console output
* Application data

---

### 🧪 JSFuck Encoder

Convert JavaScript into a JSFuck-style representation.

Designed for:

* JavaScript research
* Educational experimentation
* XSS research
* Encoding analysis

---

### 🔄 Codec Tool

Encode and decode commonly used data formats.

Supported formats include:

```text
Base64
URL Encoding
JWT Payload
```

Useful for inspecting encoded application data during development and security testing.

---

### 💣 Payload Lab

A local payload management interface for organizing security-testing payloads.

Features:

* Payload storage
* Categorization
* Search
* Payload preview
* JSON persistence

Payload data is stored locally in:

```text
payloads.json
```

---

### 🎵 Music Scanner

Scan a selected directory and detect supported audio files.

Supported formats include:

```text
MP3
WAV
FLAC
OGG
M4A
AAC
WMA
```

---

### ▶️ Music Player

Built-in playback controls for discovered audio files.

```text
Play
Pause
Stop
Next
Previous
```

---

### 🌍 Time Zone

Display the current time across multiple cities.

Example locations:

```text
Tehran
London
Tokyo
Istanbul
New York
```

---

### ⚡ Background Workers

Long-running operations are executed in separate threads to prevent the PySide6 interface from freezing.

Background operations include:

```text
Nmap Scanning
Command Execution
Directory Scanning
Network Operations
```

Architecture:

```text
GUI
 │
 ├── Main Thread
 │
 └── Background Workers
       ├── Scanner
       ├── Command Runner
       └── File Scanner
```

---

### 💾 JSON Storage

Local application data can be stored and restored using JSON.

Example:

```text
payloads.json
commands.json
music_library.json
```

This allows application data to persist between sessions.

---

## 🖼️ Screenshots

<div align="center">

<img src="assets/screenshots/dashboard.png" alt="Dashboard" width="900">

<br><br>

<img src="assets/screenshots/network-monitor.png" alt="Network Monitor" width="900">

<br><br>

<img src="assets/screenshots/nmap-scanner.png" alt="Nmap Scanner" width="900">

</div>

---

## 🏗️ Architecture

```text
Windows Admin & Security Tool
│
├── GUI
│   └── PySide6
│
├── System Tools
│   ├── Proxy Manager
│   ├── IP Information
│   └── Port Inspection
│
├── Network Tools
│   ├── Network Monitor
│   └── Nmap Scanner
│
├── Command Runner
│   ├── Command Execution
│   ├── Timeout Handler
│   └── Output Handler
│
├── DNS Tools
│   ├── nslookup
│   └── dig
│
├── Security Tools
│   ├── Text Extractor
│   ├── JSFuck Encoder
│   └── Codec
│
├── Payload Lab
│   └── payloads.json
│
├── Music
│   ├── Scanner
│   ├── Library
│   └── Player
│
├── Time Zone
│
└── Background Workers
    └── Threaded Operations
```

---

## 🚀 Installation

### Requirements

```text
Windows 10 / 11
Python 3.x
PySide6
```

Optional external tools:

```text
Nmap
dig
```

---

### Clone

```bash
git clone https://github.com/YOUR_USERNAME/windows-admin-security-tool.git

cd windows-admin-security-tool
```

### Create Virtual Environment

```bash
python -m venv venv
```

Activate:

```powershell
.\venv\Scripts\Activate.ps1
```

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Run

```bash
python main.py
```

---

## 📁 Project Structure

```text
windows-admin-security-tool/
│
├── main.py
├── requirements.txt
├── payloads.json
│
├── assets/
│   ├── logo.png
│   └── screenshots/
│       ├── dashboard.png
│       ├── network-monitor.png
│       ├── nmap-scanner.png
│       ├── payload-lab.png
│       └── music-player.png
│
├── modules/
│   ├── system_tools/
│   ├── network_monitor/
│   ├── nmap_scanner/
│   ├── command_runner/
│   ├── dns_tools/
│   ├── security_extractor/
│   ├── jsfuck_encoder/
│   ├── codec/
│   ├── payload_lab/
│   ├── music_scanner/
│   ├── music_player/
│   └── timezone/
│
└── workers/
    └── background_workers.py
```

---

## 🔐 Security & Responsible Use

This project contains functionality capable of interacting with systems, networks, and commands.

Use the application only in environments where you have explicit authorization.

Appropriate environments include:

* Personal systems
* Internal infrastructure
* Authorized penetration tests
* Security laboratories
* CTF environments
* Development environments
* Educational research

Do not use network scanning or command-execution functionality against systems without permission.

---

## 🎯 Roadmap

```text
[x] System Tools
[x] Network Monitor
[x] Nmap Scanner
[x] Command Runner
[x] DNS Tools
[x] Security Text Extractor
[x] JSFuck Encoder
[x] Codec Tool
[x] Payload Lab
[x] Music Scanner
[x] Music Player
[x] Time Zone
[x] Background Workers
[x] JSON Storage

[ ] Advanced Network Discovery
[ ] Process Analyzer
[ ] Windows Event Log Analyzer
[ ] Hash Identifier
[ ] HTTP Request Inspector
[ ] TLS / Certificate Inspector
[ ] File Hashing
[ ] PCAP Analyzer
[ ] Plugin System
[ ] Custom Security Modules
```

---

## 🛠️ Technology Stack

| Technology              | Purpose               |
| ----------------------- | --------------------- |
| Python                  | Core application      |
| PySide6                 | Desktop GUI           |
| Nmap                    | Network scanning      |
| JSON                    | Local persistence     |
| Threading               | Background operations |
| Windows APIs / Commands | System administration |

---

## 📌 Disclaimer

This project is intended for **educational, administrative, development, and authorized security-testing purposes**.

The author is not responsible for misuse, unauthorized scanning, unauthorized command execution, or any damage resulting from improper use of the software.

---

## 📜 License

This project is licensed under the **MIT License**.

See [`LICENSE`](LICENSE) for details.

---

<div align="center">

<img src="assets/logo.png" alt="Logo" width="100">

### Windows Admin & Security Tool

**Administration • Networking • Security • Utilities**

Built with Python & PySide6

</div>
