<div align="center">

<img src="assets/logo.png" alt="Windows Admin & Security Tool" width="180">

# Windows Admin & Security Tool

### A Modular Windows Administration & Cybersecurity Toolkit

A modern desktop application built with **Python** and **PySide6**, combining Windows administration, network monitoring, security analysis, encoding/decoding, payload management, and utility tools in a single interface.

![Python](https://img.shields.io/badge/Python-3.x-3776AB?style=for-the-badge&logo=python&logoColor=white)
![PySide6](https://img.shields.io/badge/PySide6-GUI-41CD52?style=for-the-badge&logo=qt&logoColor=white)
![Windows](https://img.shields.io/badge/Platform-Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white)

</div>

---

## Overview

**Windows Admin & Security Tool** is a modular Windows desktop toolkit designed to bring commonly used administration, networking, and security utilities into one centralized interface.

## Features

### 🖥️ System Tools

Manage and inspect common Windows system settings and information.

- Proxy management
- Local IP information
- Port inspection
- System utilities

### 🌐 Network Monitor

Monitor active network listeners and identify the processes responsible for them.

- TCP listening ports
- UDP listening ports
- Process ID (PID)
- Process name

### 🔎 Nmap Scanner

Perform fast network reconnaissance against authorized targets.

```bash
nmap -T4 -F -n --open
