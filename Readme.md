# 🌙 Lume

**Lume** is a minimalist, modular **browser forensics toolkit** written in Go.  
It illuminates hidden traces left behind by Chromium-based browsers — extracting artifacts such as **cookies, passwords, history, downloads, and bookmarks**, all neatly formatted in JSON for forensic analysis or research.

> _“Lume reveals what hides beneath the surface.”_

---

## Key Features

- 🔍 **Comprehensive Artifact Extraction**
  - Browser **History**, **Downloads**, **Bookmarks**, **Cookies**, **Saved Passwords**
- 🔐 **Advanced Decryption**
  - Supports **DPAPI** and **App-Bound Encryption (ABE)** on modern Chromium browsers
  - Works on **Windows 11** and compatible with Chrome v139+
- 👥 **Multi-Profile Support**
  - Automatically detects and scans all user profiles
- 📄 **Clean JSON Output**
  - Structured, indented files for easy analysis
- ⚡ **Modular & Extensible**
  - Each extractor works independently or as part of a full pipeline
- 🧩 **Cross-Browser Support**
  - Chrome, Edge, Brave, Opera, Chromium, and easily extendable

---

## Installation

### Prerequisites

- Go **1.22+**
- Windows 11 or Linux (with appropriate Chromium paths)
- Optional: SQLite support for direct database access

### Build from Source

```bash
git clone https://github.com/username/lume.git
cd lume
go build -o lume /cmd/main.go
```
