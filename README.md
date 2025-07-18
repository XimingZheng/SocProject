# WebProbe: Lightweight Pentesting via Browser Extension

**Authors:**
 Deng Shuxin (BUPT)
 Zheng Ximing (SUSTech)
 Long Zelin (SCU)
 Ma Yingyun (SCU)
 **Date:** July 2025

## 🔍 Overview

**WebProbe** is a lightweight, real-time web vulnerability scanner built as a browser extension combined with a local Python-based backend. Unlike traditional scanners like ZAP or Burp Suite, WebProbe is designed to be:

- **Zero-config:** Just install the extension and run the backend
- **Real-time:** Get scanning results within seconds as you browse
- **Pluggable:** Easily extend with new vulnerability scanners

It enables both casual users and developers to detect security risks directly during their normal browsing experience.

## 🚀 Features

- 🧩 Modular scanners:
  - **HeaderScanner**: Security header inspection (CSP, HSTS, etc.)
  - **XSSScanner**: DOM-based XSS injection detection
  - **SQLInjectionScanner**: Error-based SQLi testing
  - **SSLScanner**: TLS/SSL configuration validation
- ⚖️ Risk scoring: Penalty-Based Scoring (PBS) model for intuitive risk feedback (Red/Orange/Green badge).
- 🔄 Three scanning modes:
  - Backend Mode (via Flask API)
  - Hybrid Mode (local + backend)
  - Local-only Fallback
- 🔐 Secure by design: Minimal permissions, localhost-only communication, no external exposure.

## 🧱 Architecture

```
pgsql复制编辑[Browser Extension] <---> [Local Flask Backend]
       ↑                        ↑
 Real-time headers       Async task manager
 DOM script injection     Modular scanners
```

- **Extension (Manifest V3):** Captures HTTP headers, injects scripts for CSP/meta-tag checks.
- **Backend (Python/Flask/AsyncIO):** Runs scanners concurrently with unique task IDs.
- **Communication:** JSON REST API over `localhost:5000`.

## 📦 Installation

### Prerequisites

- Python 3.8+
- Google Chrome
- Flask, aiohttp

### Backend Setup

```
bash复制编辑git clone https://github.com/your-repo/WebProbe.git
cd WebProbe/backend
pip install -r requirements.txt
python app.py
```

### Extension Setup

1. Open `chrome://extensions`
2. Enable "Developer Mode"
3. Click "Load unpacked" and select the `extension/` folder