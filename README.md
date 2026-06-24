# VulnScan

**A free, locally-run vulnerability scanner you download and use — no accounts, no subscriptions, no data sent anywhere.**

Built by Usman Zaffar as a portfolio project demonstrating real-world security tooling, network programming, and API integration.

---

## What It Does

VulnScan scans any IP address, URL, or hostname you give it and tells you:

- Which ports are open
- What software is running on them
- Whether that software has known security vulnerabilities (CVEs)
- Whether the target has been flagged as malicious by 90+ security vendors via VirusTotal
- An overall risk level — Critical, High, Medium, Low, or None

Everything runs locally on your machine. No cloud, no account required.

---

## Download

**[Download the latest installer →](https://github.com/yourusername/vulnscan/releases/latest)**

Runs on Windows 10 and above. No Python or technical setup required — just install and run.

---

## Getting Started

1. Download and run `VulnScanSetup.exe`
2. Follow the installer — takes about 30 seconds
3. Open VulnScan from your Start Menu or Desktop
4. *(Optional)* Add a free VirusTotal API key in Settings for reputation checks
5. Type in a target and click **Scan**

### Getting a Free VirusTotal API Key

1. Go to [virustotal.com](https://www.virustotal.com) and create a free account
2. Click your profile icon → API Key
3. Copy the key and paste it into VulnScan → Settings

The free tier gives you 500 requests per day — more than enough for normal use.

---

## What You Can Scan

| Target | Example |
|---|---|
| Your home router | `192.168.1.1` |
| Your VPS or server | `your-server-ip` |
| A domain you own | `yourdomain.com` |
| A URL | `https://yourdomain.com` |
| A file | Load via the Load File button |
| Practice targets | `scanme.nmap.org` (pre-loaded) |

> **Only scan systems you own or have explicit written permission to test.**
> Unauthorized scanning may violate computer fraud laws in your jurisdiction.
> VulnScan is built for legitimate security testing only.

---

## Features

**Scan Modes**
- Quick — 15 most common ports, results in seconds
- Full — ports 1 to 1024, standard security audit
- Deep — all 65535 ports, thorough sweep

**What Gets Checked**
- Open port discovery via threaded TCP scanning
- Service identification via banner grabbing
- CVE lookup against the National Vulnerability Database (NVD)
- CVSS risk scoring (0.0 to 10.0) for every vulnerability found
- VirusTotal reputation check across 90+ security vendors
- Combined risk level that accounts for both CVE severity and VT reputation

**Output**
- Live scan terminal showing results as they come in
- Color-coded findings table (Critical / High / Medium / Low)
- Click any row to see the full vulnerability description
- One-click PDF report export — professional enough to hand to a client
- Persistent scan history so you can track how a target's exposure changes over time

---

## Screenshots

*Add screenshots here after upload*

---

## How It Works

```
Target entered
      ↓
Phase 0  →  VirusTotal reputation check (90+ vendors)
Phase 1  →  Port scan (threaded TCP)
Phase 2  →  Service detection (banner grabbing)
Phase 3  →  CVE lookup (NVD API + CVSS scoring)
Phase 4  →  Risk assessment (combines VT + CVE findings)
      ↓
Findings table + PDF report
```

---

## Tech Stack

| Layer | Technology |
|---|---|
| Language | Python 3.11+ |
| GUI | tkinter |
| Port scanning | Python sockets + threading |
| CVE data | NVD API (nvd.nist.gov) |
| Reputation | VirusTotal API v3 |
| Database | SQLite (scan history) |
| Reports | fpdf2 (PDF generation) |
| Packaging | PyInstaller + Inno Setup |

---

## Building From Source

If you want to run or modify the code directly:

```bash
git clone https://github.com/yourusername/vulnscan.git
cd vulnscan
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python scanner.py
```

To build the installer yourself:

```bash
pip install pyinstaller
pyinstaller VulnScan.spec
# Then open VulnScanInstaller.iss in Inno Setup and press F9
```

---

## Legal

This tool is for authorized security testing only. The built-in legal notice requires acknowledgment on every launch.

The pre-loaded demo target `scanme.nmap.org` is maintained by the nmap team specifically for scanner testing. All other targets should only be scanned with proper authorization.

---

## Author

**Usman Zaffar**

Built as a portfolio project to demonstrate practical skills in network security, systems programming, API integration, and desktop application development.

---

*VulnScan is free and open source. If you find it useful, give it a star.*
