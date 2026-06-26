# VulnScan (Windows Installer and Runs Locally)

A free vulnerability scanner that runs entirely on your computer. No accounts, no subscriptions, no data sent to the cloud. Just download it, install it, and start scanning.
<img width="1111" alt="Scan Results" src="https://github.com/user-attachments/assets/656c0233-479a-465c-8191-7f377f441f83" />
---

## What It Does

VulnScan scans any IP address, URL, or hostname you give it and tells you:

- Which ports are open
- What software is running on them
- Whether that software has known security vulnerabilities (CVEs)
- Whether the target has been flagged as malicious by 90+ security vendors via VirusTotal
- An overall risk level, Critical, High, Medium, Low, or None

Everything runs locally on your machine. No cloud, no account required.

---

## Download

**[Download the latest installer →](https://github.com/73256Usman/vulnscan/releases/latest)**

Runs on Windows 10 and above. No Python or technical setup required. (Just install and run)

---

## Getting Started

1. Download and run `VulnScanSetup.exe`
2. Follow the installer, takes about 30 seconds
3. Open VulnScan from your Start Menu or Desktop
4. *(Optional)* Add a free VirusTotal API key in Settings for reputation checks
5. Type in a target and click **Scan**

### Getting a Free VirusTotal API Key

1. Go to [virustotal.com](https://www.virustotal.com) and create a free account
2. Click your profile icon → API Key
3. Copy the key and paste it into VulnScan → Settings

The free tier gives you 500 requests per day, more than enough for normal use.

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
- Quick → 15 most common ports, results in seconds
- Full → ports 1 to 1024, standard security audit
- Deep → all 65535 ports, thorough sweep

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
- One-click PDF report export, professional enough to hand to a client
- Persistent scan history so you can track how a target's exposure changes over time

---

## Screenshots

<br>

**Legal Notice**

Every launch requires acknowledgment 

<img width="457" alt="Legal Notice" src="https://github.com/user-attachments/assets/de21398f-f3aa-4ae8-bf53-5d7deac9e214" />

<br>

**Dashboard**

Clean dark interface with metric cards, live scan output, findings table, and history sidebar

<img width="1113" alt="App on Launch" src="https://github.com/user-attachments/assets/2354919e-3081-4db7-976c-bc530838a3b2" />

<br>

**Settings**

Users enter their own free VirusTotal API key, stored locally on their machine and never shared

<img width="493" alt="Settings" src="https://github.com/user-attachments/assets/72ba7291-10e4-427f-9eb2-3e4e8917229d" />

<br>

**Live Scan Results**

Real time output showing all four phases. VirusTotal check, port scan, service detection, and CVE lookup

<img width="1111" alt="Scan Results" src="https://github.com/user-attachments/assets/656c0233-479a-465c-8191-7f377f441f83" />

<br>

**Scan History**

Every scan is saved locally so you can track how a target's exposure changes over time

<img width="208" alt="Scan History" src="https://github.com/user-attachments/assets/94bf885d-ab89-49a9-a04f-51a4a8f9a5fc" />

<br>

**PDF Report**

One click export

<img width="789" alt="PDF Report" src="https://github.com/user-attachments/assets/ceaf0659-4f85-425a-8711-159504206ad9" />

<br>


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

---

*VulnScan is free and open source. If you find it useful, give it a star.*
