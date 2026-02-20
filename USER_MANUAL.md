<div align="center">

<img src="assets/pcap_sentry.ico" alt="PCAP Sentry" width="96" />

# PCAP Sentry

### User Manual

![Version](https://img.shields.io/badge/Version-Date_Based_(YYYY.MM.DD)-58a6ff?style=for-the-badge&labelColor=0d1117)
![Platform](https://img.shields.io/badge/Platform-Windows-58a6ff?style=for-the-badge&logo=windows&logoColor=white&labelColor=0d1117)
![License](https://img.shields.io/badge/License-GPL_v3-58a6ff?style=for-the-badge&labelColor=0d1117)

*Learn Malware Network Traffic Analysis — Beginner-Friendly Educational Tool*

</div>

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [System Requirements](#2-system-requirements)
3. [Installation](#3-installation)
4. [Getting Started](#4-getting-started)
5. [Application Interface](#5-application-interface)
6. [Analyzing PCAP Files](#6-analyzing-pcap-files)
7. [Understanding Results](#7-understanding-results)
8. [Training the Knowledge Base](#8-training-the-knowledge-base)
9. [Managing the Knowledge Base](#9-managing-the-knowledge-base)
10. [Threat Intelligence](#10-threat-intelligence)
11. [Machine Learning Model](#11-machine-learning-model)
12. [Visual Charts](#12-visual-charts)
13. [Preferences & Settings](#13-preferences--settings)
14. [Updating PCAP Sentry](#14-updating-pcap-sentry)
15. [Troubleshooting](#15-troubleshooting)
   - [LLM Server Management (from Preferences)](#llm-server-management-from-preferences)
16. [Testing & Quality Assurance](#16-testing--quality-assurance)
17. [Known Limitations & Disclaimer](#17-known-limitations--disclaimer)
18. [FAQ](#18-faq)
19. [Appendix](#19-appendix)

---

<h2><img src="https://img.shields.io/badge/1-Introduction-58a6ff?style=flat-square&labelColor=0d1117" height="28" /></h2>

**PCAP Sentry is a beginner-friendly educational tool for learning to identify malware network traffic patterns.** It analyzes network packet captures (`.pcap` / `.pcapng`) and teaches you how to recognize suspicious activity with clear explanations and hands-on practice.

### What You'll Learn

**🎓 Malware Network Traffic Analysis**
- **Understand suspicious patterns** — Learn what makes network traffic malicious
- **Risk scoring (0–100)** — Discover which behaviors indicate threats
- **Behavioral detection** — Identify beaconing, DNS tunneling, port scanning, data exfiltration
- **Real-world threat intel** — See how security researchers flag malicious IPs, URLs, and domains
- **AI-powered guidance** — Ask questions and get plain-language explanations via local LLM chat

**🔍 Hands-On Analysis Tools**
- **Credential extraction** — Discover how attackers steal passwords from unencrypted protocols
- **C2 pattern detection** — Learn to spot command-and-control communication
- **Wireshark integration** — Generate filters for deeper packet investigation
- **Trainable knowledge base** — Build your own malware signature library as you learn
- **Pre-trained ML model** — Ships with a RandomForest baseline trained on 13 traffic profiles; accuracy improves as you label your own captures

**🛡️ Safe & Practical**
- **Works offline** — Practice with local models and threat databases
- **Privacy-first** — Optional cloud features, nothing shared without permission
- **Secure by design** — Built with best practices for handling untrusted network data

### Who Is It For?

- **Beginners** learning malware network traffic analysis
- **Students** studying cybersecurity and network forensics
- **Security analysts** performing network forensics
- **SOC teams** triaging alerts
- Anyone who wants to understand how to identify malicious network activity

---

<h2><img src="https://img.shields.io/badge/2-System_Requirements-58a6ff?style=flat-square&labelColor=0d1117" height="28" /></h2>

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| **OS** | Windows 10 (64-bit) | Windows 10/11 (64-bit) |
| **RAM** | 4 GB | 8 GB or more |
| **Disk Space** | 200 MB | 1 GB+ (KB backups, ML model, updates, PCAP working copies) |
| **Display** | 1280×720 | 1920×1080 or higher |
| **Internet** | Optional | Broadband (6 concurrent TI lookups, update checks) |
| **Runtime** | VC++ Redistributable 2015+ | Included with installer |

### Optimal System Requirements

For the best experience — especially with large captures and local LLM:

| Requirement | Optimal | Why |
|-------------|---------|-----|
| **OS** | Windows 11 (64-bit) | Best DPI scaling and Win32 support |
| **CPU** | 4+ cores | Multithreaded analysis, 6 concurrent TI workers, behavioral heuristics |
| **RAM** | 16 GB | High-memory mode loads full PCAP + pandas DataFrame + matplotlib charts. Large PCAPs (500 MB+) with LLM can peak at 10–12 GB |
| **Disk** | 1 GB+ | App ~50 MB, but KB backups + ML model + update downloads + PCAP working copies add up |
| **Display** | 1920×1080 | 4 main tabs + 5 result sub-tabs + charts window; lower res clips the UI |
| **Network** | Broadband | 6 concurrent TI API calls + update checks + LLM cloud endpoints |

### With Local LLM (Ollama)

If using a local LLM, additional resources are needed on top of the base requirements:

| Resource | Recommended | Notes |
|----------|-------------|-------|
| **RAM** | 16–32 GB | 7B models need ~5 GB, 14B models need ~10 GB, on top of app usage |
| **GPU** | Optional | Ollama uses GPU if available for faster inference; not required |
| **Disk** | +4–10 GB per model | Each model is downloaded and stored locally |

> **Note:** GPU is **not** needed for PCAP analysis itself — the RandomForest classifier is CPU-only and matplotlib renders to bitmap. SSD vs. HDD also makes little difference since parsing is CPU-bound, not I/O-bound.

### For Running from Source (Developers)

| Requirement | Version |
|-------------|---------|
| Python | 3.14 or newer |
| pandas | ≥ 2.0 |
| scapy | ≥ 2.5 |
| matplotlib | ≥ 3.8 |
| numpy | ≥ 1.26 |
| scikit-learn | ≥ 1.4 |
| joblib | ≥ 1.3 |
| Pillow | ≥ 10.0 |
| requests | ≥ 2.31 |
| tkinterdnd2 | ≥ 0.3.0 (optional, for drag-and-drop) |

---

<h2><img src="https://img.shields.io/badge/3-Installation-58a6ff?style=flat-square&labelColor=0d1117" height="28" /></h2>

### Option 1: Installer (Recommended)

1. Download **PCAP_Sentry_Setup.exe** from the [Releases](https://github.com/retr0verride/PCAP-Sentry/releases) page.
2. Run the installer and follow the on-screen prompts.
3. Choose an installation directory (default: `C:\Program Files\PCAP Sentry`).
4. Optionally create a desktop shortcut.
5. Launch PCAP Sentry from the **Start Menu** or **desktop shortcut**.
6. To set up a local LLM server, open **Preferences** and click **Manage LLM Servers…** (see [LLM Server Management](#llm-server-management-from-preferences)).

### Option 2: Run from Source

1. Clone the repository:
   ```
   git clone https://github.com/retr0verride/PCAP-Sentry.git
   ```
2. Install Python 3.14 or newer from [python.org](https://www.python.org/).
3. Create and activate a virtual environment:
   ```
   python -m venv .venv
   .venv\Scripts\activate.bat
   ```
4. Install dependencies:
   ```
   pip install -r requirements.txt
   ```
5. Run the application:
   ```
   python Python/pcap_sentry_gui.py
   ```

> **Note:** Only one instance of PCAP Sentry can run at a time. The application enforces single-instance mode via a Windows mutex.

---

<h2><img src="https://img.shields.io/badge/4-Getting_Started-58a6ff?style=flat-square&labelColor=0d1117" height="28" /></h2>

### First Launch

When you launch PCAP Sentry for the first time, the application opens to the **Analyze** tab. The interface consists of:

- A **header banner** with the application name and version
- A **toolbar** with analysis controls and preferences
- **Four main tabs**: Analyze, Train, Knowledge Base, and Chat

### Quick Start: Analyzing Your First PCAP

1. Click the **Browse** button next to "Target PCAP" (or drag-and-drop a file).
2. Select a `.pcap` or `.pcapng` file.
3. Click the **🔍 Analyze** button.
4. Wait for the analysis to complete (a progress indicator and cancel button are shown).
5. Review the results across the five results sub-tabs.

---

<h2><img src="https://img.shields.io/badge/5-Application_Interface-58a6ff?style=flat-square&labelColor=0d1117" height="28" /></h2>

### Main Tabs

PCAP Sentry has four primary tabs:

| Tab | Purpose |
|-----|--------|
| 🔍 **Analyze** | Select and analyze PCAP files, view results |
| 🧠 **Train** | Add known-safe or known-malware PCAPs to the knowledge base |
| 📚 **Knowledge Base** | Manage the KB: refresh, backup, restore, reset, import IoC feeds |
| 💬 **Chat** | Ask questions about current analysis results and general cybersecurity topics (requires an LLM) |

### Toolbar

The toolbar appears below the header and contains:

| Control | Description |
|---------|-------------|
| **Max packets for visuals** | Sets the maximum number of packets loaded for charts and the packet table (does **not** affect analysis accuracy). Range: 10,000–500,000. |
| **Parse HTTP payloads** | When checked, extracts HTTP request details (method, host, path) from unencrypted traffic. |
| **⚙ Preferences** | Opens the Preferences dialog for advanced settings. |
| **Check for Updates** | Checks GitHub for newer versions of PCAP Sentry. |

> **Tip:** Many controls throughout the interface display a **?** icon. Hover over it to see a tooltip explaining the feature.

### Header Indicators

The header bar displays:

| Indicator | Meaning |
|-----------|----------|
| **✔ LLM** (green) | LLM connection tested and working |
| **✔ LLM** (blue) | LLM auto-detected on startup |
| **✘ LLM** (red) | LLM connection test failed |
| **● LLM** (yellow) | LLM connection test in progress |
| **○ LLM** (gray) | LLM enabled but not yet tested |
| **LLM: off** (gray) | LLM features are disabled |

> **Tip:** Click the LLM indicator to run a connection test at any time.

### Supported File Types

| Format | Description |
|--------|-------------|
| `.pcap` | Standard packet capture format |
| `.pcapng` | Next-generation packet capture format |

---

<h2><img src="https://img.shields.io/badge/6-Analyzing_PCAP_Files-58a6ff?style=flat-square&labelColor=0d1117" height="28" /></h2>

### Step-by-Step Analysis

1. **Select a file** — Use any of these methods:
   - Click **Browse** and navigate to your PCAP file
   - Type or paste a file path into the Target PCAP field
   - **Drag and drop** a file onto the Analyze tab

2. **Configure options** (optional):
   - Adjust **Max packets for visuals** if working with very large captures
   - Toggle **Parse HTTP payloads** to extract/skip HTTP details

3. **Click 🔍 Analyze** — The analysis begins in the background:
   - A progress indicator shows the current phase
   - A **Cancel** button is available to stop the analysis
   - The UI remains responsive during analysis

4. **Analysis phases:**
   - **Parsing** — Reads packets using turbo parse (fast raw bytes) or Scapy
   - **Credential extraction** — Scans for cleartext authentication data
   - **Feature extraction** — Computes 25 network behavior metrics
   - **Behavioral heuristics** — Detects beaconing, DNS tunneling, port scanning, data exfiltration, and SYN floods
   - **Scoring** — Compares against the knowledge base using heuristics
   - **Threat intelligence** — Concurrent queries against ThreatFox, GreyNoise (no API key needed), URLhaus, AbuseIPDB, OTX, and VirusTotal (API keys optional for higher limits)
   - **ML classification** — Runs the local RandomForest model (ships pre-trained; improves as you label captures)

5. **Review results** across the five sub-tabs (see [Understanding Results](#7-understanding-results)).

### Post-Analysis Actions

After analysis completes, you can:

- **Mark as Safe / Mark as Malicious** — Quick-label buttons on the **Analyze** tab add this PCAP's features to the knowledge base immediately
- **Undo Last** — Revert the most recent KB addition if you labelled by mistake
- **Open Charts** — Launch the visual charts window with 7 chart types
- **Copy Wireshark Filters** — Copy auto-generated Wireshark display filters to the clipboard (found in the **Why** sub-tab)
- **File → Export Results as JSON** — Save the full analysis output (verdict, risk score, threat intel findings, suspicious flows, Wireshark filters) as a JSON file for archiving or external processing

> **Tip:** Right-click anywhere in the Results, Why, or Education text panels to access **Copy** and **Select All** context menu options.

---

<h2><img src="https://img.shields.io/badge/7-Understanding_Results-58a6ff?style=flat-square&labelColor=0d1117" height="28" /></h2>

Results are displayed across **five sub-tabs** within the Analyze tab:

### 7.1 Results Tab

The primary results view shows:

- **Risk Score** — A value from 0 to 100 indicating the likelihood of malicious activity
- **Verdict** — A plain-language assessment:
  - **Safe** — Low risk, likely benign traffic
  - **Suspicious** — Medium risk, warrants investigation
  - **Malicious** — High risk, likely contains malicious activity
- **Flow Summary Table** — Network conversations grouped by source/destination IP and port, showing packet count, bytes transferred, and duration

### Risk Score Interpretation

| Score Range | Verdict | Action |
|:---:|:---:|---|
| ![Safe](https://img.shields.io/badge/0--30-Safe-3fb950?style=flat-square&labelColor=0d1117) | ✅ Safe | Likely legitimate traffic; no immediate action needed |
| ![Suspicious](https://img.shields.io/badge/30--70-Suspicious-d29922?style=flat-square&labelColor=0d1117) | ⚠️ Suspicious | Requires further investigation |
| ![Malicious](https://img.shields.io/badge/70--100-Malicious-f85149?style=flat-square&labelColor=0d1117) | 🔴 Malicious | Likely malicious; escalate and investigate |

### 7.2 Why Tab

Provides the analytical reasoning behind the verdict:

- **Evidence breakdown** — Lists specific indicators that contributed to the score
- **Heuristic signals** — Details each detection trigger and its weight
- **Behavioral anomalies** — Summarizes detected patterns (beaconing, DNS tunneling, port scanning, data exfiltration, SYN floods, malware port usage)
- **Threat intelligence details** — Shows ThreatFox, GreyNoise, AbuseIPDB, OTX, and URLhaus findings inline where available
- **Wireshark filter generation** — Auto-generates display filters you can paste directly into Wireshark
- **Copy Wireshark Filters** button — Copies all generated filters to the clipboard

### 7.3 Education Tab

Designed for beginners and learning purposes. After every analysis, the Education tab builds a personalised guide from the actual flows found in the capture.

#### Malware Activity Summary

The first section immediately below the verdict and risk score is the **MALWARE ACTIVITY SUMMARY**, which classifies every suspicious flow from the capture into one of three categories:

| Category | What it means | Example trigger |
|----------|--------------|----------------|
| `[C&C]` | Command & control — the malware calling home | Beaconing pattern, known-malicious destination IP, unusual port |
| `[EXFIL]` | Data stolen from the host | High-volume outbound transfer (≥ P95 of all flows *and* ≥ 100 KB) |
| `[SPREAD]` | Malware spreading to other machines | Traffic to SMB (445), RDP (3389), WMI (135), SSH (22) |

Each flow entry shows the source IP → destination IP, port/protocol, byte volume, and a Wireshark display filter you can paste directly.

#### Plain-Language Stolen-Data Inference

For every `[EXFIL]` flow, PCAP Sentry infers in plain language what type of data was likely stolen:

- **Port-based hints** — 23 well-known ports are mapped to human-readable explanations:
  - Port 21 → *FTP — username + password sent in plaintext before file transfer*
  - Port 80 → *HTTP — UNENCRYPTED: Follow → TCP Stream to read raw stolen content*
  - Port 443 → *HTTPS — encrypted: likely credentials, saved passwords, files, or screenshots*
  - Port 25 → *SMTP — email messages + attachments being sent out*
  - Port 1433 → *MSSQL — database records (user tables, passwords, financial data)*
  - … and 18 more
- **Domain signals** — If the capture contacted a known stealer drop-point, it is called out by name:
  - Discord webhooks → *RedLine/Lumma/Vidar stealer drop for credentials + cookies*
  - Telegram Bot API → *stealers DM stolen credentials directly to the attacker*
  - Paste sites (Pastebin, paste.ee, Hastebin) → *malware dumping stolen text as a public paste*
  - Anonymous file hosts (transfer.sh, gofile.io) → *uploading stolen documents or archive files*
  - ngrok tunnels → *malware hiding real C2 behind a reverse proxy*
  - AWS S3, Google Cloud Storage, Dropbox, OneDrive, GitHub Gist

A five-step guide explains how to read the raw stolen content in Wireshark, including Base64 blob searching and TLS decryption via `SSLKEYLOGFILE`.

#### Six-Phase Malware Traffic Analysis Methodology

The rest of the Education tab walks through a structured six-phase approach used by professional malware analysts:

| Phase | Goal |
|-------|------|
| **1 — Filter & Orient** | Reduce noise; identify internal hosts, protocols, and external destinations |
| **2 — Inspect Headers & Payloads** | Read HTTP requests, follow TCP streams, decode Base64 payloads |
| **3 — Identify C&C Communication** | Find beaconing (regular interval callbacks), known-malicious IPs, unusual ports |
| **4 — Identify Data Exfiltration** | Detect large outbound transfers, HTTP POSTs, DNS tunneling, ICMP tunneling |
| **5 — Identify Spreading** | Find SMB/RDP/WMI/SSH lateral movement and network scanning |
| **6 — Identify the Infected Client** | Extract hostname and username from DHCP Option 12, NetBIOS, Kerberos `CNameString`, NTLM `ntlmssp.auth.username`, SMB Session Setup, HTTP `User-Agent`, LDAP `sAMAccountName` |

Each phase generates **dynamic content** from the actual flows in the current capture — for example, Phase 6 produces a per-IP block of Wireshark filters for every internal source IP found in suspicious flows.

#### Other Education Tab Content

- **Plain-English verdict explanation** — Why the current verdict was reached
- **Risk score breakdown** — How the weighted combination of ML, anomaly, and IoC checks contributes to the 0–100 score
- **What was found** — Dynamic summary of top ports, DNS queries, TLS SNI names, and flagged IPs with context
- **MITRE ATT&CK technique IDs** — Each attack pattern links to the relevant ATT&CK technique (e.g., T1071.001 for Application Layer Protocol)
- **Technical deep-dives** — How each attack pattern works at the protocol level
- **Common malware families** — Real-world malware known to use each technique
- **Host investigation steps** — What to look for on the affected machine
- **Remediation guidance** — How to contain and recover from the identified threat
- **External learning links** — MITRE ATT&CK, SANS, CISA, and vendor research pages
- **Threat intelligence details** — ThreatFox and other TI findings embedded inline with the relevant pattern explanation

### 7.4 Packets Tab

A full, filterable packet table:

- Browse individual packets from the capture
- **Column management** — Right-click column headers to show/hide columns or change alignment (single column or all at once)
- **Click any column header** to sort ascending/descending (sort arrows ▲/▼ indicate direction)
- **C2/Exfiltration hints** — Packets flagged with potential Command & Control or data exfiltration indicators
- Scrollable with mouse wheel support

#### Packet Filters

The Packets tab includes a **Packet Filters** panel to isolate specific traffic:

| Filter | Description |
|--------|-------------|
| **Protocol** | Dropdown: Any, TCP, UDP, or Other |
| **Src IP / Dst IP** | Filter by source or destination IP address |
| **Src Port / Dst Port** | Filter by source or destination port number |
| **Time (s)** | Min/max time range in seconds from the start of the capture |
| **Size (bytes)** | Min/max packet size in bytes |
| **DNS/HTTP only** | Show only DNS lookups and HTTP requests |

Click **Apply** to filter the table, or **Reset** to clear all filters.

### 7.5 Extracted Info Tab (🔑)

Displays credentials and host information found in cleartext traffic:

#### Key Findings

A summary panel at the top highlights the most important discoveries, color-coded for quick scanning:

| Color | Meaning |
|-------|--------|
| 🟦 Blue | Usernames |
| 🟥 Red | Passwords |
| 🟩 Green | Computer / host names |

#### Credentials
Extracted authentication data from cleartext protocols including:
- FTP usernames and passwords
- HTTP basic/digest authentication
- SMTP, POP3, IMAP credentials
- Telnet login sequences
- SNMP community strings
- Kerberos ticket data

**Copy All** button copies all credentials as tab-separated text.

The credentials table has columns: **Type**, **Protocol**, **Source**, **Destination**, **Value**, and **Detail**. Rows are color-coded: red for passwords, blue for usernames, green for computer names, and yellow for cookies/tokens.

#### Host Discovery
Network hosts identified from:
- IP addresses (source and destination)
- MAC addresses
- Computer names (from DNS, DHCP, SMTP EHLO, NetBIOS)

**Copy All** button copies all host information to the clipboard.

The host table has columns: **IP Address**, **MAC Address(es)**, and **Computer / Hostname**. Rows with resolved hostnames are highlighted in green.

> **⚠ Security Note:** Credential extraction only works on unencrypted (cleartext) traffic. Encrypted protocols (HTTPS, SSH, etc.) cannot be decoded without the appropriate keys.

---

<h2><img src="https://img.shields.io/badge/8-Training_the_Knowledge_Base-58a6ff?style=flat-square&labelColor=0d1117" height="28" /></h2>

The **Train** tab allows you to teach PCAP Sentry what safe and malicious traffic looks like, improving its detection accuracy over time. PCAP Sentry ships with a pre-trained RandomForest baseline model (trained on 13 synthetic traffic profiles) so the local ML model works from day one — no labeling required to get started. Every capture you label is merged with that baseline on the next retrain, so accuracy improves with use.

### Quick-Labeling the Current Analysis

The fastest way to add a capture to the knowledge base is directly from the **Train** tab after running an analysis:

1. Run an analysis on the **Analyze** tab.
2. Navigate to the **Train** tab.
3. The **Label Current Analysis** panel at the top shows the loaded file name, verdict, and risk score.
4. Click one of the three buttons:
   - **✓ Label as Safe** — Immediately adds the already-parsed features as a safe sample
   - **? Label as Unsure** — Flags for later review without training the model
   - **✗ Label as Malicious** — Immediately adds the features as a malicious sample
5. No re-parsing occurs — the features extracted during analysis are reused directly.

### Adding Safe Samples (PCAP file)

1. Navigate to the **Train** tab.
2. In the **Known Safe PCAP** section, click **Browse** or drag-and-drop a PCAP file.
3. Click **Add to Safe**.
4. The application parses the file, extracts its network features, and stores them in the knowledge base as a safe reference.
5. If you made a mistake, click **↩ Undo** to remove the last addition.

### Adding Malware Samples (PCAP file)

1. Navigate to the **Train** tab.
2. In the **Known Malware PCAP** section, click **Browse** or drag-and-drop a PCAP file.
3. Click **Add to Malware**.
4. Features are extracted and stored as a malicious reference.
5. Use **↩ Undo** to revert if needed.

### Local Model Panel

The **Local Model** section (below the PCAP file frames) shows:

- **KB entry counts** — How many safe, malicious, and unsure samples are in the knowledge base
- **Last trained** — When the model file was last updated
- **Retrain Now** — Rebuilds the model from all seed rows + KB entries in the background (requires at least 1 safe + 1 malicious KB entry, or relies on seed data alone)
- **Enable local ML model** checkbox — Toggles whether the local model contributes a prediction during analysis

> **How retraining works:** The model is always trained on the 146 seed feature rows (from the shipped baseline) **plus** your KB entries weighted 3×. This means the shipped general knowledge is never lost; your labeled captures simply personalise the model on top of it.

### Knowledge Base Entries Browser

The **Knowledge Base Entries** panel at the bottom of the Train tab shows every labeled sample:

- Entries are listed with label, date, packet count, and a summary
- **Select an entry** and click **Delete Selected** to remove it (with confirmation); the model retrains automatically if the local model is enabled
- **Refresh** reloads the list from disk

### Tips for Effective Training

- **Start with known samples** — Use PCAPs from malware sandboxes (e.g., Malware Traffic Analysis, ANY.RUN) for malware and your own clean network captures for safe samples.
- **Use Quick-Label** for captures you've already analyzed — it's faster than re-parsing the file.
- **Label accurately** — Incorrectly labeled samples degrade detection quality.
- **Build a balanced KB** — Try to add roughly equal numbers of safe and malicious samples.
- **Retrain periodically** — Add new samples as you encounter new traffic patterns.
- The knowledge base is stored as a JSON file and persists across sessions.

### LLM Label Assistant (Optional)

If enabled in Preferences, PCAP Sentry can call a local LLM (Ollama, offline) or an OpenAI-compatible endpoint (local or cloud) to suggest a label and short rationale before saving a sample. You can accept the suggestion or keep your original label. If you point to a cloud endpoint, data is sent off-device.

---

<h2><img src="https://img.shields.io/badge/9-Managing_the_Knowledge_Base-58a6ff?style=flat-square&labelColor=0d1117" height="28" /></h2>

The **Knowledge Base** tab provides tools for managing your trained data:

| Button | Function |
|--------|----------|
| **Refresh** | Reload the KB from disk and display current safe/malware counts and IoC statistics |
| **Backup** | Save the entire KB to a JSON file via a save dialog (timestamped filename) |
| **Restore** | Load a previously saved KB backup file |
| **Reset Knowledge Base** | Erase all learned patterns (requires confirmation) |
| **IoC Import** | Import Indicators of Compromise from a `.json` or `.txt` file and merge into the KB |
| **IoC Clear** | Remove all imported IoC data |

### Automatic Backups

PCAP Sentry automatically backs up the knowledge base when you close the application. The 3 most recent backups are kept in a `kb_backups/` subdirectory within the app data folder.

### Optional KB Download (Release Asset)

PCAP Sentry releases can include an optional starter knowledge base file. You can use it as a base and then continue training with your own samples.

1. Download `pcap_knowledge_base_offline.json` from the [Releases](https://github.com/retr0verride/PCAP-Sentry/releases) page.
2. Open the **Knowledge Base** tab.
3. Click **Restore** and select the downloaded JSON file.

> **Note:** Restoring a KB replaces your current KB. Use **Backup** first if you want to keep a copy.

### IoC Feed Import

You can import external threat intelligence indicators:

1. Click **IoC Import** on the Knowledge Base tab.
2. Select a `.json` or `.txt` file containing indicators (IPs, domains, hashes).
3. The indicators are merged into your knowledge base for use during analysis.

This lets you incorporate third-party threat feeds (STIX/TAXII exports, open-source blocklists, etc.) into PCAP Sentry's analysis engine.

### Popular IoC Feed Sources

Here are free threat intelligence feeds you can download and import:

**IP Address Blocklists**

- **Abuse.ch Feodo Tracker** — https://feodotracker.abuse.ch/downloads/ipblocklist.txt
- **SANS ISC Block List** — https://isc.sans.edu/api/threatlist/
- **Talos Intelligence** — https://talosintelligence.com/documents/ip-blacklist
- **FireHOL Level1** — https://iplists.firehol.org/?ipset=firehol_level1

**Domain Blocklists**

- **URLhaus (Abuse.ch)** — https://urlhaus.abuse.ch/downloads/text/
- **PhishTank** — https://phishtank.org/developer_info.php
- **OpenPhish** — https://openphish.com/feed.txt
- **MalwareBytes** — https://urlhaus.abuse.ch/downloads/text_online/

**Hash (Malware) Lists**

- **MalwareBazaar (Abuse.ch)** — https://bazaar.abuse.ch/export/txt/sha256/recent/
- **VirusShare** — https://virusshare.com/
- **MISP Feeds** — https://www.misp-project.org/feeds/

**Combined/STIX Feeds**

- **Anomali ThreatStream** — https://www.anomali.com/resources/limo (free tier)
- **AlienVault OTX** — https://otx.alienvault.com/ (export pulses)

**Supported Formats**

- Plain text files (one indicator per line)
- JSON files with `ips`, `domains`, or `hashes` arrays

---

<h2><img src="https://img.shields.io/badge/10-Threat_Intelligence-58a6ff?style=flat-square&labelColor=0d1117" height="28" /></h2>

PCAP Sentry integrates with free, public threat intelligence sources to enhance analysis accuracy.

### Supported Feeds

| Feed | Data Type | API Key Required |
|------|-----------|------------------|
| 👽 **AlienVault OTX** | IP/domain reputation, threat pulses | No |
| 🔗 **URLhaus** | Malicious URL database | No |
| 😱 **abuse.ch ThreatFox** | IOC database (malware C2, hash lookups) | No |
| 🌫️ **GreyNoise** | Internet scanner / noise classification | No (community tier) |
| 🛡️ **AbuseIPDB** | IP abuse/reputation reports | Optional (free tier, higher limits) |
| 🧬 **VirusTotal** | File/URL reputation | Optional (free tier) |

### How It Works

During analysis, PCAP Sentry:

1. **Extracts network indicators** — IPs, domains (DNS, HTTP hosts, and TLS SNI), and URLs from the capture
2. **Filters out private/bogon IPs** — Skips RFC-1918, loopback, link-local, and multicast addresses that have no public reputation data
3. **Queries threat feeds concurrently** — Checks up to 20 IPs and 20 domains in parallel using a thread pool (up to 6 workers)
4. **Scores indicators** — Each indicator receives a risk score (0–100)
5. **Displays findings** — Flagged indicators appear in the Results and Why tabs

### Threat Intelligence Results

| Risk Score | Interpretation |
|:---:|---|
| ![Low](https://img.shields.io/badge/0--30-Low_Risk-3fb950?style=flat-square&labelColor=0d1117) | Likely legitimate |
| ![Medium](https://img.shields.io/badge/30--70-Medium_Risk-d29922?style=flat-square&labelColor=0d1117) | Requires investigation |
| ![High](https://img.shields.io/badge/70--100-High_Risk-f85149?style=flat-square&labelColor=0d1117) | Likely malicious |

Example output:
```
Flagged IPs (from public threat feeds):
  - 192.0.2.55: risk score 85/100
    (AlienVault OTX: 12 pulses)
    (AbuseIPDB: 94% confidence, 237 reports)
    (GreyNoise: malicious scanner — tag: Mirai)
    (ThreatFox: malware C2 — Cobalt Strike)

Flagged Domains (from public threat feeds):
  - malicious.example.com: risk score 92/100
    (URLhaus: 15 malicious URLs)
    (ThreatFox: known IOC)
```

### Performance Notes

- All IP and domain lookups run concurrently using a thread pool (up to 6 workers)
- Within each lookup, sub-queries (e.g., OTX + AbuseIPDB) also run in parallel
- Private/bogon IPs are filtered before any network call, avoiding wasted requests
- HTTP connection pooling with keep-alive reduces TCP/TLS overhead
- Results are cached for 1 hour to reduce API calls (persisted across sessions in `ti_cache.json`)
- Daily API usage is tracked for AbuseIPDB and VirusTotal (visible in **Preferences → API Keys** tab)
- Timeouts: 2-second connect, 3-second read (fast failure on degraded APIs)
- Up to 20 IPs and 20 domains are queried per analysis
- Internet connectivity is required (disable via Offline Mode if unavailable)

### Disabling Threat Intelligence

If you don't have internet access or prefer offline analysis:

1. Open **⚙ Preferences**
2. Check **Offline mode**
3. Click **Save**

Threat intelligence lookups will be skipped, and analysis will rely solely on local heuristics and the knowledge base.

---

<h2><img src="https://img.shields.io/badge/11-Machine_Learning_Model-58a6ff?style=flat-square&labelColor=0d1117" height="28" /></h2>

PCAP Sentry includes a local machine learning model for supplemental malware detection. It works **out-of-the-box without any labeling** thanks to a pre-trained RandomForest baseline shipped with the application.

### Enabling the ML Model

1. Open the **Train** tab.
2. In the **Local Model** panel, check **Enable local ML model**.
3. The model will contribute a prediction on every subsequent analysis.

> **Alternatively:** open **⚙ Preferences** and check **Enable local ML model** there.

### How It Works

- **Algorithm:** Random Forest (120 trees, `max_depth=14`, balanced class weights)
- **Pre-trained baseline:** Ships with `assets/pcap_sentry_baseline_model.pkl` — trained on 146 synthetic feature rows covering 13 realistic traffic profiles. Copied to your app data folder on first launch automatically.
- **Combined retraining:** When you retrain (via **Retrain Now** in the Train tab or automatically after labeling), the model is rebuilt from the 146 seed rows **plus** your KB entries (weighted 3×). This means the shipped general knowledge is preserved and personalised — the more you label, the more the model adapts to your network.
- **Requirements for retraining:** At least one safe and one malicious KB entry (seed rows satisfy this for the baseline).
- **Model storage:** Saved as `pcap_local_model.joblib` in the app data directory, with HMAC-SHA256 integrity verification.

### Feature Set

The model trains on 25 features across several categories:

| Category | Features |
|----------|----------|
| **Network metrics** | Packet count, avg packet size, median packet size, protocol ratios (TCP, UDP, other) |
| **DNS behavior** | Query count, unique domains, DNS-per-packet ratio |
| **HTTP behavior** | Request count, unique hosts |
| **TLS behavior** | TLS packet count, unique TLS SNI names |
| **Host diversity** | Unique source IPs, unique destination IPs, bytes per unique destination |
| **Port usage** | Malware/C2 port hits (4444, 5555, 1337, 31337, etc.) |
| **Threat intel** | Flagged IP/domain counts, avg IP/domain risk scores |

### ML Verdict Output

When enabled, the ML model provides a supplemental verdict:

```
Local Model Verdict
Verdict: Likely Malicious
Malicious confidence: 85.30%
Backend: CPU
```

### Accuracy & Growth

The pre-trained baseline has been validated on the 13 traffic profile classes in the seed data. Real-world accuracy depends on how representative the seed profiles are of the traffic you encounter:

| Stage | Expected accuracy |
|---|---|
| Fresh install (seed only) | Good on common attack types (port scan, DDoS, C2, DNS tunnel) |
| + 10 labeled captures | Begins personalising to your network |
| + 50 balanced captures | Comparable or better than seed baseline |
| + 200+ balanced captures | Strong local accuracy |

> **Note:** The ML model is supplemental. The primary verdict comes from heuristic and knowledge-base scoring.

---

<h2><img src="https://img.shields.io/badge/12-Visual_Charts-58a6ff?style=flat-square&labelColor=0d1117" height="28" /></h2>

PCAP Sentry can generate visual charts for analyzed captures. After analysis completes, click **Open Charts** to view them in a separate window.

### Available Charts (7 Types)

| Chart | What It Shows |
|-------|--------------|
| **Timeline** | Packet activity over time |
| **Ports** | Distribution of destination ports |
| **Protocols** | Protocol breakdown (TCP, UDP, ICMP, etc.) |
| **DNS** | DNS query activity and top queried domains |
| **HTTP** | HTTP request patterns and top hosts |
| **TLS** | TLS/SSL handshake and cipher suite information |
| **Flows** | Network flow visualization |

### Chart Controls

- Charts are rendered using matplotlib within the application
- Each chart type appears on its own tab in the charts window
- The **Max packets for visuals** setting in the toolbar controls how many packets are loaded for charting (does not affect analysis accuracy)

> **Tip:** For very large PCAPs (>100 MB), consider reducing the max packets for visuals to keep chart rendering responsive.

---

<h2><img src="https://img.shields.io/badge/13-Preferences_&_Settings-58a6ff?style=flat-square&labelColor=0d1117" height="28" /></h2>

Open preferences via the **⚙ Preferences** button in the toolbar.


### LLM Status Persistence

Your LLM connection status (provider, model, endpoint) is now saved automatically when you close PCAP Sentry and restored on next launch. This ensures your LLM settings always default to your last-used configuration.

When a local LLM server is configured (Ollama, LM Studio, GPT4All, Jan, LocalAI, or KoboldCpp), PCAP Sentry will prompt on exit asking whether to stop the server. This only appears for servers running on localhost. The default is **No** to prevent accidental termination of shared servers.

### Available Settings

| Setting | Default | Description |
|---------|---------|-------------|
| 🎨 **Theme** | System | Choose `System`, `Dark`, or `Light` appearance. Changes require an app restart. |
| 📊 **Max packets for visuals** | 200,000 | Maximum packets loaded for charts and the packet table. |
| 🌐 **Parse HTTP payloads** | On | Extract HTTP method, host, and path from unencrypted traffic. |
| 💾 **High memory mode** | Off | Load entire PCAP into RAM for faster processing. Best for files under 500 MB. |
| ⚡ **Turbo parse** | On | Use fast raw-byte parsing. 5–15× faster for files over 50 MB. |
| 🧠 **Enable local ML model** | Off | Use the trained scikit-learn model for a supplemental verdict. |
| ✈️ **Offline mode** | Off | Disable all online threat intelligence lookups. |
| 🧵 **Multithreaded analysis** | On | Use multiple threads for parallel analysis. |
| 🤖 **LLM provider** | Disabled | Select `disabled`, `ollama`, or `openai_compatible`. Auto-detected on startup if a local LLM server is found. |
| 🧠 **LLM model** | llama3 | Model name dropdown — click **↻** to detect available models from the running server. You can also type a custom model name. |
| 🔗 **LLM endpoint** | http://localhost:11434 | Base URL for the LLM API. For Ollama use `http://localhost:11434`. For OpenAI-compatible servers, use the server base URL (no `/v1` suffix). |
| 🛑 **Stop LLM server on exit** | Prompt | When closing PCAP Sentry with a local LLM server configured (Ollama, LM Studio, GPT4All, Jan, LocalAI, KoboldCpp), a dialog asks whether to stop the server. Defaults to No. |
| 🧪 **Test Connection** | — | Sends a test request to verify the LLM is reachable with the current settings. Shows OK/FAIL status. |
| �️ **Uninstall** | — | Removes the currently selected Ollama model from disk. Only available when provider is `ollama`. |
| �📁 **Backup directory** | Default | Directory where KB backups are stored. |

> 🤖 **LLM Note**
>
> LLM suggestions are optional and run locally when using Ollama or an OpenAI-compatible server. Your PCAP data is not uploaded; only summarized statistics are sent to the local LLM endpoint.

### API Keys Tab

The **API Keys** tab in Preferences lets you configure optional threat intelligence API keys for higher rate limits:

| Service | Free Without Key | With Key |
|---------|:---:|---|
| **abuse.ch ThreatFox** | ✅ Full access | No key needed |
| **GreyNoise** | ✅ Community tier | Higher limits with key |
| **AbuseIPDB** | ❌ Limited | 1,000 checks/day (free account) |
| **VirusTotal** | ❌ Limited | 4 lookups/min (free account) |

To add a key:

1. Open **⚙ Preferences** and click the **API Keys** tab.
2. Click the blue **"Get a free API key →"** link next to any service to open the signup page in your browser.
3. Paste your key into the relevant field.
4. Click **Verify** to confirm the key is valid.
5. Click **Save**.

The tab also shows **"Used today: X / Y"** counters for AbuseIPDB and VirusTotal so you can monitor your daily quota usage.

### LLM Auto-Detection

On startup, if the LLM provider is set to `disabled`, PCAP Sentry automatically scans for local LLM servers:

1. **Ollama** — Checks `http://localhost:11434` for available models
2. **OpenAI-compatible** — Checks common ports (1234, 8000, 8080, 5000, 5001) for `/v1/models`

If a server is found, the provider, endpoint, and first available model are automatically configured. The header indicator shows **✔ LLM** in blue when auto-detected.

### Ollama Setup (Optional)

1. Install Ollama: https://ollama.com/download
2. Pull a model (example):
   ```
   ollama pull llama3
   ```
3. Ensure the Ollama service is running (default endpoint: `http://localhost:11434`).
4. In **⚙ Preferences**, set:
   - **LLM provider** = `ollama`
   - **LLM model** = click **↻** to detect available models, or type a model name
   - **LLM endpoint** = `http://localhost:11434`
5. Click **Test Connection** to verify.

### LLM Server Management (from Preferences)

To install or uninstall a local LLM server, open **Preferences** and click **Manage LLM Servers…**. The dialog lets you:

| Server | Description |
|--------|-------------|
| **Ollama** | Headless CLI server — no desktop app needed. Best for automation. |
| **LM Studio** | Desktop app with model browser. Download models in-app. |
| **GPT4All** | Desktop app with built-in model library. Easy setup. |
| **Jan** | Desktop app with chat UI. Download models in-app. |

Installation uses `winget` when available, with a direct-download fallback for Ollama and GPT4All. If automatic installation fails, a link to the manual download page is shown.

After installing a server, select it from the **LLM server** dropdown, click **↻** to detect available models, and click **Test Connection** to verify.

To pull Ollama models from the command line:
```
ollama pull llama3
```

To remove an Ollama model, select it in Preferences and click **Uninstall**.

### OpenAI-Compatible Server Setup (Optional)

PCAP Sentry works with any server that implements the OpenAI chat completions API (e.g., LM Studio, text-generation-webui, LocalAI, vLLM):

1. Start your OpenAI-compatible server.
2. In **⚙ Preferences**, set:
   - **LLM provider** = `openai_compatible`
   - **LLM model** = click **↻** to detect available models, or type a model name
   - **LLM endpoint** = your server's base URL (e.g., `http://localhost:1234`). Do not include `/v1`.
3. Click **Test Connection** to verify.

### Chat Tab

The **Chat** tab provides a conversational interface powered by your configured LLM:

- **Context-aware** — Automatically includes the current analysis results (verdict, risk score, protocol stats) in the conversation
- **Conversation history** — The last 6 messages are sent as context for follow-up questions
- **Send** — Type a question and press Enter or click Send
- **Clear** — Resets the conversation history
- **Disabled when LLM is off** — The tab is available but the controls are disabled until an LLM provider is configured

Example questions:
- "Why was this capture flagged as malicious?"
- "What do the DNS queries suggest?"
- "Is this level of port scanning normal?"
- "Explain the TLS certificate findings"

> 🎨 **App Color Palette Reference**
>
> PCAP Sentry uses a GitHub-inspired color palette:
>
> | Role | Dark Mode | Light Mode |
> |------|-----------|------------|
> | Background | `#0d1117` | `#f0f2f5` |
> | Panel | `#161b22` | `#ffffff` |
> | Panel Alt (tabs, headings) | `#1c2333` | `#f7f8fa` |
> | Accent (primary) | `#58a6ff` | `#2563eb` |
> | Text | `#e6edf3` | `#1a1d23` |
> | Muted text | `#8b949e` | `#6b7280` |
> | Border | `#21262d` | `#e2e5ea` |
> | Success / Safe | `#3fb950` | `#16a34a` |
> | Warning / Suspicious | `#d29922` | `#d97706` |
> | Danger / Malicious | `#f85149` | `#dc2626` |

### Resetting Preferences

Click **Reset to Defaults** at the bottom of the Preferences dialog to restore all settings to their factory values.

### Settings Storage

All preferences are saved to `settings.json` in the application data directory:
```
%LOCALAPPDATA%\PCAP_Sentry\settings.json
```

> **Security Note:** If the `keyring` Python package is installed, the LLM API key is stored in the Windows Credential Manager instead of `settings.json`. Existing plaintext keys are automatically migrated on first load. If `keyring` is not available, the API key is stored in the JSON file as a fallback.

---

<h2><img src="https://img.shields.io/badge/14-Updating_PCAP_Sentry-58a6ff?style=flat-square&labelColor=0d1117" height="28" /></h2>

### Checking for Updates

1. Click **Check for Updates** in the toolbar.
2. PCAP Sentry checks GitHub for the latest release in the background.
3. If a newer version is available:
   - A dialog shows the new version number and release notes
   - Click **Download & Update** to download the installer
   - Download progress is displayed
   - The updater prefers the full installer when available, falling back to the standalone EXE
   - The installer launches automatically when the download completes
   - Follow the installer prompts to update
4. If you're already on the latest version, a confirmation message is shown.

### Update Details

- Your knowledge base is automatically backed up before any update is applied
- Updates are downloaded to `%LOCALAPPDATA%\PCAP_Sentry\updates\`
- All connections use HTTPS with SSL verification
- User confirmation is always required — no silent updates
- Old update files are cleaned up automatically

### Versioning Scheme

PCAP Sentry uses date-based versioning: `YYYY.MM.DD` (e.g., `2026.02.13`). If multiple builds are released on the same day, a build counter is appended (e.g., `2026.02.13-2`). The version is computed automatically from the current date and git commit history.

---

<h2><img src="https://img.shields.io/badge/15-Troubleshooting-58a6ff?style=flat-square&labelColor=0d1117" height="28" /></h2>

### Application Won't Start

- **Multiple instances:** PCAP Sentry only allows one instance at a time. Check the taskbar or Task Manager for an existing instance.
- **Missing VC++ Runtime:** Download and install the [Visual C++ Redistributable](https://aka.ms/vs/17/release/vc_redist.x64.exe).
- **Antivirus blocking:** Some antivirus products may flag the application. Add an exception for the PCAP Sentry installation directory.
- **Unexpected error dialog:** If you see an error on launch, check `startup_errors.log` in the app data folder. Runtime errors are logged to `app_errors.log`.

### Analysis Takes Too Long

- **Enable Turbo parse** in Preferences (on by default) for 5–15× faster parsing of large files.
- **Reduce Max packets for visuals** — This doesn't affect accuracy, only chart and packet table rendering.
- **Enable Multithreaded analysis** in Preferences.
- **Enable High memory mode** for files under 500 MB.
- Very large PCAPs (>1 GB) may take several minutes regardless of settings.

### Threat Intelligence Not Showing

- Ensure you have **internet connectivity**.
- Verify **Offline mode** is not enabled in Preferences.
- Check that public APIs are reachable (AlienVault OTX, URLhaus, AbuseIPDB).
- API rate limits may temporarily block lookups — try again later.

### LLM Not Working

- Ensure **LLM provider** is set to `ollama` or `openai_compatible` in Preferences.
- Verify the LLM server is running and reachable at the configured endpoint.
- For Ollama: confirm the model is pulled (e.g., `ollama pull llama3`).
- Click **Test Connection** in Preferences to validate your settings — the error message includes the URL and server response for diagnostics.
- If the endpoint includes `/v1`, remove it — PCAP Sentry adds the correct API path automatically.
- Check the header indicator: **✔ LLM** (green/blue) means connected, **✘ LLM** (red) means failed.
- Error logs are written to `%LOCALAPPDATA%\PCAP_Sentry\`:
  - `startup_errors.log` — errors during application launch
  - `app_errors.log` — uncaught runtime errors

### Uninstalling

During uninstall, the installer will ask:

- **Keep Knowledge Base?** — Whether to preserve your trained knowledge base data or delete it.

LLM servers (Ollama, LM Studio, etc.) are installed separately and are not removed by the PCAP Sentry uninstaller. Uninstall them through Windows **Settings > Apps** if no longer needed.

### Ollama Connection Issues

- Verify the local API is reachable:
   - `ollama list`
   - `curl http://localhost:11434/api/tags`
- If `curl` fails, check Windows Defender Firewall and allow local loopback access for Ollama.
- In PCAP Sentry Preferences, use:
   - **LLM provider** = `ollama`
   - **LLM endpoint** = `http://localhost:11434`
- If needed, restart headless server manually:
   - `taskkill /F /IM "Ollama app.exe"`
   - `ollama serve`

### ML Model Not Working

- Ensure **Enable local ML model** is checked in Preferences.
- You need at least **one safe and one malicious sample** in the knowledge base.
- Verify that `scikit-learn` and `joblib` are installed (included in the installer).

### Charts Not Loading

- Charts require `matplotlib` (included in the installer).
- Reduce **Max packets for visuals** if charts are slow to render.
- Try closing and re-opening the charts window.

### Drag-and-Drop Not Working

- Drag-and-drop requires `tkinterdnd2`. It may not be available in all environments.
- As a workaround, use the **Browse** button or paste the file path.

### Knowledge Base Issues

- **KB corrupt?** Use **Restore** on the Knowledge Base tab to load a backup.
- **Automatic backups** are stored in the `kb_backups/` folder inside the app data directory.
- **Reset** the KB if backups are not available (this erases all trained data).

### Application Data Location

PCAP Sentry stores its data at:
```
%LOCALAPPDATA%\PCAP_Sentry\
```

This directory contains:
| File/Folder | Contents |
|-------------|----------|
| `settings.json` | User preferences |
| `pcap_knowledge_base_offline.json` | Knowledge base |
| `pcap_local_model.joblib` | Trained ML model |
| `pcap_local_model.joblib.hmac` | HMAC integrity signature for the ML model |
| `kb_backups/` | Automatic KB backups (3 most recent) |
| `updates/` | Downloaded update files |
| `startup_errors.log` | Errors during application launch |
| `app_errors.log` | Uncaught runtime errors |

---

<h2><img src="https://img.shields.io/badge/16-Testing_&_Quality_Assurance-58a6ff?style=flat-square&labelColor=0d1117" height="28" /></h2>

PCAP Sentry includes a comprehensive test suite to ensure stability, security, and performance.

### Test Suite Overview

**Total Tests:** 17 | **Pass Rate:** 100% | **Code Coverage:** 7% | **Security Score:** 100/100

| Test Suite | Tests | Purpose |
|------------|-------|----------|
| **Stability Tests** | 10 | Core functionality, input validation, security features |
| **Stress Tests** | 7 | Performance benchmarks, memory efficiency, thread safety |

### Running Tests

If running from source:

```bash
pytest tests/                     # Run all tests with coverage report
pytest tests/test_stability.py    # Core functionality tests
pytest tests/test_stress.py       # Performance tests
pytest -v                         # Verbose output
```

After running tests, open `htmlcov/index.html` to view detailed coverage report.
See [TEST_COVERAGE.md](TEST_COVERAGE.md) for coverage improvement roadmap.

### Stability Tests

Validate critical application functionality:

| Test | Validates |
|------|----------|
| Module Imports | All core modules load successfully |
| Settings Operations | Save/load functionality works |
| IOC Normalization | IP/domain/hash parsing accuracy |
| Path Security | Path traversal protection active |
| Input Validation | Malicious input detection (5/5 blocked) |
| Credential Security | Keyring storage with graceful fallback |
| Threat Intelligence | TI module availability |
| File Operations | Atomic write operations |
| Version Computation | Version format validation |
| Reservoir Sampling | Algorithm correctness |

### Stress Tests

Performance and scalability validation:

| Test | Performance Metrics |
|------|--------------------|
| Large IOC Parsing | 84K IOCs/sec (20K items in 0.238s) |
| Reservoir Sampling | 783K items/sec (1M items processed) |
| Counter Performance | 1.86M updates/sec |
| Set Operations | 541K ops/sec (200K operations) |
| Edge Cases | IPv6, malformed input, empty strings |
| Concurrent Operations | 10 threads, no race conditions |
| Memory Cleanup | 100% memory release rate |

### Security Validation

**Overall Security Score: 100/100** (20/20 points)

✅ **Strengths:**
- Keyring credential storage (Windows Credential Manager)
- HMAC-SHA256 model integrity verification
- SHA-256 update signature verification
- Path traversal protection (../blocked)
- Command injection prevention (5/5 patterns blocked)
- Thread-safe operations with proper locking
- Input sanitization and validation
- Response size limits on network operations
- No eval/exec usage
- Safe subprocess usage

🟡 **Improvements:**
- Expand GUI test coverage
- Add type hints for better maintainability

### Code Quality Assessment

For developers and security auditors, see:

- **[TEST_COVERAGE.md](TEST_COVERAGE.md)** — Coverage analysis and improvement roadmap
- **[TEST_POLICY_EVIDENCE.md](TEST_POLICY_EVIDENCE.md)** — Complete test results with performance benchmarks
- **[SECURITY_REVIEW_2026-02-15.md](SECURITY_REVIEW_2026-02-15.md)** — Comprehensive security audit with 95/100 security rating (0 medium/high vulnerabilities)

### Continuous Quality

- **CodeQL scanning** runs automatically on pushes and pull requests
- **Automated tests** validate each build
- **Security audits** ensure compliance with OWASP Top 10 and CWE 25 standards
- **Performance benchmarks** prevent regressions

---

<h2><img src="https://img.shields.io/badge/17-Known_Limitations_%26_Disclaimer-58a6ff?style=flat-square&labelColor=0d1117" height="28" /></h2>

### ⚠️ Educational Tool - Not for Production Use

**PCAP Sentry is designed for learning purposes only.** While it provides valuable insights for understanding malware network traffic patterns, it has important limitations you must understand.

### What This Tool IS

✅ **Educational resource** for learning network traffic analysis
✅ **Training platform** for recognizing malicious patterns
✅ **Research tool** for security experiments and practice
✅ **Triage assistant** to help prioritize further investigation

### What This Tool IS NOT

❌ **NOT a production security solution**
❌ **NOT a substitute for professional security tools** (e.g., enterprise IDS/IPS, SIEM)
❌ **NOT validated for compliance** (PCI-DSS, HIPAA, SOC 2, etc.)
❌ **NOT suitable for legal proceedings** (forensic evidence)
❌ **NOT a guaranteed threat detector** (will miss sophisticated attacks)

### Known Limitations

#### Detection Accuracy

- **False Positives**: Normal traffic may be flagged as suspicious
  - High packet rates from legitimate services
  - Legitimate beaconing (IoT devices, monitoring tools)
  - Benign protocols on non-standard ports

- **False Negatives**: Malicious traffic may go undetected
  - Encrypted C2 channels (HTTPS, DNS-over-HTTPS)
  - Low-and-slow attacks (evading behavioral detection)
  - Zero-day malware with unknown signatures
  - Advanced evasion techniques (domain generation algorithms, steganography)

#### Analysis Capabilities

- **No TLS/HTTPS decryption** — Cannot inspect encrypted payloads
- **No deep protocol analysis** — Limited to packet metadata and cleartext content
- **No packet reassembly** — May miss patterns spanning fragmented packets
- **Metadata-only threat intel** — Only IPs/domains are checked, not file hashes or behaviors

#### Knowledge Base & ML Model

- **Training required** — Accuracy depends on quality and quantity of labeled samples
- **Supervised learning only** — Cannot detect truly novel attack patterns
- **No model validation** — No ground truth accuracy metrics provided
- **Bias potential** — Model reflects biases in training data

#### Performance

- **Large PCAP files** (>1 GB) may take significant time to parse
- **Memory constraints** on systems with <8 GB RAM
- **CPU bottleneck** on older processors during analysis

#### Threat Intelligence

- **Third-party dependency** — Relies on AlienVault OTX and AbuseIPDB data accuracy
- **Rate limiting** — API quotas may restrict lookups
- **Delayed updates** — Threat feeds may lag behind emerging threats
- **Geographic bias** — Better coverage for some regions than others

### Responsible Use Guidelines

✓ **Always verify findings** with additional tools (Wireshark, VirusTotal, sandbox analysis)
✓ **Understand context** — High risk scores don't guarantee malicious activity
✓ **Check legal authority** — Ensure you have permission to analyze network traffic
✓ **Maintain chain of custody** — Don't rely on PCAP Sentry alone for forensic evidence
✓ **Combine with other data** — Correlate with logs, EDR, SIEM for complete picture
✓ **Report responsibly** — Clearly state tool limitations when sharing results

### Legal Disclaimer

**NO WARRANTY**: This program comes with ABSOLUTELY NO WARRANTY. See the [LICENSE](LICENSE) file for details.

By using PCAP Sentry, you acknowledge:

1. **Educational purpose** — All analysis results are for learning and reference only
2. **Independent verification** — You are responsible for validating findings
3. **Risk assumption** — You assume all risks associated with network traffic analysis
4. **No liability** — Developers are not liable for decisions made based on this tool's output
5. **Legal compliance** — You must comply with applicable laws regarding network monitoring

### Legal Compliance Requirements

#### Network Monitoring Laws

**⚠️ CRITICAL:** Analyzing network traffic may be **illegal without proper authorization**.

**United States:**
- **18 U.S.C. § 2511** (Wiretap Act) — Prohibits unauthorized interception of electronic communications
- **18 U.S.C. § 1030** (Computer Fraud and Abuse Act) — Prohibits unauthorized computer access
- **Stored Communications Act** — Regulates access to stored communications
- **State wiretapping laws** — May be stricter than federal law (check your state)

**European Union:**
- **GDPR** — Requires lawful basis for processing personal data (including IP addresses)
- **ePrivacy Directive** — Regulates electronic communications monitoring
- **National laws** — Each EU member state has specific requirements

**Other Jurisdictions:**
- **Canada:** PIPEDA and Criminal Code provisions
- **UK:** Investigatory Powers Act, Data Protection Act
- **Australia:** Telecommunications (Interception and Access) Act
- **Consult local laws** for your jurisdiction

#### When You Need Authorization

You **MUST** have legal authority before analyzing network traffic in these scenarios:

❌ **WITHOUT Authorization:**
- Intercepting traffic on networks you don't own or operate
- Monitoring employee communications without notice/consent
- Capturing WiFi traffic in public spaces
- Accessing communications of third parties without warrants (law enforcement only)
- Analyzing traffic in violation of terms of service (e.g., ISP agreements)

✅ **WITH Authorization:**
- Your own home network traffic
- Corporate network with employer consent and employee notice
- Research networks with explicit permission
- Honeypots and lab environments you control
- Public packet captures (e.g., from security research datasets)
- Law enforcement with proper legal authority (warrants, court orders)

#### Privacy Considerations

Network captures may contain **personal information** and **confidential data**:

- **Usernames and passwords** (in cleartext protocols)
- **Email addresses and contact information**
- **Browsing history** (DNS queries, HTTP requests)
- **Private communications** (if not encrypted)
- **Trade secrets or proprietary information**

**Your Responsibilities:**
1. ✅ Minimize collection of personal information
2. ✅ Secure PCAPs and analysis results (encrypt, access control)
3. ✅ Delete captures when no longer needed
4. ✅ Comply with data protection regulations (GDPR, CCPA, etc.)
5. ✅ Respect confidentiality and privacy expectations

#### Export Control Compliance

**U.S. Export Administration Regulations (EAR):**

This software uses cryptographic functions and may be subject to export controls.

**Restricted Destinations (Do NOT Export To):**
- ❌ Cuba, Iran, North Korea, Syria
- ❌ Russia-occupied regions (Crimea, Donetsk, Luhansk)
- ❌ Any country under U.S. embargo
- ❌ Denied Persons List / Entity List parties

**International Users:**
- Verify compliance with your country's import regulations
- Some countries restrict cryptographic software
- Export control laws apply to **digital transfers** (downloads, emails, cloud storage)

**Exemptions:**
- This software may qualify for publicly available exemptions
- Standard cryptography library usage (not custom crypto)
- Educational use may have additional exemptions

**Consult an Attorney:** Export control laws are complex. If you plan to distribute this software internationally, consult an export control attorney.

#### Prohibited Uses

This software **MUST NOT** be used for:

❌ **Illegal Surveillance:**
- Wiretapping without legal authority
- Spying on communications without consent
- Stalking or harassment

❌ **Unauthorized Access:**
- Hacking or penetrating networks without permission
- Circumventing security measures
- Violating Computer Fraud and Abuse Act (CFAA) or equivalent laws

❌ **Privacy Violations:**
- Collecting personal data without lawful basis
- Violating GDPR, CCPA, or other privacy regulations
- Breaching confidentiality obligations

❌ **Malicious Activity:**
- Developing or deploying malware
- Conducting attacks or exploits
- Aiding criminal activity

#### Recommended Practices

To minimize legal risk:

1. **Get Written Authorization**
   - Document permission to monitor networks
   - Maintain copies of consent forms
   - Update authorizations when scope changes

2. **Provide Notice**
   - Inform users their traffic may be monitored
   - Display banners on login screens
   - Include monitoring clauses in policies

3. **Minimize Collection**
   - Capture only what's necessary for your purpose
   - Use filters to exclude irrelevant traffic
   - Avoid capturing credentials when possible

4. **Secure Your Data**
   - Encrypt PCAP files and analysis results
   - Use access controls and authentication
   - Store in secure locations (not public cloud without encryption)

5. **Document Your Purpose**
   - Maintain logs of why captures were taken
   - Record educational/research rationale
   - Create audit trail for compliance

6. **Consult Experts**
   - Legal counsel for compliance questions
   - Privacy officer for GDPR/data protection
   - Export control attorney for international use

#### Disclaimer

This section provides **general information only** and does not constitute legal advice. Laws vary by jurisdiction and change frequently. 

**Consult a qualified attorney** licensed in your jurisdiction before:
- Analyzing network traffic in a professional capacity
- Monitoring employee or customer networks
- Distributing this software internationally
- Using in any legally sensitive context

For production security needs, use enterprise-grade tools from established vendors with:
- Validated detection accuracy
- Compliance certifications
- Professional support and SLAs
- Forensic-quality evidence handling

---

<h2><img src="https://img.shields.io/badge/18-FAQ-58a6ff?style=flat-square&labelColor=0d1117" height="28" /></h2>

**Q: Does PCAP Sentry send my PCAP files anywhere?**
A: No. All analysis is performed locally on your machine. The only network activity is optional threat intelligence lookups (which send only IP addresses and domain names, not packet contents) and update checks to GitHub.

**Q: Can PCAP Sentry decrypt HTTPS/TLS traffic?**
A: No. PCAP Sentry analyzes traffic metadata (IPs, ports, protocols, timing) and cleartext content. Encrypted payloads cannot be inspected without decryption keys.

**Q: How accurate is the risk score?**
A: Accuracy improves as you train the knowledge base with more samples. With a well-trained KB and threat intelligence enabled, PCAP Sentry provides reliable triage signals. Always validate findings with additional tools (e.g., Wireshark, VirusTotal) for critical investigations.

**Q: Can I use PCAP Sentry completely offline?**
A: Yes. Enable **Offline mode** in Preferences. Analysis will use local heuristics and the knowledge base only. Threat intelligence lookups and update checks are skipped.

**Q: What is the maximum PCAP file size supported?**
A: There is no hard limit. However, very large files (>1 GB) will take longer to analyze. Enable **High memory mode** and **Turbo parse** for best performance with large captures.

**Q: Can I export analysis reports?**
A: Currently, results can be copied to the clipboard via the **Copy Wireshark Filters**, **Copy All (Credentials)**, and **Copy All (Hosts)** buttons. You can paste them into any document or report. PDF/HTML export may be added in a future release.

**Q: How do I share my knowledge base with another analyst?**
A: Use the **Backup** button on the Knowledge Base tab to export it as a JSON file. The other analyst can then use **Restore** to import it.

**Q: Does PCAP Sentry work on macOS or Linux?**
A: PCAP Sentry is developed and tested for Windows. While it may run from source on macOS/Linux with Python and the required dependencies, this is not officially supported.

---

<h2><img src="https://img.shields.io/badge/19-Appendix-58a6ff?style=flat-square&labelColor=0d1117" height="28" /></h2>

### A. Keyboard & Mouse Controls

| Input | Action |
|-------|--------|
| Mouse wheel | Scroll the Analyze tab |
| Click column header | Sort table ascending/descending (▲/▼) |
| Right-click column header | Show/hide columns, align single column or all columns (Left/Center/Right) |
| Drag-and-drop | Drop PCAP files onto entry fields or the Analyze tab |
| Enter (in Chat) | Send the current message |
| **?** icons | Hover for contextual tooltip help |
| **✕** button on entry fields | Clear the input field |

### B. Detected Protocols & Patterns

PCAP Sentry can detect and analyze traffic involving:

| Category | Protocols/Patterns |
|----------|-------------------|
| **Web traffic** | HTTP, HTTPS/TLS |
| **Email** | SMTP, POP3, IMAP |
| **File transfer** | FTP |
| **Remote access** | Telnet, SSH (metadata only) |
| **Name resolution** | DNS, NetBIOS, DHCP |
| **Network management** | SNMP |
| **Authentication** | Kerberos |
| **Malicious patterns** | C2 beaconing, data exfiltration, port scanning, DNS tunneling |

### C. Heuristic Signals

The analysis engine evaluates numerous heuristic signals including:

- Unusual protocol distributions (e.g., high ratio of non-standard protocols)
- Connections to known malware/C2 ports (e.g., 4444, 5555, 6666–6669, 1337, 31337, 8443, 9001–9003)
- Excessive DNS queries or DNS to unusual TLDs
- **DNS tunneling** detection (high unique-query-to-packet ratios)
- High outbound data volume relative to inbound
- **Data exfiltration** detection (10:1+ outbound-to-inbound byte ratio)
- Connections to many unique external hosts
- **Beaconing** patterns (regular-interval connections with coefficient of variation < 0.25)
- **Port scanning** detection (20+ destination ports from a single source)
- **SYN flood/scan** detection (high SYN count with low established connections)
- Large file transfers to external IPs
- Cleartext credential transmission
- Beacon-like flows (high packet count with small average payload)

### D. File Locations Reference

| Item | Location |
|------|----------|
| Application | `C:\Program Files\PCAP Sentry\` (default) |
| User data | `%LOCALAPPDATA%\PCAP_Sentry\` |
| Settings | `%LOCALAPPDATA%\PCAP_Sentry\settings.json` |
| Knowledge base | `%LOCALAPPDATA%\PCAP_Sentry\pcap_knowledge_base_offline.json` |
| ML model | `%LOCALAPPDATA%\PCAP_Sentry\pcap_local_model.joblib` |
| ML model signature | `%LOCALAPPDATA%\PCAP_Sentry\pcap_local_model.joblib.hmac` |
| KB backups | `%LOCALAPPDATA%\PCAP_Sentry\kb_backups\` |
| Update downloads | `%LOCALAPPDATA%\PCAP_Sentry\updates\` |
| Logs | `%LOCALAPPDATA%\PCAP_Sentry\*.log` |

### E. Getting Help & Contributing

- **GitHub:** [github.com/retr0verride/PCAP-Sentry](https://github.com/retr0verride/PCAP-Sentry)
- **Issues:** Report bugs or request features via [GitHub Issues](https://github.com/retr0verride/PCAP-Sentry/issues)
- **License:** GNU General Public License v3.0 - see [LICENSE](LICENSE) file. Copyright (C) 2026 retr0verride

---

<div align="center">

<img src="assets/pcap_sentry.ico" alt="PCAP Sentry" width="48" />

**PCAP Sentry** — *Network traffic analysis made accessible.*

![GitHub](https://img.shields.io/badge/GitHub-industrial--dave%2FPCAP--Sentry-58a6ff?style=flat-square&logo=github&logoColor=white&labelColor=0d1117)

</div>
