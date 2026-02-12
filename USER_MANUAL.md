# PCAP Sentry — User Manual

**Version 2026.02.12** | **Windows Desktop Application**

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
16. [FAQ](#16-faq)
17. [Appendix](#17-appendix)

---

## 1. Introduction

PCAP Sentry is a malware analysis console for network packet capture (PCAP) files. It parses network captures, summarizes traffic statistics, and provides heuristic signals to help triage suspicious network activity.

### What PCAP Sentry Does

- **Analyzes PCAP/PCAPNG files** for signs of malicious activity
- **Scores network traffic** with a risk rating from 0–100
- **Extracts credentials** from cleartext protocols (FTP, HTTP, Telnet, etc.)
- **Discovers hosts** including IP addresses, MAC addresses, and hostnames
- **Detects C2 and exfiltration** patterns automatically
- **Generates Wireshark filters** for follow-up investigation
- **Queries threat intelligence feeds** for known-bad indicators
- **Learns from your data** via a trainable knowledge base and optional ML model

### Who Is It For?

- Security analysts performing network forensics
- SOC teams triaging alerts
- Penetration testers reviewing capture files
- Students learning about network security
- Anyone who needs to quickly assess whether a PCAP file contains malicious activity

---

## 2. System Requirements

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| **OS** | Windows 10 (64-bit) | Windows 10/11 (64-bit) |
| **RAM** | 4 GB | 8 GB or more |
| **Disk Space** | 200 MB | 500 MB+ (for large KB/models) |
| **Display** | 1280×720 | 1920×1080 or higher |
| **Internet** | Optional | Recommended (for threat intel) |
| **Runtime** | VC++ Redistributable 2015+ | Included with installer |

### For Running from Source (Developers)

| Requirement | Version |
|-------------|---------|
| Python | 3.10 or newer |
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

## 3. Installation

### Option 1: Installer (Recommended)

1. Download **PCAP_Sentry_Setup.exe** from the [Releases](https://github.com/industrial-dave/PCAP-Sentry/releases) page.
2. Run the installer and follow the on-screen prompts.
3. Choose an installation directory (default: `C:\Program Files\PCAP Sentry`).
4. Optionally create a desktop shortcut.
5. Launch PCAP Sentry from the **Start Menu** or **desktop shortcut**.

### Option 2: Run from Source

1. Clone the repository:
   ```
   git clone https://github.com/industrial-dave/PCAP-Sentry.git
   ```
2. Install Python 3.10 or newer from [python.org](https://www.python.org/).
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

## 4. Getting Started

### First Launch

When you launch PCAP Sentry for the first time, the application opens to the **Analyze** tab. The interface consists of:

- A **header banner** with the application name and version
- A **toolbar** with analysis controls and preferences
- **Three main tabs**: Analyze, Train, and Knowledge Base

### Quick Start: Analyzing Your First PCAP

1. Click the **Browse** button next to "Target PCAP" (or drag-and-drop a file).
2. Select a `.pcap` or `.pcapng` file.
3. Click the **🔍 Analyze** button.
4. Wait for the analysis to complete (a progress indicator and cancel button are shown).
5. Review the results across the five results sub-tabs.

---

## 5. Application Interface

### Main Tabs

PCAP Sentry has three primary tabs:

| Tab | Icon | Purpose |
|-----|------|---------|
| **Analyze** | 🔍 | Select and analyze PCAP files, view results |
| **Train** | 🧠 | Add known-safe or known-malware PCAPs to the knowledge base |
| **Knowledge Base** | 📚 | Manage the KB: refresh, backup, restore, reset, import IoC feeds |

### Toolbar

The toolbar appears below the header and contains:

| Control | Description |
|---------|-------------|
| **Max packets for visuals** | Sets the maximum number of packets loaded for charts and the packet table (does **not** affect analysis accuracy). Range: 10,000–500,000. |
| **Parse HTTP payloads** | When checked, extracts HTTP request details (method, host, path) from unencrypted traffic. |
| **⚙ Preferences** | Opens the Preferences dialog for advanced settings. |
| **Check for Updates** | Checks GitHub for newer versions of PCAP Sentry. |

### Supported File Types

| Format | Description |
|--------|-------------|
| `.pcap` | Standard packet capture format |
| `.pcapng` | Next-generation packet capture format |
| `.zip` | ZIP archives containing .pcap/.pcapng files (auto-extracts) |

---

## 6. Analyzing PCAP Files

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
   - **Feature extraction** — Computes network behavior metrics
   - **Scoring** — Compares against the knowledge base using heuristics
   - **Threat intelligence** — Queries online feeds (if enabled)
   - **ML classification** — Runs the local model (if enabled)

5. **Review results** across the five sub-tabs (see [Understanding Results](#7-understanding-results)).

### Post-Analysis Actions

After analysis completes, you can:

- **Mark as Safe** — Add this PCAP's features to the knowledge base as a safe sample
- **Mark as Malicious** — Add this PCAP's features to the knowledge base as a malware sample
- **Open Charts** — Launch the visual charts window with 7 chart types
- **Copy Wireshark Filters** — Copy auto-generated Wireshark display filters to the clipboard

### Analyzing ZIP Archives

PCAP Sentry can directly open `.zip` files. It will automatically extract and analyze the first `.pcap` or `.pcapng` file found inside the archive.

---

## 7. Understanding Results

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
|-------------|---------|--------|
| **0–30** | Safe | Likely legitimate traffic; no immediate action needed |
| **30–70** | Suspicious | Requires further investigation |
| **70–100** | Malicious | Likely malicious; escalate and investigate |

### 7.2 Why Tab

Provides the analytical reasoning behind the verdict:

- **Evidence breakdown** — Lists specific indicators that contributed to the score
- **Heuristic signals** — Details each detection trigger and its weight
- **Wireshark filter generation** — Auto-generates display filters you can paste directly into Wireshark
- **Copy Wireshark Filters** button — Copies all generated filters to the clipboard

### 7.3 Education Tab

Designed for beginners and learning purposes:

- **Plain-English explanations** of what was found and why it matters
- **Attack pattern glossary** — Common network attack patterns explained
- **Learning resources** — Links and references for further study

### 7.4 Packets Tab

A full, filterable packet table:

- Browse individual packets from the capture
- **Column management** — Right-click column headers to show/hide columns or change alignment
- **C2/Exfiltration hints** — Packets flagged with potential Command & Control or data exfiltration indicators
- Scrollable with mouse wheel support

### 7.5 Extracted Info Tab (🔑)

Displays credentials and host information found in cleartext traffic:

#### Credentials
Extracted authentication data from cleartext protocols including:
- FTP usernames and passwords
- HTTP basic/digest authentication
- SMTP, POP3, IMAP credentials
- Telnet login sequences
- SNMP community strings
- Kerberos ticket data

**Copy All** button copies all credentials as tab-separated text.

#### Host Discovery
Network hosts identified from:
- IP addresses (source and destination)
- MAC addresses
- Computer names (from DNS, DHCP, SMTP EHLO, NetBIOS)

**Copy All** button copies all host information to the clipboard.

> **⚠ Security Note:** Credential extraction only works on unencrypted (cleartext) traffic. Encrypted protocols (HTTPS, SSH, etc.) cannot be decoded without the appropriate keys.

---

## 8. Training the Knowledge Base

The **Train** tab allows you to teach PCAP Sentry what safe and malicious traffic looks like, improving its detection accuracy over time.

### Adding Safe Samples

1. Navigate to the **Train** tab.
2. In the **Known Safe PCAP** section, click **Browse** or drag-and-drop a PCAP file.
3. Click **Add to Safe**.
4. The application parses the file, extracts its network features, and stores them in the knowledge base as a safe reference.
5. If you made a mistake, click **↩ Undo** to remove the last addition.

### Adding Malware Samples

1. Navigate to the **Train** tab.
2. In the **Known Malware PCAP** section, click **Browse** or drag-and-drop a PCAP file.
3. Click **Add to Malware**.
4. Features are extracted and stored as a malicious reference.
5. Use **↩ Undo** to revert if needed.

### Tips for Effective Training

- **Start with known samples** — Use PCAPs from malware sandboxes (e.g., Malware Traffic Analysis, ANY.RUN) for malware and your own clean network captures for safe samples.
- **Label accurately** — Incorrectly labeled samples degrade detection quality.
- **Build a balanced KB** — Try to add roughly equal numbers of safe and malicious samples.
- **Retrain periodically** — Add new samples as you encounter new traffic patterns.
- The knowledge base is stored as a JSON file and persists across sessions.

---

## 9. Managing the Knowledge Base

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

### IoC Feed Import

You can import external threat intelligence indicators:

1. Click **IoC Import** on the Knowledge Base tab.
2. Select a `.json` or `.txt` file containing indicators (IPs, domains, hashes).
3. The indicators are merged into your knowledge base for use during analysis.

This lets you incorporate third-party threat feeds (STIX/TAXII exports, open-source blocklists, etc.) into PCAP Sentry's analysis engine.

---

## 10. Threat Intelligence

PCAP Sentry integrates with free, public threat intelligence sources to enhance analysis accuracy.

### Supported Feeds

| Feed | Data Type | API Key Required |
|------|-----------|-----------------|
| **AlienVault OTX** | IP/domain reputation, threat pulses | No |
| **URLhaus** | Malicious URL database | No |
| **Public IP/Domain Reputation** | Known-bad indicator lists | No |

### How It Works

During analysis, PCAP Sentry:

1. **Extracts network indicators** — IPs, domains, and URLs from the capture
2. **Queries threat feeds** — Checks the top 10 IPs and domains against public databases
3. **Scores indicators** — Each indicator receives a risk score (0–100)
4. **Displays findings** — Flagged indicators appear in the Results and Why tabs

### Threat Intelligence Results

| Risk Score | Interpretation |
|------------|---------------|
| **0–30** | Low risk — likely legitimate |
| **30–70** | Medium risk — requires investigation |
| **70–100** | High risk — likely malicious |

Example output:
```
Flagged IPs (from public threat feeds):
  - 192.0.2.55: risk score 85/100
    (AlienVault OTX: 12 pulses)

Flagged Domains (from public threat feeds):
  - malicious.example.com: risk score 92/100
    (URLhaus: 15 malicious URLs)
```

### Performance Notes

- Results are cached for 1 hour to reduce API calls
- Individual lookups time out after 5 seconds
- Only the top 10 IPs and domains are queried per analysis
- Internet connectivity is required (disable via Offline Mode if unavailable)

### Disabling Threat Intelligence

If you don't have internet access or prefer offline analysis:

1. Open **⚙ Preferences**
2. Check **Offline mode**
3. Click **Save**

Threat intelligence lookups will be skipped, and analysis will rely solely on local heuristics and the knowledge base.

---

## 11. Machine Learning Model

PCAP Sentry includes an optional local machine learning model for supplemental malware detection.

### Enabling the ML Model

1. Open **⚙ Preferences**
2. Check **Enable local ML model**
3. Click **Save**

### How It Works

- **Algorithm:** Logistic Regression with balanced class weights
- **Training data:** Features extracted from your knowledge base samples
- **Requirements:** At least one safe and one malicious sample in the KB
- **Auto-retraining:** The model automatically retrains whenever you add a new sample via the Train tab
- **Model storage:** Saved as `pcap_local_model.joblib` in the app data directory

### Feature Set

The model trains on 50+ features including:

| Category | Example Features |
|----------|-----------------|
| **Network metrics** | Packet count, average packet size, protocol ratios |
| **DNS behavior** | Query count, unique domains |
| **HTTP behavior** | Request count, unique hosts |
| **Port usage** | Top destination ports |
| **Threat intel** | Flagged IP/domain counts, average risk scores |

### ML Verdict Output

When enabled, the ML model provides a supplemental verdict:

```
Local Model Verdict
Verdict: Likely Malicious
Malicious confidence: 85.30%
Backend: CPU
```

### Feature Importance

After training, the model reports which features are most predictive:

```
Top 10 most important features:
  - avg_domain_risk_score: 2.4531
  - flagged_domain_count: 1.8924
  - avg_ip_risk_score: 1.7643
  - http_request_count: 1.2321
  ...
```

> **Note:** The ML model is supplemental. The primary verdict comes from heuristic and knowledge-base scoring.

---

## 12. Visual Charts

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

## 13. Preferences & Settings

Open preferences via the **⚙ Preferences** button in the toolbar.

### Available Settings

| Setting | Default | Description |
|---------|---------|-------------|
| **Theme** | System | Choose `System`, `Dark`, or `Light` appearance. Changes require an app restart. |
| **Max packets for visuals** | 50,000 | Maximum packets loaded for charts and the packet table. |
| **Parse HTTP payloads** | On | Extract HTTP method, host, and path from unencrypted traffic. |
| **High memory mode** | Off | Load entire PCAP into RAM for faster processing. Best for files under 500 MB. |
| **Turbo parse** | On | Use fast raw-byte parsing. 5–15× faster for files over 50 MB. |
| **Enable local ML model** | Off | Use the trained scikit-learn model for a supplemental verdict. |
| **Offline mode** | Off | Disable all online threat intelligence lookups. |
| **Multithreaded analysis** | On | Use multiple threads for parallel analysis. |
| **Backup directory** | Default | Directory where KB backups are stored. |

### Resetting Preferences

Click **Reset to Defaults** at the bottom of the Preferences dialog to restore all settings to their factory values.

### Settings Storage

All preferences are saved to `settings.json` in the application data directory:
```
%APPDATA%\PCAP Sentry\settings.json
```

---

## 14. Updating PCAP Sentry

### Checking for Updates

1. Click **Check for Updates** in the toolbar.
2. PCAP Sentry checks GitHub for the latest release in the background.
3. If a newer version is available:
   - A dialog shows the new version number and release notes
   - Click **Download & Update** to download the installer
   - Download progress is displayed
   - The installer launches automatically when the download completes
   - Follow the installer prompts to update
4. If you're already on the latest version, a confirmation message is shown.

### Update Details

- Updates are downloaded to `%APPDATA%\PCAP Sentry\updates\`
- All connections use HTTPS with SSL verification
- User confirmation is always required — no silent updates
- Old update files are cleaned up automatically

---

## 15. Troubleshooting

### Application Won't Start

- **Multiple instances:** PCAP Sentry only allows one instance at a time. Check the taskbar or Task Manager for an existing instance.
- **Missing VC++ Runtime:** Download and install the [Visual C++ Redistributable](https://aka.ms/vs/17/release/vc_redist.x64.exe).
- **Antivirus blocking:** Some antivirus products may flag the application. Add an exception for the PCAP Sentry installation directory.

### Analysis Takes Too Long

- **Enable Turbo parse** in Preferences (on by default) for 5–15× faster parsing of large files.
- **Reduce Max packets for visuals** — This doesn't affect accuracy, only chart and packet table rendering.
- **Enable Multithreaded analysis** in Preferences.
- **Enable High memory mode** for files under 500 MB.
- Very large PCAPs (>1 GB) may take several minutes regardless of settings.

### Threat Intelligence Not Showing

- Ensure you have **internet connectivity**.
- Verify **Offline mode** is not enabled in Preferences.
- Check that public APIs are reachable (AlienVault OTX, URLhaus).
- API rate limits may temporarily block lookups — try again later.

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
%APPDATA%\PCAP Sentry\
```

This directory contains:
| File/Folder | Contents |
|-------------|----------|
| `settings.json` | User preferences |
| `pcap_knowledge_base_offline.json` | Knowledge base |
| `pcap_local_model.joblib` | Trained ML model |
| `kb_backups/` | Automatic KB backups (3 most recent) |
| `updates/` | Downloaded update files |
| `*.log` | Application log files |

---

## 16. FAQ

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

## 17. Appendix

### A. Keyboard & Mouse Controls

| Input | Action |
|-------|--------|
| Mouse wheel | Scroll the Analyze tab |
| Right-click on column header | Show/hide columns, change alignment |
| Drag-and-drop | Drop PCAP files onto entry fields or the Analyze tab |

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
- Connections to known-bad ports (e.g., 4444, 1337, 31337)
- Excessive DNS queries or DNS to unusual TLDs
- High outbound data volume relative to inbound
- Connections to many unique external hosts
- Beaconing patterns (regular-interval connections)
- Large file transfers to external IPs
- Cleartext credential transmission

### D. File Locations Reference

| Item | Location |
|------|----------|
| Application | `C:\Program Files\PCAP Sentry\` (default) |
| User data | `%APPDATA%\PCAP Sentry\` |
| Settings | `%APPDATA%\PCAP Sentry\settings.json` |
| Knowledge base | `%APPDATA%\PCAP Sentry\pcap_knowledge_base_offline.json` |
| ML model | `%APPDATA%\PCAP Sentry\pcap_local_model.joblib` |
| KB backups | `%APPDATA%\PCAP Sentry\kb_backups\` |
| Update downloads | `%APPDATA%\PCAP Sentry\updates\` |
| Logs | `%APPDATA%\PCAP Sentry\*.log` |

### E. Getting Help & Contributing

- **GitHub:** [github.com/industrial-dave/PCAP-Sentry](https://github.com/industrial-dave/PCAP-Sentry)
- **Issues:** Report bugs or request features via [GitHub Issues](https://github.com/industrial-dave/PCAP-Sentry/issues)
- **License:** See [LICENSE.txt](LICENSE.txt) for license terms

---

*PCAP Sentry — Network traffic analysis made accessible.*
