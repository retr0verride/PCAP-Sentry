<div align="center">

<img src="assets/pcap_sentry.ico" alt="PCAP Sentry" width="96" />

# PCAP Sentry

### Malware Analysis Console for Network Packet Captures

![Version](https://img.shields.io/badge/Version-Date_Based_(YYYY.MM.DD)-58a6ff?style=for-the-badge&labelColor=0d1117)
![Platform](https://img.shields.io/badge/Platform-Windows-58a6ff?style=for-the-badge&logo=windows&logoColor=white&labelColor=0d1117)
![License](https://img.shields.io/badge/License-See_LICENSE.txt-58a6ff?style=for-the-badge&labelColor=0d1117)

</div>

---

PCAP Sentry parses network captures (`.pcap` / `.pcapng`), summarizes traffic statistics, and provides heuristic signals to help triage suspicious network activity.

## Features

| | Feature |
|---|---|
| 🔍 | **Analyzes PCAP/PCAPNG files** for signs of malicious activity |
| 📊 | **Scores network traffic** with a risk rating from 0–100 |
| 🔑 | **Extracts credentials** from cleartext protocols (FTP, HTTP, Telnet, etc.) |
| 🖧 | **Discovers hosts** including IP addresses, MAC addresses, and hostnames |
| 🛡️ | **Detects C2 and exfiltration** patterns automatically |
| 🦈 | **Generates Wireshark filters** for follow-up investigation |
| 🌐 | **Queries threat intelligence feeds** for known-bad indicators |
| 🧠 | **Learns from your data** via a trainable knowledge base and optional ML model |
| 💬 | **Chat interface** powered by a local LLM (Ollama or OpenAI-compatible) |
| ♻️ | **LLM status is now saved and restored automatically** |

## Quick Start

### Option 1: Installer (Recommended)

1. Download **PCAP_Sentry_Setup.exe** from the [Releases](https://github.com/industrial-dave/PCAP-Sentry/releases) page.
2. Run the installer and follow the prompts.
3. Launch PCAP Sentry from the Start Menu or desktop shortcut.

### Option 2: Run from Source

```bash
git clone https://github.com/industrial-dave/PCAP-Sentry.git
cd PCAP-Sentry
python -m venv .venv
.venv\Scripts\activate.bat
pip install -r requirements.txt
python Python/pcap_sentry_gui.py
```

**Requirements:** Python 3.14+, Windows 10/11 (64-bit)

## System Requirements

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| **OS** | Windows 10 (64-bit) | Windows 10/11 (64-bit) |
| **RAM** | 4 GB | 8 GB or more |
| **Disk Space** | 200 MB | 500 MB+ |
| **Runtime** | VC++ Redistributable 2015+ | Included with installer |

## Documentation

- **[User Manual](USER_MANUAL.md)** — Full guide covering installation, analysis, training, settings, and troubleshooting
- **[Update System](UPDATER.md)** — Technical details on the built-in update mechanism
- **[Version Log](VERSION_LOG.md)** — Changelog

## Project Structure

```
Python/
├── pcap_sentry_gui.py        # Main application (GUI + analysis engine)
├── update_checker.py          # GitHub release update checker
├── threat_intelligence.py     # Threat intel integration (OTX, URLhaus)
└── enhanced_ml_trainer.py     # ML model training module
assets/
├── pcap_sentry.ico            # Application icon
installer/
├── PCAP_Sentry.iss            # Inno Setup installer script
```

## Building

### Build the EXE

```bash
build_exe.bat
```

### Build the Installer

```bash
build_installer.bat
```

Both scripts auto-increment the version, build the artifact, and optionally push to GitHub and create a release. Pass `-NoPush` to skip the git push, or `-Notes "description"` to set release notes.

## License

See [LICENSE.txt](LICENSE.txt) for license terms.
