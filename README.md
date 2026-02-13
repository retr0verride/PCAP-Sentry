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
| 💬 | **Chat interface** powered by a local LLM (Ollama, offline) or OpenAI-compatible endpoint (local or cloud) |
| ♻️ | **LLM status is now saved and restored automatically** |
| 🔒 | **Security hardened** with path-traversal guards, input sanitization, model-name validation, and response-size limits |
| ⚡ | **Optimized analysis engine** with cached vector computations, mask-based filtering, and centralized LLM retry logic |

## Quick Start

### Option 1: Installer (Recommended)

1. Download **PCAP_Sentry_Setup.exe** from the [Releases](https://github.com/industrial-dave/PCAP-Sentry/releases) page.
2. Run the installer and follow the prompts.
3. Optional: choose **Install Ollama** and select one or more models to pull.
	- The Ollama Models page supports selecting multiple models via checkboxes.
	- The page includes a link to the Ollama model library with descriptions.
	- Installer progress is shown for runtime setup and each selected model.
	- Ollama is started headless for model pulls; the desktop UI is not required.
	- In Preferences, Stop Ollama on exit is enabled by default and can be changed.
4. Launch PCAP Sentry from the Start Menu or desktop shortcut.

Optional: download `pcap_knowledge_base_offline.json` from the [Releases](https://github.com/industrial-dave/PCAP-Sentry/releases) page and import it via **Knowledge Base** > **Restore** to use it as a starter KB.

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

## Security Automation

- **CodeQL scanning** runs on pushes, pull requests, and a weekly schedule via `.github/workflows/codeql.yml`.
- **Release checksums** are generated and uploaded as `SHA256SUMS.txt` for each published GitHub release via `.github/workflows/release-checksums.yml`.
- Users can verify downloaded artifacts against the published SHA-256 checksum file.

## Project Structure

```
build_exe.bat                 # Builds EXE, updates version, can optionally commit/push/release
build_installer.bat           # Builds installer, updates version, local-only by default; pass -Push to publish
run_app.bat                   # Runs the GUI from source (uses .venv Python when available)
PCAP_Sentry.spec              # PyInstaller build specification
requirements.txt              # Python dependencies for source/dev builds
version_info.txt              # Windows version metadata embedded into EXE/installer
VERSION_LOG.md                # Human-readable changelog updated by version script
UPDATER.md                    # Update subsystem behavior and constraints
USER_MANUAL.md                # End-user documentation
Python/
├── pcap_sentry_gui.py        # Main application (GUI + analysis engine)
├── update_checker.py          # GitHub release checker + deferred update replacement logic
├── threat_intelligence.py     # Threat intel integration (OTX, URLhaus)
└── enhanced_ml_trainer.py     # Optional local ML model training/inference helper
assets/
├── pcap_sentry.ico            # Default application icon
├── custom.ico                 # Optional preferred icon if present
├── vcredist_x64.exe           # Optional bundled VC++ redistributable (if downloaded)
installer/
├── PCAP_Sentry.iss            # Inno Setup installer (Ollama model management, uninstall prompts)
dist/                          # Build outputs (PCAP_Sentry.exe, PCAP_Sentry_Setup.exe)
build/                         # Intermediate build artifacts generated by PyInstaller
logs/                          # Build/runtime logs
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

### Build EXE + Installer (Single Version Release)

```bash
build_release.bat
```

Both scripts auto-increment the version and build artifacts; publish behavior is script-specific (details below).

- `build_exe.bat`: updates version, builds `PCAP_Sentry.exe`, then commits/pushes/releases unless `-NoPush` is provided.
- `build_installer.bat`: updates version and builds `PCAP_Sentry_Setup.exe`; it is local-only by default and only commits/pushes/releases when `-Push` is provided. Use `-Release` to upload the installer to an existing release without pushing.
- `build_release.bat`: recommended for publishing both EXE and installer to the same version tag. It lets `build_exe.bat` bump once, then reuses that version for the installer.
- Both scripts support `-Notes "description"` for version log/release notes text.

## License

See [LICENSE.txt](LICENSE.txt) for license terms.
