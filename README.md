<div align="center">

<img src="assets/pcap_sentry.ico" alt="PCAP Sentry" width="96" />

# PCAP Sentry

### Malware Analysis and Education Console for Network Packet Captures

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
| 🔬 | **Behavioral anomaly detection** — beaconing, DNS tunneling, port scanning, SYN floods, data exfiltration |
| 🦈 | **Generates Wireshark filters** for follow-up investigation |
| 🌐 | **Concurrent threat intelligence** — queries OTX, URLhaus & AbuseIPDB in parallel with connection pooling |
| 🧠 | **Learns from your data** via a trainable knowledge base and optional ML model (25-feature vector) |
| 💬 | **Chat interface** powered by a local LLM (Ollama, offline) or OpenAI-compatible endpoint (local or cloud) |
| ♻️ | **LLM status is now saved and restored automatically** |
| 🔒 | **Security hardened** with SHA-256 download verification, HMAC model integrity, OS credential storage, path-traversal guards, input sanitization, response-size limits, and API-key-over-HTTP protection |
| ⚡ | **Optimized analysis engine** with cached vector computations, mask-based filtering, and centralized LLM retry logic |
| 🐍 | **Python 3.14 compatible** with onedir build architecture for reliable DLL loading and dependency management |

## Quick Start

### Option 1: Installer (Recommended)

1. Download **PCAP_Sentry_Setup.exe** from the [Releases](https://github.com/industrial-dave/PCAP-Sentry/releases) page.
2. Run the installer and follow the prompts.
3. Launch PCAP Sentry from the Start Menu or desktop shortcut.
4. To set up a local LLM, open **Preferences** and click **Manage LLM Servers…** to install Ollama, LM Studio, GPT4All, or Jan.
5. On exit, PCAP Sentry will ask whether to stop any running local LLM server.

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

| Requirement | Minimum | Optimal |
|-------------|---------|---------|
| **OS** | Windows 10 (64-bit) | Windows 11 (64-bit) |
| **CPU** | 2 cores | 4+ cores |
| **RAM** | 4 GB | 16 GB (32 GB with local LLM) |
| **Disk Space** | 200 MB | 1 GB+ (+4–10 GB per LLM model) |
| **Runtime** | VC++ Redistributable 2015+ | Included with installer |

## Documentation

- **[User Manual](USER_MANUAL.md)** — Full guide covering installation, analysis, training, settings, and troubleshooting
- **[Update System](UPDATER.md)** — Technical details on the built-in update mechanism
- **[Update System Simplified](UPDATE_SYSTEM_SIMPLIFIED.md)** — Recent simplification improvements for reliability
- **[Version Log](VERSION_LOG.md)** — Changelog
- **[Test Summary](TEST_SUMMARY.md)** — Comprehensive test results and performance benchmarks
- **[Code Review Report](CODE_REVIEW_REPORT.md)** — Security audit and code quality assessment (95% security score)

## Security Automation

- **CodeQL scanning** runs on pushes, pull requests, and a weekly schedule via `.github/workflows/codeql.yml`.
- **Release checksums** are generated locally by `build_release.bat` after all assets are uploaded and published as `SHA256SUMS.txt`; a manual-trigger GitHub Actions workflow (`.github/workflows/release-checksums.yml`) is available as a fallback.
- **Download verification**: The built-in updater automatically verifies downloaded EXE files against the published `SHA256SUMS.txt` hashes before execution, with a second verification at launch time (TOCTOU prevention).
- **ML model integrity**: Trained models are signed with HMAC-SHA256 using a persisted random secret key and verified before loading to prevent deserialization attacks.
- **Credential storage**: LLM API keys are stored in the OS credential manager (Windows Credential Manager via `keyring`) when available, with automatic migration from plaintext settings.
- **LLM endpoint validation**: Only `http://` and `https://` schemes are accepted; plaintext HTTP to non-localhost hosts is blocked.
- **Atomic file writes**: Settings and knowledge base saves use `tempfile.mkstemp` + `os.replace` to prevent symlink/race attacks.
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
├── threat_intelligence.py     # Concurrent threat intel (OTX, URLhaus, AbuseIPDB) with connection pooling
└── enhanced_ml_trainer.py     # Optional local ML model training/inference (25-feature LogisticRegression)
assets/
├── pcap_sentry.ico            # Default application icon
├── custom.ico                 # Optional preferred icon if present
├── vcredist_x64.exe           # Optional bundled VC++ redistributable (if downloaded)
installer/
├── PCAP_Sentry.iss            # Inno Setup installer (uninstall prompts, KB cleanup)
dist/
├── PCAP_Sentry/               # Onedir build (Python 3.14+ compatible)
│   ├── PCAP_Sentry.exe        # Main executable
│   └── _internal/             # Dependencies (Python DLLs, libraries)
└── PCAP_Sentry_Setup.exe      # Installer (includes all files)
```

## Testing

### Run Tests

```bash
python tests/test_stability.py   # Core functionality and security (10 tests)
python tests/test_stress.py      # Performance and scalability (7 tests)
```

**Test Coverage:** 17 tests (100% pass rate)
- ✅ Stability tests validate core functionality, input validation, and security features
- ✅ Stress tests verify performance (783K items/sec), memory efficiency (100% cleanup), and thread safety
- ✅ Security score: 100/100 (production-ready)

See [TEST_SUMMARY.md](TEST_SUMMARY.md) for detailed results and [CODE_REVIEW_REPORT.md](CODE_REVIEW_REPORT.md) for the complete security audit.

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
