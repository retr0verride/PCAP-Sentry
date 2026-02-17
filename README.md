<div align="center">

<img src="assets/pcap_sentry.ico" alt="PCAP Sentry" width="96" />

# PCAP Sentry

### Learn Malware Network Traffic Analysis — Beginner-Friendly Educational Tool

![Version](https://img.shields.io/badge/Version-Date_Based_(YYYY.MM.DD)-58a6ff?style=for-the-badge&labelColor=0d1117)
![Platform](https://img.shields.io/badge/Platform-Windows-58a6ff?style=for-the-badge&logo=windows&logoColor=white&labelColor=0d1117)
![License](https://img.shields.io/badge/License-GPL_v3-58a6ff?style=for-the-badge&labelColor=0d1117)

[![CI](https://github.com/industrial-dave/PCAP-Sentry/actions/workflows/ci.yml/badge.svg)](https://github.com/industrial-dave/PCAP-Sentry/actions/workflows/ci.yml) [![OpenSSF Best Practices](https://www.bestpractices.dev/projects/11952/badge)](https://www.bestpractices.dev/projects/11952)

</div>

---

**PCAP Sentry is a beginner-friendly educational tool for learning to identify malware network traffic patterns.** It analyzes network packet captures (`.pcap` / `.pcapng`) and teaches you how to recognize suspicious activity with clear explanations and hands-on practice.

## Features

### 🎓 Learn Malware Network Traffic Analysis

- **Beginner-focused explanations** — Understand what makes network traffic suspicious
- **Risk scoring (0–100)** — Learn which patterns indicate malicious behavior
- **Behavioral detection** — Identify beaconing, DNS tunneling, port scanning, data exfiltration
- **Real-world threat intel** — See how malicious IPs, URLs, and domains are flagged by security researchers
- **AI-powered guidance** — Ask questions and get plain-language explanations via local LLM chat

### 🔍 Hands-On Analysis Tools

- **Credential extraction** — Discover how attackers steal passwords from unencrypted protocols
- **C2 pattern detection** — Learn to spot command-and-control communication
- **Wireshark integration** — Generate filters for deeper packet investigation
- **Trainable knowledge base** — Build your own malware signature library as you learn

### 🛡️ Safe & Offline-Capable

- **Works offline** — Practice with local models and threat databases
- **Privacy-first** — Optional cloud features, nothing shared without permission
- **Secure by design** — Built with best practices for handling untrusted network data

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
- **[Version Log](VERSION_LOG.md)** — Changelog
- **[Test Coverage](TEST_COVERAGE.md)** — Coverage analysis and improvement roadmap
- **[Test Policy Evidence](TEST_POLICY_EVIDENCE.md)** — Proof that testing policy is followed for all major changes
- **[CI/CD](CI_CD.md)** — Continuous integration and automated testing infrastructure
- **[Code Quality](CODE_QUALITY.md)** — Linting and static analysis tools (Ruff, Bandit, Safety)
- **[Linting Policy](LINTING_POLICY.md)** — Maximum strictness approach and pragmatic exceptions
- **[Linter Evidence](LINTER_EVIDENCE.md)** — Proof that linter tools are configured and actively used
- **[Secure Design Evidence](SECURE_DESIGN_EVIDENCE.md)** — Proof that developers know how to design secure software (OWASP, CWE coverage, cryptographic compliance)
- **[Security Review (2026-02-15)](SECURITY_REVIEW_2026-02-15.md)** — Comprehensive security audit and code quality assessment (95/100 security rating, 0 medium/high vulnerabilities)

## Security Automation

- **CI/CD Pipeline**: GitHub Actions runs automated tests, code quality checks, and security scans on every push and pull request (see [CI_CD.md](CI_CD.md))
- **CodeQL scanning** runs on pushes, pull requests, and a weekly schedule via `.github/workflows/codeql.yml`
- **Dependency scanning**: Safety and Bandit security tools scan for vulnerabilities in CI
- **Release checksums** are generated locally by `build_release.bat` after all assets are uploaded and published as `SHA256SUMS.txt`; a manual-trigger GitHub Actions workflow (`.github/workflows/release-checksums.yml`) is available as a fallback
- **Download verification**: The built-in updater automatically verifies downloaded EXE files against the published `SHA256SUMS.txt` hashes before execution, with a second verification at launch time (TOCTOU prevention)
- **ML model integrity**: Trained models are signed with HMAC-SHA256 using a persisted random secret key and verified before loading to prevent deserialization attacks
- **Credential storage**: LLM API keys are stored in the OS credential manager (Windows Credential Manager via `keyring`) when available, with automatic migration from plaintext settings
- **LLM endpoint validation**: Only `http://` and `https://` schemes are accepted; plaintext HTTP to non-localhost hosts is blocked
- **URL scheme validation**: Centralized `_safe_urlopen()` wrapper prevents file:// and other dangerous URL schemes (CWE-22 defense-in-depth)
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
pytest tests/                     # Run all tests (21 tests)
pytest tests/test_stability.py    # Core functionality and security (14 tests)
pytest tests/test_stress.py       # Performance and scalability (7 tests)
pytest -v                         # Verbose output
```

**Test Coverage:** 21 tests (100% pass rate), 7% code coverage
- ✅ Stability tests validate core functionality, input validation, and security features
- ✅ Stress tests verify performance (783K items/sec), memory efficiency (100% cleanup), and thread safety
- ✅ Security score: 100/100 (production-ready)
- 📊 Coverage report: `pytest tests/` generates htmlcov/index.html

See [TEST_COVERAGE.md](TEST_COVERAGE.md) for coverage analysis and [SECURITY_REVIEW_2026-02-15.md](SECURITY_REVIEW_2026-02-15.md) for the complete security audit.

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

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for:
- How to report bugs and request features
- Development setup and coding standards
- Pull request process
- Security vulnerability reporting

Quick links:
- [Report a Bug](https://github.com/industrial-dave/PCAP-Sentry/issues/new?template=bug_report.yml)
- [Request a Feature](https://github.com/industrial-dave/PCAP-Sentry/issues/new?template=feature_request.yml)
- [View All Issues](https://github.com/industrial-dave/PCAP-Sentry/issues)

## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

Copyright (C) 2026 industrial-dave
