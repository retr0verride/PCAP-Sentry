<div align="center">

<img src="assets/pcap_sentry_512.png" alt="PCAP Sentry" width="96" />

# PCAP Sentry

### Learn Malware Network Traffic Analysis — Beginner-Friendly Educational Tool

![Version](https://img.shields.io/badge/Version-Date_Based_(YYYY.MM.DD)-58a6ff?style=for-the-badge&labelColor=0d1117)
![Platform](https://img.shields.io/badge/Platform-Windows-58a6ff?style=for-the-badge&logo=windows&logoColor=white&labelColor=0d1117)
![License](https://img.shields.io/badge/License-GPL_v3-58a6ff?style=for-the-badge&labelColor=0d1117)

[![CI](https://github.com/retr0verride/PCAP-Sentry/actions/workflows/ci.yml/badge.svg)](https://github.com/retr0verride/PCAP-Sentry/actions/workflows/ci.yml) [![OpenSSF Best Practices](https://www.bestpractices.dev/projects/11952/badge)](https://www.bestpractices.dev/projects/11952)

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
- **Six-phase malware analysis methodology** — Education tab walks through a structured analyst workflow (filter → headers → C&C → exfil → spread → client identity) using the actual flows from each capture; `[EXFIL]` flows include plain-language inference of what was likely stolen based on port number and contacted domains (Discord webhooks, Telegram Bot API, paste sites, anonymous file hosts, ngrok tunnels, cloud storage)

### 🔍 Hands-On Analysis Tools

- **Credential extraction** — Discover how attackers steal passwords from unencrypted protocols
- **C2 pattern detection** — Learn to spot command-and-control communication
- **Wireshark integration** — Generate filters for deeper packet investigation
- **Trainable knowledge base** — Build your own malware signature library as you learn; PARRY chat assistant can label captures, confirm safe flows, manage trusted IPs, and retrain the model — all without an LLM
- **Pre-trained ML model** — Ships with a RandomForest baseline trained on 13 realistic traffic profiles; improves automatically as you label your own captures; learns internal vs external traffic ratios for better contextual scoring
- **ThreatFox & GreyNoise integration** — abuse.ch ThreatFox and GreyNoise community lookups work out-of-the-box without any API key
- **Export results** — Save full analysis results (verdict, risk score, TI findings, flows) as JSON via File → Export Results as JSON

### 🛡️ Safe & Offline-Capable

- **Works offline** — Practice with local models and threat databases
- **Privacy-first** — Optional cloud features, nothing shared without permission
- **Secure by design** — Built with best practices for handling untrusted network data

## Quick Start

### Option 1: Windows Package Manager (winget) - Easiest

```powershell
winget install retr0verride.PCAP-Sentry
```

**Note:** Pending review ([PR #340251](https://github.com/microsoft/winget-pkgs/pull/340251)). Once approved, this will be the fastest way to install.

### Option 2: Installer (Recommended)

1. Download **PCAP_Sentry_Setup.exe** from the [Releases](https://github.com/retr0verride/PCAP-Sentry/releases) page.
2. Run the installer and follow the prompts.
3. Launch PCAP Sentry from the Start Menu or desktop shortcut.
4. To set up a local LLM, open **Preferences** and click **Manage LLM Servers…** to install Ollama, LM Studio, GPT4All, or Jan.
5. On exit, PCAP Sentry will ask whether to stop any running local LLM server.

Optional: download `pcap_knowledge_base_offline.json` from the [Releases](https://github.com/retr0verride/PCAP-Sentry/releases) page and import it via **Knowledge Base** > **Restore** to use it as a starter KB.

### Option 3: Run from Source

```bash
git clone https://github.com/retr0verride/PCAP-Sentry.git
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
- **ML model integrity**: Trained models are signed with HMAC-SHA256 using a persisted random secret key and verified before loading to prevent deserialization attacks; the shipped baseline is integrity-checked against a SHA-256 file before being copied to the user's app data directory
- **Credential storage**: All API keys (LLM providers, AlienVault OTX, AbuseIPDB, GreyNoise, VirusTotal) and the model encryption key are each stored under a unique Windows Credential Manager target of the form `PCAP_Sentry/<key_name>` via `keyring`, with a fixed username `"credential"`; each key has its own WCM target so no two credentials can overwrite each other
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
├── threat_intelligence.py     # Concurrent threat intel (OTX, URLhaus, AbuseIPDB, ThreatFox, GreyNoise) with persistent cache
└── enhanced_ml_trainer.py     # Optional standalone ML trainer class
assets/
├── pcap_sentry.ico            # Multi-size ICO (16–256px, used by Windows taskbar/title bar)
├── pcap_sentry_512.png        # 512px master PNG (app header logo, spin animation source)
├── pcap_sentry_256.png        # 256px PNG
├── pcap_sentry_128.png        # 128px PNG
├── pcap_sentry_48.png         # 48px PNG
├── custom.ico                 # Optional preferred icon override (if present, used instead)
├── pcap_sentry_baseline_model.pkl         # Pre-trained RandomForest baseline model (199 KB)
├── pcap_sentry_baseline_model.pkl.sha256  # SHA-256 integrity hash for the baseline model
├── pcap_sentry_seed_data.json             # 146 seed feature rows used in combined retraining
├── vcredist_x64.exe           # Optional bundled VC++ redistributable (if downloaded)
generate_seed_data.py          # Dev-time script: regenerates seed data + baseline model from synthetic profiles
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
- [Report a Bug](https://github.com/retr0verride/PCAP-Sentry/issues/new?template=bug_report.yml)
- [Request a Feature](https://github.com/retr0verride/PCAP-Sentry/issues/new?template=feature_request.yml)
- [View All Issues](https://github.com/retr0verride/PCAP-Sentry/issues)

## ⚠️ Disclaimer

**EDUCATIONAL TOOL - NOT FOR PRODUCTION USE**

PCAP Sentry is designed for **learning purposes only**. It should NOT be used for:
- Production security decisions
- Legal proceedings or investigations
- Mission-critical threat detection
- Compliance requirements

**Important Limitations:**
- ❌ **No accuracy guarantee** — May produce false positives or miss real threats
- ❌ **Not a substitute** for professional security analysis tools
- ❌ **Results are not validated** — Manual verification required
- ⚠️ **Use responsibly** — Ensure you have legal authority to analyze network traffic

By using this tool, you acknowledge:
1. All analysis results are for educational reference only
2. You are responsible for verifying any findings independently  
3. You assume all risks associated with analyzing network captures
4. The developers are not liable for decisions made based on this tool's output

See [LICENSE](LICENSE) for full warranty disclaimer and limitation of liability.

## 🔒 Legal Compliance & Export Control

### Network Monitoring Legality

**⚠️ IMPORTANT:** Network traffic analysis may be subject to legal restrictions in your jurisdiction.

**You are responsible for:**
- ✅ Obtaining **legal authorization** before capturing or analyzing network traffic
- ✅ Complying with **wiretapping and electronic surveillance laws** (e.g., 18 U.S.C. § 2511 in the United States, GDPR in the EU)
- ✅ Ensuring you have **consent from network owners** or participants
- ✅ Respecting **privacy rights** and confidentiality obligations
- ✅ Following **corporate policies** regarding network monitoring

**Prohibited Uses:**
- ❌ Intercepting communications without legal authority
- ❌ Unauthorized network access or surveillance
- ❌ Violating wiretapping, privacy, or computer fraud laws
- ❌ Any illegal or malicious activity

**If in doubt, consult a qualified attorney** before analyzing network traffic.

### Export Control Notice

This software uses cryptographic functions and may be subject to export control regulations.

**U.S. Export Controls:**
- This software may be subject to U.S. Export Administration Regulations (EAR)
- Public availability and standard cryptography library usage may qualify for exemptions
- Users are responsible for compliance with applicable export control laws

**Restricted Destinations:**
- Do not export to embargoed countries (Cuba, Iran, North Korea, Syria, Russia-occupied regions)
- Do not export to prohibited parties (Denied Persons List, Entity List, etc.)

**International Users:**
- Verify compliance with your local export/import regulations
- Some features may be restricted in certain jurisdictions

**Disclaimer:** Export control laws are complex and change frequently. This notice is informational only and does not constitute legal advice. Consult an export control attorney or the U.S. Department of Commerce Bureau of Industry and Security for specific guidance.

### Dual-Use Technology Notice

This software is a **dual-use security tool** that can be used for both defensive (security analysis) and potentially offensive purposes.

**Intended Use:** Educational training and defensive security research only.

**Prohibited Use:** This software must not be used for:
- ❌ Unauthorized computer access
- ❌ Network attacks or exploitation
- ❌ Violation of computer fraud laws (e.g., CFAA in the U.S.)
- ❌ Privacy violations or illegal surveillance

**User Responsibility:** You are solely responsible for ensuring your use of this software complies with all applicable laws and regulations.

## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

**NO WARRANTY:** This program comes with ABSOLUTELY NO WARRANTY. This is free software, and you are welcome to redistribute it under certain conditions. See LICENSE for details.

Copyright (C) 2026 retr0verride
