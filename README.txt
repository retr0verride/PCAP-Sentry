PCAP Sentry - Malware Analysis Console

PCAP Sentry is a malware analysis console for PCAP files. It parses
network captures, summarizes traffic statistics, and provides heuristic
signals to help triage suspicious activity.

Installation

Option 1: Download Installer
The latest installer is available in the dist/ folder:
- PCAP_Sentry_Setup.exe (Recommended for end users)

To install:
1. Download PCAP_Sentry_Setup.exe from the repository
2. Run the installer and follow the prompts
3. Choose installation directory (default: C:\Program Files\PCAP Sentry)
4. Create desktop shortcut (optional)
5. Launch PCAP Sentry from the Start menu or desktop

Option 2: Run from Source
For development or custom deployments:
1. Clone the repository
2. Install Python 3.10+
3. Create virtual environment: python -m venv .venv
4. Activate: .venv\Scripts\activate.bat
5. Install dependencies: pip install -r requirements.txt
6. Run: python Python/pcap_sentry_gui.py

Notes
- Large PCAP files can take several minutes to parse.
- App data is stored under the user profile if the install directory is not
  writable.
- To bundle the VC++ runtime in the installer, run download_vcredist.ps1 before
  building.
- Performance has been optimized for 4-6x faster analysis with KB caching and
  top-K similarity filtering.

Support
If you encounter issues, capture logs from the build process and note the
steps to reproduce the problem.
