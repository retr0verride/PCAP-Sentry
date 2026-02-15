PCAP Sentry - Malware Analysis and Education Console for Network Packet Captures
=================================================================================

PCAP Sentry parses network captures (.pcap / .pcapng), summarizes
traffic statistics, and provides heuristic signals to help triage
suspicious network activity.

Features
--------
- Analyzes PCAP/PCAPNG files for signs of malicious activity
- Scores network traffic with a risk rating from 0-100
- Behavioral anomaly detection (beaconing, DNS tunneling, port scanning,
  data exfiltration, SYN floods)
- Extracts credentials from cleartext protocols (FTP, HTTP, Telnet, etc.)
- Discovers hosts including IP addresses, MAC addresses, and hostnames
- Detects C2 and exfiltration patterns automatically
- Generates Wireshark filters for follow-up investigation
- Concurrent threat intelligence lookups (AlienVault OTX, URLhaus, AbuseIPDB)
- Trainable knowledge base and optional ML model (25-feature vector)
- Chat interface powered by a local LLM (Ollama) or OpenAI-compatible endpoint
- Security hardened with SHA-256 download verification, HMAC model integrity, OS credential storage, input sanitization, response-size limits, and API-key-over-HTTP protection
- On exit, prompts to stop any running local LLM server

System Requirements
-------------------
- Windows 10/11 (64-bit)
- 4 GB RAM minimum (8 GB recommended)
- VC++ Redistributable 2015+ (included with installer)

Documentation
-------------
See USER_MANUAL.md for the full user guide.
See VERSION_LOG.md for the changelog.

License
-------
See LICENSE.txt for license terms.

GitHub: https://github.com/industrial-dave/PCAP-Sentry
