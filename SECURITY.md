# Security Policy

## Supported Versions

PCAP Sentry follows a date-based versioning scheme (YYYY.MM.DD-increment). We recommend always using the latest release.

| Version Pattern | Supported          |
| --------------- | ------------------ |
| Latest Release  | :white_check_mark: |
| Older Releases  | :x:                |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

### Responsible Disclosure Policy

We are committed to working with security researchers to address vulnerabilities responsibly.

**Guidelines for Researchers:**
- ✅ Report vulnerabilities privately (not via public issues)
- ✅ Give us reasonable time to fix before public disclosure (90 days preferred)
- ✅ Avoid exploiting vulnerabilities beyond proof-of-concept testing
- ✅ Do not access, modify, or delete user data
- ✅ Use your own test systems, not production environments
- ❌ Do not perform testing that violates laws or terms of service

**What We Promise:**
- Acknowledge receipt within 48 hours
- Work diligently to verify and fix valid issues
- Credit researchers (unless anonymity requested)
- Not pursue legal action against researchers following these guidelines
- Coordinate disclosure timeline with you

**Out of Scope:**
- Vulnerabilities in third-party dependencies (report to upstream)
- Social engineering attacks
- Physical attacks requiring access to user's device
- Issues requiring malicious PCAP files (expected by design)

### Preferred Method: Private Security Advisory

Use GitHub's private security advisory feature:
1. Go to the [Security tab](https://github.com/retr0verride/PCAP-Sentry/security)
2. Click **Report a vulnerability**
3. Fill out the advisory form with:
   - Description of the vulnerability
   - Steps to reproduce
   - Affected versions
   - Potential impact
   - Suggested fix (if any)

### Alternative: Private Email

If you prefer email or cannot use GitHub's advisory feature, contact the repository owner directly through GitHub.

### What to Include

- **Description**: Clear explanation of the vulnerability
- **Impact**: What an attacker could do
- **Reproduction**: Detailed steps to reproduce
- **System Info**: OS, Python version, PCAP Sentry version
- **Proof of Concept**: Code/files if applicable (use a private gist or attachment)
- **Suggested Fix**: If you have a recommendation

## Response Timeline

- **Initial Response**: Within 48 hours
- **Status Update**: Within 7 days
- **Fix Timeline**: Depends on severity
  - Critical: 7-14 days
  - High: 14-30 days
  - Medium: 30-60 days
  - Low: Next planned release

## Security Practices

PCAP Sentry implements multiple security controls:

### Input Validation
- Path traversal protection for file operations
- PCAP file signature verification
- URL scheme validation (centralized `_safe_urlopen()` wrapper blocks file://, ftp://, etc.)
- URL validation and sanitization
- Size limits on API responses (10MB)

### Cryptographic Security
- SHA-256 verification for downloads
- HMAC validation for ML model integrity
- Secure random number generation for cryptographic operations

### Credential Management
- OS native credential storage (Windows Credential Manager)
- No hardcoded credentials or API keys
- API key protection (blocks transmission over HTTP)

### Network Security
- TLS verification for HTTPS requests
- Connection pooling with timeout limits
- User-Agent identification
- Response size limits

### Code Security
- Regular dependency updates
- CodeQL scanning via GitHub Actions
- Static analysis in development
- Input sanitization throughout codebase

### Data Privacy & Encryption
- **Chat history** encrypted using Fernet symmetric encryption (stored in `%LOCALAPPDATA%\PCAP_Sentry\settings.json`)
- **Knowledge Base** encrypted on disk to protect network analysis data (IP addresses, ports, protocols, IOCs)
- **API keys** stored in OS credential manager (Windows Credential Manager / keyring)
- Encryption keys stored securely in OS keyring, never in code or config files
- Automatic migration from plaintext to encrypted format on first save

**Files That Should NEVER Be Committed:**
- `settings.json` - Contains encrypted chat history and user preferences
- `pcap_knowledge_base_offline.json` in AppData - Contains real network analysis data
- `*.pcap` / `*.pcapng` - Network capture files may contain sensitive traffic
- `app_errors.log` / `startup_errors.log` - May contain system paths or error details
- Any files in `%LOCALAPPDATA%\PCAP_Sentry\` - User runtime data directory

The repository includes an empty template `Python/pcap_knowledge_base_offline.json` for distribution only.

## Responsible Use

### Legal Compliance

**Users are responsible for complying with all applicable laws** when using PCAP Sentry, including:

⚠️ **Network Monitoring Laws:**
- Wiretapping and electronic surveillance regulations (e.g., 18 U.S.C. § 2511 in the U.S.)
- Computer fraud and abuse laws (e.g., CFAA in the U.S.)
- Privacy regulations (GDPR, CCPA, etc.)
- National and local data protection laws

⚠️ **Authorization Required:**
- Obtain legal authority before capturing or analyzing network traffic
- Ensure you have consent from network owners or participants
- Follow corporate policies regarding network monitoring
- Respect privacy rights and confidentiality obligations

⚠️ **Export Control:**
- This software may be subject to U.S. Export Administration Regulations (EAR)
- Do not export to embargoed countries or denied parties
- Verify compliance with your local export/import regulations

**Prohibited Uses:**
- ❌ Unauthorized network interception or surveillance
- ❌ Violating wiretapping, privacy, or computer fraud laws
- ❌ Accessing networks without permission
- ❌ Any illegal or malicious activity

**Consult legal counsel** if you have questions about lawful use in your jurisdiction.

### Educational Purpose

PCAP Sentry is designed for **defensive security education and research**. The project:

- ✅ Supports learning and skill development
- ✅ Enables security research and analysis
- ✅ Helps identify malicious network patterns
- ❌ Does not promote or facilitate illegal activities
- ❌ Is not intended for offensive security operations

**Users must verify they have legal authority** to analyze network traffic before using this tool.

## Scope

**In Scope:**
- PCAP Sentry application code (Python/)
- Build and installer scripts
- Bundled dependencies in releases

**Out of Scope:**
- Third-party packages (report to upstream)
- User-provided PCAP files (malicious files by design)
- Local LLM servers (Ollama, LM Studio, etc.)
- Operating system vulnerabilities

## Disclosure Policy

- We follow **coordinated disclosure** principles
- We will credit reporters (unless anonymity is requested)
- Security fixes will be released with a security advisory
- CVE IDs will be requested for significant vulnerabilities

## Security Updates

Security updates are announced through:
- GitHub Security Advisories
- Release notes with `[SECURITY]` prefix
- Commits tagged with `security:` type

## Recognition

We appreciate security researchers who report vulnerabilities responsibly. Contributors will be credited in:
- Security advisories
- Release notes
- This SECURITY.md file (Hall of Fame section, if applicable)

Thank you for helping keep PCAP Sentry secure!
