# Contributing to PCAP Sentry

Thank you for your interest in contributing to PCAP Sentry! This document provides guidelines for contributing to the project.

## Code of Conduct

This project is committed to providing a welcoming and inclusive experience for everyone. Be respectful and considerate in all interactions.

## Responsible Use & Ethics

**PCAP Sentry is an educational tool for defensive security research.** By contributing, you agree:

✅ **DO:**
- Contribute features that help users **learn** network traffic analysis
- Focus on **defensive** security capabilities (threat detection, analysis, research)
- Support lawful and ethical use cases
- Document security implications of new features
- Follow responsible disclosure for security issues

❌ **DO NOT:**
- Add features designed primarily for **offensive** hacking or unauthorized access
- Include exploits, attack tools, or malicious code
- Contribute code that facilitates illegal surveillance or privacy violations
- Promote or enable unauthorized network interception
- Include techniques primarily useful for evading detection

**If in doubt**, open an issue to discuss whether a feature aligns with the project's educational and defensive security mission.

## How Can I Contribute?

### Reporting Bugs

Before creating a bug report:
- **Check existing issues** to avoid duplicates
- **Test with the latest release** to ensure the bug still exists
- **Gather details**: version, OS, steps to reproduce, expected vs actual behavior

Use the [Bug Report template](https://github.com/retr0verride/PCAP-Sentry/issues/new?template=bug_report.yml) when filing issues.

### Suggesting Features

Feature suggestions are welcome! Use the [Feature Request template](https://github.com/retr0verride/PCAP-Sentry/issues/new?template=feature_request.yml).

Consider:
- How does it fit with PCAP Sentry's focus on **beginner education** in malware network traffic identification?
- Would this help users learn to recognize malicious network patterns?
- Would this benefit multiple users?
- Is it feasible given the project's architecture?

### Pull Requests

1. **Fork** the repository
2. **Create a branch** from `main`: `git checkout -b feature/your-feature-name`
3. **Make your changes** following the coding standards below
4. **Add tests for new functionality** - See [Testing Policy](#testing-policy) below
   - **REQUIRED:** All major new functionality MUST include automated tests
   - Run existing tests and add new tests for your changes
   - Ensure tests pass locally before submitting
5. **Commit** with clear messages following [Conventional Commits](https://www.conventionalcommits.org/)
6. **Push** to your fork and submit a pull request

**Note:** Pull requests that add major functionality without tests will not be merged. See the [Testing Policy](#testing-policy) section for details on what requires tests and how to write them.

#### Coding Standards

**Python Style:**
- Follow [PEP 8](https://pep8.org/)
- Use descriptive variable names
- Add docstrings for functions and classes
- Keep functions focused and under 50 lines when possible

**Security:**
- Never hardcode credentials or API keys
- Validate and sanitize all user inputs
- Use secure random number generation for cryptographic purposes
- Follow principle of least privilege

**Comments:**
- Explain *why*, not *what*
- Document security-sensitive code thoroughly
- Keep comments up-to-date with code changes

#### Code Quality Tools

**REQUIRED:** All code must pass linter checks before being merged.

**Ruff Linter:**
PCAP Sentry uses [Ruff](https://docs.astral.sh/ruff/) for fast, comprehensive linting and formatting.

Run before committing:
```bash
# Check for issues
ruff check Python/ tests/

# Auto-fix issues where possible
ruff check --fix Python/ tests/

# Check formatting
ruff format --check Python/ tests/

# Apply formatting
ruff format Python/ tests/
```

**Security Linting:**
```bash
# Scan for security issues
bandit -r Python/

# Check for vulnerable dependencies
safety check
```

**Installation:**
```bash
pip install -r requirements-dev.txt
```

**Configuration:** See [ruff.toml](../ruff.toml) for linting rules and exclusions.

**Note:** CI automatically runs ruff checks on all pull requests. PRs with linting errors will not be merged.

#### Commit Messages

Format: `<type>: <description>`

Types:
- `feat:` - New feature
- `fix:` - Bug fix
- `docs:` - Documentation changes
- `style:` - Code style/formatting (no logic changes)
- `refactor:` - Code restructuring (no behavior changes)
- `test:` - Adding or updating tests
- `security:` - Security improvements
- `perf:` - Performance improvements
- `build:` - Build system changes
- `ci:` - CI/CD changes

Examples:
```
feat: Add DNS tunneling detection heuristic
fix: Prevent crash when parsing malformed PCAP files
security: Implement HMAC verification for ML models
docs: Update installation instructions for Python 3.14
```

### Testing

#### Testing Policy

**REQUIRED:** All major new functionality MUST include automated tests before being merged.

This is a project policy to ensure code quality, prevent regressions, and maintain reliability. When contributing:

- ✅ **New features** → Add tests demonstrating the feature works correctly
- ✅ **Bug fixes** → Add tests that would have caught the bug
- ✅ **Security improvements** → Add tests validating the security measure
- ✅ **API changes** → Update existing tests and add new ones for changed behavior

**What qualifies as "major new functionality":**
- New analysis capabilities (e.g., protocol detection, IOC extraction)
- New security features (e.g., input validation, authentication)
- New data processing functions
- Changes to core algorithms or heuristics
- New API endpoints or interfaces

**Minor changes that may not require tests:**
- Documentation-only changes
- UI layout adjustments (non-functional)
- Simple formatting or style fixes
- Configuration file updates

If unsure whether tests are needed, ask in the pull request—maintainers will provide guidance.

**Policy Compliance:** See [TEST_POLICY_EVIDENCE.md](TEST_POLICY_EVIDENCE.md) for documented proof that this policy is actively followed for all major changes.

#### Running Tests

Run the test suite before submitting:

```bash
pytest tests/                  # Run all tests with coverage
pytest tests/test_stability.py # Run stability tests only
pytest tests/test_stress.py    # Run stress tests only
pytest -v                      # Verbose output
```

View coverage report: Open `htmlcov/index.html` after running tests.

**Continuous Integration**: All pull requests automatically run:
- Test suite on Ubuntu and Windows (Python 3.10, 3.11, 3.12)
- Code quality checks (ruff linter)
- Security scans (safety, bandit)
- Build verification

Your PR must pass CI checks before merging.

#### Writing Tests

Add tests for new features:
- Unit tests for new functions (use `test_` prefix)
- Integration tests for new analysis features
- Security tests for input validation
- All tests use pytest framework with assert statements
- Aim for 60%+ coverage on new non-GUI modules
- See [TEST_COVERAGE.md](TEST_COVERAGE.md) for coverage improvement plan

### Documentation

Update documentation when changing functionality:
- **USER_MANUAL.md** - User-facing feature changes
- **README.md** - Installation, quick start, or overview changes
- **Code comments** - Complex logic or security-sensitive code

## Development Setup

### Prerequisites

- Windows 10/11 (64-bit)
- Python 3.14+
- Git
- Virtual environment recommended

### Setup Steps

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/PCAP-Sentry.git
cd PCAP-Sentry

# Create virtual environment
python -m venv .venv
.venv\Scripts\activate.bat

# Install dependencies
pip install -r requirements.txt

# Run from source
python Python/pcap_sentry_gui.py
```

### Building

```bash
# Build EXE only
build_exe.bat -NoPush

# Build installer only
build_installer.bat

# Build both (for releases)
build_release.bat
```

## Security Vulnerabilities

**Do not** report security vulnerabilities through public GitHub issues.

Instead, email details to the repository owner or use GitHub's private security advisory feature. Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

## OpenSSF Best Practices Compliance

PCAP Sentry follows [OpenSSF (Open Source Security Foundation) Best Practices](https://bestpractices.coreinfrastructure.org/) to ensure high-quality, secure software development. **All contributions must maintain compliance with these standards.**

### Why OpenSSF Best Practices Matter

OpenSSF Best Practices provide industry-standard guidelines for:
- **Security**: Protecting users from vulnerabilities
- **Quality**: Ensuring reliable, well-tested code
- **Transparency**: Maintaining clear documentation and processes
- **Sustainability**: Building maintainable, long-term projects

### Key Requirements for Contributors

When contributing to PCAP Sentry, ensure your changes comply with these OpenSSF requirements:

#### 1. **Testing Requirements** (MUST)
- ✅ All major functionality MUST include automated tests
- ✅ Tests MUST pass before code is merged
- ✅ Security features MUST have corresponding security tests
- 📚 See: [Testing Policy](#testing-policy) above

#### 2. **Static Analysis** (MUST)
- ✅ Code MUST pass Ruff linter checks (runs automatically in CI/CD)
- ✅ Code MUST pass Bandit security scanner (no medium+ vulnerabilities)
- ✅ Fix any static analysis findings before submitting PR
- 📚 See: [Code Quality Tools](#code-quality-tools) above

#### 3. **Vulnerability Response** (MUST)
- ✅ Report security issues privately (not in public issues)
- ✅ Medium+ severity vulnerabilities fixed within 60 days
- ✅ Critical vulnerabilities fixed within 7-14 days
- 📚 See: [SECURITY.md](SECURITY.md) for response timelines

#### 4. **Secure Development** (MUST)
- ✅ No hardcoded credentials or API keys
- ✅ Validate and sanitize all user inputs
- ✅ Use cryptographically secure random number generation
- ✅ Protect against path traversal attacks
- 📚 See: [Coding Standards - Security](#coding-standards) above

#### 5. **Code Review** (MUST)
- ✅ All changes go through pull request review
- ✅ No direct commits to main branch
- ✅ CI/CD checks must pass before merge
- ✅ At least one maintainer approval required

#### 6. **Documentation** (MUST)
- ✅ Update relevant documentation for functional changes
- ✅ Document security-sensitive code thoroughly
- ✅ Keep SECURITY.md accurate if security processes change
- 📚 See: [Documentation](#documentation) above

#### 7. **Dependency Management** (MUST)
- ✅ Keep dependencies up-to-date
- ✅ Use known-good versions (specified in requirements.txt)
- ✅ Scan for vulnerable dependencies (Safety scanner in CI/CD)
- ✅ Justify adding new dependencies in PR description

### OpenSSF Compliance Status

Track the project's OpenSSF compliance:
- 📋 **Checklist**: [OPENSSF_BADGE_CHECKLIST.md](OPENSSF_BADGE_CHECKLIST.md) - All requirements and compliance status
- 🔒 **Security Evidence**: [SECURE_DESIGN_EVIDENCE.md](SECURE_DESIGN_EVIDENCE.md) - Detailed security documentation
- 🧪 **Testing Evidence**: [TEST_POLICY_EVIDENCE.md](TEST_POLICY_EVIDENCE.md) - Test coverage and policy compliance
- 📝 **Policy**: [SECURITY.md](SECURITY.md) - Vulnerability reporting and response

### How CI/CD Enforces Compliance

Every pull request automatically validates OpenSSF requirements:

```yaml
Automated Checks (Required to Pass):
  ✅ Test Suite - All 21 tests across 6 configurations (Ubuntu/Windows × Python 3.10/3.11/3.12)
  ✅ Ruff Linter - 700+ code quality rules
  ✅ Bandit Security Scanner - 30+ security vulnerability checks
  ✅ CodeQL Analysis - Semantic security analysis
  ✅ Safety Scanner - Dependency vulnerability checks
  ✅ Coverage Tracking - Code coverage measurement
```

**Your PR will not be merged if any of these checks fail.** This ensures all code meets OpenSSF standards before reaching production.

### Maintaining Compliance in Your Contribution

**Before submitting your PR:**

1. ✅ **Run tests locally**: `pytest tests/ -v`
2. ✅ **Run linter**: `ruff check Python/ tests/`
3. ✅ **Run security scan**: `bandit -r Python/`
4. ✅ **Add tests for new code**: See [Writing Tests](#writing-tests)
5. ✅ **Document security changes**: Update relevant .md files
6. ✅ **Review OpenSSF checklist**: Ensure your change doesn't break compliance

**During PR review:**

- Maintainers will verify OpenSSF compliance
- CI/CD will automatically check all requirements
- Address any compliance issues before merge

**After merge:**

- Your contribution becomes part of the auditable compliance record
- Changes are reflected in public CI logs
- OpenSSF compliance documentation may be updated

### Questions About OpenSSF Compliance?

- 📖 **General Info**: https://bestpractices.coreinfrastructure.org/
- 📋 **Project Checklist**: [OPENSSF_BADGE_CHECKLIST.md](OPENSSF_BADGE_CHECKLIST.md)
- 💬 **Ask in PR**: Maintainers will help ensure your contribution meets standards
- 🔍 **Check CI Logs**: See what automated checks are failing and why

**Remember:** These requirements exist to protect users and maintain project quality. They're not bureaucratic overhead—they're essential security and quality practices that make PCAP Sentry trustworthy and reliable.

## Recognition

Contributors will be recognized in:
- Pull request merge acknowledgments
- Release notes for significant contributions
- Special recognition for security disclosures

## Questions?

- Check the [User Manual](USER_MANUAL.md)
- Search [existing issues](https://github.com/retr0verride/PCAP-Sentry/issues)
- Open a new issue for clarification

## License

By contributing to PCAP Sentry, you agree that your contributions will be licensed under the [GNU General Public License v3.0](LICENSE).

---

Thank you for helping make PCAP Sentry better! 🛡️
