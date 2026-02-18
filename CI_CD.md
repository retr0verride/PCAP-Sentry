# Continuous Integration & Deployment

This document describes PCAP Sentry's CI/CD infrastructure for automated testing, code quality, and security scanning.

## Overview

[![CI Status](https://github.com/retr0verride/PCAP-Sentry/actions/workflows/ci.yml/badge.svg)](https://github.com/retr0verride/PCAP-Sentry/actions/workflows/ci.yml)

PCAP Sentry uses **GitHub Actions** for continuous integration. Every push to `main` or `develop` and every pull request automatically triggers:

1. **Test Suite** - Automated tests on multiple OS/Python versions
2. **Code Quality** - Linting and formatting checks
3. **Security Scanning** - Vulnerability detection
4. **Build Verification** - Ensure the application builds successfully

## Pre-Deployment Validation

To ensure every deployment meets quality standards, PCAP Sentry implements **automated deployment gates** that validate:

### Automated Pre-Deployment Script

Run `pre_deploy_checks.ps1` before any deployment:

```powershell
# Full validation (recommended)
.\pre_deploy_checks.ps1

# Quick validation (critical checks only)
.\pre_deploy_checks.ps1 -Fast

# With options
.\pre_deploy_checks.ps1 -SkipTests  # Not recommended for production
```

**What it checks:**
- ✅ **Code Quality** - Ruff linting and formatting
- ✅ **Security** - Safety (dependencies) + Bandit (code patterns)
- ✅ **Tests** - Full test suite with coverage requirements
- ✅ **Performance** - Stress/performance test validation
- ✅ **Build** - PyInstaller compilation verification
- ✅ **OpenSSF** - Best practices compliance
- ✅ **Git Status** - Uncommitted changes, branch status

**Exit codes:**
- `0` = All checks passed, safe to deploy
- `1` = One or more checks failed, DO NOT DEPLOY

### Integrated Build Validation

The `build_release.bat` script automatically runs validation before building:

```batch
build_release.bat
```

To bypass validation (NOT RECOMMENDED):
```batch
set PCAP_SKIP_CHECKS=1
build_release.bat
```

### GitHub Actions Deployment Workflow

The `.github/workflows/deploy.yml` workflow enforces all quality gates on tag pushes:

```bash
git tag v2026.02.16-1
git push origin v2026.02.16-1
```

**Deployment Gates:**
1. **Quality Gates** - Linting, formatting, syntax validation
2. **Security Gates** - Bandit, Safety, CodeQL analysis
3. **Test Gates** - Full test suite on Windows & Ubuntu
4. **Build Gates** - PyInstaller build verification
5. **OpenSSF Gates** - Documentation and CI compliance

All gates must pass before deployment is approved. View results in the GitHub Actions tab.

**See also:** [DEPLOYMENT_CHECKLIST.md](DEPLOYMENT_CHECKLIST.md) for detailed manual verification steps.

## GitHub Actions Workflows

### 1. CI Workflow (`.github/workflows/ci.yml`)

**Triggers:**
- Push to `main` or `develop` branch (Python/test files only)
- Pull requests to `main` or `develop` branch
- Manual workflow dispatch

**Jobs:**

#### Test Suite
- **Runs on:** Ubuntu + Windows
- **Python versions:** 3.10, 3.11, 3.12
- **Steps:**
  1. Checkout code
  2. Set up Python with pip caching
  3. Install system dependencies (libpcap on Linux)
  4. Install Python requirements
  5. Run pytest with coverage (`pytest tests/ -v --cov=Python`)
  6. Upload coverage to Codecov (Ubuntu + Python 3.12 only)

**Matrix Strategy:** Tests run on 6 configurations (2 OS × 3 Python versions) in parallel.

#### Code Quality (Lint)
- **Runs on:** Ubuntu Latest
- **Python version:** 3.12
- **Tools:**
  - **Ruff** - Fast Python linter and formatter
  - Checks code style, common bugs, and best practices
  - Validates formatting consistency
- **Steps:**
  1. Install ruff
  2. Run linter: `ruff check Python/ tests/`
  3. Check formatting: `ruff format --check Python/ tests/`

#### Security Scan
- **Runs on:** Ubuntu Latest
- **Python version:** 3.12
- **Tools:**
  - **Safety** - Checks dependencies for known vulnerabilities
  - **Bandit** - Python security issue scanner
- **Steps:**
  1. Run `safety check` on installed packages
  2. Run `bandit -r Python/` for code security issues
  3. Upload security reports as artifacts

#### Build Check
- **Runs on:** Windows Latest
- **Python version:** 3.12
- **Purpose:** Verify application builds successfully
- **Steps:**
  1. Compile Python syntax check
  2. Run PyInstaller with PCAP_Sentry.spec
  3. Verify build artifacts created

**Note:** Safety and Codecov upload use `continue-on-error: true` to provide warnings without blocking PRs. Ruff, Bandit (medium+), and PyInstaller build checks will fail the pipeline if they detect issues.

### 2. CodeQL Workflow (`.github/workflows/codeql.yml`)

**Triggers:**
- Push to `main` branch
- Pull requests to `main` branch
- Weekly schedule (Mondays at 04:17 UTC)

**Purpose:** GitHub's semantic code analysis for security vulnerabilities

**Steps:**
1. Initialize CodeQL for Python
2. Analyze code for security patterns
3. Upload results to GitHub Security tab

**Permissions:** `security-events: write` to create security alerts

### 3. Release Checksums Workflow (`.github/workflows/release-checksums.yml`)

**Triggers:**
- Manual workflow dispatch (with optional tag input)

**Purpose:** Generate SHA256 checksums for release assets

**Steps:**
1. Download release assets
2. Generate SHA256SUMS.txt
3. Upload checksums to release

**Note:** Checksums are primarily generated locally by `build_release.bat`. This workflow serves as a fallback.

### 4. Deployment Workflow (`.github/workflows/deploy.yml`)

**Triggers:**
- Push to version tags (e.g., `v2026.02.16-1`)
- Manual workflow dispatch (with optional skip flags)

**Purpose:** Enforce all quality gates before deployment approval

**Jobs:**

#### 1. Quality Gates (`validate-quality`)
- **Runs on:** Ubuntu Latest
- **Validates:**
  - Ruff linting (no errors)
  - Code formatting consistency
  - Python syntax correctness

#### 2. Security Gates (`validate-security`)
- **Runs on:** Ubuntu Latest
- **Validates:**
  - Safety dependency scan (no critical vulnerabilities)
  - Bandit code security scan (no HIGH/MEDIUM issues)
  - CodeQL semantic analysis

#### 3. Test Gates (`validate-tests`)
- **Runs on:** Ubuntu + Windows (Python 3.12)
- **Validates:**
  - Full test suite passes (100% pass rate)
  - Code coverage meets minimum 60% threshold
  - Performance/stress tests complete

#### 4. Build Gates (`validate-build`)
- **Runs on:** Windows Latest
- **Validates:**
  - PyInstaller build succeeds
  - EXE artifact created and functional
  - Dependencies properly bundled

#### 5. OpenSSF Gates (`validate-openssf`)
- **Runs on:** Ubuntu Latest
- **Validates:**
  - Required documentation files exist
  - CI/CD workflows configured
  - Test suite present and adequate

#### 6. Deployment Ready (`deployment-ready`)
- **Depends on:** All previous gates
- **Action:** Creates deployment summary and approves deployment
- **Fails if:** Any gate fails

**Manual skip options:**
```bash
# Trigger manually with test skip (not recommended)
gh workflow run deploy.yml -f skip_tests=true
```

**Permissions:**
- `contents: write` - To upload build artifacts
- `security-events: write` - For CodeQL analysis

**View deployment status:** GitHub Actions tab → Deploy workflow

## Local Testing Before Push

To match CI environment locally:

### Automated Pre-Deployment Validation (Recommended)

The fastest way to validate everything before deployment:

```powershell
# Run all checks (matches deployment workflow)
.\pre_deploy_checks.ps1

# Quick check (critical only)
.\pre_deploy_checks.ps1 -Fast

# With specific options
.\pre_deploy_checks.ps1 -SkipTests  # Not recommended for production
```

This script validates:
- Code quality (Ruff)
- Security (Safety + Bandit)
- Tests with coverage
- Performance tests
- Build verification
- OpenSSF compliance
- Git status

**Exit code 0 = safe to deploy**

### Run Individual CI Jobs Locally

For troubleshooting specific failures:

```bash
# Test suite (matches CI test job)
pytest tests/ -v --cov=Python --cov-report=term --cov-report=html

# Code quality (matches CI lint job)
pip install ruff
ruff check Python/ tests/
ruff format --check Python/ tests/

# Security scan (matches CI security job)
pip install safety bandit
safety check
bandit -r Python/

# Build check (Windows, matches CI build job)
python -c "import py_compile; py_compile.compile('Python/pcap_sentry_gui.py', doraise=True)"
pyinstaller --noconfirm PCAP_Sentry.spec
```

### Quick Pre-Commit Checks

```bash
# Run tests only
pytest tests/

# Run linter only
ruff check Python/ tests/
```

## CI Status & Results

### View CI Results

1. **On Pull Requests:** CI status appears as checks at the bottom of the PR
2. **On Main Branch:** Visit [Actions tab](https://github.com/retr0verride/PCAP-Sentry/actions)
3. **Badges:** README.md shows real-time CI status badge

### Understanding CI Failures

#### Test Failures
- **Symptom:** Red X on "Test Suite" job
- **Debug:** Click "Details" → View failed test output
- **Common causes:** 
  - New code broke existing functionality
  - Missing dependencies
  - OS-specific issues (test passes locally but fails on different OS)

#### Lint Failures
- **Symptom:** Red X on "Code Quality" job
- **Fix locally:** `ruff check --fix Python/ tests/`
- **Format locally:** `ruff format Python/ tests/`
- **Common causes:**
  - Unused imports
  - Line too long
  - Inconsistent formatting

#### Security Warnings
- **Symptom:** Orange warning on "Security Scan" job
- **Review:** Download security report artifacts
- **Common causes:**
  - Outdated dependencies with CVEs
  - Insecure code patterns (hardcoded passwords, eval usage)
- **Note:** Safety uses `continue-on-error` so it won't block PRs. Bandit blocks on medium+ severity findings.

#### Build Failures
- **Symptom:** Red X on "Build Check" job
- **Common causes:**
  - Syntax errors in Python files
  - Missing imports at build time
  - PyInstaller spec issues

## Coverage Reporting

### Codecov Integration

CI automatically uploads coverage reports to Codecov (if configured):
- **When:** After test suite runs on Ubuntu + Python 3.12
- **What:** Line coverage, branch coverage, function coverage
- **Where:** View at `https://codecov.io/gh/retr0verride/PCAP-Sentry`

### Coverage Badges

Add to README.md:
```markdown
[![codecov](https://codecov.io/gh/retr0verride/PCAP-Sentry/branch/main/graph/badge.svg)](https://codecov.io/gh/retr0verride/PCAP-Sentry)
```

### Local Coverage Reports

CI generates HTML reports locally:
```bash
pytest tests/ --cov=Python --cov-report=html
# Open: htmlcov/index.html
```

## CI Configuration Files

### Matrix Testing Strategy

The CI runs tests on multiple configurations to ensure compatibility:

```yaml
matrix:
  os: [ubuntu-latest, windows-latest]
  python-version: ['3.10', '3.11', '3.12']
```

This creates **6 test jobs** running in parallel:
- Ubuntu + Python 3.10
- Ubuntu + Python 3.11
- Ubuntu + Python 3.12
- Windows + Python 3.10
- Windows + Python 3.11
- Windows + Python 3.12

### Caching

CI uses pip caching to speed up workflow runs:
```yaml
uses: actions/setup-python@v5
with:
  cache: 'pip'
```

This caches installed packages between runs, reducing installation time from ~2 minutes to ~30 seconds.

### Path Filters

CI only runs when relevant files change:
```yaml
on:
  push:
    paths:
      - 'Python/**.py'
      - 'tests/**.py'
      - 'requirements.txt'
      - '.github/workflows/ci.yml'
```

This prevents unnecessary CI runs on documentation-only changes.

## Permissions

CI workflows follow the principle of least privilege:

| Workflow | Permissions | Reason |
|----------|-------------|--------|
| CI | `contents: read` | Read-only access to code |
| CodeQL | `security-events: write` | Create security alerts |
| Release Checksums | `contents: write` | Upload release assets |

## Troubleshooting

### CI is Not Running

**Check:**
1. Is the file in the right directory? (`.github/workflows/`)
2. Is the YAML syntax valid? Use [YAML Lint](https://www.yamllint.com/)
3. Are path filters excluding your changes?
4. Check Actions tab for workflow runs (may be queued)

### Tests Pass Locally but Fail in CI

**Common reasons:**
1. **OS differences** - File paths (Windows `\` vs Linux `/`)
2. **Missing dependencies** - System library not installed in CI
3. **Timezone/locale** - CI runs in UTC
4. **File permissions** - Different on Windows vs Linux
5. **Environment variables** - Not set in CI

**Debug:**
- Add debug prints: `print(f"DEBUG: {variable}")`
- Check environment: `import sys; print(sys.platform)`
- List files: `import os; print(os.listdir('.'))`

### Security Scan False Positives

If bandit or safety report false positives:

**Option 1:** Add inline comment to suppress
```python
# nosec B101 - False positive: assert is for testing
assert value > 0
```

**Option 2:** Configure in `.bandit` file
```yaml
skips:
  - B101  # Use of assert detected
```

**Option 3:** Update deps to resolve CVEs
```bash
pip list --outdated
pip install --upgrade package-name
```

## Best Practices

### For Contributors

✅ **DO:**
- Run tests locally before pushing
- Fix lint errors before committing
- Keep PRs small and focused
- Wait for CI to pass before requesting review
- Read CI error messages carefully

❌ **DON'T:**
- Force-push while CI is running
- Ignore failing tests with "works on my machine"
- Disable CI checks to "temporarily" bypass failures
- Commit code without running local tests

### For Maintainers

✅ **DO:**
- Review CI results before merging PRs
- Investigate flaky tests immediately
- Keep dependencies updated
- Monitor security scan results
- Add CI status checks to branch protection rules

❌ **DON'T:**
- Merge PRs with failing tests
- Ignore security warnings indefinitely
- Let CI become too slow (>10 minutes)

## Performance Optimization

Current CI runtime: **~5-8 minutes per workflow**

### Future Optimizations

1. **Parallel test execution** - Use `pytest-xdist` for parallel testing
2. **Selective testing** - Only run tests for changed modules
3. **Docker caching** - Pre-build Docker images with dependencies
4. **Artifact caching** - Cache build artifacts between runs

## OpenSSF Compliance

✅ **Continuous Integration Requirement:**

> "It is SUGGESTED that the project implement continuous integration (where new or changed code is frequently integrated into a central code repository and automated tests are run on the result)"

**PCAP Sentry's CI implementation:**
- ✅ Automated tests run on every push and PR
- ✅ Tests run on multiple OS and Python versions
- ✅ Code quality checks integrated
- ✅ Security scanning automated
- ✅ Build verification included
- ✅ Results visible in real-time via badges
- ✅ Branch protection can enforce passing CI

This fully satisfies the OpenSSF Best Practices CI suggestion.

## Resources

- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [pytest Documentation](https://docs.pytest.org/)
- [Ruff Linter](https://docs.astral.sh/ruff/)
- [Bandit Security Scanner](https://bandit.readthedocs.io/)
- [Safety Vulnerability Database](https://github.com/pyupio/safety)
- [OpenSSF CI Guidance](https://www.bestpractices.dev/en/criteria#test_continuous_integration)
