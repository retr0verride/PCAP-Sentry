# Deployment Checklist

This checklist ensures all quality gates, security checks, and best practices are validated before every deployment of PCAP Sentry.

## Overview

Every deployment MUST pass all validation gates to ensure:
- ✅ **Code Quality** - Consistent, maintainable code
- ✅ **Security** - No known vulnerabilities 
- ✅ **Functionality** - All tests pass
- ✅ **Performance** - Acceptable resource usage
- ✅ **OpenSSF Compliance** - Best practices followed
- ✅ **Build Integrity** - Application builds successfully

## Automated Validation

### Method 1: Pre-Deployment Script (Recommended for Local Builds)

Run the automated validation script before building a release:

```powershell
# Run all checks (recommended)
.\pre_deploy_checks.ps1

# Quick validation (critical checks only)
.\pre_deploy_checks.ps1 -Fast

# Skip tests (not recommended for production)
.\pre_deploy_checks.ps1 -SkipTests
```

**When to use:**
- Before running `build_release.bat`
- Before pushing release tags
- During local development to catch issues early

**Exit codes:**
- `0` = All checks passed, safe to deploy
- `1` = One or more checks failed, DO NOT DEPLOY

### Method 2: GitHub Actions Workflow (Automatic on Tag Push)

The deployment workflow automatically runs when you push a version tag:

```powershell
git tag v2026.02.16-1
git push origin v2026.02.16-1
```

This triggers the `.github/workflows/deploy.yml` workflow which validates:
1. Code quality (Ruff linting & formatting)
2. Security scans (Bandit, Safety, CodeQL)
3. Test suite with coverage requirements
4. Build verification
5. OpenSSF best practices compliance

**View results:** Check the Actions tab on GitHub

### Method 3: Integrated Build Script

The `build_release.bat` script now automatically runs validation checks:

```batch
build_release.bat
```

To skip validation (NOT RECOMMENDED):
```batch
set PCAP_SKIP_CHECKS=1
build_release.bat
```

## Manual Deployment Checklist

Use this checklist for manual verification or troubleshooting automated failures:

### Pre-Deployment: Code Quality

- [ ] **Linting passes**: Run `ruff check Python/ tests/`
  - [ ] No errors
  - [ ] All warnings addressed or documented
- [ ] **Formatting consistent**: Run `ruff format --check Python/ tests/`
  - [ ] No formatting issues
- [ ] **No syntax errors**: `python -c "import py_compile; py_compile.compile('Python/pcap_sentry_gui.py', doraise=True)"`

**How to fix:**
```powershell
# Auto-fix linting issues
ruff check Python/ tests/ --fix

# Auto-format code
ruff format Python/ tests/
```

### Pre-Deployment: Security

- [ ] **Dependency scan passes**: Run `safety check`
  - [ ] No HIGH/CRITICAL vulnerabilities in dependencies
  - [ ] Known LOW/MEDIUM vulnerabilities documented in SECURITY.md
- [ ] **Code security scan passes**: Run `bandit -r Python/`
  - [ ] No HIGH or MEDIUM severity issues
  - [ ] All LOW findings reviewed and accepted
- [ ] **CodeQL analysis clean**: Check GitHub Security tab
  - [ ] No security alerts
  - [ ] No code scanning findings

**How to fix:**
```powershell
# Check for vulnerable dependencies
pip install safety
safety check --json

# Run security scan
pip install bandit
bandit -r Python/ -f json -o bandit-report.json

# Review findings
cat bandit-report.json | jq '.results[] | select(.issue_severity == "HIGH" or .issue_severity == "MEDIUM")'
```

### Pre-Deployment: Testing

- [ ] **All unit tests pass**: Run `pytest tests/ -v`
  - [ ] 100% pass rate
  - [ ] No skipped tests (unless documented)
- [ ] **Code coverage adequate**: Run `pytest tests/ --cov=Python --cov-report=term`
  - [ ] Overall coverage ≥ 60% (target: 75%+)
  - [ ] Critical modules covered
- [ ] **Performance tests pass**: Run `pytest tests/test_stress.py -v`
  - [ ] No performance regressions
  - [ ] Memory usage acceptable
- [ ] **Manual smoke test**: Run the application
  - [ ] Application launches without errors
  - [ ] Can load and analyze a sample PCAP file
  - [ ] UI is responsive
  - [ ] No crash on exit

**How to fix:**
```powershell
# Run tests with verbose output
pytest tests/ -v --cov=Python --cov-report=html

# View coverage report
start htmlcov/index.html

# Run specific failing test
pytest tests/test_stability.py::test_name -vv
```

### Pre-Deployment: Build Verification

- [ ] **PyInstaller spec valid**: Run `pyinstaller --noconfirm PCAP_Sentry.spec`
  - [ ] Build completes without errors
  - [ ] EXE created in `dist/PCAP_Sentry/`
  - [ ] EXE is functional (basic smoke test)
- [ ] **Installer builds**: Run `build_installer.bat -NoPush`
  - [ ] Installer EXE created
  - [ ] Installer runs and completes
- [ ] **File sizes reasonable**:
  - [ ] PCAP_Sentry.exe: ~50-150 MB
  - [ ] PCAP_Sentry_Setup.exe: ~50-150 MB
- [ ] **Dependencies bundled**: Check `dist/PCAP_Sentry/`
  - [ ] All required DLLs present
  - [ ] Python runtime embedded
  - [ ] Data files (icons, knowledge base) included

**How to fix:**
```powershell
# Clean build
Remove-Item -Recurse -Force build, dist
pyinstaller --clean --noconfirm PCAP_Sentry.spec

# Check for missing dependencies
.\dist\PCAP_Sentry\PCAP_Sentry.exe --version
```

### Pre-Deployment: OpenSSF Best Practices

- [ ] **Required documentation exists**:
  - [ ] LICENSE (GNU GPLv3)
  - [ ] README.md with project description
  - [ ] SECURITY.md with vulnerability reporting process
  - [ ] CONTRIBUTING.md with contribution guidelines
  - [ ] VERSION_LOG.md with release notes
- [ ] **CI/CD configured**:
  - [ ] `.github/workflows/ci.yml` present and passing
  - [ ] `.github/workflows/codeql.yml` present and passing
  - [ ] `.github/workflows/deploy.yml` present
- [ ] **Version control proper**:
  - [ ] All changes committed
  - [ ] No uncommitted modifications in working directory
  - [ ] Version number updated in `version_info.txt`
  - [ ] VERSION_LOG.md updated with release notes
- [ ] **Test policy followed**:
  - [ ] New features have corresponding tests
  - [ ] Test policy documented in CONTRIBUTING.md

**How to check:**
```powershell
# Verify documentation
Get-ChildItem LICENSE, README.md, SECURITY.md, CONTRIBUTING.md, VERSION_LOG.md

# Check git status
git status

# Verify CI status
gh run list --workflow=ci.yml --limit 1
```

### Pre-Deployment: Version Management

- [ ] **Version updated**: `version_info.txt` contains new version
  - [ ] Format: `filevers=(YYYY, MM, DD, increment)`
  - [ ] Increment is correct for the day
- [ ] **Release notes ready**:
  - [ ] VERSION_LOG.md updated with changes
  - [ ] Release notes describe what's new
  - [ ] Breaking changes highlighted (if any)
- [ ] **Git tag prepared**:
  - [ ] Tag format: `vYYYY.MM.DD-increment`
  - [ ] Tag matches version in `version_info.txt`

**How to update:**
```powershell
# Update version automatically
.\update_version.ps1 -BuildNotes "Description of changes"

# Create git tag
git tag v2026.02.16-1
git push origin v2026.02.16-1
```

### Post-Deployment: Verification

- [ ] **Release created on GitHub**:
  - [ ] Release tag exists
  - [ ] Release notes are accurate
  - [ ] Assets uploaded (EXE, installer, knowledge base)
  - [ ] SHA256SUMS.txt present
- [ ] **Checksums valid**: Verify `SHA256SUMS.txt`
  - [ ] All files have checksums
  - [ ] Checksums can be verified
- [ ] **Installation test**:
  - [ ] Download installer from release
  - [ ] Install on clean Windows system
  - [ ] Run application and verify functionality
- [ ] **Update checker works**:
  - [ ] Previous version detects new update
  - [ ] Update notification appears
  - [ ] Update process completes successfully

**How to verify:**
```powershell
# Verify release on GitHub
gh release view v2026.02.16-1

# Check release assets
gh release download v2026.02.16-1 --pattern "SHA256SUMS.txt"
cat SHA256SUMS.txt

# Verify checksums
Get-FileHash PCAP_Sentry_Setup.exe -Algorithm SHA256
```

## Troubleshooting

### Common Issues and Solutions

#### Linting Failures

**Problem:** Ruff reports style violations
**Solution:**
```powershell
# Auto-fix most issues
ruff check Python/ tests/ --fix

# Format code
ruff format Python/ tests/
```

#### Security Scan Failures

**Problem:** Bandit reports HIGH/MEDIUM issues
**Solution:**
1. Review the specific issue in `bandit-report.json`
2. Fix the code to address the vulnerability
3. If it's a false positive, add `# nosec` comment with justification
4. Document in SECURITY.md if intentional

#### Test Failures

**Problem:** Tests fail in CI or locally
**Solution:**
```powershell
# Run failing test with full output
pytest tests/test_name.py::test_function -vv

# Check test dependencies
pip install -r requirements.txt

# Clear pytest cache
Remove-Item -Recurse -Force .pytest_cache
```

#### Build Failures

**Problem:** PyInstaller fails to build EXE
**Solution:**
1. Check `logs/build_exe.log` for error details
2. Verify all dependencies are installed
3. Clean build directories and retry:
   ```powershell
   Remove-Item -Recurse -Force build, dist
   pyinstaller --clean PCAP_Sentry.spec
   ```

#### Low Code Coverage

**Problem:** Coverage below 60%
**Solution:**
1. Identify uncovered code: `pytest --cov=Python --cov-report=html`
2. Open `htmlcov/index.html` to see line-by-line coverage
3. Add tests for critical uncovered code
4. Document why some code is not tested (if intentional)

## Performance Tweaks Validation

While not blocking deployment, these performance checks should be reviewed:

- [ ] **Startup time**: Application launches in < 5 seconds
- [ ] **Memory usage**: Base memory < 200 MB
- [ ] **PCAP analysis**: Can process 10K packets in < 10 seconds
- [ ] **UI responsiveness**: No freezing during analysis
- [ ] **Resource cleanup**: Memory released after analysis

**How to measure:**
```powershell
# Run performance tests
pytest tests/test_stress.py -v

# Profile application startup
Measure-Command { .\dist\PCAP_Sentry\PCAP_Sentry.exe --version }
```

## Continuous Improvement

After each deployment, review:

1. **Automation coverage**: Are there manual steps that could be automated?
2. **Test coverage**: Are there untested code paths that caused issues?
3. **Security posture**: Are there new vulnerability categories to address?
4. **Performance metrics**: Are there regressions to investigate?
5. **User feedback**: Are there quality issues users reported?

Update this checklist and the automated validation scripts as the project evolves.

## References

- **Pre-deployment script**: [`pre_deploy_checks.ps1`](pre_deploy_checks.ps1)
- **Deployment workflow**: [`.github/workflows/deploy.yml`](.github/workflows/deploy.yml)
- **CI workflow**: [`.github/workflows/ci.yml`](.github/workflows/ci.yml)
- **Build scripts**: [`build_release.bat`](build_release.bat), [`build_exe.bat`](build_exe.bat), [`build_installer.bat`](build_installer.bat)
- **OpenSSF checklist**: [`OPENSSF_BADGE_CHECKLIST.md`](OPENSSF_BADGE_CHECKLIST.md)
- **Security policy**: [`SECURITY.md`](SECURITY.md)
- **Contribution guide**: [`CONTRIBUTING.md`](CONTRIBUTING.md)

---

**Last Updated:** February 18, 2026  
**Version:** 1.1
