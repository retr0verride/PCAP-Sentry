#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Pre-deployment validation script for PCAP Sentry.

.DESCRIPTION
    Runs all required checks before deployment:
    - Code quality (Ruff linting and formatting)
    - Security scans (Safety, Bandit)
    - Test suite with coverage
    - Performance/stress tests
    - OpenSSF best practices compliance
    - Build verification

    Exit code 0 = all checks passed, safe to deploy
    Exit code 1+ = one or more checks failed, DO NOT DEPLOY

.PARAMETER SkipTests
    Skip running the full test suite (not recommended for production)

.PARAMETER SkipSecurity
    Skip security scans (not recommended for production)

.PARAMETER Fast
    Run only critical checks (linting + security, skip tests)

.EXAMPLE
    .\pre_deploy_checks.ps1
    Run all checks before deployment

.EXAMPLE
    .\pre_deploy_checks.ps1 -Fast
    Run only critical checks for quick validation
#>

param(
    [switch]$SkipTests,
    [switch]$SkipSecurity,
    [switch]$Fast
)

$ErrorActionPreference = "Stop"
$SCRIPT_START = Get-Date

Write-Host "`n============================================" -ForegroundColor Cyan
Write-Host "PCAP Sentry Pre-Deployment Validation" -ForegroundColor Cyan
Write-Host "============================================`n" -ForegroundColor Cyan

# Track overall status
$CHECKS_PASSED = 0
$CHECKS_FAILED = 0
$CHECKS_WARNED = 0

function Write-CheckHeader {
    param([string]$Title)
    Write-Host "`n[$(Get-Date -Format 'HH:mm:ss')] ===== $Title =====" -ForegroundColor Yellow
}

function Write-CheckPass {
    param([string]$Message)
    Write-Host "[PASS] $Message" -ForegroundColor Green
    $script:CHECKS_PASSED++
}

function Write-CheckFail {
    param([string]$Message)
    Write-Host "[FAIL] $Message" -ForegroundColor Red
    $script:CHECKS_FAILED++
}

function Write-CheckWarn {
    param([string]$Message)
    Write-Host "[WARN] $Message" -ForegroundColor Yellow
    $script:CHECKS_WARNED++
}

# Ensure we're in the repo root
if (-not (Test-Path "PCAP_Sentry.spec")) {
    Write-Host "Error: Must run from repository root" -ForegroundColor Red
    exit 1
}

# Detect Python executable
$PYTHON = "python"
if (Test-Path ".venv\Scripts\python.exe") {
    $PYTHON = ".venv\Scripts\python.exe"
    Write-Host "Using virtual environment: .venv" -ForegroundColor Cyan
}

# Verify Python environment
Write-CheckHeader "Environment Check"
try {
    $pythonVersion = & $PYTHON --version 2>&1
    Write-Host "Python: $pythonVersion"
    
    # Check required packages
    $requiredPackages = @("ruff", "safety", "bandit", "pytest", "pytest-cov")
    foreach ($pkg in $requiredPackages) {
        $installed = & $PYTHON -m pip show $pkg 2>$null
        if ($LASTEXITCODE -eq 0) {
            Write-Host "  [OK] $pkg installed" -ForegroundColor Gray
        } else {
            Write-Host "  Installing $pkg..." -ForegroundColor Yellow
            & $PYTHON -m pip install $pkg -q
            if ($LASTEXITCODE -ne 0) {
                Write-CheckFail "Failed to install $pkg"
                exit 1
            }
        }
    }
    Write-CheckPass "Environment configured correctly"
} catch {
    Write-CheckFail "Python environment check failed: $_"
    exit 1
}

# 1. CODE QUALITY CHECKS
Write-CheckHeader "Code Quality (Ruff)"
try {
    # Linting
    Write-Host "Running Ruff linter..."
    & $PYTHON -m ruff check Python/ tests/ --output-format=concise
    if ($LASTEXITCODE -eq 0) {
        Write-CheckPass "Ruff linting passed"
    } else {
        Write-CheckFail "Ruff linting failed (run 'ruff check Python/ tests/' to see details)"
    }
    
    # Formatting
    Write-Host "Checking code formatting..."
    & $PYTHON -m ruff format --check Python/ tests/ > $null 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-CheckPass "Code formatting is consistent"
    } else {
        Write-CheckFail "Code formatting issues (run 'ruff format Python/ tests/' to fix)"
    }
} catch {
    Write-CheckFail "Code quality check failed: $_"
}

# 2. SECURITY SCANS
if (-not $SkipSecurity -and -not $Fast) {
    Write-CheckHeader "Security Scans"
    
    # Safety check
    Write-Host "Running Safety (dependency vulnerability scan)..."
    try {
        & $PYTHON -m pip install -r requirements.txt -q
        & $PYTHON -m safety check --json > safety-report.json 2>$null
        if ($LASTEXITCODE -eq 0 -or $LASTEXITCODE -eq 64) {
            $safetyReport = Get-Content safety-report.json -Raw | ConvertFrom-Json
            $vulnCount = 0
            if ($safetyReport.vulnerabilities) {
                $vulnCount = $safetyReport.vulnerabilities.Count
            }
            if ($vulnCount -eq 0) {
                Write-CheckPass "No known vulnerabilities in dependencies"
            } else {
                Write-CheckWarn "$vulnCount known vulnerabilities found (review safety-report.json)"
            }
        } else {
            Write-CheckWarn "Safety check completed with warnings"
        }
    } catch {
        Write-CheckWarn "Safety check failed: $_"
    }
    
    # Bandit security scan
    Write-Host "Running Bandit (Python security scan)..."
    try {
        & $PYTHON -m bandit -r Python/ -f json -o bandit-report.json 2>&1 | Out-Null
        if (Test-Path "bandit-report.json") {
            $banditReport = Get-Content bandit-report.json -Raw | ConvertFrom-Json
            $highMed = $banditReport.results | Where-Object { $_.issue_severity -in @('HIGH', 'MEDIUM') }
            
            if ($highMed.Count -eq 0) {
                Write-CheckPass "No HIGH/MEDIUM security issues found"
                Write-Host "  Total findings: $($banditReport.results.Count) (0 critical)" -ForegroundColor Gray
            } else {
                Write-CheckFail "$($highMed.Count) HIGH/MEDIUM security issues found (review bandit-report.json)"
                foreach ($issue in $highMed | Select-Object -First 3) {
                    Write-Host "    - $($issue.filename):$($issue.line_number) - $($issue.issue_text)" -ForegroundColor Red
                }
            }
        } else {
            Write-CheckWarn "Bandit report not generated"
        }
    } catch {
        Write-CheckWarn "Bandit security scan warning: $_"
    }
} elseif ($Fast) {
    Write-Host "`n[Fast mode] Skipping security scans" -ForegroundColor Gray
} else {
    Write-Host "`n[Warning] Skipping security scans (use -SkipSecurity)" -ForegroundColor Yellow
}

# 3. TEST SUITE
if (-not $SkipTests -and -not $Fast) {
    Write-CheckHeader "Test Suite"
    try {
        Write-Host "Running pytest with coverage..."
        & $PYTHON -m pytest tests/ -v --cov=Python --cov-report=term --cov-report=html --cov-report=xml
        if ($LASTEXITCODE -eq 0) {
            Write-CheckPass "All tests passed"
            
            # Check coverage
            if (Test-Path "coverage.xml") {
                $coverage = Select-Xml -Path "coverage.xml" -XPath "//coverage" | Select-Object -ExpandProperty Node
                $lineRate = [math]::Round([double]$coverage.'line-rate' * 100, 1)
                Write-Host "  Coverage: $lineRate%" -ForegroundColor Gray
                if ($lineRate -ge 75) {
                    Write-CheckPass "Code coverage is adequate ($lineRate%)"
                } else {
                    Write-CheckWarn "Code coverage is below 75% ($lineRate%)"
                }
            }
        } else {
            Write-CheckFail "Test suite failed"
        }
    } catch {
        Write-CheckFail "Test execution failed: $_"
    }
    
    # Stress tests
    Write-Host "`nRunning performance/stress tests..."
    try {
        & $PYTHON -m pytest tests/test_stress.py -v
        if ($LASTEXITCODE -eq 0) {
            Write-CheckPass "Performance tests passed"
        } else {
            Write-CheckWarn "Performance tests failed (not blocking deployment)"
        }
    } catch {
        Write-CheckWarn "Stress test execution failed: $_"
    }
} elseif ($Fast) {
    Write-Host "`n[Fast mode] Skipping test suite" -ForegroundColor Gray
} else {
    Write-Host "`n[Warning] Skipping test suite (use -SkipTests)" -ForegroundColor Yellow
}

# 4. BUILD VERIFICATION
Write-CheckHeader "Build Verification"
try {
    Write-Host "Verifying Python syntax..."
    $mainFile = "Python/pcap_sentry_gui.py"
    & $PYTHON -c "import py_compile; py_compile.compile('$mainFile', doraise=True)"
    if ($LASTEXITCODE -eq 0) {
        Write-CheckPass "Python syntax valid"
    } else {
        Write-CheckFail "Python syntax errors detected"
    }
    
    # Check if PyInstaller spec exists
    if (Test-Path "PCAP_Sentry.spec") {
        Write-CheckPass "PyInstaller spec file exists"
    } else {
        Write-CheckFail "PyInstaller spec file missing"
    }
    
    # Verify critical dependencies
    Write-Host "Checking critical dependencies..."
    $criticalDeps = @("scapy", "sklearn", "joblib", "pandas", "matplotlib")
    $missingDeps = @()
    foreach ($dep in $criticalDeps) {
        & $PYTHON -c "import $dep" 2>$null
        if ($LASTEXITCODE -ne 0) {
            $missingDeps += $dep
        }
    }
    if ($missingDeps.Count -eq 0) {
        Write-CheckPass "All critical dependencies available"
    } else {
        Write-CheckFail "Missing dependencies: $($missingDeps -join ', ')"
    }
} catch {
    Write-CheckFail "Build verification failed: $_"
}

# 5. OPENSSF BEST PRACTICES COMPLIANCE
Write-CheckHeader "OpenSSF Best Practices"
try {
    $requiredFiles = @(
        "LICENSE",
        "README.md",
        "SECURITY.md",
        "CONTRIBUTING.md",
        "VERSION_LOG.md",
        ".github/workflows/ci.yml",
        ".github/workflows/codeql.yml"
    )
    
    $missingFiles = @()
    foreach ($file in $requiredFiles) {
        if (-not (Test-Path $file)) {
            $missingFiles += $file
        }
    }
    
    if ($missingFiles.Count -eq 0) {
        Write-CheckPass "All required documentation present"
    } else {
        Write-CheckWarn "Missing files: $($missingFiles -join ', ')"
    }
    
    # Check if tests directory exists and has tests
    if (Test-Path "tests") {
        $testFiles = Get-ChildItem "tests" -Filter "test_*.py"
        if ($testFiles.Count -gt 0) {
            Write-CheckPass "Test suite present ($($testFiles.Count) test files)"
        } else {
            Write-CheckFail "No test files found in tests/"
        }
    } else {
        Write-CheckFail "tests/ directory not found"
    }
} catch {
    Write-CheckWarn "OpenSSF compliance check incomplete: $_"
}

# 6. GIT STATUS CHECK
Write-CheckHeader "Git Status"
try {
    $gitStatus = git status --porcelain 2>$null
    if ($LASTEXITCODE -eq 0) {
        $uncommitted = ($gitStatus | Measure-Object).Count
        if ($uncommitted -eq 0) {
            Write-CheckPass "No uncommitted changes"
        } else {
            Write-CheckWarn "$uncommitted uncommitted changes (consider committing before deployment)"
        }
        
        # Check current branch
        $branch = git rev-parse --abbrev-ref HEAD 2>$null
        Write-Host "  Current branch: $branch" -ForegroundColor Gray
        
        # Check if we're behind origin
        git fetch origin 2>$null
        $behind = git rev-list HEAD..origin/$branch --count 2>$null
        if ($LASTEXITCODE -eq 0 -and $behind -gt 0) {
            Write-CheckWarn "Local branch is $behind commits behind origin/$branch"
        }
    } else {
        Write-CheckWarn "Not a git repository or git not available"
    }
} catch {
    Write-CheckWarn "Git status check failed: $_"
}

# SUMMARY
$DURATION = (Get-Date) - $SCRIPT_START
Write-Host "`n============================================" -ForegroundColor Cyan
Write-Host "Validation Summary" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "Passed:  $CHECKS_PASSED" -ForegroundColor Green
Write-Host "Warned:  $CHECKS_WARNED" -ForegroundColor Yellow
Write-Host "Failed:  $CHECKS_FAILED" -ForegroundColor Red
Write-Host "Duration: $($DURATION.TotalSeconds.ToString('F1'))s" -ForegroundColor Gray

if ($CHECKS_FAILED -eq 0) {
    Write-Host "`n[SUCCESS] ALL CHECKS PASSED - Safe to deploy!" -ForegroundColor Green
    exit 0
} else {
    Write-Host "`n[BLOCKED] DEPLOYMENT BLOCKED - Fix failed checks before deploying" -ForegroundColor Red
    Write-Host "Review the errors above and run this script again." -ForegroundColor Yellow
    exit 1
}
