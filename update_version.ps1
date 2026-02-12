#requires -version 5.0
<#
.SYNOPSIS
    Automatically increments version number for PCAP Sentry builds.
#>
param(
    [string]$BuildNotes = "Build update",
    [switch]$DryRun
)

Write-Host "PCAP Sentry Version Updater" -ForegroundColor Cyan
Write-Host "=============================" -ForegroundColor Cyan
Write-Host ""

# Read current version
$versionFile = "version_info.txt"
if (-not (Test-Path $versionFile)) {
    Write-Error "version_info.txt not found"
    exit 1
}

$content = Get-Content $versionFile -Raw
if ($content -match 'filevers=\((\d+),\s*(\d+),\s*(\d+),\s*(\d+)\)') {
    $year = [int]$matches[1]
    $month = [int]$matches[2]
    $day = [int]$matches[3]
    $build = [int]$matches[4]
    $currentVersion = "$year.$month.$day-$build"
} else {
    Write-Error "Could not parse version from version_info.txt"
    exit 1
}

Write-Host "Current version: $currentVersion" -ForegroundColor Yellow

# Calculate next version
$today = Get-Date
$newYear = $today.Year
$newMonth = $today.Month
$newDay = $today.Day

if ($year -eq $newYear -and $month -eq $newMonth -and $day -eq $newDay) {
    $newBuild = $build + 1
} else {
    $newBuild = 1
}

$newVersion = "{0:D4}.{1:D2}.{2:D2}-{3:D1}" -f $newYear, $newMonth, $newDay, $newBuild

if ($newVersion -ne $currentVersion) {
    Write-Host "New version: $newVersion" -ForegroundColor Green
} else {
    Write-Host "Already at latest version for today"
}

Write-Host ""

if ($DryRun) {
    Write-Host "DRY-RUN MODE - No changes will be made" -ForegroundColor Yellow
    Write-Host ""
}

# Update version_info.txt
if (-not $DryRun) {
    $updatedContent = $content -replace 'filevers=\(\d+,\s*\d+,\s*\d+,\s*\d+\)', `
        "filevers=($newYear, $newMonth, $newDay, $newBuild)"
    $updatedContent = $updatedContent -replace 'prodvers=\(\d+,\s*\d+,\s*\d+,\s*\d+\)', `
        "prodvers=($newYear, $newMonth, $newDay, $newBuild)"
    Set-Content -Path $versionFile -Value $updatedContent -NoNewline
    Write-Host "Updated version_info.txt to $newVersion"
} else {
    Write-Host "Would update version_info.txt to $newVersion"
}

# Update APP_VERSION in pcap_sentry_gui.py
$guiFile = "Python\pcap_sentry_gui.py"
if (Test-Path $guiFile) {
    $guiContent = Get-Content $guiFile -Raw
    if (-not $DryRun) {
        $updatedGui = $guiContent -replace 'APP_VERSION\s*=\s*"[^"]+"', "APP_VERSION = `"$newVersion`""
        Set-Content -Path $guiFile -Value $updatedGui -NoNewline
        Write-Host "Updated Python/pcap_sentry_gui.py APP_VERSION to $newVersion"
    } else {
        Write-Host "Would update Python/pcap_sentry_gui.py APP_VERSION to $newVersion"
    }
} else {
    Write-Host "Warning: Python/pcap_sentry_gui.py not found" -ForegroundColor Yellow
}

# Update installer script
$issFile = "installer\PCAP_Sentry.iss"
if (Test-Path $issFile) {
    $issContent = Get-Content $issFile -Raw
    if (-not $DryRun) {
        $updatedIss = $issContent -replace 'AppVersion=[\d.]+-\d+', "AppVersion=$newVersion"
        Set-Content -Path $issFile -Value $updatedIss -NoNewline
        Write-Host "Updated installer/PCAP_Sentry.iss to $newVersion"
    } else {
        Write-Host "Would update installer/PCAP_Sentry.iss to $newVersion"
    }
} else {
    Write-Host "Warning: installer/PCAP_Sentry.iss not found" -ForegroundColor Yellow
}

# Update VERSION_LOG.md
$logFile = "VERSION_LOG.md"
if (Test-Path $logFile) {
    $dateStr = Get-Date -Format "yyyy-MM-dd"
    $newEntry = @"
## $newVersion - $dateStr
- $BuildNotes

"@
    
    if (-not $DryRun) {
        $logContent = Get-Content $logFile -Raw
        $updatedLog = $logContent -replace '(# Version Log\s*\n)', "`$1`n$newEntry"
        Set-Content -Path $logFile -Value $updatedLog -NoNewline
        Write-Host "Updated VERSION_LOG.md with $newVersion entry"
    } else {
        Write-Host "Would add entry to VERSION_LOG.md:"
        Write-Host $newEntry
    }
} else {
    Write-Host "Warning: VERSION_LOG.md not found" -ForegroundColor Yellow
}

if (-not $DryRun) {
    Write-Host ""
    Write-Host "Version updated successfully to $newVersion" -ForegroundColor Green
}
