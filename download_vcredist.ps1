param(
    [string]$OutputPath = "assets\\vcredist_x64.exe"
)

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$sourceUrl = "https://aka.ms/vs/17/release/vc_redist.x64.exe"
$destPath = Join-Path -Path $PSScriptRoot -ChildPath $OutputPath
$destDir = Split-Path -Path $destPath -Parent

if (-not (Test-Path -Path $destDir)) {
    New-Item -ItemType Directory -Path $destDir | Out-Null
}

Write-Host "Downloading VC++ runtime to $destPath"
try {
    Invoke-WebRequest -Uri $sourceUrl -OutFile $destPath -UseBasicParsing -ErrorAction Stop
    if (-not (Test-Path -Path $destPath)) {
        Write-Error "Download failed: file not found at $destPath"
        exit 1
    }
    Write-Host "Done. File size: $((Get-Item $destPath).Length) bytes"
} catch {
    Write-Error "Download failed: $_"
    exit 1
}
