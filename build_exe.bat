@echo off
setlocal

REM Build a self-contained EXE using PyInstaller.
REM Run from repo root after activating your Python environment.

set "LOG_DIR=logs"
if not exist "%LOG_DIR%" mkdir "%LOG_DIR%"
set "LOG_PATH=%LOG_DIR%\build_exe.log"
set "PYTHON=python"
if exist ".venv\Scripts\python.exe" set "PYTHON=.venv\Scripts\python.exe"
set "PYTHONWARNINGS=ignore:Core Pydantic V1 functionality isn't compatible with Python 3.14 or greater:UserWarning"
echo.>> "%LOG_PATH%"
echo ==== Build started %DATE% %TIME% ====>> "%LOG_PATH%"

REM Update version before build
echo ==== Updating Version ====>> "%LOG_PATH%"
powershell -NoProfile -ExecutionPolicy Bypass -File "update_version.ps1" -BuildNotes "Rebuild artifacts" >> "%LOG_PATH%" 2>&1
if errorlevel 1 (
	echo Failed to update version. See %LOG_PATH% for details.
	exit /b 1
)
echo ==== System Info ====>> "%LOG_PATH%"
ver >> "%LOG_PATH%" 2>&1
%PYTHON% --version >> "%LOG_PATH%" 2>&1
%PYTHON% -c "import sys; print(sys.executable)" >> "%LOG_PATH%" 2>&1
%PYTHON% -m PyInstaller --version >> "%LOG_PATH%" 2>&1
%PYTHON% -c "import scapy" >> "%LOG_PATH%" 2>&1
if errorlevel 1 (
	echo Scapy is missing in the build environment. Install it and retry.
	exit /b 1
)
%PYTHON% -c "import sklearn, joblib" >> "%LOG_PATH%" 2>&1
if errorlevel 1 (
	echo scikit-learn/joblib is missing in the build environment. Install it and retry.
	exit /b 1
)
echo ==== Python Packages (key) ====>> "%LOG_PATH%"
%PYTHON% -m pip list | findstr /I "pyinstaller scapy pandas matplotlib numpy pyarrow pillow certifi urllib3 tkinterdnd2" >> "%LOG_PATH%" 2>&1
%PYTHON% -m PyInstaller --noconfirm --clean "PCAP_Sentry.spec" >> "%LOG_PATH%" 2>&1
if errorlevel 1 (
	echo EXE build failed. See %LOG_PATH% for details.
	exit /b 1
)

echo ==== Build succeeded! ====>> "%LOG_PATH%"
echo ==== Pushing to GitHub ====>> "%LOG_PATH%"

REM Get current version from version_info.txt
powershell -NoProfile -Command "$c = Get-Content -Path 'version_info.txt' -Raw; if ($c -match 'filevers=\((\d+),\s*(\d+),\s*(\d+),\s*(\d+)\)') { '{0}.{1}.{2}-{3}' -f $matches[1],$matches[2],$matches[3],$matches[4] }" > "%TEMP%\pcap_version.txt"
set /p VERSION=<"%TEMP%\pcap_version.txt"
del "%TEMP%\pcap_version.txt" >nul 2>&1

REM Stage and commit version changes
git add version_info.txt VERSION_LOG.md installer\PCAP_Sentry.iss Python\pcap_sentry_gui.py >> "%LOG_PATH%" 2>&1
git commit -m "EXE Build: Version %VERSION%" >> "%LOG_PATH%" 2>&1

REM Push to GitHub
git push origin main >> "%LOG_PATH%" 2>&1
if errorlevel 1 (
	echo Warning: Failed to push to GitHub. See %LOG_PATH% for details.
) else (
	echo Pushed version %VERSION% to GitHub
)

endlocal
