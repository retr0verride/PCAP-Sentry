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
for /f "tokens=2 delims=,()" %%A in ('findstr /R "filevers=" version_info.txt ^| findstr /v "prod"') do (
	for /f "tokens=1,2,3,4 delims=, " %%B in ("%%A") do (
		set "VERSION=%%B.%%C.%%D-%%E"
	)
)

REM Stage and commit version changes
git add version_info.txt VERSION_LOG.md installer\PCAP_Sentry.iss >> "%LOG_PATH%" 2>&1
git commit -m "EXE Build: Version %VERSION%" >> "%LOG_PATH%" 2>&1

REM Push to GitHub
git push origin main >> "%LOG_PATH%" 2>&1
if errorlevel 1 (
	echo Warning: Failed to push to GitHub. See %LOG_PATH% for details.
) else (
	echo Pushed version %VERSION% to GitHub
)

endlocal
