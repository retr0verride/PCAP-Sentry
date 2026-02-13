@echo off
setlocal enabledelayedexpansion

REM Builds the installer using Inno Setup.
REM Run this after building the EXE.
REM Default behavior: local build only (no commit/push).
REM Optional: pass -Push to enable git commit/push and release creation.
REM Optional: pass -NoPush to force local-only mode.
REM Optional: pass -Release to upload installer without git push.
REM Optional: pass -NoBump to skip version update (use current version).
REM Optional: pass -Notes "your notes here" to set release notes / What's New.
REM   If omitted, defaults to "Minor tweaks and improvements".

set "NO_PUSH=1"
set "NO_BUMP="
set "DO_RELEASE="
set "BUILD_NOTES=Minor tweaks and improvements"
if defined PCAP_NO_BUMP set "NO_BUMP=1"

:parse_args
if "%~1"=="" goto :args_done
if /I "%~1"=="-Push" (
	set "NO_PUSH="
	set "DO_RELEASE=1"
	shift
	goto :parse_args
)
if /I "%~1"=="-Release" (
	set "DO_RELEASE=1"
	shift
	goto :parse_args
)
if /I "%~1"=="-NoBump" (
	set "NO_BUMP=1"
	shift
	goto :parse_args
)
if /I "%~1"=="-NoPush" (
	set "NO_PUSH=1"
	shift
	goto :parse_args
)
if /I "%~1"=="-Notes" (
	set "BUILD_NOTES=%~2"
	shift
	shift
	goto :parse_args
)
shift
goto :parse_args
:args_done

set "ISCC_EXE="
for %%I in (iscc.exe) do set "ISCC_EXE=%%~$PATH:I"

if not defined ISCC_EXE (
	if exist "%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe" set "ISCC_EXE=%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe"
)

if not defined ISCC_EXE (
	if exist "%ProgramFiles%\Inno Setup 6\ISCC.exe" set "ISCC_EXE=%ProgramFiles%\Inno Setup 6\ISCC.exe"
)

if not defined ISCC_EXE (
	if exist "%LocalAppData%\Programs\Inno Setup 6\ISCC.exe" set "ISCC_EXE=%LocalAppData%\Programs\Inno Setup 6\ISCC.exe"
)

if not defined ISCC_EXE (
	echo Inno Setup not found. Install it or add ISCC.exe to PATH.
	exit /b 1
)

set "LOG_DIR=logs"
if not exist "%LOG_DIR%" mkdir "%LOG_DIR%"
set "LOG_PATH=%LOG_DIR%\build_installer.log"
set "PYTHON=python"
if exist ".venv\Scripts\python.exe" set "PYTHON=.venv\Scripts\python.exe"
echo.>> "%LOG_PATH%"
echo ==== Build started %DATE% %TIME% ====>> "%LOG_PATH%"
echo Args: %*>> "%LOG_PATH%"

REM Update version before build (unless -NoBump is set)
if defined NO_BUMP (
	echo ==== Skipping Version Update -NoBump ====>> "%LOG_PATH%"
) else (
	echo ==== Updating Version ====>> "%LOG_PATH%"
	echo Build Notes: !BUILD_NOTES!>> "%LOG_PATH%"
	powershell -NoProfile -ExecutionPolicy Bypass -File "update_version.ps1" -BuildNotes "!BUILD_NOTES!" >> "%LOG_PATH%" 2>&1
	if errorlevel 1 (
		echo Failed to update version. See %LOG_PATH% for details.
		exit /b 1
	)
)
echo ==== System Info ====>> "%LOG_PATH%"
ver >> "%LOG_PATH%" 2>&1
echo ISCC_EXE=%ISCC_EXE%>> "%LOG_PATH%"
"%ISCC_EXE%" /? >> "%LOG_PATH%" 2>&1
echo ==== Python Packages (key) ====>> "%LOG_PATH%"
%PYTHON% -m pip list | findstr /I "pyinstaller scapy pandas matplotlib numpy pyarrow pillow certifi urllib3 tkinterdnd2" >> "%LOG_PATH%" 2>&1
"%ISCC_EXE%" installer\PCAP_Sentry.iss >> "%LOG_PATH%" 2>&1
if errorlevel 1 (
	echo Installer build failed. See %LOG_PATH% for details.
	exit /b 1
)

echo ==== Build succeeded! ====>> "%LOG_PATH%"
echo ==== Push Step ====>> "%LOG_PATH%"

REM Get current version from version_info.txt
powershell -NoProfile -Command "$c = Get-Content -Path 'version_info.txt' -Raw; if ($c -match 'filevers=\((\d+),\s*(\d+),\s*(\d+),\s*(\d+)\)') { '{0}.{1}.{2}-{3}' -f $matches[1],$matches[2],$matches[3],$matches[4] }" > "%TEMP%\pcap_version.txt"
set /p VERSION=<"%TEMP%\pcap_version.txt"
del "%TEMP%\pcap_version.txt" >nul 2>&1
if not defined VERSION (
	echo Failed to read version from version_info.txt.>> "%LOG_PATH%"
	echo Failed to read version from version_info.txt.
	exit /b 1
)

if defined NO_PUSH (
	echo Skipping git commit/push because -NoPush was provided.>> "%LOG_PATH%"
) else (
	REM Stage and commit version changes (not the large setup binary)
	git add version_info.txt VERSION_LOG.md installer\PCAP_Sentry.iss Python\pcap_sentry_gui.py Python\update_checker.py Python\threat_intelligence.py Python\enhanced_ml_trainer.py >> "%LOG_PATH%" 2>&1
	git commit -m "Installer Build: Version %VERSION% - !BUILD_NOTES!" >> "%LOG_PATH%" 2>&1

	REM Push to GitHub
	git push origin main >> "%LOG_PATH%" 2>&1
	if errorlevel 1 (
		echo Warning: Failed to push to GitHub. See %LOG_PATH% for details.
	) else (
		echo Pushed version %VERSION% and installer to GitHub
	)

)

if defined DO_RELEASE (
	REM Create or update GitHub Release with the installer (requires gh CLI)
	where gh >nul 2>&1
	if errorlevel 1 (
		echo Warning: GitHub CLI not found. Skipping release upload.>> "%LOG_PATH%"
		echo Warning: Install gh CLI to auto-create releases: winget install GitHub.cli
	) else (
		set "RELEASE_TAG=v!VERSION!"
		echo ==== Publishing GitHub Release !RELEASE_TAG! ====>> "%LOG_PATH%"
		echo Publishing GitHub Release !RELEASE_TAG!
		echo Release Notes: !BUILD_NOTES!>> "%LOG_PATH%"
		gh release view "!RELEASE_TAG!" >nul 2>&1
		if errorlevel 1 (
			gh release create "!RELEASE_TAG!" "dist\PCAP_Sentry_Setup.exe" --title "PCAP Sentry v%VERSION%" --notes "What's New: !BUILD_NOTES!" >> "%LOG_PATH%" 2>&1
			if errorlevel 1 (
				echo Warning: Failed to create GitHub release. See %LOG_PATH% for details.
			) else (
				echo Created GitHub release !RELEASE_TAG! with PCAP_Sentry_Setup.exe
			)
		) else (
			gh release upload "!RELEASE_TAG!" "dist\PCAP_Sentry_Setup.exe" --clobber >> "%LOG_PATH%" 2>&1
			if errorlevel 1 (
				echo Warning: Failed to upload installer to GitHub release. See %LOG_PATH% for details.
			) else (
				echo Uploaded PCAP_Sentry_Setup.exe to GitHub release !RELEASE_TAG!
			)
		)
	)
)

endlocal
