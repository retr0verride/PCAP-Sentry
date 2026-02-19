@echo off
setlocal enabledelayedexpansion

REM Build EXE + installer with a single shared version and one GitHub release.
REM Default behavior: build EXE (which bumps version) then build installer.
REM The EXE build commits/pushes the version bump and creates the release.
REM The installer build uploads to the same release without bumping.
REM Optional: pass -NoBump to skip version update (use current version).
REM Optional: pass -Notes "your notes here" to set release notes / What's New.
REM   If omitted, defaults to "Minor tweaks and improvements".

set "NO_BUMP="
set "BUILD_NOTES=Minor tweaks and improvements"

:parse_args
if "%~1"=="" goto :args_done
if /I "%~1"=="-NoBump" (
	set "NO_BUMP=1"
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

REM Run pre-deployment validation checks
echo ==== Running Pre-Deployment Validation ====
powershell -NoProfile -ExecutionPolicy Bypass -File "pre_deploy_checks.ps1"
if errorlevel 1 (
	echo.
	echo ============================================
	echo PRE-DEPLOYMENT CHECKS FAILED
	echo ============================================
	echo One or more quality gates failed.
	echo Review the errors above and fix them before deploying.
	echo.
	echo To skip checks (NOT RECOMMENDED):
	echo   set PCAP_SKIP_CHECKS=1
	echo   build_release.bat
	echo ============================================
	if not defined PCAP_SKIP_CHECKS exit /b 1
	echo WARNING: Proceeding with deployment despite failed checks!
	timeout /t 5
)
echo.

REM Avoid calling a label-heavy batch from inside an else() compound block
 REM (CMD GOTO inside a called script can break the else-block context).
if not defined NO_BUMP goto :build_exe_normal
call build_exe.bat -NoBump -Notes "!BUILD_NOTES!"
goto :after_exe_build
:build_exe_normal
call build_exe.bat -Notes "!BUILD_NOTES!"
:after_exe_build
if errorlevel 1 exit /b 1

set "PCAP_NO_BUMP=1"
call build_installer.bat -NoPush -Release -Notes "!BUILD_NOTES!"
set "PCAP_NO_BUMP="
if errorlevel 1 exit /b 1

REM Read version for the remaining upload steps
powershell -NoProfile -Command "$c = Get-Content -Path 'version_info.txt' -Raw; if ($c -match 'filevers=\((\d+),\s*(\d+),\s*(\d+),\s*(\d+)\)') { '{0}.{1}.{2}-{3}' -f $matches[1],$matches[2],$matches[3],$matches[4] }" > "%TEMP%\pcap_version.txt"
set /p VERSION=<"%TEMP%\pcap_version.txt"
del "%TEMP%\pcap_version.txt" >nul 2>&1
if not defined VERSION (
	echo Failed to read version from version_info.txt.
	exit /b 1
)
set "RELEASE_TAG=v!VERSION!"

where gh >nul 2>&1
if errorlevel 1 (
	echo Warning: GitHub CLI not found. Skipping KB + checksum uploads.
	goto :DONE
)

REM Upload knowledge base if it exists
set "KB_PATH=Python\pcap_knowledge_base_offline.json"
if exist "!KB_PATH!" (
	echo Uploading optional KB to !RELEASE_TAG!
	gh release upload "!RELEASE_TAG!" "!KB_PATH!" --clobber
	if errorlevel 1 (
		echo Warning: Failed to upload KB to GitHub release.
	)
)

REM Generate SHA256SUMS.txt locally so the checksums cover ALL assets
REM (EXE, installer, KB). The GitHub Actions workflow can re-trigger
REM checksums later via workflow_dispatch if needed.
echo ==== Generating SHA256SUMS.txt ====
set "SUMS_FILE=%TEMP%\SHA256SUMS.txt"
if exist "!SUMS_FILE!" del "!SUMS_FILE!"
if exist "dist\PCAP_Sentry.exe" (
	powershell -NoProfile -Command "(Get-FileHash 'dist\PCAP_Sentry.exe' -Algorithm SHA256).Hash.ToLower() + '  PCAP_Sentry.exe'" >> "!SUMS_FILE!"
)
if exist "dist\PCAP_Sentry_Setup.exe" (
	powershell -NoProfile -Command "(Get-FileHash 'dist\PCAP_Sentry_Setup.exe' -Algorithm SHA256).Hash.ToLower() + '  PCAP_Sentry_Setup.exe'" >> "!SUMS_FILE!"
)
if exist "!KB_PATH!" (
	powershell -NoProfile -Command "(Get-FileHash '!KB_PATH!' -Algorithm SHA256).Hash.ToLower() + '  pcap_knowledge_base_offline.json'" >> "!SUMS_FILE!"
)
if exist "!SUMS_FILE!" (
	echo Uploading SHA256SUMS.txt to !RELEASE_TAG!
	type "!SUMS_FILE!"
	gh release upload "!RELEASE_TAG!" "!SUMS_FILE!" --clobber
	if errorlevel 1 (
		echo Warning: Failed to upload SHA256SUMS.txt to GitHub release.
	) else (
		echo SHA256SUMS.txt uploaded successfully.
	)
	del "!SUMS_FILE!" >nul 2>&1
) else (
	echo Warning: No assets found to checksum.
)

:DONE
endlocal
