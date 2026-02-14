# PCAP Sentry Update System

## Overview

PCAP Sentry now includes an integrated update system that allows users to check for and install new versions directly from within the application when it's installed.

## Features

- **One-Click Update Checks**: Users can click "Check for Updates" button in the main toolbar
- **GitHub Integration**: Automatically fetches the latest release from the GitHub repository
- **Version Comparison**: Intelligently compares versions to identify available updates
- **Download & Install**: Prefers downloading the installer and launching it
- **Background Checking**: Update checks run in the background without blocking the UI
- **Version History Support**: Handles multiple version formats (2.1.0, 2026.02.11-1, etc.)

## How to Use

### For End Users

1. Launch PCAP Sentry
2. Click the **"Check for Updates"** button in the toolbar (next to Preferences)
3. The app will connect to GitHub and check for new versions
4. If an update is available:
   - A dialog will show the version numbers and release notes
   - Click **"Download & Update"** to download the installer
   - The installer will launch automatically
   - Review the installation and complete it
   - Restart PCAP Sentry
5. If you're already on the latest version, you'll see a confirmation message

### For Developers

#### Module Structure

The update system consists of two main components:

**1. `update_checker.py`** - Core update logic
- `UpdateChecker`: Main class for checking and downloading updates
  - `fetch_latest_release()`: Get latest release from GitHub
  - `is_update_available()`: Compare versions
  - `download_update()`: Download the new executable
  - `launch_installer()`: Run the installer
   - `replace_executable()`: Deferred replacement after app exit (standalone EXE fallback)

- `BackgroundUpdateChecker`: Thread wrapper for non-blocking checks
  - Runs update checks in background
  - Calls a callback function when complete

**2. Integration in `pcap_sentry_gui.py`**
- Import: `from update_checker import BackgroundUpdateChecker, UpdateChecker`
- UI Button in toolbar: "Check for Updates"
- Methods:
  - `_check_for_updates_ui()`: Handle button click and show results
  - `_download_and_install_update()`: Download and launch installer

#### Configuration

The update system connects to:
- **Owner**: `industrial-dave`
- **Repository**: `PCAP-Sentry`
- **Release Source**: GitHub Releases API (https://api.github.com/repos/industrial-dave/PCAP-Sentry/releases/latest)

#### Version Format Support

The system supports multiple version formats:
- Semantic versioning: `2.1.0`, `2.1.0.0`
- Date-based versioning: `2026.02.11-1`
- Any numeric version with dots and dashes

#### Release Requirements

For updates to work, GitHub releases must include:
1. A release with a tag (e.g., `v2026.2.13-39` or `2026.02.11-1`)
2. An executable named `PCAP_Sentry.exe` or `PCAP_Sentry_Setup.exe` (installer preferred)
3. Release notes (body text)

Example release structure:
```
Release: v2026.2.13-39
Assets:
  - PCAP_Sentry.exe (standalone application)
  - PCAP_Sentry_Setup.exe (installer, preferred by updater)
Description: 
  - Fixed bug X
  - Added feature Y
```

## Installation Workflow

1. **Check Phase**: App connects to GitHub via HTTPS
2. **Version Comparison**: Current version vs. latest available
3. **Download Phase**: If newer version exists, download to app data directory:
   - Default location: `%LOCALAPPDATA%\PCAP_Sentry\updates\`
4. **Installation Phase**: Launch the downloaded installer (preferred)
5. **Completion**: User completes installer wizard
6. **Cleanup**: Keeps 3 most recent update files automatically

## Security Considerations

- **HTTPS Only**: All GitHub API calls use HTTPS with SSL verification
- **SHA-256 Verification**: Downloaded executables are verified against the release's `SHA256SUMS.txt` before execution; mismatches abort the update
- **SHA-256 at Launch Time**: The installer hash is re-verified immediately before execution to prevent TOCTOU (time-of-check-to-time-of-use) attacks
- **SHA256SUMS Built Locally**: `build_release.bat` generates checksums after all assets (EXE, installer, KB) are uploaded, guaranteeing full coverage; the GitHub Actions workflow remains as a manual fallback
- **UAC Elevation**: Installer launch uses `os.startfile()` (ShellExecuteW) for proper Windows UAC elevation; standalone EXE replacement uses `ShellExecuteW` with `runas` verb
- **Download Size Limit**: Downloads are capped at 500 MB and API responses at 5 MB to prevent disk-fill or memory-exhaustion attacks
- **URL Domain Validation**: Only download URLs from `github.com` / `*.github.com` domains are accepted
- **CMD Path Sanitization**: Paths embedded in the update batch script are sanitized to prevent command injection via special characters
- **No Auto-Update**: Updates require user confirmation (no silent updates)
- **Installer Trust**: Updates are launched as installers when available
- **Backup**: Before replacing executables, a `.backup` file is created; the knowledge base is also backed up automatically
- **Sandboxed Download**: Updates are downloaded to app data directory, not system paths

## Error Handling

The system gracefully handles:
- Network connectivity issues
- GitHub API failures
- Missing or invalid releases
- Download interruptions
- Installer launching failures

All errors are reported to the user with helpful messages.

## Update Directory Management

Updates are stored in: `%LOCALAPPDATA%\PCAP_Sentry\updates\`

Files are named with timestamp: `PCAP_Sentry_{version}_{timestamp}.exe`

Automatic cleanup keeps the 3 most recent files.

## Development Notes

### Testing Updates Locally

To test the update system:

1. Create a test release on GitHub with a newer version number
2. Build PCAP_Sentry.exe and attach it to the release
3. Run the current version and click "Check for Updates"
4. Verify the update is detected and offers download

### Building Release Versions

The build process is fully automated via `build_exe.bat`. Version numbers use **date-based format** (`YYYY.MM.DD-BuildNumber`) and are managed by `update_version.ps1` — no manual version editing is required.

1. Build, commit, push, and create a GitHub release in one step:
   ```batch
   build_exe.bat -Notes "Description of changes"
   ```
   This automatically:
   - Bumps the build number in `version_info.txt`, `pcap_sentry_gui.py`, and `installer/PCAP_Sentry.iss`
   - Builds the EXE with PyInstaller
   - Commits and pushes to GitHub
   - Creates a tagged GitHub release with the EXE attached

2. Optional flags:
   - `-NoPush` — Build only, skip git commit/push and release creation
   - `-NoBump` — Skip version increment (rebuild with current version)

3. Example output:
   ```
   Tag: v2026.2.13-39
   Title: PCAP Sentry v2026.2.13-39
   Assets: PCAP_Sentry.exe from dist/ folder
   ```

## Troubleshooting

### Update button not appearing
- Ensure `update_checker.py` is in the `Python/` directory
- Check that Python version is 3.6+ (required for SSL context)

### "Failed to check for updates" error
- Check internet connection
- Verify GitHub API is accessible (try browsing to https://api.github.com in browser)
- Check window firewall/proxy settings

### Update doesn't install
- Ensure you have permissions to modify Program Files (or custom install location)
- Run installer as Administrator if needed
- Check that the installer is actually being launched (check Windows Task Manager)

### Can't find downloaded update
- Check: `%LOCALAPPDATA%\PCAP_Sentry\updates\`
- Files are named with timestamp

## Future Enhancements

Potential improvements:
- Auto-check for updates on startup (configurable)
- Differential updates (download only changed files)
- Rollback capability with automatic recovery
- Update scheduling and background installation
- Changelog display in-app before download

## Support

For issues with the update system:
1. Check the error message carefully - it often contains the root cause
2. Verify you have internet connectivity
3. Try restarting the application
4. Report issues to the GitHub repository with:
   - Current version number
   - Error message shown
   - Steps to reproduce
