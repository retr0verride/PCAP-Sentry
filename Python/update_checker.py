#!/usr/bin/env python3
# PCAP Sentry - Malware Analysis and Education Console for Network Packet Captures
# Copyright (C) 2026 industrial-dave
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""
PCAP Sentry Update Checker

Handles checking for new versions on GitHub and downloading updates.
"""

import hashlib
import json
import os
import re
import shutil
import ssl
import subprocess
import sys
import threading
import urllib.request


class UpdateChecker:
    """Checks for and manages updates for PCAP Sentry."""

    REPO_OWNER = "industrial-dave"
    REPO_NAME = "PCAP-Sentry"
    RELEASES_URL = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/releases/latest"
    RELEASES_ALL_URL = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/releases"

    def __init__(self, current_version: str):
        """
        Initialize the update checker.

        Args:
            current_version: Current version string (e.g., "2.1.0")
        """
        self.current_version = current_version
        self.latest_release = None
        self.latest_version = None
        self.download_url = None
        self.release_notes = None
        self._last_error = None

    @staticmethod
    def _parse_version(version_string: str) -> tuple:
        """
        Parse version string into comparable tuple.

        Handles formats like:
        - "2.1.0"
        - "2026.02.11-1"
        - "2.1.0.0"

        Args:
            version_string: Version string to parse

        Returns:
            Tuple of integers for comparison
        """
        # Remove leading 'v' if present
        version_string = version_string.lstrip("v")

        # Try to extract numeric parts
        parts = []
        current_part = ""

        for char in version_string:
            if char.isdigit():
                current_part += char
            else:
                if current_part:
                    parts.append(int(current_part))
                    current_part = ""

        if current_part:
            parts.append(int(current_part))

        return tuple(parts) if parts else (0,)

    def is_update_available(self) -> bool:
        """
        Check if an update is available.

        Returns:
            True if a newer version is available
        """
        if self.latest_version is None:
            return False

        current = self._parse_version(self.current_version)
        latest = self._parse_version(self.latest_version)

        # Pad with zeros for comparison
        max_len = max(len(current), len(latest))
        current = current + (0,) * (max_len - len(current))
        latest = latest + (0,) * (max_len - len(latest))

        return latest > current

    # Maximum download size (500 MB) to prevent disk-fill DoS
    _MAX_DOWNLOAD_BYTES = 500 * 1024 * 1024
    # Maximum API JSON response size (5 MB)
    _MAX_API_RESPONSE_BYTES = 5 * 1024 * 1024

    def fetch_latest_release(self) -> bool:
        """
        Fetch the latest release information from GitHub.

        Returns:
            True if successful, False otherwise
        """
        try:
            ctx = ssl.create_default_context()
            req = urllib.request.Request(
                self.RELEASES_URL,
                headers={"Accept": "application/vnd.github+json", "User-Agent": "PCAP-Sentry-Updater"},
            )
            
            with urllib.request.urlopen(req, context=ctx, timeout=15) as response:
                raw = response.read(self._MAX_API_RESPONSE_BYTES + 1)
                if len(raw) > self._MAX_API_RESPONSE_BYTES:
                    self._last_error = "GitHub API response too large"
                    return False
                release = json.loads(raw.decode("utf-8"))

            if not release or release.get("draft") or release.get("prerelease"):
                self._last_error = "No stable release found"
                return False

            self.latest_release = release
            self.latest_version = release.get("tag_name", "").lstrip("v")
            self.release_notes = release.get("body", "")

            # Find downloadable assets - prefer installer
            assets = release.get("assets", [])
            installer_url = None
            standalone_url = None
            
            for asset in assets:
                name = asset.get("name", "")
                url = asset.get("browser_download_url", "")
                
                if not name.lower().endswith(".exe"):
                    continue
                    
                if not self._is_trusted_download_url(url):
                    continue
                    
                if ("setup" in name.lower() or "install" in name.lower()) and "PCAP_Sentry" in name:
                    installer_url = url
                elif "PCAP_Sentry" in name:
                    standalone_url = url

            # Use installer if available, otherwise standalone
            if installer_url:
                self.download_url = installer_url
                self.download_is_installer = True
            elif standalone_url:
                self.download_url = standalone_url
                self.download_is_installer = False
            else:
                self._last_error = "No downloadable files found in release"
                return False

            # Fetch SHA-256 checksums for verification
            self._expected_sha256 = self._fetch_sha256_for_asset(release, ctx)
            return True

        except Exception as e:
            self._last_error = f"Failed to fetch release: {str(e)}"
            print(f"Error fetching latest release: {e}")
            return False

    @staticmethod
    def _is_trusted_download_url(url: str) -> bool:
        """Only allow downloads from known GitHub domains and the expected repo."""
        from urllib.parse import urlparse
        try:
            parsed = urlparse(url)
            host = (parsed.hostname or "").lower()
            path = (parsed.path or "").lower()
            if not (host.endswith(".github.com") or host == "github.com"):
                return False
            # Verify the URL path references the expected repository
            expected_prefix = f"/{UpdateChecker.REPO_OWNER}/{UpdateChecker.REPO_NAME}/".lower()
            return path.startswith(expected_prefix)
        except Exception:
            return False

    def _fetch_sha256_for_asset(self, release: dict, ctx) -> dict:
        """Download SHA256SUMS.txt from the release and return a {filename: hash} dict."""
        result = {}
        try:
            for asset in release.get("assets", []):
                if asset.get("name", "").upper() == "SHA256SUMS.TXT":
                    url = asset["browser_download_url"]
                    if not self._is_trusted_download_url(url):
                        break
                    req = urllib.request.Request(url, headers={"User-Agent": "PCAP-Sentry-Updater"})
                    with urllib.request.urlopen(req, context=ctx, timeout=15) as resp:
                        raw = resp.read(1 * 1024 * 1024)  # 1 MB limit
                        text = raw.decode("utf-8", errors="replace")
                    for line in text.strip().splitlines():
                        parts = line.split()
                        if len(parts) >= 2:
                            sha256_hash = parts[0].lower().strip()
                            filename = parts[-1].strip()
                            if len(sha256_hash) == 64:
                                result[filename] = sha256_hash
                    break
        except Exception:
            pass
        return result

    def download_update(self, destination: str, progress_callback=None) -> bool:
        """
        Download the latest release.

        Args:
            destination: Path where the update should be saved
            progress_callback: Optional callback(downloaded_bytes, total_bytes)

        Returns:
            True if successful, False otherwise
        """
        if not self.download_url:
            self._last_error = "No download URL available"
            return False

        try:
            # Ensure destination directory exists
            os.makedirs(os.path.dirname(destination), exist_ok=True)
            
            ctx = ssl.create_default_context()
            req = urllib.request.Request(
                self.download_url,
                headers={"User-Agent": "PCAP-Sentry-Updater"},
            )
            
            with urllib.request.urlopen(req, context=ctx, timeout=120) as response:
                total_size = int(response.headers.get("Content-Length", 0))
                
                # Validate size
                if total_size > self._MAX_DOWNLOAD_BYTES:
                    self._last_error = f"Download too large: {total_size} bytes"
                    return False
                
                # Download to temporary file first
                temp_dest = destination + ".tmp"
                downloaded = 0
                sha256 = hashlib.sha256()
                
                with open(temp_dest, "wb") as f:
                    while True:
                        chunk = response.read(65536)
                        if not chunk:
                            break
                        downloaded += len(chunk)
                        
                        if downloaded > self._MAX_DOWNLOAD_BYTES:
                            os.remove(temp_dest)
                            self._last_error = "Download exceeded size limit"
                            return False
                        
                        f.write(chunk)
                        sha256.update(chunk)
                        
                        if progress_callback:
                            progress_callback(downloaded, total_size)

            # Verify SHA-256 hash if available
            actual_hash = sha256.hexdigest().lower()
            expected = getattr(self, "_expected_sha256", {}) or {}
            filename = os.path.basename(destination)
            download_filename = self.download_url.rsplit("/", 1)[-1]
            
            expected_hash = expected.get(download_filename) or expected.get(filename)
            
            if expected_hash:
                if actual_hash != expected_hash.lower():
                    os.remove(temp_dest)
                    self._last_error = (
                        f"SHA-256 verification failed!\n"
                        f"Expected: {expected_hash}\n"
                        f"Got: {actual_hash}\n\n"
                        f"The download may be corrupted or tampered with."
                    )
                    return False
                print(f"✓ SHA-256 verified for {filename}")
            else:
                print(f"⚠ No SHA-256 hash available for {filename}")

            # Move to final destination
            if os.path.exists(destination):
                os.remove(destination)
            os.rename(temp_dest, destination)
            
            return True

        except Exception as e:
            self._last_error = f"Download failed: {str(e)}"
            print(f"Error downloading update: {e}")
            # Clean up temp file
            temp_dest = destination + ".tmp"
            if os.path.exists(temp_dest):
                try:
                    os.remove(temp_dest)
                except OSError:
                    # Ignore errors during cleanup
                    pass
            return False

    @staticmethod
    def get_app_data_dir() -> str:
        """Get the app data directory (aligned with GUI's LOCALAPPDATA path)."""
        app_data = os.getenv("LOCALAPPDATA") or os.getenv("APPDATA") or os.path.expanduser("~")
        app_dir = os.path.join(app_data, "PCAP_Sentry")
        os.makedirs(app_dir, exist_ok=True)
        return app_dir

    @staticmethod
    def get_update_dir() -> str:
        """Get the update staging directory."""
        update_dir = os.path.join(UpdateChecker.get_app_data_dir(), "updates")
        os.makedirs(update_dir, exist_ok=True)
        return update_dir

    def _backup_knowledge_base_before_update(self) -> None:
        """Back up the knowledge base file before applying an update."""
        try:
            app_dir = self.get_app_data_dir()
            kb_path = os.path.join(app_dir, "pcap_knowledge_base_offline.json")
            if not os.path.exists(kb_path):
                return
            backup_dir = os.path.join(app_dir, "kb_backups")
            os.makedirs(backup_dir, exist_ok=True)
            from datetime import datetime
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = os.path.join(backup_dir, f"pcap_knowledge_base_{ts}.json")
            shutil.copy2(kb_path, backup_path)
        except Exception as e:
            print(f"Warning: could not back up knowledge base: {e}")

    def launch_installer(self, installer_path: str) -> bool:
        """
        Launch the downloaded installer.

        Args:
            installer_path: Path to the installer EXE

        Returns:
            True if successfully launched, False otherwise
        """
        try:
            # Validate path is under expected staging directory
            real_path = os.path.realpath(installer_path)
            real_update_dir = os.path.realpath(self.get_update_dir())
            
            if not real_path.startswith(real_update_dir + os.sep):
                self._last_error = "Installer path validation failed"
                print(f"Security: Installer path outside update directory")
                return False
            
            if not os.path.exists(real_path):
                self._last_error = "Installer file not found"
                return False
            
            # Re-verify SHA-256 before launch (TOCTOU protection)
            expected = getattr(self, "_expected_sha256", {}) or {}
            filename = os.path.basename(real_path)
            download_filename = self.download_url.rsplit("/", 1)[-1] if self.download_url else ""
            expected_hash = expected.get(download_filename) or expected.get(filename)
            
            if expected_hash:
                sha = hashlib.sha256()
                with open(real_path, "rb") as f:
                    while True:
                        chunk = f.read(65536)
                        if not chunk:
                            break
                        sha.update(chunk)
                
                if sha.hexdigest().lower() != expected_hash.lower():
                    self._last_error = "SHA-256 verification failed before launch"
                    print(f"Security: SHA-256 mismatch at launch time")
                    return False
                print(f"✓ SHA-256 verified before launch")
            
            # Launch installer (Windows will show UAC prompt if needed)
            print(f"Launching installer: {real_path}")
            os.startfile(real_path)
            
            # Schedule cleanup after a delay
            def cleanup_later():
                import time
                time.sleep(3)
                try:
                    if os.path.exists(real_path):
                        os.remove(real_path)
                        print(f"Cleaned up installer: {real_path}")
                except Exception as e:
                    print(f"Could not delete installer: {e}")
            
            threading.Thread(target=cleanup_later, daemon=True).start()
            return True
            
        except Exception as e:
            self._last_error = f"Failed to launch installer: {str(e)}"
            print(f"Error launching installer: {e}")
            return False

    def replace_executable(self, new_exe_path: str, current_exe_path: str = None) -> bool:
        """
        Replace the current executable with the updated one.
        Uses a batch script to handle the replacement after app exit.

        Args:
            new_exe_path: Path to the new executable
            current_exe_path: Path to current executable (defaults to sys.executable)

        Returns:
            True if successful, False otherwise
        """
        if current_exe_path is None:
            current_exe_path = sys.executable

        try:
            # Check if running from frozen executable
            if not getattr(sys, "frozen", False):
                self._last_error = "Cannot update when running from source. Use the installer."
                return False
            
            # Check if current exe looks like a Python interpreter
            current_name = os.path.basename(current_exe_path).lower()
            if current_name.startswith("python"):
                self._last_error = "Cannot update Python interpreter. Use the installer."
                return False

            if not os.path.exists(new_exe_path):
                self._last_error = f"Update file not found: {new_exe_path}"
                return False

            # Back up knowledge base
            self._backup_knowledge_base_before_update()

            # Create update script
            update_dir = self.get_update_dir()
            script_path = os.path.join(update_dir, "apply_update.bat")
            backup_path = current_exe_path + ".backup"
            exe_dir = os.path.dirname(current_exe_path)
            exe_name = os.path.basename(current_exe_path)

            # Simple batch script to replace executable
            script = f'''@echo off
echo Applying PCAP Sentry update...
timeout /t 2 /nobreak >nul

REM Wait for app to close
:wait_loop
tasklist /FI "IMAGENAME eq PCAP_Sentry.exe" 2>NUL | find /I /N "PCAP_Sentry.exe">NUL
if "%ERRORLEVEL%"=="0" (
    timeout /t 1 /nobreak >nul
    goto wait_loop
)

REM Backup current executable
copy /Y "{current_exe_path}" "{backup_path}" >nul 2>&1

REM Replace with new version
move /Y "{new_exe_path}" "{current_exe_path}"
if errorlevel 1 (
    echo Update failed!
    pause
    exit /b 1
)

REM Refresh Windows icon cache to show new logo
echo Refreshing desktop icons...
ie4uinit.exe -show >nul 2>&1
timeout /t 1 /nobreak >nul

REM Force Explorer to refresh all icons
powershell -NoProfile -Command "$code = '[DllImport(\\"shell32.dll\\")]public static extern void SHChangeNotify(int wEventId,int uFlags,IntPtr dwItem1,IntPtr dwItem2);'; $type = Add-Type -MemberDefinition $code -Name IconRefresh -PassThru; $type::SHChangeNotify(0x8000000, 0, [IntPtr]::Zero, [IntPtr]::Zero)" >nul 2>&1

REM Launch updated executable from its directory
cd /D "{exe_dir}"
start "" "{exe_name}"

REM Clean up
del "%~f0"
exit /b 0
'''

            with open(script_path, "w", encoding="utf-8") as f:
                f.write(script)

            # Launch update script
            subprocess.Popen(
                ["cmd.exe", "/c", script_path],
                creationflags=subprocess.CREATE_NO_WINDOW,
                cwd=update_dir,
            )
            
            print(f"Update script launched: {script_path}")
            return True

        except Exception as e:
            self._last_error = f"Failed to prepare update: {str(e)}"
            print(f"Error replacing executable: {e}")
            return False

    def cleanup_old_updates(self, keep_count: int = 0) -> None:
        """
        Clean up old update files.

        Args:
            keep_count: Number of recent updates to keep (0 = delete all)
        """
        try:
            update_dir = self.get_update_dir()
            if not os.path.exists(update_dir):
                return

            files = [
                os.path.join(update_dir, f)
                for f in os.listdir(update_dir)
                if f.endswith(".exe")
            ]
            files.sort(key=os.path.getmtime, reverse=True)

            for old_file in files[keep_count:]:
                try:
                    os.remove(old_file)
                except Exception:
                    pass

        except Exception as e:
            print(f"Error cleaning up old updates: {e}")


class BackgroundUpdateChecker(threading.Thread):
    """Background thread for checking updates without blocking the UI."""

    def __init__(
        self, current_version: str, callback=None, check_on_startup: bool = False
    ):
        """
        Initialize the background update checker.

        Args:
            current_version: Current version
            callback: Function to call when update check completes
            check_on_startup: Whether to check immediately
        """
        super().__init__(daemon=True)
        self.checker = UpdateChecker(current_version)
        self.callback = callback
        self.check_on_startup = check_on_startup
        self.result = None

    def run(self):
        """Run the update check in the background."""
        try:
            if self.checker.fetch_latest_release():
                self.result = {
                    "success": True,
                    "available": self.checker.is_update_available(),
                    "current": self.checker.current_version,
                    "latest": self.checker.latest_version,
                    "release_notes": self.checker.release_notes,
                }
            else:
                error_detail = getattr(self.checker, "_last_error", "Failed to fetch release info")
                self.result = {"success": False, "error": error_detail}

        except Exception as e:
            self.result = {"success": False, "error": str(e)}

        if self.callback:
            self.callback(self.result)
