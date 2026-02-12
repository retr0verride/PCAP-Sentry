"""
PCAP Sentry Update Checker

Handles checking for new versions on GitHub and downloading updates.
"""

import json
import os
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

    def fetch_latest_release(self) -> bool:
        """
        Fetch the latest release information from GitHub.

        Queries all releases and picks the one with the highest
        version number, which is more reliable than /releases/latest
        (GitHub sorts that by created_at, not by semantic version).

        Returns:
            True if successful, False otherwise
        """
        try:
            ctx = ssl.create_default_context()

            # Try fetching all releases first (more reliable)
            best = None
            best_ver = (0,)
            try:
                req = urllib.request.Request(
                    self.RELEASES_ALL_URL,
                    headers={"Accept": "application/vnd.github+json"},
                )
                with urllib.request.urlopen(req, context=ctx, timeout=15) as response:
                    releases = json.loads(response.read().decode("utf-8"))
                for rel in releases:
                    if rel.get("draft") or rel.get("prerelease"):
                        continue
                    tag = rel.get("tag_name", "").lstrip("v")
                    parsed = self._parse_version(tag)
                    if parsed > best_ver:
                        best_ver = parsed
                        best = rel
            except Exception:
                # Fall back to /releases/latest
                with urllib.request.urlopen(self.RELEASES_URL, context=ctx, timeout=10) as response:
                    best = json.loads(response.read().decode("utf-8"))

            if best is None:
                self._last_error = "No published releases found."
                return False

            self.latest_release = best
            self.latest_version = best.get("tag_name", "").lstrip("v")
            self.release_notes = best.get("body", "")

            # Find the Windows EXE asset
            assets = best.get("assets", [])
            for asset in assets:
                name = asset.get("name", "")
                if name.endswith(".exe") and "PCAP_Sentry" in name:
                    self.download_url = asset["browser_download_url"]
                    break

            return True

        except Exception as e:
            print(f"Error fetching latest release: {e}")
            self._last_error = str(e)
            return False

    def download_update(self, destination: str, progress_callback=None) -> bool:
        """
        Download the latest release.

        Args:
            destination: Path where the update should be saved
            progress_callback: Optional callback for progress updates

        Returns:
            True if successful, False otherwise
        """
        if not self.download_url:
            return False

        try:
            ctx = ssl.create_default_context()
            req = urllib.request.Request(
                self.download_url,
                headers={"User-Agent": "PCAP-Sentry-Updater"},
            )
            with urllib.request.urlopen(req, context=ctx, timeout=120) as response:
                total_size = int(response.headers.get("Content-Length", 0))
                downloaded = 0
                chunk_size = 65536
                with open(destination, "wb") as f:
                    while True:
                        chunk = response.read(chunk_size)
                        if not chunk:
                            break
                        f.write(chunk)
                        downloaded += len(chunk)
                        if progress_callback:
                            progress_callback(downloaded, total_size)
            return os.path.exists(destination) and os.path.getsize(destination) > 0

        except Exception as e:
            print(f"Error downloading update: {e}")
            return False

    @staticmethod
    def get_app_data_dir() -> str:
        """Get the app data directory."""
        app_data = os.getenv("APPDATA", os.path.expanduser("~\\AppData\\Roaming"))
        app_dir = os.path.join(app_data, "PCAP Sentry")
        os.makedirs(app_dir, exist_ok=True)
        return app_dir

    @staticmethod
    def get_update_dir() -> str:
        """Get the update staging directory."""
        update_dir = os.path.join(UpdateChecker.get_app_data_dir(), "updates")
        os.makedirs(update_dir, exist_ok=True)
        return update_dir

    def launch_installer(self, installer_path: str) -> bool:
        """
        Launch the downloaded installer.

        Args:
            installer_path: Path to the installer EXE

        Returns:
            True if successfully launched, False otherwise
        """
        try:
            subprocess.Popen([installer_path])
            return True
        except Exception as e:
            print(f"Error launching installer: {e}")
            return False

    def replace_executable(
        self, new_exe_path: str, current_exe_path: str = None
    ) -> bool:
        """
        Replace the current executable with the updated one.

        Args:
            new_exe_path: Path to the new executable
            current_exe_path: Path to current executable (defaults to sys.executable)

        Returns:
            True if successful, False otherwise
        """
        if current_exe_path is None:
            current_exe_path = sys.executable

        try:
            # Create a backup
            backup_path = current_exe_path + ".backup"
            if os.path.exists(current_exe_path):
                shutil.copy2(current_exe_path, backup_path)

            # Replace the executable
            shutil.move(new_exe_path, current_exe_path)
            return True

        except Exception as e:
            print(f"Error replacing executable: {e}")
            # Attempt to restore from backup
            try:
                if os.path.exists(backup_path) and not os.path.exists(current_exe_path):
                    shutil.copy2(backup_path, current_exe_path)
            except Exception as restore_err:
                print(f"Error restoring backup: {restore_err}")
            return False

    def cleanup_old_updates(self, keep_count: int = 3) -> None:
        """
        Clean up old update files.

        Args:
            keep_count: Number of recent updates to keep
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
