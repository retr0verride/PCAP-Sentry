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
                    raw = response.read(self._MAX_API_RESPONSE_BYTES + 1)
                    if len(raw) > self._MAX_API_RESPONSE_BYTES:
                        raise RuntimeError("GitHub API response too large")
                    releases = json.loads(raw.decode("utf-8"))
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
                    raw = response.read(self._MAX_API_RESPONSE_BYTES + 1)
                    if len(raw) > self._MAX_API_RESPONSE_BYTES:
                        raise RuntimeError("GitHub API response too large")
                    best = json.loads(raw.decode("utf-8"))

            if best is None:
                self._last_error = "No published releases found."
                return False

            self.latest_release = best
            self.latest_version = best.get("tag_name", "").lstrip("v")
            self.release_notes = best.get("body", "")

            # Find the best downloadable asset.
            # Prefer the installer (Setup EXE) so that ALL files
            # (EXE, README, LICENSE, VC++ runtime, etc.) are replaced.
            assets = best.get("assets", [])
            installer_url = None
            standalone_url = None
            self.download_is_installer = False
            for asset in assets:
                name = asset.get("name", "")
                url = asset.get("browser_download_url", "")
                if not name.lower().endswith(".exe"):
                    continue
                # Only accept download URLs from GitHub domains
                if not self._is_trusted_download_url(url):
                    continue
                if "setup" in name.lower() or "install" in name.lower():
                    if "PCAP_Sentry" in name:
                        installer_url = url
                elif "PCAP_Sentry" in name:
                    standalone_url = url

            if installer_url:
                self.download_url = installer_url
                self.download_is_installer = True
            elif standalone_url:
                self.download_url = standalone_url
                self.download_is_installer = False

            # Fetch expected SHA-256 hash from the release's SHA256SUMS.txt asset
            self._expected_sha256 = self._fetch_sha256_for_asset(best, ctx)

            return True

        except Exception as e:
            print(f"Error fetching latest release: {e}")
            self._last_error = str(e)
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
                # Enforce download size limit
                if total_size > self._MAX_DOWNLOAD_BYTES:
                    raise RuntimeError(f"Download too large ({total_size} bytes)")
                downloaded = 0
                chunk_size = 65536
                sha256 = hashlib.sha256()
                with open(destination, "wb") as f:
                    while True:
                        chunk = response.read(chunk_size)
                        if not chunk:
                            break
                        downloaded += len(chunk)
                        if downloaded > self._MAX_DOWNLOAD_BYTES:
                            raise RuntimeError("Download exceeded size limit")
                        f.write(chunk)
                        sha256.update(chunk)
                        if progress_callback:
                            progress_callback(downloaded, total_size)

            if not (os.path.exists(destination) and os.path.getsize(destination) > 0):
                return False

            # Verify SHA-256 hash if available
            actual_hash = sha256.hexdigest().lower()
            expected = getattr(self, "_expected_sha256", {}) or {}
            filename = os.path.basename(destination)
            # Try matching by the download URL's filename first, then by destination filename
            download_filename = self.download_url.rsplit("/", 1)[-1] if self.download_url else ""
            expected_hash = expected.get(download_filename) or expected.get(filename)
            if expected_hash:
                if actual_hash != expected_hash.lower():
                    os.remove(destination)
                    self._last_error = (
                        f"SHA-256 mismatch!\n"
                        f"Expected: {expected_hash}\n"
                        f"Actual:   {actual_hash}\n"
                        f"The download may have been tampered with."
                    )
                    print(f"Security: SHA-256 mismatch for {filename}")
                    return False
                print(f"Security: SHA-256 verified for {filename}")
            else:
                print(f"Security: No SHA-256 hash available for {filename} (skipping verification)")

            return True

        except Exception as e:
            print(f"Error downloading update: {e}")
            self._last_error = str(e)
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
                print(f"Security: installer_path is not under update dir — refusing to launch.")
                self._last_error = "Installer path validation failed."
                return False
            # Re-verify SHA-256 immediately before execution (prevent TOCTOU)
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
                    print(f"Security: SHA-256 mismatch at launch time — refusing to execute.")
                    self._last_error = "SHA-256 verification failed before launch."
                    return False
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
            self._last_error = None

            current_name = os.path.basename(current_exe_path).lower()
            if (not getattr(sys, "frozen", False)) or current_name.startswith("python"):
                self._last_error = (
                    "Automatic replacement is unavailable when running from source/venv. "
                    "Use the installer build for in-app updates."
                )
                return False

            if not os.path.exists(new_exe_path):
                self._last_error = f"Downloaded update not found: {new_exe_path}"
                return False

            # Back up the knowledge base so user data is preserved
            self._backup_knowledge_base_before_update()

            backup_path = current_exe_path + ".backup"
            script_path = os.path.join(self.get_update_dir(), "apply_update.cmd")

            # Sanitize paths to prevent command injection via special characters
            def _sanitize_cmd_path(p: str) -> str:
                """Remove characters that could break out of CMD variable quoting."""
                # Only allow safe path characters: letters, digits, spaces, \, /, :, ., -, _
                return re.sub(r'[^\w\s\\/:._-]', '', p)

            safe_new = _sanitize_cmd_path(new_exe_path)
            safe_cur = _sanitize_cmd_path(current_exe_path)
            safe_bak = _sanitize_cmd_path(backup_path)

            script_lines = [
                "@echo off",
                "setlocal",
                f'set "NEW_EXE={safe_new}"',
                f'set "CUR_EXE={safe_cur}"',
                f'set "BACKUP_EXE={safe_bak}"',
                "set RETRIES=30",
                "",
                ":retry",
                "copy /Y \"%CUR_EXE%\" \"%BACKUP_EXE%\" >nul 2>&1",
                "move /Y \"%NEW_EXE%\" \"%CUR_EXE%\" >nul 2>&1",
                "if errorlevel 1 (",
                "  set /a RETRIES-=1",
                "  if %RETRIES% LEQ 0 goto fail",
                "  timeout /t 1 /nobreak >nul",
                "  goto retry",
                ")",
                "start \"\" \"%CUR_EXE%\"",
                "del \"%~f0\"",
                "exit /b 0",
                "",
                ":fail",
                "exit /b 1",
            ]

            with open(script_path, "w", encoding="utf-8", newline="\r\n") as f:
                f.write("\r\n".join(script_lines) + "\r\n")

            creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
            subprocess.Popen(
                ["cmd", "/c", script_path],
                creationflags=creation_flags,
            )
            return True

        except Exception as e:
            self._last_error = str(e)
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
