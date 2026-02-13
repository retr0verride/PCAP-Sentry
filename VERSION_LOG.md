# Version Log


## 2026.02.13-2 - 2026-02-13
- Minor tweaks and improvements
## 2026.02.13-1 - 2026-02-13
- Bug fixes: KB cache invalidation, NaN packet filter, domain validation, duplicate tab select, unused import cleanup, missing offline_mode default.
- Corrected user manual data paths to match actual code behavior.

## 2026.02.12-27 - 2026-02-12
- Multiple build iterations for installer packaging and testing.

## 2026.02.12-13 - 2026-02-12
- Clean rebuild with performance optimizations and bug fixes.

## 2026.02.11-2 - 2026-02-11
- Added built-in update system with GitHub Releases integration.
- Users can now check for and download updates directly from the app.
- Background update checking with progress feedback.
- Automatic version comparison and installer launching.

## 2026.02.11-1 - 2026-02-11
- Added analysis explanations with packet inspection and Wireshark filter suggestions.
- Improved UI tab order defaults and icon loading across dev/builds.
- Hardened app startup, parsing timestamps, and dependency metadata.

## 2026.02.10-6 - 2026-02-10
- Removed optional acceleration support and related packaging.

## 2026.02.10-5 - 2026-02-10
- Bundled ML runtime into the build and trimmed non-essential modules.
- Improved local model training/inference handling.
- Added accelerator availability status in Preferences.
- Updated build scripts to use the workspace venv when present.
- Added optional VC++ runtime inclusion for the installer.

## 2026.02.10-4 - 2026-02-10
- Added a git post-commit hook to auto-push changes.

## 2026.02.10-3 - 2026-02-10
- Suppressed PyInstaller warnings by using collect_submodules with on_error=ignore.

## 2026.02.10-2 - 2026-02-10
- Suppressed additional PyInstaller warnings by excluding optional modules.

## 2026.02.10-1 - 2026-02-10
- Switched to date-based versioning.
- Added version display in the app UI.
- Added build logging with system/package info.
- Added installer script and metadata packaging.
- Added app data fallback notice and UI improvements.
