# Version Log













## 2026.02.13-16 - 2026-02-13
- Move model uninstall to Preferences; simplify installer model flow
- Add deepseek-r1:14b to installer model presets
- Remove redundant model-selection copy and streamline installer wording
- Add installer link to Ollama model library with descriptions
- Enable selecting multiple installer models via checkboxes
- Keep installer progress visible through runtime + per-model pulls
- Start Ollama in headless mode during installer model setup and avoid opening desktop UI
- Add optional "Stop Ollama on exit" setting (enabled by default)
- Update README and USER_MANUAL for installer model workflow changes
## 2026.02.13-15 - 2026-02-13
- Minor tweaks and improvements
## 2026.02.13-14 - 2026-02-13
- Added deferred in-app standalone update replacement with clearer failure reasons.
- Added installer progress for Ollama runtime install and per-model actions.
- Added installer model management mode to install/update or remove selected Ollama models.
- Updated updater and user manuals for new update and model-management behavior.
## 2026.02.13-13 - 2026-02-13
- Minor tweaks and improvements
## 2026.02.13-12 - 2026-02-13
- Minor tweaks and improvements
## 2026.02.13-11 - 2026-02-13
- Minor tweaks and improvements
## 2026.02.13-10 - 2026-02-13
- Avoid installer stall by running Ollama setup in background
## 2026.02.13-9 - 2026-02-13
- Clarify offline Ollama vs cloud LLM endpoints in UI/docs
## 2026.02.13-8 - 2026-02-13
- Installer disk space estimates and checks for Ollama models
## 2026.02.13-7 - 2026-02-13
- Installer option to install Ollama and pull models
## 2026.02.13-6 - 2026-02-13
- Upgrade build/runtime to Python 3.14, bundle active Python DLL, update docs
## 2026.02.13-5 - 2026-02-13
- LLM status persistence, indicator button, DLL fix
## 2026.02.13-4 - 2026-02-13
- Minor tweaks and improvements
## 2026.02.13-3 - 2026-02-13
- Fix: bundle python312.dll for DLL load error
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
