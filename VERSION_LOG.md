# Version Log











## 2026.02.13-49 - 2026-02-13
- 2026.02.14-1 release
## 2026.02.13-48 - 2026-02-13
- Updater test
## 2026.02.13-47 - 2026-02-13
- Bundle VC++ runtime for updater
## 2026.02.13-46 - 2026-02-13
- Minor tweaks and improvements
## 2026.02.13-45 - 2026-02-13
- Minor tweaks and improvements
## 2026.02.13-44 - 2026-02-13
- Restore original logo and high-res icon assets
## 2026.02.13-43 - 2026-02-13
- Security hardening, UAC elevation fix, optimization, SHA256 pipeline
## 2026.02.13 — Security Hardening & Optimization

### Security Fixes
- **Randomized HMAC key** — ML model integrity keys are now `os.urandom(32)` persisted to app data instead of being derived from predictable `COMPUTERNAME`/`USERNAME` environment variables; applies to both `pcap_sentry_gui.py` and `enhanced_ml_trainer.py`
- **Atomic settings save** — `save_settings()` now uses `tempfile.mkstemp` + `os.replace` instead of a predictable `.tmp` path, preventing symlink race attacks
- **LLM endpoint scheme validation** — `_llm_http_request()` now rejects `file://`, `ftp://`, and other non-HTTP schemes; blocks all plaintext HTTP to non-localhost hosts (not just when API key is present)
- **Drag-and-drop path hardening** — `_extract_drop_path()` now canonicalizes paths with `os.path.realpath()` and validates against allowed PCAP extensions (`.pcap`, `.pcapng`, `.cap`, `.pcap.gz`, `.pcapng.gz`)
- **UAC elevation for updates** — `launch_installer()` now uses `os.startfile()` (ShellExecuteW) and `replace_executable()` uses `ShellExecuteW` with `runas` verb, fixing the WinError 740 that prevented installers from launching

### Optimization
- **Eliminated double DataFrame copy** — `detect_suspicious_flows()` no longer copies the DataFrame returned by `compute_flow_stats()` (already a new object)
- **Cached sklearn imports** — `_get_sklearn()` results are cached in a module-level variable, avoiding repeated import lookups
- **Chat history cap** — `chat_history` is now capped at 50 entries to prevent unbounded memory growth in long sessions

### Build Pipeline
- **Local SHA256SUMS generation** — `build_release.bat` now generates and uploads `SHA256SUMS.txt` locally after all assets are uploaded, ensuring the installer hash is always included
- **Removed auto-trigger from checksums workflow** — `release-checksums.yml` no longer fires on `release: published` (which raced the build); kept as `workflow_dispatch` fallback


## 2026.02.13-42 - 2026-02-13
- Regenerated app icon at 512px source resolution for crisp display at all sizes
## 2026.02.13-41 - 2026-02-13
- Fix update dialog buttons, bundle update_checker module
## 2026.02.13-40 - 2026-02-13
- Fix version display: use build-stamped version in frozen EXE instead of dynamic date
## 2026.02.13-39 - 2026-02-13
- Rebuild ICO with multi-size icons for crisp desktop display
## 2026.02.13-38 - 2026-02-13

### LLM Server Download Progress Enhancements
- **Download speed indicator** — LLM server installer downloads now show real-time speed in MB/s, updated every 0.5 seconds
- **ETA display** — Estimated time remaining shown during download (e.g., "45s left" or "1.2m left") based on current throughput
- **Window title progress** — The application title bar now reflects download/install progress (e.g., "PCAP Sentry - 45% Downloading Ollama") so progress is visible even when the app is minimized or in the taskbar
- **Indeterminate activity in title** — Non-percentage tasks (winget installs, elevated installer execution) also update the title bar with the current activity
- **Speed display for unknown-size downloads** — Downloads without a Content-Length header now also show speed in MB/s

### General Progress Bar Improvements
- **`_set_progress()` title updates** — All task types (analysis, export, model training, LLM install) now update the window title with progress, not just the status bar
## 2026.02.13-31 - 2026-02-13

### Installer Fixes
- **Fixed "invalid string length" runtime error** — Installer log file could grow unbounded during long Ollama model pulls; `LoadStringFromFile` now checks file size (2 MB cap), parses only the tail 2 KB for progress, and wraps reads in try-except
- **Prevented Ollama desktop app from auto-launching** — Both winget and direct-download install paths now kill the desktop app immediately after install, remove the `Startup\Ollama.lnk` shortcut, and delete the registry Run key
- **Added `StopOllamaHeadless` cleanup** — The headless `ollama.exe serve` process spawned for model pulls is now terminated after pulls complete
- **Guaranteed post-install Ollama cleanup** — A final cleanup block always runs when Ollama was installed, regardless of whether models were selected

### Application Exit Behavior
- **LLM server shutdown prompt on close** — When closing PCAP Sentry with a local LLM server configured (Ollama, LM Studio, GPT4All, Jan, LocalAI, KoboldCpp), a dialog asks whether to stop the server; defaults to No to prevent accidental termination

### Security Hardening
- **HMAC integrity for GUI model loader** — `_save_local_model()` and `_load_local_model()` now sign and verify models with HMAC-SHA256 (matching `EnhancedMLTrainer` pattern); unsigned models are rejected
- **Removed HMAC legacy bypass** — `EnhancedMLTrainer._verify_hmac()` no longer allows loading models with a missing `.hmac` file; users must retrain
- **API key over HTTP blocked** — `_llm_http_request()` refuses to send API keys over plain `http://` to non-localhost endpoints with a clear error message
- **Temp directory cleanup** — Downloaded installer temp directories are now cleaned up in `finally` blocks (`shutil.rmtree`) for both generic and Ollama installer paths

### Documentation
- Updated VERSION_LOG.md, README.md, README.txt, and USER_MANUAL.md


## 2025-06-19 — Security Hardening

### Summary
Comprehensive security hardening across update pipeline, ML model loading, threat-intelligence networking, credential storage, and CI/CD workflow.

### Changes
- **SHA-256 download verification** — downloaded update executables are checked against `SHA256SUMS.txt` published alongside each GitHub release; mismatched hashes abort the update
- **Download size limits** — update downloads capped at 500 MB, API responses at 5 MB
- **URL domain validation** — only `github.com` / `*.github.com` download URLs are accepted
- **CMD path sanitization** — paths embedded in the restart batch script are stripped of shell-special characters to prevent command injection
- **HMAC model integrity** — ML models are signed with HMAC-SHA256 on save; signature is verified before `joblib.load()`, and deserialized objects are type-checked for expected sklearn interfaces
- **Keyring credential storage** — LLM API keys are stored in the OS credential manager (Windows Credential Locker) via `keyring`; existing plaintext keys are auto-migrated on first load; graceful fallback to JSON if keyring is unavailable
- **Response size limits on TI APIs** — OTX, AbuseIPDB, and URLhaus responses are capped at 2 MB before JSON parsing
- **HTTP adapter removed** — `threat_intelligence.py` no longer mounts an HTTP adapter; all requests go through HTTPS only
- **GH Actions script-injection fix** — `release-checksums.yml` moves `${{ }}` expressions to `env:` block to prevent tag-name injection into shell scripts
- **Added `keyring>=25.0`** to `requirements.txt`

## 2026.02.13-30 - 2026-02-13
- Detection accuracy + TI speed optimization + behavioral heuristics + docs update
## 2026.02.13-30 - 2026-02-13

### Detection Accuracy Improvements
- Expanded ML feature vector from 13 to 25 dimensions (median size, TLS metrics, host diversity, malware port hits, DNS-per-packet ratio, bytes-per-unique-dest)
- Added `MALWARE_PORTS` constant (~30 known C2/backdoor ports: 4444, 5555, 6666–6669, 1337, 31337, etc.)
- New `detect_behavioral_anomalies()` engine: beaconing (CV < 0.25), DNS tunneling, port scanning (20+ dst ports), data exfiltration (10:1 ratio), SYN flood/scan detection
- `detect_suspicious_flows()` now flags malware/C2 ports and beacon-like patterns (high pkt count + small payload)
- Rebalanced risk scoring weights (classifier 0.35, IoC 0.25, anomaly 0.20, behavioral 0.20) with hard escalation floors
- Behavioral findings displayed in Results and Why tabs under new "[D] BEHAVIORAL HEURISTICS" section
- Wireshark filter generation prioritizes malware port filters
- Packet hints flag known malware/C2 ports with ⚠ marker
- Updated `enhanced_ml_trainer.py` vectorizer to match expanded 25-feature set

### Threat Intelligence Speed Optimization
- All IP and domain lookups now run concurrently via ThreadPoolExecutor (up to 6 workers)
- Sub-queries within each lookup (OTX + AbuseIPDB, OTX + URLhaus) also run in parallel
- Added HTTP connection pooling with keep-alive (requests.Session, pool_connections=8, pool_maxsize=12)
- Shortened timeouts from 5s flat to 2s connect + 3s read for faster failure on degraded APIs
- Private/bogon IPs filtered before any network call via `_is_routable_ip()` (ipaddress.is_global)
- TLS SNI domains now included in threat intelligence domain checks
- Increased IP/domain query limits from 10 to 20 each (feasible due to concurrency)
- Added timing diagnostics (`[TIMING]` log line with elapsed time and worker count)

### Cleanup
- Removed unused directories: build/, logs/, logo_previews/, __pycache__/
- Removed duplicate README.txt
- Added logo_previews/ to .gitignore

### Documentation
- Updated README.md, USER_MANUAL.md, and VERSION_LOG.md to reflect all changes
- Updated feature descriptions, analysis phase list, threat intelligence performance notes
- Updated ML feature set documentation (50+ → 25 specific features)
- Expanded heuristic signals appendix with behavioral detection details

## 2026.02.13-29 - 2026-02-13

### Installer – Ollama Progress Overhaul
- Real-time download progress with MB transferred and percentage display
- Win32 process management for reliable Ollama lifecycle control
- Cancel support with confirmation dialog during model pulls
- Movable wizard window while operations are in progress
- Log file paths shown in error and cancellation dialogs for troubleshooting

### Performance Optimizations
- Deduplicated TCP data-offset calculation in PCAP parser (computed once, reused for HTTP and TLS)
- Capped HTTP payload extraction at 2 KB to avoid excess memory use
- Extracted shared `_build_llm_summary_stats()` helper to eliminate duplicate stat-building code
- Extracted shared `_parse_llm_label_response()` helper for consistent JSON label parsing across LLM providers
- Replaced `iterrows()` with `to_dict("records")` in packet table updates for faster row insertion
- Switched to mask-based filtering in `_apply_packet_filters` instead of full DataFrame copy
- Added `_vectorize_kb()` for one-time cached KB vector computation during analysis
- Centralized LLM HTTP calls into `_llm_http_request()` with automatic retry on transient errors
- Simplified `_compute_app_version()` to use already-imported modules

### Security Hardening
- **Zip Slip protection**: path traversal guard on ZIP extraction using `os.path.realpath()` validation
- **Regex injection prevention**: packet filters now use literal string matching (`regex=False`)
- **Model name validation**: Ollama model names validated with `re.fullmatch()` before subprocess use
- **URL encoding**: IP addresses URL-encoded in OTX threat intelligence lookups
- **Response size cap**: LLM HTTP responses limited to 10 MB to prevent memory exhaustion

### UI Polish
- Subdued "Reset Knowledge Base" button style (red text on panel background, solid red on hover)

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
