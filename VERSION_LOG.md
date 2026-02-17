# Version Log













































































## 2026.02.17-13 - 2026-02-17
- Model validation fixes: auto-clear invalid models, startup validation, enhanced cloud provider handling
## 2026.02.17-13 - 2026-02-17
- **Fix:** Invalid model persistence when no models available (automatically clear invalid models like llama3 when Gemini selected)
- **Fix:** Startup model validation ensures saved model matches provider (auto-fixes mismatches on program startup)
- **Fix:** Enhanced model validation logic to handle empty model lists from cloud providers without API keys

## 2026.02.17-12 - 2026-02-17
- **UX:** Simplified installer information screen (43 lines instead of 209-line README)
- **UX:** Created focused INSTALL_INFO.txt with only essential installation information

## 2026.02.17-11 - 2026-02-17
- **Fix:** Model field now always matches selected server (automatically clears invalid models when switching servers)
- **Fix:** Auto-select best model when current model is not in the provider's available models list

## 2026.02.17-10 - 2026-02-17
- **UX:** Move API key link below the API key field for better visibility
- **UX:** Make cancel button instant (1ms polling instead of 30ms when cancelling)
- **UX:** Always default to best model for selected LLM provider (deepseek-r1 for Ollama, gpt-4o for OpenAI, claude-3.5-sonnet for Anthropic)
- **UX:** Ensure all LLM fields update appropriately when server selection changes
- **UX:** Ensure all LLM fields are in appropriate state on dialog startup
- **Fix:** Disable LLM by default (don't assume Ollama is installed)
- **Fix:** Preserve empty values in settings instead of forcing Ollama defaults
- **Fix:** Disable deprecated use_local_model flag
- **Fix:** Enable/disable Test Connection button appropriately
- **Fix:** Enable/disable API key Show checkbox with API key fields
- **Fix:** Clear verification status when switching servers
- **Fix:** Prevent double model refresh on startup and server change
## 2026.02.17-9 - 2026-02-17
- Update VERSION_LOG with comprehensive change details for v2026.2.17-8
## 2026.02.17-8 - 2026-02-17
- **Feature:** Mark Unsure - Add uncertain classifications to Knowledge Base for later review
- **Security:** API key verification with provider validation (OpenAI, Google, Anthropic)
- **Security:** Encrypt chat history, Knowledge Base, and API keys (Fernet encryption)
- **Security:** Git history sanitization - removed sensitive network data from all 281 commits
- **Legal:** Comprehensive liability protections and export control compliance
- **Legal:** U.S. Export Administration Regulations (EAR) compliance notices
- **Legal:** Network monitoring legality warnings (18 U.S.C. § 2511, GDPR, CCPA)
- **Legal:** Dual-use technology notice (defensive vs. offensive use)
- **Legal:** Prohibited uses documentation and responsible disclosure policy
- **Documentation:** LEGAL_PROTECTIONS.md - Complete legal protection inventory
- **Documentation:** DOCUMENTATION_AUDIT.md - Comprehensive documentation verification
- **Documentation:** COPYRIGHT_HEADER.txt - GPL header template for source files
- **Documentation:** HISTORY_REWRITE_NOTICE.md - Git sanitization notice
- **Documentation:** USER_MANUAL.md Section 17 - Legal compliance guide (200+ lines)
- **UI:** Improved button ordering and dropdown clearing
## 2026.02.17-7 - 2026-02-17
- Fix pcapng reading - use PcapReader instead of RawPcapNgReader to prevent freeze
## 2026.02.17-6 - 2026-02-17
- Fix pcapng file reader freeze during initialization
## 2026.02.17-5 - 2026-02-17
- Fix pcapng file support and correct SHA256 checksums
## 2026.02.17-4 - 2026-02-17
- Update dependencies to latest versions (pyinstaller 6.19.0, filelock 3.24.2, platformdirs 4.9.2, cssselect2 0.9.0, typer-slim 0.24.0)
## 2026.02.17-3 - 2026-02-17
- Add Windows Package Manager (winget) support - submitted to microsoft/winget-pkgs for publication
## 2026.02.17-2 - 2026-02-17
- Suppress Bandit B608 false positive for batch script creation
## 2026.02.17-1 - 2026-02-17
- **Critical Fix:** Handle .pcapng files without linktype attribute (RawPcapNgReader compatibility) - resolves "object has no attribute 'linktype'" errors
- **UX Improvement:** Ask user choice when LLM fails instead of automatically saving label (prevents accidental duplicates)
- **UX Improvement:** Disabled automatic progress status messages in bottom-right corner
## 2026.02.16-22 - 2026-02-16
- Fixed update process crash after download completes
## 2026.02.16-21 - 2026-02-16
- Minor tweaks and improvements
## 2026.02.16-20 - 2026-02-16
- Minor tweaks and improvements
## 2026.02.16-19 - 2026-02-16
- Minor tweaks and improvements
## 2026.02.16-18 - 2026-02-16
- Minor tweaks and improvements
## 2026.02.16-17 - 2026-02-16
- Minor tweaks and improvements
## 2026.02.16-16 - 2026-02-16
- Minor tweaks and improvements
## 2026.02.16-15 - 2026-02-16
- Minor tweaks and improvements
## 2026.02.16-14 - 2026-02-16
- Minor tweaks and improvements
## 2026.02.16-13 - 2026-02-16
- Minor tweaks and improvements
## 2026.02.16-12 - 2026-02-16
- Minor tweaks and improvements
## 2026.02.16-11 - 2026-02-16
- Minor tweaks and improvements
## 2026.02.16-10 - 2026-02-16
- Minor tweaks and improvements
## 2026.02.16-9 - 2026-02-16
- Minor tweaks and improvements
## 2026.02.16-8 - 2026-02-16
- Minor tweaks and improvements
## 2026.02.16-7 - 2026-02-16
- Minor tweaks and improvements
## 2026.02.16-6 - 2026-02-16
- **Breaking Change:** Removed ZIP file support - application now only accepts .pcap and .pcapng files directly
- **Feature:** LLM analysis now enabled by default (uses Ollama with llama3 model on localhost:11434)
- **UX Improvement:** Added initialization counter showing elapsed seconds during analysis startup
- **UX Improvement:** Progress bar and logo animations now start only when actual progress begins (not during initialization)
- **Performance:** Eliminated ZIP extraction overhead and simplified file handling logic
- **Docs:** Updated all documentation to remove ZIP references and reflect new initialization behavior
## 2026.02.16-5 - 2026-02-16
- Docs refresh + CI updates + UI polish + test updates
## 2026.02.16-4 - 2026-02-16
- Performance fix: Removed blocking update_idletasks() calls from busy state changes. Eliminates stuttering during analysis startup by letting the event loop update naturally instead of forcing synchronous GUI updates.
## 2026.02.16-3 - 2026-02-16
- UX improvement: Re-added spinning logo animation during analysis. Changed initial message to 'Initializing...' before progress starts, providing clearer feedback during startup phase.
## 2026.02.16-2 - 2026-02-16
- UX change: Removed pulsing progress bar animation and spinning logo. Progress bar now stays in determinate mode starting at 0, providing cleaner visual feedback during analysis.
## 2026.02.16-1 - 2026-02-16
- UX change: Removed pulsing progress bar animation and spinning logo. Progress bar now stays in determinate mode starting at 0, providing cleaner visual feedback during analysis.
## 2026.02.15-31 - 2026-02-15
- Performance fix: Eliminated UI freezes during analysis. Removed blocking .update() call and optimized tree table operations. Analysis completion now processes instantly without freezing UI thread.
## 2026.02.15-30 - 2026-02-15
- Critical fix: Mark as Malicious/Safe no longer freezes UI. Local model training now runs in background thread instead of blocking UI thread. Eliminates multi-second freeze when labeling captures with Use Local Model enabled.
## 2026.02.15-29 - 2026-02-15
- Major UX improvement: Progress bar now pulses smoothly in constant motion until actual progress available, then shows real progress. Logo spins continuously throughout. Much simpler and smoother experience.
## 2026.02.15-28 - 2026-02-15
- Fix: Smooth continuous progress flow - parsing shows 0-30 (no more backwards jumps)
## 2026.02.15-27 - 2026-02-15
- Fix: Progress bar stays at 0 until 0.5 progress reached - prevents premature movement and percentage display during initial analysis startup
## 2026.02.15-26 - 2026-02-15
- Fix: Eliminate initial analysis stuttering. Added startup grace period with 4x more aggressive throttling (2 to prevent UI flooding while threads spawn.
## 2026.02.15-25 - 2026-02-15
- Fix: Eliminate initial analysis stuttering. Added startup grace period with 4x more aggressive throttling (2 to prevent UI flooding while threads spawn.
## 2026.02.15-24 - 2026-02-15
- Fix: Progress bar stuttering. Removed easing animation in favor of direct updates for precise, stutter-free progress tracking during analysis.
## 2026.02.15-23 - 2026-02-15
- Enhancement: Smoother progress updates. Reduced thresholds (0.5, 100ms vs 150ms), faster animation (40 easing, 20ms ticks), longer progress bar (300px), smoother spinner (8ms).
## 2026.02.15-22 - 2026-02-15
- Fix: Window hang on close (file I/O blocking). Moved KB backup and settings save to background thread for instant window closure.
## 2026.02.15-21 - 2026-02-15
- Fix: Window hang on close (resolved blocking messagebox). Removed LLM server stop prompt during shutdown to prevent UI freeze.
## 2026.02.15-20 - 2026-02-15
- Fix: Window hang on close. Added proper cleanup of pending callbacks and animations before window destruction.
## 2026.02.15-19 - 2026-02-15
- Fix: UI stuttering during analysis (progress throttling). Performance: Optimized update frequency and reduced UI thread overhead.
## 2026.02.15-18 - 2026-02-15
- Bug fix: Drag and drop file handling. Performance: Reduced startup time and UI stuttering (optimized gradient rendering, deferred animation loading, improved widget batching).
## 2026.02.15-17 - 2026-02-15
- Security: Add encrypted keyring storage for OTX API keys. Update: Fix UAC elevation for Program Files updates.
## 2026.02.15-16 - 2026-02-15
- Minor tweaks and improvements
## 2026.02.15-15 - 2026-02-15
- Minor tweaks and improvements
## 2026.02.15-14 - 2026-02-15
- Minor tweaks and improvements
## 2026.02.15-13 - 2026-02-15
- Bug fix: Mouse wheel scrolling in text widgets. License: Relicensed under GNU GPLv3.
## 2026.02.15-12 - 2026-02-15
- Minor tweaks and improvements
## 2026.02.15-11 - 2026-02-15
- Minor tweaks and improvements
## 2026.02.15-10 - 2026-02-15
- Minor tweaks and improvements
## 2026.02.15-9 - 2026-02-15
- Minor tweaks and improvements
## 2026.02.15-8 - 2026-02-15
- Minor tweaks and improvements
## 2026.02.15-7 - 2026-02-15
- Minor tweaks and improvements
## 2026.02.15-6 - 2026-02-15
- Minor tweaks and improvements
## 2026.02.15-5 - 2026-02-15
- Minor tweaks and improvements
## 2026.02.15-5 - 2026-02-15
**Security Audit & Hardening**
- Completed comprehensive security audit with excellent results
- Fixed bare exception clause in update_checker.py for better error handling
- Fixed test suite UTF-8 encoding issues on Windows console
- Updated pip to 26.0.1 (fixes CVE-2026-1703)
- Verified all security measures: HMAC model verification, path traversal prevention, secure credential storage
- Confirmed secure credential storage in Windows Credential Manager
- Validated network security: TLS by default, HTTP blocking for remote hosts, domain validation
- Verified SHA-256 download verification with TOCTOU protection
- All modules import successfully, zero compilation errors
- Security score: Excellent 🛡️ (production-ready)

## 2026.02.15-4 - 2026-02-15
- Minor tweaks and improvements
## 2026.02.15-3 - 2026-02-15
- Minor tweaks and improvements
## 2026.02.15-2 - 2026-02-15
- Minor tweaks and improvements
## 2026.02.15-1 - 2026-02-15
- Minor tweaks and improvements
## 2026.02.14-14 - 2026-02-14
- Minor tweaks and improvements
## 2026.02.14-13 - 2026-02-14
- Minor tweaks and improvements
## 2026.02.14-12 - 2026-02-14
**Stable Release - Python 3.14 Compatible**
- Fixed LLM indicator button to run connection test (instead of toggle)
- Fixed Python 3.14 DLL loading issues by switching to onedir build mode
- Fixed update system relaunch with proper working directory
- Improved installer update messaging for clarity
- Disabled UPX compression for Python 3.14+ compatibility
- All dependencies now properly bundled in `_internal/` folder
## 2026.02.14-11 - 2026-02-14
- Minor tweaks and improvements
## 2026.02.14-10 - 2026-02-14
- Switched to onedir mode for Python 3.14 compatibility - fixes DLL loading issues
## 2026.02.14-9 - 2026-02-14
- Testing update system and Python 3.14 DLL bundling
## 2026.02.14-8 - 2026-02-14
- Minor tweaks and improvements
## 2026.02.14-7 - 2026-02-14
- Minor tweaks and improvements
## 2026.02.14-6 - 2026-02-14
- Minor tweaks and improvements
## 2026.02.14-5 - 2026-02-14
- Minor tweaks and improvements
## 2026.02.14-8 - 2026-02-14
- Move LLM configuration to dedicated LLM Settings dialog
- LLM button in header now toggles LLM on/off for quick access
- Add "LLM Settings..." option to File menu for configuration
- Remove LLM configuration section from Preferences dialog
- Simplify Preferences dialog by focusing on general application settings
- Add standard Edit menu functions: Undo, Redo, Cut, Copy, Paste, Select All
- Edit menu now includes keyboard shortcuts for all operations (Ctrl+Z, Ctrl+Y, Ctrl+X, Ctrl+C, Ctrl+V, Ctrl+A)
- Move Preferences from Edit menu to File menu for better organization

## 2026.02.14-7 - 2026-02-14
- Add File, Edit, and Help menu bar
- Apply theme colors to menu bar (dark/light mode support)
- Move Check for Updates and Preferences to menus
- Remove User Manual button from header (now in Help menu)
- Add keyboard shortcuts (Ctrl+O, Ctrl+L, Ctrl+,)
- Add User Manual, View Logs, and About menu items
- Clean up toolbar and header by removing redundant buttons

## 2026.02.14-6 - 2026-02-14
- Simplify update system for improved reliability
- Streamline download and install flow
- Add progress indicators with MB display
- Improve error messages and user feedback
- Add automated update system test (test_update_system.py)
- Maintain all security features (SHA-256, domain validation, path security)

## 2026.02.14-5 - 2026-02-14
- Add comprehensive test suite (17 tests, 100% pass rate)
- Create stability tests for core functionality and security validation
- Create stress tests for performance and memory benchmarks
- Generate code review report (95% security score)
- Document testing infrastructure and results

## 2026.02.14-4 - 2026-02-14
- Updater test build
## 2026.02.14-3 - 2026-02-14
- Bundle VC runtime DLLs
## 2026.02.14-2 - 2026-02-14
- Updater test build
## 2026.02.14-1 - 2026-02-14
- VC++ runtime check
## 2026.02.13-53 - 2026-02-13
- Updater test build
## 2026.02.13-52 - 2026-02-13
- Always bundle VC++ runtime
## 2026.02.13-51 - 2026-02-13
- Require admin for VC++ runtime install
## 2026.02.13-50 - 2026-02-13
- Updater test
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
- **Path validation**: All file operations use canonical paths with safety checks
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
