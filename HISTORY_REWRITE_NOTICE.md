# Git History Rewrite Notice

**Date**: February 17, 2026

## What Happened

The git history of this repository was rewritten to remove sensitive network data that was accidentally committed in the Knowledge Base sample file (`Python/pcap_knowledge_base_offline.json`).

## What Was Removed

- Internal hostnames (DESKTOP-* names)
- Network traffic statistics from real PCAP captures
- Port numbers and protocol distributions
- DNS query data

This data was replaced with an empty template throughout the entire git history.

## Impact

- All commit hashes have changed
- All tags have been updated with new hashes
- Force push was applied to both `main` and `develop` branches

## Action Required for Contributors

If you have a local clone of this repository:

1. **Backup any uncommitted work**
2. **Delete your local repository**
3. **Clone fresh from GitHub**:
   ```bash
   git clone https://github.com/industrial-dave/PCAP-Sentry.git
   ```

**DO NOT** try to merge or pull - this will create issues due to the history rewrite.

## Security Improvements

Along with this history rewrite, the following security measures were implemented:

1. **Encryption**: Chat history and Knowledge Base are now encrypted on disk
2. **`.gitignore` updated**: Sensitive files (settings.json, *.pcap, logs) now excluded
3. **Documentation**: Added data privacy section to SECURITY.md
4. **Template-only**: Repository now contains only empty KB template

## Questions

If you have any questions about this change, please open an issue.
