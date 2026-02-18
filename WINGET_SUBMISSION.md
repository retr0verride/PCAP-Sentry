# Windows Package Manager (winget) Manifests

This directory contains winget manifest files for PCAP Sentry.

## Submitting to winget-pkgs Repository

To make PCAP Sentry available via `winget install PCAP-Sentry`:

### Option 1: Automated Submission (Recommended)

1. Install wingetcreate:
   ```powershell
   winget install wingetcreate
   ```

2. Update manifest for new release:
   ```powershell
   wingetcreate update retr0verride.PCAP-Sentry -u https://github.com/retr0verride/PCAP-Sentry/releases/download/v2026.2.17-2/PCAP_Sentry_Setup.exe -v 2026.2.17.2 -t <GITHUB_TOKEN>
   ```
   
   This will automatically:
   - Download the installer
   - Calculate SHA256 hash
   - Update version number
   - Create a PR to microsoft/winget-pkgs

### Option 2: Manual Submission

1. Fork https://github.com/microsoft/winget-pkgs

2. Create directory structure:
   ```
   winget-pkgs/
   └── manifests/
       └── i/
           └── retr0verride/
               └── PCAP-Sentry/
                   └── 2026.2.17.2/
                       ├── retr0verride.PCAP-Sentry.installer.yaml
                       ├── retr0verride.PCAP-Sentry.locale.en-US.yaml
                       └── retr0verride.PCAP-Sentry.yaml
   ```

3. Copy the three YAML files from this directory

4. Validate manifests:
   ```powershell
   winget validate --manifest manifests/i/retr0verride/PCAP-Sentry/2026.2.17.2/
   ```

5. Create PR to microsoft/winget-pkgs

## Updating for New Releases

When publishing a new version:

1. Update all three YAML files with new version number
2. Update `InstallerUrl` with new release download URL
3. Update `InstallerSha256` with new checksum (from SHA256SUMS.txt)
4. Update `ReleaseDate` and `ReleaseNotes`
5. Submit PR to winget-pkgs

## Manifest Schema

- **installer.yaml**: Installer-specific metadata (URL, hash, architecture)
- **locale.en-US.yaml**: Package description, tags, publisher info
- **version.yaml**: Version manifest linking the above files

## Resources

- [winget documentation](https://learn.microsoft.com/en-us/windows/package-manager/)
- [Manifest schema reference](https://learn.microsoft.com/en-us/windows/package-manager/package/manifest)
- [winget-pkgs repository](https://github.com/microsoft/winget-pkgs)
- [wingetcreate tool](https://github.com/microsoft/winget-create)
