# Changelog

## 1.0.0

First public release.

- Window and console mode in one pure-PowerShell script; pastes into PowerShell ISE.
- Recovers quarantined files, alternate data streams, extended attributes, security descriptors and registry hives.
- Writes AES-256 (default) or ZipCrypto archives directly, verifies them by reading back, optional one zip per file,
  one-click export of a single item.
- Inputs: zip, gzip, nested zips, password-protected zips (ZipCrypto and AES), folders at any level, flattened or
  renamed files, several sources at once.
- Decodes quarantine entries, DetectionHistory, scan results, AMSI captures and scan context, MPLog, MPDetection and
  the Defender operational event log into one timeline.
- Confirms recovered hashes against Defender's own records.
- Offline HTML report with light and dark themes; case ID, analyst, title and description.
- Test suite and screenshots built on synthetic evidence.
