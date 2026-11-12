# Security policy

## Reporting a vulnerability

If you find a way for recovered content to reach the disk unencrypted, for the archive to be produced in a form that
does not protect its content, or for crafted evidence to make the tool run code, please report it privately through
GitHub's **Report a vulnerability** button on the Security tab rather than opening a public issue.

Please include the collection layout and the steps to reproduce, but **no real malware or real evidence**.
`tests\New-DemoEvidence.ps1` can build synthetic inputs.

## Scope notes

- The tool parses untrusted, attacker-influenced data (quarantine files and logs from a compromised host). Parsing
  errors are reported in the Notes section and never stop a run or execute content. Sizes declared inside evidence
  are not trusted: reads are capped per kind of artifact, decompression stops at the data actually present, and
  nested archives share a memory budget. `tests\Invoke-SecurityTests.ps1` exercises these guarantees.
- The default archive password `infected` is a convention, not a secret.
- The report masks captured script text so on-access scanners do not quarantine it. This is not encryption.
