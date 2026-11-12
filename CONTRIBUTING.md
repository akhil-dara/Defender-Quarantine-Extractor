# Contributing

Thanks for helping. Bug reports with a clear description of the collection layout are as valuable as code.

## Ground rules

- **Never attach real malware, real quarantine files or evidence from real hosts** to issues or pull requests. Describe
  the layout instead, or reproduce it with `tests\New-DemoEvidence.ps1`.
- The tool must stay a single pure-PowerShell file: no compiled code (`Add-Type -TypeDefinition`), no external modules,
  no downloads, no temporary files. Only .NET types that ship with Windows.
- Recovered content must never reach the disk unencrypted. The test suite checks this.
- Keep sources ASCII. The build refuses anything else, because pasted scripts must survive any editor.

## Layout

| Path | What |
|---|---|
| `src\Header.ps1` | Comment-based help and parameters |
| `src\Engine.ps1` | Source readers, Defender parsers, archive writer |
| `src\Gui.ps1` | WPF window |
| `src\Main.ps1` | Console mode and entry point |
| `src\Report.html` | Report template |
| `src\assets\` | Emblem |
| `build\Build.ps1` | Stitches the parts into `Defender-Quarantine-Extractor.ps1` |
| `build\Update-Screenshots.ps1` | Regenerates `docs\images` from synthetic evidence |
| `tests\New-DemoEvidence.ps1` | Writes synthetic Defender evidence in eight collection layouts |
| `tests\Invoke-Tests.ps1` | Test suite (runs the security suite too) |
| `tests\New-HostileEvidence.ps1` | Writes crafted evidence: traversal names, injection text, decompression bombs, lying sizes, fuzzed artifacts |
| `tests\Invoke-SecurityTests.ps1` | Security suite: runs the tool against that evidence, measuring memory per bomb |

## Workflow

```powershell
# edit files under src\, then
powershell -File build\Build.ps1
powershell -File tests\Invoke-Tests.ps1
```

Commit both the `src\` changes and the rebuilt `Defender-Quarantine-Extractor.ps1`; CI fails if they differ.

When you add support for a new artifact or layout, extend `tests\New-DemoEvidence.ps1` so the case is covered by
synthetic data, and document the format in `docs\artifacts.md`.
