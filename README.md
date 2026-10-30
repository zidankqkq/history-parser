# History Parser

What ran on this PC, and whether those records can be trusted. Execution evidence (Prefetch, BAM, PCA, UserAssist, ShimCache, Amcache, USN journal, Recycle Bin, memory) cross-checked for deleted/swapped files and clock changes, plus the integrity of the recording services. It does not judge cheats by name.

**This is one tool of a screenshare forensics set.** Each tool is its own repository; download only the ones you need and keep them in a folder together.

## Download

Get `HistoryParser.exe` from the [latest release](../../releases/latest). Nothing installs. It only reads; it never changes, deletes or uploads anything. Run it as administrator for a complete scan.

The exe is built on GitHub's servers from this source and carries a signed build-provenance attestation, so you can verify your download matches the code:

```
gh attestation verify HistoryParser.exe --repo <your-user>/history-parser
```

It is not code-signed, so Windows SmartScreen shows a warning on first run (More info -> Run anyway).

## Build it yourself

Needs the .NET 9 SDK on Windows.

```
dotnet test tests/HistoryParser.Core.Tests -c Release
./publish.ps1 -Version 1.0.0
```

## Releasing

Push a tag like `v1.0.0`; GitHub Actions builds HistoryParser.exe, writes its SHA-256, signs the provenance and creates the release.

## Layout

- `src/HistoryParser.App` - the program.
- `src/HistoryParser.Core`, `src/RatChecker.Core` - the shared forensics libraries.
- `tests/HistoryParser.Core.Tests` - the test suite.
