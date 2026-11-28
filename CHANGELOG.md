# Changelog

## [0.2.0]

### Highlights & UI
- **Crash frequency.** Repeated identical crashes are counted inside the selected 7d/14d/30d/All window and shown as `[xN]` next to the incident plus a `Frequency: N times ...` line in the details and copied report. Chronological rows are never merged.
- **Folder watcher.** FrameFault watches the real Windows crash folders — per-user and machine-wide WER queues/archives (recursively), `%LOCALAPPDATA%\CrashDumps`, LocalLow (`Player.log` only) and UE `Saved\Crashes` — and rescans after a 1.5 s debounce. A manually dropped crash is never overwritten; **Return to local PC** switches back.
- **Universal scope.** One verdict for Windows apps, GPU drivers, BSODs and PC game crashes, not just games.
- The status bar now reports `User-space .dmp` instead of claiming dumps are ignored.

### Accuracy & Parsers
- **User-mode minidumps.** `.dmp` (MDMP) files are read through the `minidump` crate: crash time, exception code, faulting module and non-system module paths. No stack/heap memory, environment blocks, in-memory strings, symbols or PDB downloads.
- Automatic dump discovery is limited to `%LOCALAPPDATA%\CrashDumps` and UE `Saved\Crashes`; dropped folders are searched to depth 5, newest six dumps. `C:\Windows\Minidump` and LiveKernelReports are never touched.
- Kernel `PAGEDU64` dumps are detected safely: skipped in automatic scans and reported as unsupported (admin-only) when dropped explicitly. dmp verdicts decode the exception code and match anti-cheat modules.
- Minidump events become primary anchors, so a dump-only crash still produces a verdict.
- DMP GPU context appears only when a GPU/display module (`nvlddmkm`, `amdkmd`, `igdkmd`, `igfx`, `d3d11`, `d3d12`, `dxgi`) is named.
- WER watchers now recurse into `ReportArchive\<folder>\Report.wer`.

### Privacy & Redaction
- Minidump evidence is limited to exception metadata and non-system module paths; no process memory is read.
- Reports keep the existing irreversible redaction of profile paths, identifiers and network addresses before the clipboard.

### Build & CI
- Version 0.2.0. CI keeps `--locked`, formatting, clippy, all-feature tests, pinned third-party actions and least-privilege permissions.

## [0.1.8]

### Highlights & UI
- 7d/14d/30d/All filters with honest "older incidents found" hints; at 30 days the hint offers "All".
- Visible/total counts, hidden-app deduplication, copied-state reset, and storage warnings that no longer assume `C:`.
- Reports show confidence and independent source count, clean evidence, and the real Event Log ring-buffer depth, including on "no anchor" results.

### Accuracy & Parsers
- Event timestamps are converted from UTC to local time; timestamps in the DST fall-back hour use the earliest valid local instant.
- Event XML parsing handles self-closing `<Data />`, `>` inside quoted attributes, and retries `EvtRender` when the buffer is too small.
- Correlation shares one consumed set, anchors an incident on its newest event, sorts equal-score findings deterministically, and keeps standalone BSOD/WHEA/Kernel-Power 41/TDR/2004 events as fallback incidents.
- Bugcheck parsing prefers `BugcheckCode` over `BugcheckParameter1`, and Kernel-Power 41 advice follows the decoded stop code.
- WER supports UTF-16BE, skips empty values, understands `FaultingModule`, and reads a dropped `.wer` without mixing in machine-wide reports.
- Paths use `%ProgramData%`, `%WINDIR%`, `%SystemRoot%` and `SystemDrive` instead of assuming `C:`.
- Unreal XML accepts a dropped `<CrashContext>` file; folder discovery requires the tag in the first 4 KiB. Only whitelisted fields reach evidence, so account IDs cannot leak.
- Game logs are read from a bounded 2 MiB tail with the partial first line dropped; anti-cheat markers require error context or an exact driver module.
- Exported `.evtx` is read through `System32\wevtutil.exe` with `/f:xml`, a 10 s timeout and exit-status checking.
- Pagefiles list every `PagingFiles` entry, understand `\??\` and `?:\`, and only growable pagefiles are checked for free space.
- GPU markers are more precise; unknown GPU/driver values no longer duplicate prefixes.

### Privacy & Redaction
- Profile paths are matched case-insensitively; emails, `file://` URLs, 32-char hex IDs, SteamID64, keyed IDs (including quoted or spaced values) and dash MACs are masked. Sentence punctuation stays outside markers, and six-group numeric dates are not mistaken for MACs.

### Build & CI
- CLI adds `--version` and limits `--days` to `1..=3650`.
- The 0.1.8 release uses `panic = "abort"`.
- CI uses `--locked`, `cargo fmt --check`, a CLI self-test smoke run, least-privilege permissions, pinned third-party actions, and verifies the changelog section before publishing.

## 0.1.7
- Exception codes without a `0x` prefix are decoded again, restoring Next steps for Application Error 1000.
- Standalone BugCheck 1001, WHEA, Kernel-Power 41, GPU 153, Display 4101 and Resource-Exhaustion 2004 now form their own incident when no primary anchor is present.
- The Event Log keeps up to 300 events per channel, WER keeps 25 reports, and empty Event XML data fields are skipped.
- `Player.log` is found in LocalLow, Unreal logs only under `Saved\Logs`, and logs are read newest-first.
- System Context now includes HAGS, TDR overrides, low-disk warnings and uptime; `steam.exe` is no longer reported as an overlay.
- Reports show uptime and storage warnings plus HAGS/TDR for GPU incidents; `Copy Clean Report` drops noisy Event 1000 fields.
- Added incident category filters and free-text search in the incident list, with hardware warnings in the header.
- Bumped version to 0.1.7.

## 0.1.6
- Correctly report Windows 11 when ProductName still says Windows 10 but the build is 22000 or newer.
- Added CPU to System Context, the header panel and Markdown reports.
- MPO and live overlays now appear in reports only for GPU/display/game incidents.
- Increased the event detail excerpt to 512 characters with word-boundary trimming.
- Bumped version to 0.1.6.

## 0.1.5
- Confidence now scales up with independent corroboration: two or more sources upgrade a verdict to High, while a single source keeps the rule's own confidence.
- Added rules for EasyAntiCheat/BattlEye crashes, Intel Arc and Intel graphics drivers, WHEA CPU-cache/PCIe errors, Kernel-Power 41 and D3D12/Vulkan out-of-VRAM errors.
- Bumped version to 0.1.5.

## 0.1.4
- Fixed long `Raw Proof` lines being clipped at the window edge — evidence text now wraps inside the panel.
