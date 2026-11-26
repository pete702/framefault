# Changelog

## [0.1.8]
- Event XML `SystemTime` is converted from UTC to local time; missing or malformed timestamps are skipped instead of becoming a fake "now" anchor.
- `log_reach()` now reports the real Event Log ring-buffer depth; `read_recent()` uses `EvtQueryChannelPath`.
- Event XML parser handles self-closing `<Data />` and `>` inside quoted attributes; `tag_value()` is quote-aware.
- Correlation shares one `consumed` set across primary and fallback groups, uses the newest anchor for incident time, and sorts equal-score findings by verdict.
- Ring-buffer note is kept for `NoAnchor` and shown in the GUI/report.
- `BugcheckCode=59` is parsed correctly and takes priority over `BugcheckParameter1=0x...`; Kernel-Power 41 no longer reports the parameter as the stop code.
- `match_field` is strict for named fields; `ue_oom_flag` no longer triggers from an unrelated `IsEnsure=true`.
- WER title/module lookup understands `FaultingModule`; anti-cheat WER matching uses the real field; Unity logs are accepted by anti-cheat rules; `DXGI_ERROR_DEVICE_REMOVED` no longer produces a duplicate out-of-VRAM verdict.
- WER skips empty values and supports UTF-16BE; a dropped `.wer` is read alone without mixing in machine-wide reports.
- UE accepts a dropped `.xml` containing `<CrashContext>` and only puts whitelisted fields (plus optional CallStack) into evidence, so `EpicAccountId`, `LoginId` and similar IDs cannot leak.
- Game logs are read lossily (non-UTF8 no longer discards the file), markers are case-insensitive, and mtime ties are broken by path.
- Redaction is case-insensitive for `\Users\` / `Documents and Settings`, masks emails, `file://` URLs and 32-char hex IDs, and keeps sentence punctuation outside `[REDACTED-UNC]`.
- System-DLL detection ignores trailing punctuation, GPU context markers are more precise (`igdlh64` added; broad anti-cheat/engine words removed), and unknown GPU/driver values no longer duplicate prefixes.
- Markdown reports show `[confidence | source_count source(s)]`, apply clean-evidence filtering everywhere, and keep the NoAnchor ring-buffer note.
- Pagefile display distinguishes fixed and dynamic sizes; registry adapter matching scans `0000..0015` and prefers the longest name match.
- GUI handles a disconnected scan worker, supports `All` days plus older-incident hints, shows visible/total counts, deduplicates hidden apps, resets copied state, and removes the dead `last_scanned` field.
- CLI adds `--version` and rejects `--days < 1`.
- CI uses `--locked`, `cargo fmt --check`, CLI self-test smoke, and verifies the CHANGELOG section before publishing.
- Bumped version to 0.1.8.

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
