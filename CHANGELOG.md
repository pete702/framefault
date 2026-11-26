# Changelog

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
