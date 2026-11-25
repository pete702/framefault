# Changelog

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
