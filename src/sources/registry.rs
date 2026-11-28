use crate::model::SystemContext;

const GPU_CLASS: &str =
    r"SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}";
const MEMORY_MGMT: &str = r"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management";
const GRAPHICS: &str = r"SYSTEM\CurrentControlSet\Control\GraphicsDrivers";
const DWM: &str = r"SOFTWARE\Microsoft\Windows\Dwm";
const NT_CURRENT: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
const CPU_PATH: &str = r"HARDWARE\DESCRIPTION\System\CentralProcessor\0";
const GIB: f64 = 1024.0 * 1024.0 * 1024.0;

/// Some Windows 11 installations still report "Windows 10" in ProductName.
/// The build number is the reliable discriminator.
pub fn product_name(product: &str, build: &str) -> String {
    let build_number = build.trim().parse::<u32>().unwrap_or(0);
    if build_number < 22000 {
        return product.to_owned();
    }
    let lower = product.to_ascii_lowercase();
    if let Some(pos) = lower.find("windows 10") {
        let mut out = String::with_capacity(product.len());
        out.push_str(&product[..pos]);
        out.push_str("Windows 11");
        out.push_str(&product[pos + "windows 10".len()..]);
        return out;
    }
    product.to_owned()
}

/// Registry CPU names contain repeated spaces from the OEM string.
pub fn normalize_cpu(name: &str) -> String {
    name.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(windows)]
#[allow(clippy::field_reassign_with_default)]
pub fn read_context() -> SystemContext {
    use windows::Win32::System::Registry::HKEY_LOCAL_MACHINE;

    let mut ctx = SystemContext::default();
    ctx.mpo = match read_dword_win(HKEY_LOCAL_MACHINE, DWM, "OverlayTestMode") {
        Some(5) => "Disabled (5)".to_owned(),
        Some(v) => format!("Enabled (override = {v})"),
        None => "Enabled (default)".to_owned(),
    };

    // DXGI names the adapter with the most VRAM (the discrete GPU on a
    // hybrid laptop). Match that name against the registry subkeys so the
    // driver version belongs to the same adapter, not to index 0000.
    let mut gpu = dxgi_gpu_name().unwrap_or_default();
    let mut adapters: Vec<(String, String)> = Vec::new();
    for index in 0..16 {
        let path = format!("{GPU_CLASS}\\{index:04}");
        let name = read_string_win(HKEY_LOCAL_MACHINE, &path, "DriverDesc")
            .or_else(|| read_string_win(HKEY_LOCAL_MACHINE, &path, "DeviceDescription"))
            .unwrap_or_default();
        let version =
            read_string_win(HKEY_LOCAL_MACHINE, &path, "DriverVersion").unwrap_or_default();
        if !name.is_empty() || !version.is_empty() {
            adapters.push((name, version));
        }
    }
    if gpu.is_empty() {
        gpu = adapters
            .iter()
            .find(|(name, _)| !name.is_empty())
            .map(|(name, _)| name.clone())
            .unwrap_or_default();
    }
    let driver = driver_for_gpu(&gpu, &adapters)
        .or_else(|| {
            adapters
                .iter()
                .find(|(_, version)| !version.is_empty())
                .map(|(_, version)| version.as_str())
        })
        .unwrap_or("")
        .to_owned();
    ctx.gpu = if gpu.is_empty() {
        "GPU: unknown".to_owned()
    } else {
        gpu
    };
    ctx.driver = if driver.is_empty() {
        "driver: unknown".to_owned()
    } else {
        format!("driver {driver}")
    };

    let pagefiles = read_multistring_win(HKEY_LOCAL_MACHINE, MEMORY_MGMT, "PagingFiles");
    ctx.pagefile = match &pagefiles {
        Some(values) if !values.is_empty() => human_pagefile(values),
        Some(_) => "system managed".to_owned(),
        None => "unknown".to_owned(),
    };

    ctx.hags = read_hags();
    ctx.tdr_note = read_tdr_note();
    ctx.disk_warn = read_disk_warn(pagefiles.as_deref().unwrap_or(&[]));
    ctx.uptime_hours =
        unsafe { windows::Win32::System::SystemInformation::GetTickCount64() } / 3_600_000;

    let product = read_string_win(HKEY_LOCAL_MACHINE, NT_CURRENT, "ProductName")
        .unwrap_or_else(|| "Windows".to_owned());
    let build = read_string_win(HKEY_LOCAL_MACHINE, NT_CURRENT, "CurrentBuild").unwrap_or_default();
    ctx.windows = format!("{} (build {})", product_name(&product, &build), build);

    let cpu = read_string_win(HKEY_LOCAL_MACHINE, CPU_PATH, "ProcessorNameString")
        .map(|value| normalize_cpu(&value))
        .unwrap_or_default();
    ctx.cpu = if cpu.is_empty() {
        "unknown".to_owned()
    } else {
        cpu
    };

    // GlobalMemoryStatusEx -> RAM + commit. ullTotalPageFile is the commit limit.
    unsafe {
        let mut status: windows::Win32::System::SystemInformation::MEMORYSTATUSEX =
            std::mem::zeroed();
        status.dwLength = std::mem::size_of_val(&status) as u32;
        if windows::Win32::System::SystemInformation::GlobalMemoryStatusEx(&mut status).is_ok() {
            ctx.ram_total_gib = status.ullTotalPhys as f64 / GIB;
            ctx.ram_used_gib = (status.ullTotalPhys - status.ullAvailPhys) as f64 / GIB;
            ctx.commit_limit_gib = status.ullTotalPageFile as f64 / GIB;
            ctx.commit_used_gib = (status.ullTotalPageFile - status.ullAvailPageFile) as f64 / GIB;
        }
    }

    ctx.overlays_now = live_overlays();
    ctx.log_reach = crate::sources::evt::log_reach();
    ctx
}

#[cfg(not(windows))]
pub fn read_context() -> SystemContext {
    SystemContext::default()
}

#[cfg(windows)]
fn read_reg_bytes(
    hive: windows::Win32::System::Registry::HKEY,
    path: &str,
    value_name: &str,
) -> Option<Vec<u8>> {
    use windows::core::PCWSTR;
    use windows::Win32::System::Registry::{
        RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY, KEY_READ,
    };

    let wide_path = windows::core::HSTRING::from(path);
    let wide_name = windows::core::HSTRING::from(value_name);
    let mut key: HKEY = HKEY::default();

    unsafe {
        if RegOpenKeyExW(hive, PCWSTR(wide_path.as_ptr()), None, KEY_READ, &mut key).is_err() {
            return None;
        }
        let mut len = 0u32;
        let first = RegQueryValueExW(
            key,
            PCWSTR(wide_name.as_ptr()),
            None,
            None,
            None,
            Some(&mut len),
        );
        if first.is_err() || len == 0 {
            let _ = RegCloseKey(key);
            return None;
        }
        let mut buffer = vec![0u8; len as usize];
        let result = RegQueryValueExW(
            key,
            PCWSTR(wide_name.as_ptr()),
            None,
            None,
            Some(buffer.as_mut_ptr()),
            Some(&mut len),
        );
        let _ = RegCloseKey(key);
        if result.is_err() {
            return None;
        }
        buffer.truncate(len as usize);
        Some(buffer)
    }
}

#[cfg(windows)]
fn read_dword_win(
    hive: windows::Win32::System::Registry::HKEY,
    path: &str,
    name: &str,
) -> Option<u32> {
    let bytes = read_reg_bytes(hive, path, name)?;
    let raw: [u8; 4] = bytes.get(..4)?.try_into().ok()?;
    Some(u32::from_le_bytes(raw))
}

/// HwSchMode: 2 = on, 1 = off, anything else (including absent) = default.
#[cfg(any(windows, test))]
fn hags_label(value: Option<u32>) -> &'static str {
    match value {
        Some(2) => "Enabled",
        Some(1) => "Disabled",
        _ => "Default/Unknown",
    }
}

/// Find the DriverVersion whose DeviceDescription belongs to the DXGI GPU,
/// tolerating OEM suffixes such as "Ti" or "with Max-Q".
#[cfg(any(windows, test))]
fn driver_for_gpu<'a>(gpu: &str, adapters: &'a [(String, String)]) -> Option<&'a str> {
    let wanted = gpu.trim();
    if wanted.is_empty() {
        return None;
    }
    if let Some((_, version)) = adapters
        .iter()
        .find(|(name, version)| !version.is_empty() && name.trim().eq_ignore_ascii_case(wanted))
    {
        return Some(version.as_str());
    }
    let needle = wanted.to_ascii_lowercase();
    adapters
        .iter()
        .filter(|(name, version)| {
            let known = name.trim().to_ascii_lowercase();
            !version.is_empty()
                && !known.is_empty()
                && (known.contains(&needle) || needle.contains(&known))
        })
        .max_by_key(|(name, _)| name.trim().chars().count())
        .map(|(_, version)| version.as_str())
}

/// Only non-default TDR settings are worth showing in a report.
#[cfg(any(windows, test))]
fn tdr_note(level: Option<u32>, delay: Option<u32>) -> Option<String> {
    if level == Some(0) {
        return Some("TdrLevel=0 (recovery disabled!)".to_owned());
    }
    match delay {
        Some(delay) if delay != 2 => Some(format!("TdrDelay={delay}s")),
        _ => None,
    }
}

/// Pulls a drive letter such as `C:` out of a formatted pagefile string.
#[cfg(any(windows, test))]
fn pagefile_drive(pagefile: &str) -> Option<String> {
    let bytes = pagefile.as_bytes();
    for index in 0..bytes.len().saturating_sub(1) {
        if bytes[index].is_ascii_alphabetic() && bytes[index + 1] == b':' {
            return Some(format!("{}:", bytes[index] as char).to_ascii_uppercase());
        }
    }
    None
}

/// Drives to check for free space. The system drive is always checked. A
/// pagefile drive is checked only when its pagefile can grow (min != max or
/// system managed): a fixed pagefile (min == max > 0) has nowhere to grow, so
/// low free space there is expected and must not be reported as a warning.
#[cfg(any(windows, test))]
fn system_drive() -> String {
    std::env::var("SystemDrive")
        .ok()
        .map(|value| value.trim().trim_end_matches('\\').to_ascii_uppercase())
        .filter(|value| {
            value.len() == 2
                && value.as_bytes()[0].is_ascii_alphabetic()
                && value.as_bytes()[1] == b':'
        })
        .unwrap_or_else(|| "C:".to_owned())
}

#[cfg(any(windows, test))]
fn pagefile_targets(values: &[String]) -> Vec<String> {
    pagefile_targets_with_system(&system_drive(), values)
}

#[cfg(any(windows, test))]
fn pagefile_targets_with_system(system: &str, values: &[String]) -> Vec<String> {
    let mut drives = vec![system.to_owned()];
    for entry in values {
        let mut parts = entry.split_whitespace();
        let path = parts.next().unwrap_or("");
        let min = parts.next().and_then(|value| value.parse::<u64>().ok());
        let max = parts.next().and_then(|value| value.parse::<u64>().ok());
        if matches!((min, max), (Some(min), Some(max)) if min > 0 && min == max) {
            continue;
        }
        let Some(drive) = pagefile_drive(path) else {
            continue;
        };
        if !drives
            .iter()
            .any(|known| known.eq_ignore_ascii_case(&drive))
        {
            drives.push(drive);
        }
    }
    drives
}

#[cfg(windows)]
fn read_hags() -> String {
    use windows::Win32::System::Registry::HKEY_LOCAL_MACHINE;
    hags_label(read_dword_win(HKEY_LOCAL_MACHINE, GRAPHICS, "HwSchMode")).to_owned()
}

#[cfg(windows)]
fn read_tdr_note() -> Option<String> {
    use windows::Win32::System::Registry::HKEY_LOCAL_MACHINE;
    tdr_note(
        read_dword_win(HKEY_LOCAL_MACHINE, GRAPHICS, "TdrLevel"),
        read_dword_win(HKEY_LOCAL_MACHINE, GRAPHICS, "TdrDelay"),
    )
}

#[cfg(windows)]
fn free_gib(drive: &str) -> Option<f64> {
    use windows::core::{HSTRING, PCWSTR};
    use windows::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;

    let root = HSTRING::from(format!("{drive}\\"));
    let mut available = 0u64;
    let mut total = 0u64;
    let mut total_free = 0u64;
    unsafe {
        GetDiskFreeSpaceExW(
            PCWSTR(root.as_ptr()),
            Some(&mut available),
            Some(&mut total),
            Some(&mut total_free),
        )
        .ok()?;
    }
    Some(available as f64 / GIB)
}

#[cfg(windows)]
fn read_disk_warn(pagefiles: &[String]) -> Option<String> {
    const MIN_GIB: f64 = 10.0;
    // free_gib() returns None on API errors, so a failed query never becomes
    // a fake "0.0 GiB" warning.
    let warnings: Vec<String> = pagefile_targets(pagefiles)
        .into_iter()
        .filter_map(|drive| {
            free_gib(&drive).and_then(|free| {
                (free < MIN_GIB).then(|| format!("Low free space on {drive} {free:.1} GiB free"))
            })
        })
        .collect();
    (!warnings.is_empty()).then(|| warnings.join("; "))
}

#[cfg(windows)]
fn decode_utf16(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&units)
}

#[cfg(windows)]
fn read_string_win(
    hive: windows::Win32::System::Registry::HKEY,
    path: &str,
    name: &str,
) -> Option<String> {
    let bytes = read_reg_bytes(hive, path, name)?;
    let text = decode_utf16(&bytes);
    Some(text.trim_end_matches('\0').to_owned())
}

/// Prefer the adapter with the most dedicated VRAM (discrete GPU on hybrids).
#[cfg(windows)]
fn dxgi_gpu_name() -> Option<String> {
    use windows::Win32::Graphics::Dxgi::{CreateDXGIFactory1, IDXGIFactory1};

    unsafe {
        let factory: IDXGIFactory1 = CreateDXGIFactory1().ok()?;
        let mut best: (usize, String) = (0, String::new());
        for index in 0..16u32 {
            let adapter = match factory.EnumAdapters1(index) {
                Ok(adapter) => adapter,
                Err(_) => break,
            };
            if let Ok(description) = adapter.GetDesc1() {
                let name = String::from_utf16_lossy(&description.Description)
                    .trim_end_matches('\0')
                    .trim()
                    .to_owned();
                if description.DedicatedVideoMemory > best.0 {
                    best = (description.DedicatedVideoMemory, name);
                }
            }
        }
        if best.1.is_empty() {
            None
        } else {
            Some(best.1)
        }
    }
}

#[cfg(not(windows))]
fn dxgi_gpu_name() -> Option<String> {
    None
}

#[cfg(any(windows, test))]
fn human_pagefile(values: &[String]) -> String {
    let mut parts: Vec<String> = Vec::new();
    for entry in values {
        if let Some(text) = human_pagefile_entry(entry) {
            parts.push(text);
        }
    }
    if parts.is_empty() {
        "system managed".to_owned()
    } else {
        parts.join("; ")
    }
}

#[cfg(any(windows, test))]
fn human_pagefile_entry(entry: &str) -> Option<String> {
    let mut parts = entry.split_whitespace();
    let raw_path = parts.next()?;
    let path = raw_path.strip_prefix(r"\??\").unwrap_or(raw_path);
    let min_mb = parts
        .next()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0);
    let max_mb = parts
        .next()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0);
    // `0 0` and `?:` mean Windows manages the file size and location.
    if min_mb == 0 && max_mb == 0 || path.starts_with("?:") {
        return Some("system managed".to_owned());
    }
    let drive = pagefile_drive(path)?;
    let min_gib = min_mb as f64 / 1024.0;
    let max_gib = max_mb as f64 / 1024.0;
    if min_mb == max_mb {
        Some(format!("{min_gib:.1} GiB fixed ({drive})"))
    } else {
        Some(format!("{min_gib:.1}-{max_gib:.1} GiB ({drive})"))
    }
}

#[cfg(windows)]
fn read_multistring_win(
    hive: windows::Win32::System::Registry::HKEY,
    path: &str,
    name: &str,
) -> Option<Vec<String>> {
    let bytes = read_reg_bytes(hive, path, name)?;
    let text = decode_utf16(&bytes);
    Some(
        text.split('\0')
            .map(str::to_owned)
            .filter(|s| !s.is_empty())
            .collect(),
    )
}

#[cfg(windows)]
fn live_overlays() -> Vec<String> {
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };

    const KNOWN: [&str; 10] = [
        "rtss.exe",
        "rivatunerstatisticsserver.exe",
        "discord.exe",
        "overwolf.exe",
        "specialk.exe",
        "amdow.exe",
        "nvidia overlay.exe",
        "geforceexperience.exe",
        "reshade.exe",
        "gameoverlayui.exe",
    ];

    let mut found = Vec::new();
    unsafe {
        let Ok(snapshot) = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) else {
            return found;
        };
        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of_val(&entry) as u32;
        if Process32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                let name = String::from_utf16_lossy(&entry.szExeFile)
                    .trim_end_matches('\0')
                    .to_owned();
                let lower = name.to_ascii_lowercase();
                if KNOWN.iter().any(|k| lower == *k) && !found.contains(&name) {
                    found.push(name);
                }
                if Process32NextW(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }
        let _ = windows::Win32::Foundation::CloseHandle(snapshot);
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_11_is_detected_from_build_number() {
        assert_eq!(product_name("Windows 10 Pro", "22000"), "Windows 11 Pro");
        assert_eq!(product_name("Windows 10 Pro", "26100"), "Windows 11 Pro");
        assert_eq!(product_name("Windows 10 Pro", "19045"), "Windows 10 Pro");
        assert_eq!(product_name("Windows 11 Home", "22631"), "Windows 11 Home");
    }

    #[test]
    fn cpu_name_is_trimmed() {
        assert_eq!(
            normalize_cpu("  Intel(R)  Core(TM)  i7-13700K   "),
            "Intel(R) Core(TM) i7-13700K"
        );
    }

    #[test]
    fn hags_and_tdr_values_are_formatted() {
        assert_eq!(hags_label(Some(2)), "Enabled");
        assert_eq!(hags_label(Some(1)), "Disabled");
        assert_eq!(hags_label(None), "Default/Unknown");
        assert_eq!(hags_label(Some(7)), "Default/Unknown");

        assert_eq!(
            tdr_note(Some(0), None),
            Some("TdrLevel=0 (recovery disabled!)".to_owned())
        );
        assert_eq!(tdr_note(None, Some(10)), Some("TdrDelay=10s".to_owned()));
        assert_eq!(tdr_note(None, Some(2)), None);
        assert_eq!(tdr_note(None, None), None);
    }

    #[test]
    fn driver_version_comes_from_the_matching_adapter() {
        let adapters = vec![
            (
                "Intel(R) UHD Graphics 770".to_owned(),
                "31.0.101.5081".to_owned(),
            ),
            (
                "NVIDIA GeForce RTX 4070".to_owned(),
                "32.0.15.6094".to_owned(),
            ),
        ];
        assert_eq!(
            driver_for_gpu("NVIDIA GeForce RTX 4070", &adapters),
            Some("32.0.15.6094")
        );
        assert_eq!(
            driver_for_gpu("Intel(R) UHD Graphics 770", &adapters),
            Some("31.0.101.5081")
        );
        assert_eq!(
            driver_for_gpu("NVIDIA GeForce RTX 4070 Ti", &adapters),
            Some("32.0.15.6094"),
            "OEM suffix must still find the same adapter"
        );
        assert_eq!(driver_for_gpu("AMD Radeon Graphics", &adapters), None);
        assert_eq!(driver_for_gpu("", &adapters), None);

        let similar = vec![
            ("NVIDIA GeForce RTX 4070".to_owned(), "short".to_owned()),
            ("NVIDIA GeForce RTX 4070 Ti".to_owned(), "long".to_owned()),
        ];
        assert_eq!(
            driver_for_gpu("NVIDIA GeForce RTX 4070 Ti Super", &similar),
            Some("long"),
            "imprecise matching must pick the longest adapter name"
        );
    }

    #[test]
    fn pagefile_size_is_rendered_as_fixed_or_range() {
        let fixed = vec![r"E:\pagefile.sys 2048 2048".to_owned()];
        assert_eq!(human_pagefile(&fixed), "2.0 GiB fixed (E:)");

        let dynamic = vec![r"E:\pagefile.sys 2048 16384".to_owned()];
        assert_eq!(human_pagefile(&dynamic), "2.0-16.0 GiB (E:)");

        let managed = vec![r"E:\pagefile.sys 0 0".to_owned()];
        assert_eq!(human_pagefile(&managed), "system managed");
    }

    #[test]
    fn multiple_pagefiles_are_all_rendered() {
        let values = vec![
            r"C:\pagefile.sys 2048 4096".to_owned(),
            r"E:\pagefile.sys 13685 13685".to_owned(),
        ];
        assert_eq!(
            human_pagefile(&values),
            "2.0-4.0 GiB (C:); 13.4 GiB fixed (E:)"
        );
    }

    #[test]
    fn native_and_unknown_pagefile_paths_are_parsed() {
        let native = vec![r"\??\D:\pagefile.sys 2048 4096".to_owned()];
        assert_eq!(human_pagefile(&native), "2.0-4.0 GiB (D:)");

        let anywhere = vec![r"?:\pagefile.sys 0 0".to_owned()];
        assert_eq!(human_pagefile(&anywhere), "system managed");

        // `?:` is system-managed location semantics even with explicit sizes.
        let anywhere_sized = vec![r"?:\pagefile.sys 2048 4096".to_owned()];
        assert_eq!(human_pagefile(&anywhere_sized), "system managed");
    }

    #[test]
    fn pagefile_drive_is_extracted() {
        assert_eq!(pagefile_drive("12.0 GiB (E:)"), Some("E:".to_owned()));
        assert_eq!(pagefile_drive("system managed"), None);
        assert_eq!(pagefile_drive("unknown"), None);
    }

    #[test]
    fn fixed_pagefile_drive_is_not_checked_for_free_space() {
        let fixed = vec![r"E:\pagefile.sys 13685 13685".to_owned()];
        assert_eq!(
            pagefile_targets_with_system("C:", &fixed),
            vec!["C:".to_owned()]
        );

        let dynamic = vec![r"E:\pagefile.sys 2048 16384".to_owned()];
        assert_eq!(
            pagefile_targets_with_system("C:", &dynamic),
            vec!["C:".to_owned(), "E:".to_owned()]
        );

        // System managed on an explicit drive can still grow.
        let managed = vec![r"E:\pagefile.sys 0 0".to_owned()];
        assert_eq!(
            pagefile_targets_with_system("C:", &managed),
            vec!["C:".to_owned(), "E:".to_owned()]
        );

        // Windows' "?:\\pagefile.sys" has no drive to check.
        let anywhere = vec![r"?:\pagefile.sys 0 0".to_owned()];
        assert_eq!(
            pagefile_targets_with_system("C:", &anywhere),
            vec!["C:".to_owned()]
        );
    }

    #[test]
    fn system_drive_is_used_and_multi_pagefile_drives_are_included() {
        let values = vec![
            r"C:\pagefile.sys 2048 2048".to_owned(),
            r"\??\D:\pagefile.sys 0 0".to_owned(),
            r"E:\pagefile.sys 2048 4096".to_owned(),
        ];
        assert_eq!(
            pagefile_targets_with_system("D:", &values),
            vec!["D:".to_owned(), "E:".to_owned()],
            "system drive plus every growable pagefile, without duplicates"
        );
    }
}
