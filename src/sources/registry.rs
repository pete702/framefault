use chrono::Local;

use crate::model::{Signal, SystemContext};

const GPU_CLASS: &str = r"SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}";
const MEMORY_MGMT: &str = r"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management";
const DWM: &str = r"SOFTWARE\Microsoft\Windows\Dwm";
const NT_CURRENT: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion";

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

    let (mut gpu, mut driver) = (dxgi_gpu_name().unwrap_or_default(), String::new());
    for index in 0..4 {
        let path = format!("{GPU_CLASS}\\{index:04}");
        if gpu.is_empty() {
            gpu = read_string_win(HKEY_LOCAL_MACHINE, &path, "DriverDesc")
                .or_else(|| read_string_win(HKEY_LOCAL_MACHINE, &path, "DeviceDescription"))
                .unwrap_or_default();
        }
        if driver.is_empty() {
            driver = read_string_win(HKEY_LOCAL_MACHINE, &path, "DriverVersion")
                .unwrap_or_default();
        }
        if !gpu.is_empty() && !driver.is_empty() {
            break;
        }
    }
    ctx.gpu = if gpu.is_empty() { "GPU: unknown".to_owned() } else { gpu };
    ctx.driver = if driver.is_empty() {
        "driver: unknown".to_owned()
    } else {
        format!("driver {driver}")
    };

    let pagefiles = read_multistring_win(HKEY_LOCAL_MACHINE, MEMORY_MGMT, "PagingFiles");
    ctx.pagefile = match pagefiles {
        Some(values) if !values.is_empty() => human_pagefile(&values),
        Some(_) => "system managed".to_owned(),
        None => "unknown".to_owned(),
    };

    let product = read_string_win(HKEY_LOCAL_MACHINE, NT_CURRENT, "ProductName")
        .unwrap_or_else(|| "Windows".to_owned());
    let build = read_string_win(HKEY_LOCAL_MACHINE, NT_CURRENT, "CurrentBuild")
        .unwrap_or_default();
    ctx.windows = format!("{product} (build {build})");

    // GlobalMemoryStatusEx -> RAM + commit. ullTotalPageFile is the commit limit.
    unsafe {
        let mut status: windows::Win32::System::SystemInformation::MEMORYSTATUSEX =
            std::mem::zeroed();
        status.dwLength = std::mem::size_of_val(&status) as u32;
        if windows::Win32::System::SystemInformation::GlobalMemoryStatusEx(&mut status).is_ok() {
            const GIB: f64 = 1024.0 * 1024.0 * 1024.0;
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

/// Registry signals participate in correlation as context, never timed events.
pub fn read_context_signals() -> Vec<Signal> {
    let mut out = Vec::new();
    #[cfg(windows)]
    {
        use windows::Win32::System::Registry::HKEY_LOCAL_MACHINE;
        if let Some(value) = read_dword_win(HKEY_LOCAL_MACHINE, DWM, "OverlayTestMode") {
            let mut signal = Signal::new("registry", Local::now());
            signal.provider = "HKLM\\SOFTWARE\\Microsoft\\Windows\\Dwm".to_owned();
            signal
                .fields
                .insert("value".to_owned(), value.to_string());
            signal.detail = format!("OverlayTestMode={value}");
            out.push(signal);
        }
        if let Some(value) = read_dword_win(
            HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\GraphicsDrivers",
            "TdrLevel",
        ) {
            let mut signal = Signal::new("registry", Local::now());
            signal.provider = "GraphicsDrivers".to_owned();
            signal
                .fields
                .insert("value".to_owned(), value.to_string());
            signal.detail = format!("TdrLevel={value}");
            out.push(signal);
        }
    }
    out
}

#[cfg(windows)]
fn read_reg_bytes(
    hive: windows::Win32::System::Registry::HKEY,
    path: &str,
    value_name: &str,
) -> Option<Vec<u8>> {
    use windows::core::PCWSTR;
    use windows::Win32::System::Registry::{RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY, KEY_READ};

    let wide_path = windows::core::HSTRING::from(path);
    let wide_name = windows::core::HSTRING::from(value_name);
    let mut key: HKEY = HKEY::default();

    unsafe {
        if RegOpenKeyExW(
            hive,
            PCWSTR(wide_path.as_ptr()),
            None,
            KEY_READ,
            &mut key,
        )
        .is_err()
        {
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
        if best.1.is_empty() { None } else { Some(best.1) }
    }
}

#[cfg(not(windows))]
fn dxgi_gpu_name() -> Option<String> {
    None
}

#[cfg(windows)]
fn human_pagefile(values: &[String]) -> String {
    let Some(first) = values.first() else {
        return "unknown".to_owned();
    };
    let parts: Vec<&str> = first.split_whitespace().collect();
    let path = parts.first().copied().unwrap_or("");
    let drive = path
        .chars()
        .take(2)
        .collect::<String>()
        .trim_end_matches(':')
        .to_owned();
    let mb = parts
        .get(1)
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0);
    let gib = mb as f64 / 1024.0;
    if drive.is_empty() || gib == 0.0 {
        "system managed".to_owned()
    } else {
        format!("{gib:.1} GiB ({drive}:)")
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
        "steam.exe",
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
