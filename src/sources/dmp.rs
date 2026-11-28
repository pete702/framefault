//! User-space minidump (`.dmp`) metadata reader.
//!
//! Only the exception record and module paths are read. Stack/heap memory,
//! environment blocks and in-memory strings are never touched, and no
//! symbols/PDB files are fetched. Kernel `PAGEDU64` dumps are out of scope.

use std::collections::HashSet;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use chrono::{DateTime, Local, Utc};
use minidump::{Minidump, MinidumpException, MinidumpModule, MinidumpModuleList, Module};
use walkdir::WalkDir;

use crate::model::Signal;

const MAX_DUMPS: usize = 6;

/// GPU/display modules that make MPO/HAGS context useful for a minidump.
/// Bare `d3d11`/`d3d12` stay out of the global report markers because every
/// System32 DLL would match them.
pub const GPU_MODULE_MARKERS: &[&str] = &[
    "nvlddmkm", "amdkmd", "igdkmd", "igfx", "d3d11", "d3d12", "dxgi",
];

fn is_dmp_file(path: &Path) -> bool {
    path.extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("dmp"))
}

/// A kernel dump starts with `PAGE` (`PAGEDU64` on 64-bit systems); `MDMP`
/// user-mode dumps start with `MDMP`.
fn is_kernel_dump(path: &Path) -> bool {
    let Ok(mut file) = File::open(path) else {
        return false;
    };
    let mut header = [0u8; 8];
    let Ok(read) = file.read(&mut header) else {
        return false;
    };
    let head = &header[..read];
    head.starts_with(b"PAGEDU64") || head.starts_with(b"PAGE")
}

fn is_saved_crashes_dir(path: &Path) -> bool {
    let mut parts = path.components().rev();
    let crashes = parts.next().is_some_and(|part| {
        part.as_os_str()
            .to_string_lossy()
            .eq_ignore_ascii_case("Crashes")
    });
    let saved = parts.next().is_some_and(|part| {
        part.as_os_str()
            .to_string_lossy()
            .eq_ignore_ascii_case("Saved")
    });
    crashes && saved
}

fn collect_dumps(root: &Path, max_depth: usize, found: &mut Vec<(PathBuf, SystemTime)>) {
    for entry in WalkDir::new(root)
        .max_depth(max_depth)
        .into_iter()
        .flatten()
    {
        if !entry.file_type().is_file() || !is_dmp_file(entry.path()) {
            continue;
        }
        if let Some(modified) = entry.metadata().ok().and_then(|meta| meta.modified().ok()) {
            found.push((entry.path().to_path_buf(), modified));
        }
    }
}

/// User-space dump locations only. Never machine-wide kernel dump folders.
pub fn scan(root: &Path) -> Vec<Signal> {
    if root.is_file() {
        if !is_dmp_file(root) {
            return Vec::new();
        }
        return parse_dump(root, true).into_iter().collect();
    }
    if !root.exists() {
        return Vec::new();
    }

    let is_default_local = dirs::data_local_dir().is_some_and(|dir| dir.as_path() == root);
    let mut found: Vec<(PathBuf, SystemTime)> = Vec::new();

    if is_default_local {
        // UE stores dumps in <game>\Saved\Crashes\<crash>\*.dmp. Discover the
        // crash folders (bounded) instead of reading every file in Local.
        for entry in WalkDir::new(root).max_depth(4).into_iter().flatten() {
            if entry.file_type().is_dir() && is_saved_crashes_dir(entry.path()) {
                collect_dumps(entry.path(), 3, &mut found);
            }
        }
        // Windows LocalDumps for any user-mode application.
        collect_dumps(&root.join("CrashDumps"), 1, &mut found);
    } else {
        // A folder the user dropped explicitly: keep the broad search bounded.
        collect_dumps(root, 5, &mut found);
    }

    // Newest first, path breaks ties, and the cap stays deterministic.
    found.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let mut seen = HashSet::new();
    found
        .into_iter()
        .filter(|(path, _)| seen.insert(path.clone()))
        .take(MAX_DUMPS)
        .filter_map(|(path, _)| parse_dump(&path, false))
        .collect()
}

fn parse_dump(path: &Path, explicit: bool) -> Option<Signal> {
    let mtime = fs::metadata(path)
        .and_then(|meta| meta.modified())
        .ok()
        .map(DateTime::<Local>::from)?;

    if is_kernel_dump(path) {
        // Kernel dumps need admin-only APIs; never crash the scan over one.
        // An explicitly dropped file still gets a safe Info signal.
        return explicit.then(|| kernel_signal(mtime));
    }

    let dump = Minidump::read_path(path).ok()?;
    let exception = dump.get_stream::<MinidumpException>().ok()?;
    let code = exception.raw.exception_record.exception_code;
    let address = exception.raw.exception_record.exception_address;

    let time = dump_time(dump.header.time_date_stamp).unwrap_or(mtime);
    let modules = dump.get_stream::<MinidumpModuleList>().ok();
    let faulting = modules
        .as_ref()
        .and_then(|list| module_for_address(list, address));
    let faulting_name = faulting.map(|module| module_basename(&module.name));

    let mut signal = Signal::new("dmp", time);
    signal.provider = faulting_name
        .clone()
        .unwrap_or_else(|| "Minidump".to_owned());
    signal
        .fields
        .insert("ExceptionCode".to_owned(), format!("0x{code:08X}"));
    if let Some(name) = &faulting_name {
        signal
            .fields
            .insert("FaultingModule".to_owned(), name.clone());
    }

    let mut detail = format!("User-mode minidump: 0x{code:08X} at 0x{address:016X}");
    if let Some(name) = &faulting_name {
        detail.push_str(&format!("; faulting module {name}"));
    }

    if let Some(list) = &modules {
        let mut gpu: Vec<String> = Vec::new();
        for module in list.iter() {
            if is_gpu_module(&module.name) {
                let name = module_basename(&module.name);
                if !gpu.contains(&name) {
                    gpu.push(name);
                }
            }
        }
        if !gpu.is_empty() {
            detail.push_str(&format!("; GPU modules: {}", gpu.join(", ")));
        }

        signal.loaded_modules = list
            .iter()
            .map(|module| module.name.clone())
            .filter(|name| !crate::sources::wer::is_system_dll_path(name))
            .collect();
    }

    signal.detail = detail;
    Some(signal)
}

/// Windows time_t in the dump header; zero/absent falls back to file mtime.
/// MiscInfo only records process creation, so it is not used as crash time.
fn dump_time(stamp: u32) -> Option<DateTime<Local>> {
    if stamp == 0 {
        return None;
    }
    DateTime::<Utc>::from_timestamp(stamp as i64, 0).map(|utc| utc.with_timezone(&Local))
}

fn module_for_address(modules: &MinidumpModuleList, address: u64) -> Option<&MinidumpModule> {
    modules.iter().find(|module| {
        let base = module.base_address();
        let end = base.saturating_add(module.size());
        address >= base && address < end
    })
}

fn module_basename(name: &str) -> String {
    name.rsplit(['\\', '/']).next().unwrap_or(name).to_owned()
}

fn is_gpu_module(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    GPU_MODULE_MARKERS
        .iter()
        .any(|marker| lower.contains(marker))
}

fn kernel_signal(time: DateTime<Local>) -> Signal {
    let mut signal = Signal::new("dmp", time);
    signal.provider = "Minidump".to_owned();
    signal.fields.insert("Kind".to_owned(), "kernel".to_owned());
    signal.detail = "Kernel-mode PAGEDU64 minidump: not parsed without administrator rights. \
                     FrameFault reads user-mode MDMP dumps only."
        .to_owned();
    signal
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEADER_SIZE: usize = 32;
    const DIRECTORY_ENTRY: usize = 12;
    const EXCEPTION_OFFSET: usize = HEADER_SIZE + 2 * DIRECTORY_ENTRY;
    const EXCEPTION_SIZE: usize = 168;
    const MODULE_LIST_OFFSET: usize = EXCEPTION_OFFSET + EXCEPTION_SIZE;
    const MODULE_SIZE: usize = 108;
    const MODULE_LIST_SIZE: usize = 4 + 2 * MODULE_SIZE;
    const NAME1_OFFSET: usize = MODULE_LIST_OFFSET + MODULE_LIST_SIZE;

    const EXCEPTION_CODE: u32 = 0xC000_0005;
    const CRASH_ADDRESS: u64 = 0x1000_1234;
    const DUMP_TIMESTAMP: u32 = 1_765_000_000;

    fn push_u32(out: &mut Vec<u8>, value: u32) {
        out.extend_from_slice(&value.to_le_bytes());
    }

    fn push_u64(out: &mut Vec<u8>, value: u64) {
        out.extend_from_slice(&value.to_le_bytes());
    }

    fn push_utf16_string(out: &mut Vec<u8>, value: &str) {
        let units: Vec<u16> = value.encode_utf16().collect();
        push_u32(out, (units.len() * 2) as u32);
        for unit in units {
            out.extend_from_slice(&unit.to_le_bytes());
        }
        out.extend_from_slice(&0u16.to_le_bytes());
    }

    fn push_module(out: &mut Vec<u8>, base: u64, size: u32, name_rva: u32) {
        push_u64(out, base);
        push_u32(out, size);
        push_u32(out, 0); // checksum
        push_u32(out, 0); // PE timestamp
        push_u32(out, name_rva);
        out.extend_from_slice(&[0u8; 52]); // VS_FIXEDFILEINFO
        push_u32(out, 0);
        push_u32(out, 0); // CV record
        push_u32(out, 0);
        push_u32(out, 0); // misc record
        out.extend_from_slice(&[0u8; 8]); // reserved0
        out.extend_from_slice(&[0u8; 8]); // reserved1
    }

    /// Minimal little-endian MDMP: header + directory + exception stream +
    /// module list (game module and one System32 module) + UTF-16 names.
    fn synthetic_mdmp() -> Vec<u8> {
        let game_module = r"C:\Games\Game\Game.dll";
        let system_module = r"C:\Windows\System32\kernel32.dll";
        let game_name_size = 4 + game_module.encode_utf16().count() * 2 + 2;
        let system_name_offset = NAME1_OFFSET + game_name_size;

        let mut out = Vec::new();
        push_u32(&mut out, 0x504D_444D); // MDMP
        push_u32(&mut out, 0x0000_A793); // MINIDUMP_VERSION
        push_u32(&mut out, 2); // stream count
        push_u32(&mut out, HEADER_SIZE as u32);
        push_u32(&mut out, 0); // checksum
        push_u32(&mut out, DUMP_TIMESTAMP);
        push_u64(&mut out, 0); // flags

        // ExceptionStream (6), then ModuleListStream (4).
        push_u32(&mut out, 6);
        push_u32(&mut out, EXCEPTION_SIZE as u32);
        push_u32(&mut out, EXCEPTION_OFFSET as u32);
        push_u32(&mut out, 4);
        push_u32(&mut out, MODULE_LIST_SIZE as u32);
        push_u32(&mut out, MODULE_LIST_OFFSET as u32);

        push_u32(&mut out, 1); // thread id
        push_u32(&mut out, 0); // alignment
        push_u32(&mut out, EXCEPTION_CODE);
        push_u32(&mut out, 0); // exception flags
        push_u64(&mut out, 0); // nested exception
        push_u64(&mut out, CRASH_ADDRESS);
        push_u32(&mut out, 2); // parameter count
        push_u32(&mut out, 0); // alignment
        for _ in 0..15 {
            push_u64(&mut out, 0);
        }
        push_u32(&mut out, 0);
        push_u32(&mut out, 0); // thread context descriptor

        push_u32(&mut out, 2); // module count
        push_module(&mut out, 0x1000_0000, 0x1_0000, NAME1_OFFSET as u32);
        push_module(&mut out, 0x2000_0000, 0x2_0000, system_name_offset as u32);

        push_utf16_string(&mut out, game_module);
        push_utf16_string(&mut out, system_module);
        out
    }

    fn unique_temp_path(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("system clock")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "framefault-dmp-{}-{nanos}-{name}",
            std::process::id()
        ))
    }

    #[test]
    fn synthetic_user_mode_minidump_is_parsed() {
        let path = unique_temp_path("user.dmp");
        fs::write(&path, synthetic_mdmp()).expect("write synthetic minidump");

        let signal = parse_dump(&path, true).expect("user-mode dump");
        let _ = fs::remove_file(&path);

        assert_eq!(signal.source, "dmp");
        assert_eq!(signal.provider, "Game.dll");
        assert_eq!(signal.get("ExceptionCode"), Some("0xC0000005"));
        assert_eq!(signal.get("FaultingModule"), Some("Game.dll"));
        assert_eq!(signal.loaded_modules, vec![r"C:\Games\Game\Game.dll"]);
        assert!(signal.detail.contains("0xC0000005"));
        assert!(signal.detail.contains("Game.dll"));

        let expected = DateTime::<Utc>::from_timestamp(DUMP_TIMESTAMP as i64, 0)
            .expect("fixture timestamp")
            .with_timezone(&Local);
        assert_eq!(signal.t, expected);

        let ruleset = crate::rules::load();
        let crash_rule = ruleset
            .rules
            .iter()
            .find(|rule| rule.id == "dmp_crash")
            .expect("dmp_crash rule missing");
        assert!(crash_rule.matches(&signal));
    }

    #[test]
    fn kernel_pagedu64_is_skipped_automatically_and_reported_safely_on_drop() {
        let path = unique_temp_path("kernel.dmp");
        fs::write(&path, b"PAGEDU64\x00\x00\x00\x00kernel payload").expect("write kernel fixture");

        assert!(
            parse_dump(&path, false).is_none(),
            "automatic scans must skip kernel dumps safely"
        );
        let explicit = parse_dump(&path, true).expect("explicit drop gets an Info signal");
        let signals = scan(&path);
        let _ = fs::remove_file(&path);

        assert_eq!(explicit.get("Kind"), Some("kernel"));
        assert!(explicit.detail.contains("PAGEDU64"));
        assert_eq!(signals.len(), 1);
        assert_eq!(signals[0].get("Kind"), Some("kernel"));

        let ruleset = crate::rules::load();
        let crash_rule = ruleset
            .rules
            .iter()
            .find(|rule| rule.id == "dmp_crash")
            .expect("dmp_crash rule missing");
        let kernel_rule = ruleset
            .rules
            .iter()
            .find(|rule| rule.id == "dmp_kernel_unsupported")
            .expect("dmp_kernel_unsupported rule missing");
        assert!(!crash_rule.matches(&explicit));
        assert!(kernel_rule.matches(&explicit));
    }
}
