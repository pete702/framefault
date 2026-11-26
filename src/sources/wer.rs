use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use chrono::DateTime;
use walkdir::WalkDir;

use crate::model::Signal;

/// Any `<drive>:\Windows\System32\dxgi.dll` is Windows itself, not ReShade.
pub fn is_system_dll_path(path: &str) -> bool {
    let p = path.to_ascii_lowercase().replace('/', "\\");
    p.contains("\\windows\\system32\\") || p.contains("\\windows\\syswow64\\")
}

pub fn is_system_dll_name(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "dxgi.dll" | "d3d12.dll" | "d3d11.dll" | "d3d10.dll" | "opengl32.dll"
    )
}

fn is_wer_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.starts_with("report") && lower.ends_with(".wer")
}

pub fn scan(root: &Path) -> Vec<Signal> {
    let mut files: Vec<(PathBuf, SystemTime)> = Vec::new();
    let mut seen = HashSet::new();

    let mut add = |path: PathBuf| {
        if let Ok(meta) = fs::metadata(&path) {
            if let Ok(modified) = meta.modified() {
                if seen.insert(path.clone()) {
                    files.push((path, modified));
                }
            }
        }
    };

    if root.is_file() {
        // An explicitly dropped file is authoritative: accept any *.wer and
        // do not mix in unrelated machine-wide reports.
        let is_wer = root
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("wer"));
        if is_wer {
            add(root.to_path_buf());
        }
    } else {
        for entry in WalkDir::new(root).max_depth(8).into_iter().flatten() {
            if is_wer_name(&entry.file_name().to_string_lossy()) {
                add(entry.path().to_path_buf());
            }
        }

        // Per-user WER first, then machine-wide. AccessDenied is silently ignored.
        if let Some(local) = dirs::data_local_dir() {
            for dir in ["ReportArchive", "ReportQueue"] {
                collect_wer_dir(&local.join("Microsoft\\Windows\\WER").join(dir), &mut add);
            }
        }
        let programdata = PathBuf::from(r"C:\ProgramData\Microsoft\Windows\WER");
        for dir in ["ReportArchive", "ReportQueue"] {
            collect_wer_dir(&programdata.join(dir), &mut add);
        }
    }

    // Newest first; path breaks ties so the 25-file cap is deterministic
    // regardless of directory enumeration order.
    files.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    files
        .into_iter()
        .take(25)
        .filter_map(|(p, _)| parse(&p))
        .collect()
}

fn collect_wer_dir<F: FnMut(PathBuf)>(dir: &Path, add: &mut F) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            for file in WalkDir::new(path).max_depth(3).into_iter().flatten() {
                if is_wer_name(&file.file_name().to_string_lossy()) {
                    add(file.path().to_path_buf());
                }
            }
        } else if is_wer_name(&path.file_name().unwrap_or_default().to_string_lossy()) {
            add(path);
        }
    }
}

fn read_wer_text(path: &Path) -> Option<String> {
    let bytes = fs::read(path).ok()?;
    if bytes.starts_with(&[0xFF, 0xFE]) {
        let units: Vec<u16> = bytes[2..]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        Some(String::from_utf16_lossy(&units))
    } else if bytes.starts_with(&[0xFE, 0xFF]) {
        let units: Vec<u16> = bytes[2..]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect();
        Some(String::from_utf16_lossy(&units))
    } else {
        Some(String::from_utf8_lossy(&bytes).into_owned())
    }
}

/// LiveKernelEvent 141 must be proven by the report itself, never inferred
/// from a stray "141" in a version, path, timestamp or module name.
fn live_kernel_141_code(
    text: &str,
    fields: &std::collections::HashMap<String, String>,
) -> Option<&'static str> {
    let is_live_kernel = fields.iter().any(|(key, value)| {
        key.eq_ignore_ascii_case("EventType")
            && value.trim().eq_ignore_ascii_case("LiveKernelEvent")
    });
    if !is_live_kernel {
        return None;
    }

    const CODE_KEYS: [&str; 4] = ["P1", "Code", "Sig[0].Value", "ProblemSignature"];
    let has_code = CODE_KEYS.iter().any(|key| {
        fields
            .iter()
            .find(|(field, _)| field.eq_ignore_ascii_case(key))
            .is_some_and(|(_, value)| {
                value
                    .split(|c: char| !c.is_ascii_alphanumeric())
                    .any(|token| token.eq_ignore_ascii_case("141"))
            })
    });
    if has_code || text.to_ascii_lowercase().contains("lkd_0x141") {
        Some("141")
    } else {
        None
    }
}

/// WER has shipped several casings of the same timestamp keys over the years.
fn report_time(
    fields: &std::collections::HashMap<String, String>,
) -> Option<DateTime<chrono::Local>> {
    [
        "ReportCreateTimeStamp",
        "TimeCreated",
        "ReportTime",
        "EventTime",
        "Timestamp",
    ]
    .iter()
    .find_map(|key| {
        fields
            .iter()
            .find(|(field, _)| field.eq_ignore_ascii_case(key))
            .and_then(|(_, value)| crate::model::parse_timestamp(value))
    })
}

fn parse(path: &Path) -> Option<Signal> {
    let text = read_wer_text(path)?;
    let mtime = fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .map(DateTime::<chrono::Local>::from);

    let mut fields = std::collections::HashMap::new();
    let mut modules = Vec::new();
    // Evidence shows event fields and third-party modules only. The complete
    // path list stays in `loaded_modules` for overlay rules, but dozens of
    // Windows System32/SysWOW64 DLLs must not pollute the report nor make a
    // plain BSOD look like a GPU/game incident.
    let mut detail_lines: Vec<String> = Vec::new();
    for line in text.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim();
        if key.is_empty() || value.is_empty() {
            continue;
        }
        if key.to_ascii_lowercase().starts_with("loadedmodule") {
            modules.push(value.to_owned());
            if !is_system_dll_path(value) {
                detail_lines.push(format!("{key}={value}"));
            }
        } else {
            detail_lines.push(format!("{key}={value}"));
            fields.insert(key.to_owned(), value.to_owned());
        }
    }

    // Real crash time from inside the report, mtime only as a fallback.
    let time = report_time(&fields).or(mtime)?;

    if let Some(code) = live_kernel_141_code(&text, &fields) {
        fields.insert("LiveKernelCode".to_owned(), code.to_owned());
    }

    let mut signal = Signal::new("wer", time);
    signal.provider = "WER".to_owned();
    signal.detail = detail_lines.join("\n");
    signal.fields = fields;
    signal.loaded_modules = modules;
    Some(signal)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fields(pairs: &[(&str, &str)]) -> std::collections::HashMap<String, String> {
        pairs
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect()
    }

    #[test]
    fn report_time_keys_are_case_insensitive() {
        let mut fields = std::collections::HashMap::new();
        fields.insert(
            "reportcreatetimestamp".to_owned(),
            "2026-11-25T10:00:00".to_owned(),
        );
        let parsed = report_time(&fields).expect("lowercase timestamp key must be accepted");
        assert_eq!(
            parsed.format("%Y-%m-%d %H:%M:%S").to_string(),
            "2026-11-25 10:00:00"
        );

        fields.clear();
        fields.insert("EventTime".to_owned(), "not a date".to_owned());
        assert!(report_time(&fields).is_none());
    }

    #[test]
    fn system_dll_paths_work_on_any_windows_drive() {
        for path in [
            r"C:\Windows\System32\dxgi.dll",
            r"D:\Windows\System32\dxgi.dll",
            r"E:\Windows\SysWOW64\d3d12.dll",
        ] {
            assert!(is_system_dll_path(path), "must be system: {path}");
        }
        assert!(!is_system_dll_path(r"D:\Games\Game\dxgi.dll"));
        assert!(!is_system_dll_path(r"D:\MyWindows\System32\dxgi.dll"));
    }

    #[test]
    fn live_kernel_code_requires_a_live_kernel_event() {
        let live = fields(&[("EventType", "livekernelevent")]);
        assert_eq!(
            live_kernel_141_code("BugCheck LKD_0x141: video engine timeout", &live),
            Some("141")
        );

        let wrong_type = fields(&[("EventType", "ApplicationCrash"), ("Code", "141")]);
        assert_eq!(
            live_kernel_141_code("BugCheck LKD_0x141: video engine timeout", &wrong_type),
            None
        );
    }

    #[test]
    fn live_kernel_code_uses_named_signature_fields() {
        let live = fields(&[("EventType", "LiveKernelEvent")]);
        let with_version = fields(&[
            ("EventType", "LiveKernelEvent"),
            ("AppVersion", "1.41.0"),
            ("AppPath", r"C:\Apps\141\Game.exe"),
        ]);
        assert_eq!(live_kernel_141_code("plain crash", &with_version), None);

        for key in ["P1", "Code", "Sig[0].Value", "ProblemSignature"] {
            let with_code = fields(&[("EventType", "LiveKernelEvent"), (key, "141")]);
            assert_eq!(live_kernel_141_code("plain crash", &with_code), Some("141"));
        }
        assert_eq!(live_kernel_141_code("plain crash", &live), None);
    }
}
