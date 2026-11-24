use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use chrono::DateTime;
use walkdir::WalkDir;

use crate::model::Signal;

/// C:\Windows\System32\dxgi.dll is Windows itself, not ReShade.
pub fn is_system_dll_path(path: &str) -> bool {
    let p = path.to_ascii_lowercase().replace('/', "\\");
    p.starts_with("c:\\windows\\system32\\") || p.starts_with("c:\\windows\\syswow64\\")
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
        if is_wer_name(&root.file_name().unwrap_or_default().to_string_lossy()) {
            add(root.to_path_buf());
        }
    } else {
        for entry in WalkDir::new(root).max_depth(8).into_iter().flatten() {
            if is_wer_name(&entry.file_name().to_string_lossy()) {
                add(entry.path().to_path_buf());
            }
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

    files.sort_by_key(|entry| std::cmp::Reverse(entry.1));
    files
        .into_iter()
        .take(6)
        .filter_map(|(p, _)| parse(&p))
        .collect()
}

fn collect_wer_dir<F: FnMut(PathBuf)>(dir: &Path, add: &mut F) {
    let Ok(entries) = fs::read_dir(dir) else { return };
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
    } else {
        Some(String::from_utf8_lossy(&bytes).into_owned())
    }
}

fn parse(path: &Path) -> Option<Signal> {
    let text = read_wer_text(path)?;
    let mtime = fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .map(DateTime::<chrono::Local>::from);

    let mut fields = std::collections::HashMap::new();
    let mut modules = Vec::new();
    for line in text.lines() {
        let Some((key, value)) = line.split_once('=') else { continue };
        let key = key.trim();
        let value = value.trim();
        if key.to_ascii_lowercase().starts_with("loadedmodule") {
            modules.push(value.to_owned());
        } else {
            fields.insert(key.to_owned(), value.to_owned());
        }
    }

    // Real crash time from inside the report, mtime only as a fallback.
    let time = [
        "ReportCreateTimeStamp",
        "TimeCreated",
        "ReportTime",
        "EventTime",
        "Timestamp",
    ]
    .iter()
    .find_map(|key| fields.get(*key).and_then(|value| crate::model::parse_timestamp(value)))
    .or(mtime)?;

    let mut signal = Signal::new("wer", time);
    signal.provider = "WER".to_owned();
    signal.detail = text;
    signal.fields = fields;
    signal.loaded_modules = modules;
    Some(signal)
}
