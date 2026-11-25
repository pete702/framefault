use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use chrono::DateTime;
use walkdir::WalkDir;

use crate::model::Signal;

const MARKERS: &[&str] = &[
    "DXGI_ERROR_DEVICE_HUNG",
    "DXGI_ERROR_DEVICE_REMOVED",
    "0x887A0006",
    "0x887A0005",
    "GetDeviceRemovedReason",
    "Out of video memory",
    "VK_ERROR_OUT_OF_DEVICE_MEMORY",
    "Fatal error",
    "LogD3D12RHI: Error",
    "EasyAntiCheat",
    "BEDaisy",
    "BattlEye",
    "Crash!!!",
    "OutOfMemoryException",
];

fn source_for(name: &str) -> &'static str {
    if name.eq_ignore_ascii_case("player.log") {
        "unity_log"
    } else {
        "game_log"
    }
}

pub fn scan(root: &Path) -> Vec<Signal> {
    let files: Vec<PathBuf> = if root.is_file() {
        let is_log = root
            .extension()
            .map(|e| e.eq_ignore_ascii_case("log"))
            .unwrap_or(false);
        if is_log {
            vec![root.to_path_buf()]
        } else {
            Vec::new()
        }
    } else {
        let mut found: Vec<(PathBuf, SystemTime)> = Vec::new();
        for entry in WalkDir::new(root).max_depth(7).into_iter().flatten() {
            let is_log = entry
                .path()
                .extension()
                .map(|e| e.eq_ignore_ascii_case("log"))
                .unwrap_or(false);
            if !is_log {
                continue;
            }
            if let Some(modified) = entry.metadata().ok().and_then(|m| m.modified().ok()) {
                found.push((entry.path().to_path_buf(), modified));
            }
        }
        found.sort_by_key(|entry| std::cmp::Reverse(entry.1));
        found.into_iter().take(6).map(|(p, _)| p).collect()
    };

    files.iter().filter_map(|p| parse(p)).collect()
}

fn parse(path: &Path) -> Option<Signal> {
    let text = fs::read_to_string(path).ok()?;
    let time = fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .map(DateTime::<chrono::Local>::from)?;

    let mut matched = Vec::new();
    for line in text.lines().rev().take(2000) {
        if MARKERS.iter().any(|m| line.contains(m)) {
            matched.push(line.to_owned());
        }
    }
    if matched.is_empty() {
        return None;
    }

    let name = path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned();
    let mut signal = Signal::new(source_for(&name), time);
    signal.provider = name;
    signal.detail = matched.into_iter().rev().take(60).collect::<Vec<_>>().join("\n");
    Some(signal)
}
