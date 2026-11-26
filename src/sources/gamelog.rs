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

/// UE/UE5 writes its logs to `<game>\Saved\Logs\`. Nothing else under
/// %LOCALAPPDATA% is a game log, so browsers and editor caches stay untouched.
fn in_saved_logs(path: &Path) -> bool {
    path.components()
        .filter_map(|c| c.as_os_str().to_str())
        .collect::<Vec<_>>()
        .windows(2)
        .any(|pair| pair[0].eq_ignore_ascii_case("Saved") && pair[1].eq_ignore_ascii_case("Logs"))
}

fn is_log_file(path: &Path) -> bool {
    path.extension()
        .map(|e| e.eq_ignore_ascii_case("log"))
        .unwrap_or(false)
}

pub fn scan(root: &Path) -> Vec<Signal> {
    if root.is_file() {
        return if is_log_file(root) {
            parse(root).into_iter().collect()
        } else {
            Vec::new()
        };
    }

    let is_default_local = dirs::data_local_dir().is_some_and(|d| d.as_path() == root);
    let mut found: Vec<(PathBuf, SystemTime)> = Vec::new();

    if is_default_local {
        // a) Unreal logs inside *\Saved\Logs\ only, never Chrome/Discord/VS Code.
        for entry in WalkDir::new(root).max_depth(5).into_iter().flatten() {
            if !entry.file_type().is_file()
                || !is_log_file(entry.path())
                || !in_saved_logs(entry.path())
            {
                continue;
            }
            if let Some(modified) = entry.metadata().ok().and_then(|m| m.modified().ok()) {
                found.push((entry.path().to_path_buf(), modified));
            }
        }

        // b) Unity always puts Player.log in the sibling AppData\LocalLow.
        if let Some(parent) = root.parent() {
            let locallow = parent.join("LocalLow");
            if locallow.is_dir() {
                for entry in WalkDir::new(locallow).max_depth(4).into_iter().flatten() {
                    if !entry.file_type().is_file()
                        || !entry
                            .file_name()
                            .to_string_lossy()
                            .eq_ignore_ascii_case("player.log")
                    {
                        continue;
                    }
                    if let Some(modified) = entry.metadata().ok().and_then(|m| m.modified().ok()) {
                        found.push((entry.path().to_path_buf(), modified));
                    }
                }
            }
        }
    } else {
        // Explicit folder from drag-and-drop: keep the broad search.
        for entry in WalkDir::new(root).max_depth(7).into_iter().flatten() {
            if !entry.file_type().is_file() || !is_log_file(entry.path()) {
                continue;
            }
            if let Some(modified) = entry.metadata().ok().and_then(|m| m.modified().ok()) {
                found.push((entry.path().to_path_buf(), modified));
            }
        }
    }

    found.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    found
        .into_iter()
        .take(10)
        .filter_map(|(path, _)| parse(&path))
        .collect()
}

fn parse(path: &Path) -> Option<Signal> {
    // Game logs on non-English Windows are often ANSI/Windows-1252; a single
    // invalid byte must not discard the whole crash log.
    let bytes = fs::read(path).ok()?;
    let text = String::from_utf8_lossy(&bytes);
    let time = fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .map(DateTime::<chrono::Local>::from)?;

    let mut matched = Vec::new();
    for line in text.lines().rev().take(2000) {
        let lower = line.to_ascii_lowercase();
        if MARKERS
            .iter()
            .any(|marker| lower.contains(&marker.to_ascii_lowercase()))
        {
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
    // `matched` is newest-first (lines are scanned in reverse). Take the 60
    // newest matches, then reverse for chronological detail.
    signal.detail = matched
        .into_iter()
        .take(60)
        .rev()
        .collect::<Vec<_>>()
        .join("\n");
    Some(signal)
}
