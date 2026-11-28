use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use chrono::DateTime;
use walkdir::WalkDir;

use crate::model::Signal;

/// A game log can be hundreds of MiB; only the tail can contain the crash.
const TAIL_BYTES: u64 = 2 * 1024 * 1024;
const TAIL_LINES: usize = 2000;

/// Anti-cheat names are common in normal startup logs. A bare mention is not
/// a crash; it needs an error context or an exact driver module name.
const ANTICHEAT_MARKERS: &[&str] = &["easyanticheat", "bedaisy", "battleye"];
const ANTICHEAT_MODULES: &[&str] = &["easyanticheat_eos.sys", "easyanticheat.sys", "bedaisy.sys"];
const CRASH_CONTEXT: &[&str] = &[
    "error",
    "fail",
    "crash",
    "violation",
    "kicked",
    "blocked",
    "untrusted",
    "denied",
    "fatal",
    "0x",
];

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

fn marker_matches(line_lower: &str, marker: &str) -> bool {
    let marker = marker.to_ascii_lowercase();
    if !line_lower.contains(&marker) {
        return false;
    }
    if ANTICHEAT_MARKERS.iter().any(|name| marker.contains(*name)) {
        return ANTICHEAT_MODULES
            .iter()
            .any(|module| line_lower.contains(*module))
            || CRASH_CONTEXT
                .iter()
                .any(|context| line_lower.contains(*context));
    }
    true
}

/// Read at most the last 2 MiB. When the tail starts mid-line, drop that
/// partial line; when it starts exactly after a newline, keep every line.
fn read_tail<R: Read + Seek>(reader: &mut R, len: u64) -> std::io::Result<String> {
    let mut bytes = Vec::with_capacity(len.min(TAIL_BYTES) as usize);

    if len > TAIL_BYTES {
        // Read the byte just before the tail start to tell a partial first
        // line from a complete one on the exact 2 MiB boundary.
        reader.seek(SeekFrom::End(-(TAIL_BYTES as i64) - 1))?;
        let mut previous = [0u8; 1];
        reader.read_exact(&mut previous)?;
        reader.read_to_end(&mut bytes)?;
        if previous[0] == b'\n' {
            return Ok(String::from_utf8_lossy(&bytes).into_owned());
        }
        let Some(start) = bytes.iter().position(|&byte| byte == b'\n') else {
            return Ok(String::new());
        };
        Ok(String::from_utf8_lossy(&bytes[start + 1..]).into_owned())
    } else {
        reader.read_to_end(&mut bytes)?;
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }
}

fn read_log_text(path: &Path) -> Option<String> {
    let mut file = File::open(path).ok()?;
    let len = file.metadata().ok()?.len();
    read_tail(&mut file, len).ok()
}

fn parse(path: &Path) -> Option<Signal> {
    // Game logs on non-English Windows are often ANSI/Windows-1252; a single
    // invalid byte must not discard the whole crash log.
    let text = read_log_text(path)?;
    let time = fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .map(DateTime::<chrono::Local>::from)?;

    let name = path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned();
    parse_text(&name, &text, time)
}

fn parse_text(name: &str, text: &str, time: DateTime<chrono::Local>) -> Option<Signal> {
    let mut matched = Vec::new();
    for line in text.lines().rev().take(TAIL_LINES) {
        let lower = line.to_ascii_lowercase();
        if MARKERS.iter().any(|marker| marker_matches(&lower, marker)) {
            matched.push(line.to_owned());
        }
    }
    if matched.is_empty() {
        return None;
    }

    let mut signal = Signal::new(source_for(name), time);
    signal.provider = name.to_owned();
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anticheat_init_is_not_a_crash_but_an_error_is() {
        assert!(!marker_matches(
            "easyanticheat initialized",
            "EasyAntiCheat"
        ));
        assert!(marker_matches(
            "easyanticheat error: untrusted system file",
            "EasyAntiCheat"
        ));
        assert!(marker_matches("bedaisy.sys", "BEDaisy"));
        assert!(!marker_matches("battleye service started", "BattlEye"));
        assert!(marker_matches("battleye: blocked client", "BattlEye"));
    }

    #[test]
    fn anticheat_game_log_verdict_needs_crash_context() {
        let now = chrono::Local::now();
        assert!(
            parse_text("game.log", "EasyAntiCheat initialized\n", now).is_none(),
            "normal anti-cheat init must not create a signal"
        );

        let signal = parse_text(
            "game.log",
            "EasyAntiCheat error: untrusted system file\n",
            now,
        )
        .expect("an anti-cheat error line must create a signal");
        let ruleset = crate::rules::load();
        let rule = ruleset
            .rules
            .iter()
            .find(|rule| rule.id == "anticheat_game_log")
            .expect("anticheat_game_log rule missing");
        assert!(rule.matches(&signal), "detail: {}", signal.detail);
    }

    #[test]
    fn tail_read_keeps_only_the_last_two_mib_and_drops_the_partial_line() {
        let mut data = Vec::new();
        data.extend_from_slice(b"OLD_MARKER\n");
        data.resize(TAIL_BYTES as usize + 64, b'x');
        data.push(b'\n');
        data.extend_from_slice(b"TAIL_MARKER\n");

        let len = data.len() as u64;
        let mut cursor = std::io::Cursor::new(data);
        let text = read_tail(&mut cursor, len).expect("tail read");

        assert_eq!(text, "TAIL_MARKER\n");
        assert!(!text.contains("OLD_MARKER"), "tail read the whole file");
    }

    #[test]
    fn tail_read_keeps_a_full_first_line_on_the_exact_boundary() {
        let first_line = b"BOUNDARY_MARKER\n";
        let mut data = Vec::new();
        data.extend_from_slice(b"OPAQUE_PREFIX\n");
        data.extend_from_slice(first_line);
        data.resize(
            data.len() + TAIL_BYTES as usize - first_line.len() - 1,
            b'y',
        );
        data.push(b'\n');

        let len = data.len() as u64;
        let text = read_tail(&mut std::io::Cursor::new(data), len).expect("boundary read");

        assert!(
            text.starts_with("BOUNDARY_MARKER\n"),
            "a complete first line was dropped: {:?}",
            &text[..text.len().min(40)]
        );
        assert_eq!(text.len(), TAIL_BYTES as usize);
        assert!(!text.contains("OPAQUE_PREFIX"));
    }

    #[test]
    fn small_log_is_read_whole() {
        let mut cursor = std::io::Cursor::new(b"small\n".to_vec());
        assert_eq!(read_tail(&mut cursor, 6).expect("small read"), "small\n");
    }
}
