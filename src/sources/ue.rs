use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use chrono::DateTime;
use quick_xml::events::Event;
use quick_xml::Reader;
use walkdir::WalkDir;

use crate::model::Signal;

const FIELDS: [&str; 10] = [
    "GameName",
    "EngineVersion",
    "BuildConfiguration",
    "EngineMode",
    "CrashType",
    "IsEnsure",
    "IsAssert",
    "bIsOOM",
    "GPUBrand",
    "ErrorMessage",
];

/// UE5 tag casing varies; all tags are normalised to lowercase here and looked
/// up case-insensitively in Signal::get. Empty Shipping CallStack is ignored.
fn is_xml_file(path: &Path) -> bool {
    path.extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("xml"))
}

/// A file whose name contains "crashcontext" is not enough: read the first
/// 4 KiB and require the actual root tag before treating it as UE context.
fn has_crash_context_tag(path: &Path) -> bool {
    use std::io::Read;

    const PROBE_BYTES: usize = 4096;
    let Ok(mut file) = fs::File::open(path) else {
        return false;
    };
    let mut buffer = [0u8; PROBE_BYTES];
    let Ok(read) = file.read(&mut buffer) else {
        return false;
    };
    String::from_utf8_lossy(&buffer[..read])
        .to_ascii_lowercase()
        .contains("<crashcontext")
}

pub fn scan(root: &Path) -> Vec<Signal> {
    let files: Vec<PathBuf> = if root.is_file() {
        let name = root.file_name().unwrap_or_default().to_string_lossy();
        // Keep the canonical UE filename (it ends in .runtime-xml, not .xml),
        // and accept any dropped .xml that actually contains CrashContext.
        let canonical = name.eq_ignore_ascii_case("crashcontext.runtime-xml");
        let is_xml = is_xml_file(root);
        let has_crash_context = is_xml
            && fs::read_to_string(root)
                .map(|text| text.to_ascii_lowercase().contains("<crashcontext"))
                .unwrap_or(false);
        if canonical || has_crash_context {
            vec![root.to_path_buf()]
        } else {
            Vec::new()
        }
    } else {
        let mut found: Vec<(PathBuf, SystemTime)> = Vec::new();
        for entry in WalkDir::new(root).max_depth(9).into_iter().flatten() {
            let name = entry.file_name().to_string_lossy().to_ascii_lowercase();
            // The canonical file ends in `.runtime-xml`, not `.xml`. Any other
            // XML name containing "crashcontext" is also a UE crash report.
            let canonical = name == "crashcontext.runtime-xml";
            let xml_named = name.ends_with(".xml") && name.contains("crashcontext");
            if !(canonical || xml_named) {
                continue;
            }
            if xml_named && !has_crash_context_tag(entry.path()) {
                continue;
            }
            if let Some(modified) = entry.metadata().ok().and_then(|m| m.modified().ok()) {
                found.push((entry.path().to_path_buf(), modified));
            }
        }
        found.sort_by_key(|entry| std::cmp::Reverse(entry.1));
        found.into_iter().take(4).map(|(p, _)| p).collect()
    };

    files.iter().filter_map(|p| parse(p)).collect()
}

fn parse(path: &Path) -> Option<Signal> {
    let text = fs::read_to_string(path).ok()?;
    let mtime = fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .map(DateTime::<chrono::Local>::from);
    let map = read_tags(&text);
    let time = ["time", "crashtime", "timestamp"]
        .iter()
        .find_map(|key| {
            map.get(*key)
                .and_then(|value| crate::model::parse_timestamp(value))
        })
        .or(mtime)?;

    let mut signal = Signal::new("ue_xml", time);
    signal.provider = map
        .get("gamename")
        .cloned()
        .unwrap_or_else(|| "UnrealEngine".to_owned());

    for key in FIELDS {
        if let Some(value) = map.get(&key.to_ascii_lowercase()) {
            signal.fields.insert(key.to_owned(), value.clone());
        }
    }
    if let Some(stack) = map.get("callstack") {
        if stack.chars().any(|c| c.is_ascii_alphabetic()) {
            signal
                .fields
                .insert("CallStack(optional)".to_owned(), stack.clone());
        }
    }

    signal.detail = detail_from_map(&map);
    Some(signal)
}

/// Only the diagnostic whitelist reaches evidence/report. Unknown UE tags
/// (EpicAccountId, LoginId, SteamID64, machine GUIDs, ...) are never copied.
fn detail_from_map(map: &HashMap<String, String>) -> String {
    let mut keys: Vec<String> = FIELDS.iter().map(|key| key.to_ascii_lowercase()).collect();
    keys.push("callstack".to_owned());

    let mut out = String::new();
    for key in &keys {
        if let Some(value) = map.get(key) {
            out.push_str(key);
            out.push('=');
            out.push_str(value);
            out.push('\n');
        }
    }
    out
}

fn read_tags(text: &str) -> HashMap<String, String> {
    let mut reader = Reader::from_str(text);
    reader.config_mut().trim_text(true);
    let mut out = HashMap::new();
    let mut current: Option<String> = None;

    loop {
        match reader.read_event() {
            Ok(Event::Start(event)) => {
                current = Some(event.name().as_ref().to_ascii_lowercase());
            }
            Ok(Event::Text(event)) => {
                if let Some(tag) = &current {
                    let value = event.into_inner().into_owned();
                    if !value.is_empty() {
                        out.entry(tag.clone()).or_insert(value);
                    }
                }
            }
            Ok(Event::Empty(_)) | Ok(Event::End(_)) => current = None,
            Ok(Event::Eof) | Err(_) => break,
            _ => {}
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detail_lines_follow_a_fixed_key_order() {
        let mut map = HashMap::new();
        map.insert("errormessage".to_owned(), "boom".to_owned());
        map.insert("gamename".to_owned(), "Game".to_owned());
        map.insert("bisoom".to_owned(), "true".to_owned());
        map.insert("zzz_extra".to_owned(), "last".to_owned());
        map.insert("aaa_extra".to_owned(), "first".to_owned());
        map.insert("epicaccountid".to_owned(), "deadbeef".to_owned());

        assert_eq!(
            detail_from_map(&map),
            "gamename=Game\nbisoom=true\nerrormessage=boom\n"
        );
    }

    #[test]
    fn directory_scan_ignores_xml_without_the_crash_context_tag() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/ue-fake");
        assert!(
            scan(&dir).is_empty(),
            "notes-crashcontext.xml without <CrashContext> must be ignored"
        );
    }
}
