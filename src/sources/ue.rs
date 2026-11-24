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
pub fn scan(root: &Path) -> Vec<Signal> {
    let files: Vec<PathBuf> = if root.is_file() {
        let name = root.file_name().unwrap_or_default().to_string_lossy();
        if name.to_ascii_lowercase() == "crashcontext.runtime-xml" {
            vec![root.to_path_buf()]
        } else {
            Vec::new()
        }
    } else {
        let mut found: Vec<(PathBuf, SystemTime)> = Vec::new();
        for entry in WalkDir::new(root).max_depth(9).into_iter().flatten() {
            if entry
                .file_name()
                .to_string_lossy()
                .to_ascii_lowercase()
                != "crashcontext.runtime-xml"
            {
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
        .find_map(|key| map.get(*key).and_then(|value| crate::model::parse_timestamp(value)))
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

    let mut detail = String::new();
    for (key, value) in &map {
        detail.push_str(key);
        detail.push('=');
        detail.push_str(value);
        detail.push('\n');
    }
    signal.detail = detail;
    Some(signal)
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
