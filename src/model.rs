use std::collections::HashMap;

use chrono::{DateTime, Local, NaiveDateTime, TimeZone};

/// Best-effort timestamp parser for WER fields and UE crash XML.
pub fn parse_timestamp(value: &str) -> Option<DateTime<Local>> {
    let value = value.trim();
    if let Ok(date) = DateTime::parse_from_rfc3339(value) {
        return Some(date.with_timezone(&Local));
    }
    for format in [
        "%Y-%m-%dT%H:%M:%S%.f",
        "%Y-%m-%d %H:%M:%S%.f",
        "%Y-%m-%d %H:%M:%S",
        "%m/%d/%Y %H:%M:%S",
    ] {
        if let Ok(naive) = NaiveDateTime::parse_from_str(value, format) {
            if let Some(local) = Local.from_local_datetime(&naive).single() {
                return Some(local);
            }
        }
    }
    None
}

#[derive(Clone, Debug)]
pub struct Signal {
    pub t: DateTime<Local>,
    pub source: &'static str,
    pub provider: String,
    pub event_id: Option<u16>,
    pub fields: HashMap<String, String>,
    pub detail: String,
    /// Full paths from Report.wer -> LoadedModule[N]. Historical, not live.
    pub loaded_modules: Vec<String>,
}

impl Signal {
    pub fn new(source: &'static str, t: DateTime<Local>) -> Self {
        Self {
            t,
            source,
            provider: String::new(),
            event_id: None,
            fields: HashMap::new(),
            detail: String::new(),
            loaded_modules: Vec::new(),
        }
    }

    /// Case-insensitive lookup: UE5 tag casing varies between engine versions.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(key))
            .map(|(_, v)| v.as_str())
    }
}

#[derive(Clone, Debug)]
pub struct Finding {
    pub verdict: String,
    pub score: i32,
    pub confidence: String,
    pub source_count: usize,
    pub evidence: Vec<String>,
    pub next_steps: Vec<String>,
    pub link: Option<String>,
}

#[derive(Clone, Debug)]
pub struct Incident {
    pub title: String,
    pub time: DateTime<Local>,
    pub findings: Vec<Finding>,
}

#[derive(Clone, Debug, Default)]
pub enum Analysis {
    Results {
        incidents: Vec<Incident>,
        note: Option<String>,
    },
    NoAnchor,
    #[default]
    Empty,
}

#[derive(Clone, Debug, Default)]
pub struct SystemContext {
    pub gpu: String,
    pub driver: String,
    pub ram_total_gib: f64,
    pub ram_used_gib: f64,
    pub commit_limit_gib: f64,
    pub commit_used_gib: f64,
    pub pagefile: String,
    pub mpo: String,
    pub overlays_now: Vec<String>,
    pub log_reach: String,
    pub windows: String,
}
