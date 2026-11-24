pub mod app;
pub mod codes;
#[cfg(feature = "cli")]
pub mod cli;
pub mod correlate;
pub mod model;
pub mod redact;
pub mod report;
pub mod rules;
pub mod sources;

use std::path::Path;

use crate::model::{Analysis, SystemContext};

pub fn context() -> SystemContext {
    sources::registry::read_context()
}

pub fn analyze(root: &Path) -> Analysis {
    let ruleset = rules::load();
    let mut signals = sources::evt::read_recent();
    signals.extend(sources::wer::scan(root));
    signals.extend(sources::ue::scan(root));
    signals.extend(sources::gamelog::scan(root));
    signals.extend(sources::registry::read_context_signals());

    #[cfg(feature = "evtx")]
    if root.is_file()
        && root
            .extension()
            .map(|e| e.eq_ignore_ascii_case("evtx"))
            .unwrap_or(false)
    {
        signals.extend(sources::evt::scan_evtx(root));
    }

    let mut analysis = correlate::run(&signals, &ruleset);
    if let Analysis::Results { note, .. } = &mut analysis {
        *note = Some(format!(
            "Event Log ring buffer: {}. If the crash is older than this, absence of events is NOT evidence of absence.",
            sources::evt::log_reach()
        ));
    }
    analysis
}

pub fn self_test() -> Result<(), String> {
    let ruleset = rules::load();
    if ruleset.rules.is_empty() {
        return Err("no rules loaded".to_owned());
    }
    let sample = model::Analysis::Results {
        incidents: vec![model::Incident {
            title: "self-test".to_owned(),
            time: chrono::Local::now(),
            findings: vec![model::Finding {
                verdict: "self".to_owned(),
                score: 1,
                confidence: "Info".to_owned(),
                source_count: 1,
                evidence: vec!["C:\\Users\\alice\\192.168.0.1".to_owned()],
                next_steps: Vec::new(),
                link: None,
            }],
        }],
        note: None,
    };
    let report = report::markdown(&sample);
    if report.contains("alice") || report.contains("192.168") {
        return Err("redaction leaked".to_owned());
    }
    if !report.contains("FrameFault") {
        return Err("report footer missing".to_owned());
    }
    Ok(())
}
