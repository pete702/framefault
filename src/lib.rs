pub mod app;
#[cfg(feature = "cli")]
pub mod cli;
pub mod codes;
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
    analyze_with_context(root, &context())
}

/// Scan using a context that was already collected (once, off the UI thread).
pub fn analyze_with_context(root: &Path, ctx: &SystemContext) -> Analysis {
    let ruleset = rules::load();
    let mut signals = sources::evt::read_recent();
    signals.extend(sources::wer::scan(root));
    signals.extend(sources::ue::scan(root));
    signals.extend(sources::gamelog::scan(root));

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
    let ring_note = format!(
        "Event Log ring buffer: {}. If the crash is older than this, absence of events is NOT evidence of absence.",
        ctx.log_reach
    );
    match &mut analysis {
        Analysis::Results { note, .. } | Analysis::NoAnchor { note } => {
            *note = Some(ring_note);
        }
        Analysis::Empty => {}
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
                note: None,
            }],
        }],
        note: None,
    };
    // No registry / Event Log reads: CI must get the same result everywhere.
    let report = report::markdown_with_context(&sample, &model::SystemContext::default());
    if report.contains("alice") || report.contains("192.168") {
        return Err("redaction leaked".to_owned());
    }
    // Do not look for the literal product name: if USERNAME/COMPUTERNAME is
    // "FrameFault", redaction legitimately replaces it with [REDACTED-*].
    if !report.contains("Read-only | 0 Admin | No Drivers.") || !report.contains("Evidence chain:")
    {
        return Err("report structure missing".to_owned());
    }
    Ok(())
}
