use std::collections::{HashMap, HashSet};

use crate::model::{Analysis, Finding, Incident, Signal};
use crate::rules::RuleSet;

/// Groups signals into incidents. Anchors closer together than `window_sec`
/// are merged so the same crash produces one card, not three.
pub fn run(signals: &[Signal], ruleset: &RuleSet) -> Analysis {
    if signals.is_empty() {
        return Analysis::Empty;
    }

    let mut anchors: Vec<&Signal> = signals
        .iter()
        .filter(|s| {
            s.source == "wer"
                || s.source == "ue_xml"
                || s.source == "unity_log"
                || s.source == "game_log"
                || (s.source == "eventlog" && s.event_id == Some(1000))
        })
        .collect();
    anchors.sort_by_key(|s| s.t);

    if anchors.is_empty() {
        return Analysis::NoAnchor;
    }

    let mut groups: Vec<Vec<&Signal>> = Vec::new();
    for anchor in anchors {
        if let Some(group) = groups.last_mut() {
            let last = group[0];
            if (anchor.t - last.t).num_seconds().abs() <= ruleset.window_sec * 2 {
                group.push(anchor);
                continue;
            }
        }
        groups.push(vec![anchor]);
    }

    let mut incidents = Vec::new();
    for group in groups {
        let anchor = group[0];
        let mut nearby: Vec<&Signal> = group.clone();
        for signal in signals.iter().filter(|s| {
            s.source == "registry" || (s.t - anchor.t).num_seconds().abs() <= ruleset.window_sec
        }) {
            if !nearby
                .iter()
                .any(|existing| std::ptr::eq(*existing, signal))
            {
                nearby.push(signal);
            }
        }
        nearby.sort_by_key(|s| s.t);

        let findings = findings_from(&nearby, ruleset);
        if findings.is_empty() {
            continue;
        }

        let title = nearby
            .iter()
            .find_map(|signal| {
                crate::rules::headline(signal).or_else(|| crate::rules::bugcheck_headline(signal))
            })
            .or_else(|| {
                nearby
                    .iter()
                    .find(|s| !s.provider.is_empty() && s.source != "registry")
                    .map(|s| s.provider.clone())
            })
            .unwrap_or_else(|| "Crash incident".to_owned());

        incidents.push(Incident {
            title,
            time: anchor.t,
            findings,
        });
    }

    incidents.sort_by_key(|incident| std::cmp::Reverse(incident.time));
    if incidents.is_empty() {
        return Analysis::NoAnchor;
    }
    Analysis::Results {
        incidents,
        note: None,
    }
}

fn findings_from(signals: &[&Signal], ruleset: &RuleSet) -> Vec<Finding> {
    let mut grouped: HashMap<String, Finding> = HashMap::new();
    let mut sources: HashMap<String, HashSet<&'static str>> = HashMap::new();

    for signal in signals {
        for rule in &ruleset.rules {
            if !rule.matches(signal) {
                continue;
            }
            let verdict = rule.verdict_for(signal);
            sources.entry(verdict.clone()).or_default().insert(signal.source);
            let evidence = format!(
                "{} | {} | {} | {}",
                signal.t.format("%Y-%m-%d %H:%M:%S"),
                signal.source,
                signal.provider,
                crate::sources::evt::excerpt(
                    &crate::redact::redact(&signal.detail),
                    crate::sources::evt::DETAIL_LIMIT,
                )
            );

            let entry = grouped.entry(verdict.clone()).or_insert_with(|| Finding {
                verdict,
                score: 0,
                confidence: rule.confidence.clone(),
                source_count: 0,
                evidence: Vec::new(),
                next_steps: rule.next_steps.clone(),
                link: rule.link.clone(),
            });
            entry.score += rule.weight;
            if !entry.evidence.contains(&evidence) {
                entry.evidence.push(evidence);
            }
            if (rule.id == "bugcheck_1001" || rule.id == "kernel_power_41")
                && entry.next_steps.is_empty()
            {
                if let Some(code) = crate::rules::bugcheck_code(signal) {
                    entry
                        .next_steps
                        .push(crate::codes::decode(code).1.to_owned());
                }
            }
            if rule.id == "application_error_1000" && entry.next_steps.is_empty() {
                if let Some(raw) = signal.get("ExceptionCode") {
                    if let Some(code) = crate::codes::parse_code(raw) {
                        entry
                            .next_steps
                            .push(crate::codes::decode_exception(code).1.to_owned());
                    }
                }
            }
            if entry.next_steps.is_empty() {
                entry.next_steps = rule.next_steps.clone();
            }
            if entry.link.is_none() {
                entry.link = rule.link.clone();
            }
        }
    }

    for (verdict, set) in sources {
        if let Some(finding) = grouped.get_mut(&verdict) {
            finding.source_count = set.len();
            // Confidence is derived from corroboration, but it must never drop
            // below the confidence already assigned by the matching rule.
            // Two independent sources are enough to call a verdict High;
            // a single source keeps the rule's own confidence (e.g. a lone
            // BugCheck 1001 stays High, a lone overlay stays Medium/Info).
            if finding.source_count >= 2 {
                finding.confidence = "High".to_owned();
            }
        }
    }

    let mut findings: Vec<Finding> = grouped.into_values().collect();
    findings.sort_by_key(|finding| std::cmp::Reverse(finding.score));
    findings.truncate(12);
    findings
}

