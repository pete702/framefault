use std::collections::{HashMap, HashSet};

use chrono::{DateTime, Local};

use crate::model::{Analysis, Finding, Incident, Signal};
use crate::rules::RuleSet;

/// System events that are a crash on their own, even without a WER report or
/// an Event 1000 next to them.
const CRITICAL_IDS: &[u16] = &[1001, 41, 17, 18, 19, 153, 4101, 2004];

fn group_anchors(anchors: Vec<&Signal>, window: i64) -> Vec<Vec<&Signal>> {
    let mut groups: Vec<Vec<&Signal>> = Vec::new();
    for anchor in anchors {
        if let Some(group) = groups.last_mut() {
            if (anchor.t - group[0].t).num_seconds().abs() <= window {
                group.push(anchor);
                continue;
            }
        }
        groups.push(vec![anchor]);
    }
    groups
}

/// All signals belonging to one crash window: the anchors themselves plus
/// anything within `window_sec` of the whole anchor range, not just the
/// first anchor. `skip` keeps fallback groups from duplicating signals
/// already claimed by a primary group.
fn expand_group<'a>(
    anchors: &[&'a Signal],
    signals: &'a [Signal],
    ruleset: &RuleSet,
    skip: &HashSet<*const Signal>,
) -> Vec<&'a Signal> {
    let earliest = anchors
        .iter()
        .map(|s| s.t)
        .min()
        .expect("empty anchor group");
    let latest = anchors
        .iter()
        .map(|s| s.t)
        .max()
        .expect("empty anchor group");
    let span = chrono::Duration::seconds(ruleset.window_sec);
    let lower = earliest - span;
    let upper = latest + span;
    let mut nearby: Vec<&Signal> = anchors.to_vec();
    for signal in signals.iter().filter(|s| s.t >= lower && s.t <= upper) {
        if skip.contains(&(signal as *const Signal)) {
            continue;
        }
        if !nearby
            .iter()
            .any(|existing| std::ptr::eq(*existing, signal))
        {
            nearby.push(signal);
        }
    }
    nearby.sort_by_key(|s| s.t);
    nearby
}

/// Drop anchors already claimed by an earlier group, then return the newest
/// remaining anchor and its full window. This prevents overlapping primary
/// groups from putting the same signal into two incidents.
fn take_group<'a>(
    group: Vec<&'a Signal>,
    signals: &'a [Signal],
    ruleset: &RuleSet,
    consumed: &HashSet<*const Signal>,
) -> Option<(Vec<&'a Signal>, &'a Signal)> {
    let anchors: Vec<&Signal> = group
        .into_iter()
        .filter(|signal| !consumed.contains(&(*signal as *const Signal)))
        .collect();
    let newest = *anchors.last()?;
    let nearby = expand_group(&anchors, signals, ruleset, consumed);
    Some((nearby, newest))
}

/// Groups signals into incidents. Primary anchors (WER, UE/Unity/game logs,
/// user-mode minidumps, Event 1000) are preferred; critical system events that
/// did not fall into any primary window become fallback anchors instead of
/// being dropped.
pub fn run(signals: &[Signal], ruleset: &RuleSet) -> Analysis {
    if signals.is_empty() {
        return Analysis::Empty;
    }

    let mut primary: Vec<&Signal> = signals
        .iter()
        .filter(|s| {
            s.source == "wer"
                || s.source == "ue_xml"
                || s.source == "unity_log"
                || s.source == "game_log"
                || s.source == "dmp"
                || (s.source == "eventlog" && s.event_id == Some(1000))
        })
        .collect();
    primary.sort_by_key(|s| s.t);

    let mut secondary: Vec<&Signal> = signals
        .iter()
        .filter(|s| {
            s.source == "eventlog" && matches!(s.event_id, Some(id) if CRITICAL_IDS.contains(&id))
        })
        .collect();
    secondary.sort_by_key(|s| s.t);

    if primary.is_empty() && secondary.is_empty() {
        return Analysis::NoAnchor { note: None };
    }

    let window = ruleset.window_sec * 2;
    let mut work: Vec<_> = Vec::new();
    let mut consumed: HashSet<*const Signal> = HashSet::new();

    for group in group_anchors(primary, window) {
        if let Some((nearby, newest)) = take_group(group, signals, ruleset, &consumed) {
            for signal in &nearby {
                consumed.insert(*signal as *const Signal);
            }
            work.push((nearby, newest.t, false));
        }
    }

    let leftover: Vec<&Signal> = secondary
        .into_iter()
        .filter(|s| !consumed.contains(&(*s as *const Signal)))
        .collect();
    for group in group_anchors(leftover, window) {
        if let Some((nearby, newest)) = take_group(group, signals, ruleset, &consumed) {
            for signal in &nearby {
                consumed.insert(*signal as *const Signal);
            }
            work.push((nearby, newest.t, true));
        }
    }

    let mut incidents = Vec::new();
    for (nearby, time, is_fallback) in work {
        let findings = findings_from(&nearby, ruleset);
        if findings.is_empty() {
            continue;
        }

        let title = if is_fallback {
            nearby
                .iter()
                .find_map(|signal| crate::rules::bugcheck_headline(signal))
                .or_else(|| findings.first().map(|f| f.verdict.clone()))
                .or_else(|| {
                    nearby
                        .iter()
                        .find(|s| !s.provider.is_empty())
                        .map(|s| s.provider.clone())
                })
                .unwrap_or_else(|| "Crash incident".to_owned())
        } else {
            nearby
                .iter()
                .find_map(|signal| {
                    crate::rules::headline(signal)
                        .or_else(|| crate::rules::bugcheck_headline(signal))
                })
                .or_else(|| {
                    nearby
                        .iter()
                        .find(|s| !s.provider.is_empty())
                        .map(|s| s.provider.clone())
                })
                .unwrap_or_else(|| "Crash incident".to_owned())
        };

        incidents.push(Incident {
            title,
            time,
            findings,
            repeat_count: 1,
            first_seen: None,
        });
    }

    incidents.sort_by_key(|incident| std::cmp::Reverse(incident.time));
    if incidents.is_empty() {
        return Analysis::NoAnchor { note: None };
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
            sources
                .entry(verdict.clone())
                .or_default()
                .insert(signal.source);
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
                note: rule.note.clone(),
            });
            entry.score += rule.weight;
            if !entry.evidence.contains(&evidence) {
                entry.evidence.push(evidence);
            }
            if rule.id == "kernel_power_41" {
                // A recorded non-zero bugcheck is a real BSOD: the generic
                // "check the PSU" steps must give way to the decoded stop code.
                match crate::rules::bugcheck_code(signal) {
                    Some(code) if code != 0 => {
                        entry.next_steps = vec![crate::codes::decode(code).1.to_owned()];
                    }
                    _ => entry.next_steps = rule.next_steps.clone(),
                }
            } else if rule.id == "bugcheck_1001" && entry.next_steps.is_empty() {
                if let Some(code) = crate::rules::bugcheck_code(signal) {
                    entry
                        .next_steps
                        .push(crate::codes::decode(code).1.to_owned());
                }
            }
            if rule.id == "application_error_1000" && entry.next_steps.is_empty() {
                if let Some(raw) = signal.get("ExceptionCode") {
                    if let Some(code) = crate::codes::parse_exception_code(raw) {
                        entry
                            .next_steps
                            .push(crate::codes::decode_exception(code).1.to_owned());
                    }
                }
            }
            if rule.id == "dmp_crash" {
                if let Some(raw) = signal.get("ExceptionCode") {
                    if let Some(code) = crate::codes::parse_exception_code(raw) {
                        let advice = crate::codes::decode_exception(code).1;
                        if !entry.next_steps.iter().any(|step| step == advice) {
                            entry.next_steps.push(advice.to_owned());
                        }
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
    findings.sort_by_key(|finding| (std::cmp::Reverse(finding.score), finding.verdict.clone()));
    findings.truncate(12);
    findings
}

/// App part of a title: everything before " - ", lowercased.
fn repeated_app_key(title: &str) -> String {
    title
        .split(" - ")
        .next()
        .unwrap_or(title)
        .trim()
        .to_lowercase()
}

/// Counts repeated (app, primary verdict) crashes across the incident list
/// that is already filtered by the selected day window, without merging any
/// chronological rows. Call this after the day filter but before UI-only
/// filters (hidden apps, category, search), so the count matches the window
/// the user sees and search cannot change it.
pub fn attach_frequencies(incidents: &mut [Incident]) {
    let mut groups: HashMap<(String, String), (usize, DateTime<Local>)> = HashMap::new();
    for incident in incidents.iter() {
        let app = repeated_app_key(&incident.title);
        let verdict = incident
            .findings
            .first()
            .map(|finding| finding.verdict.clone())
            .unwrap_or_default();
        let entry = groups.entry((app, verdict)).or_insert((0, incident.time));
        entry.0 += 1;
        if incident.time < entry.1 {
            entry.1 = incident.time;
        }
    }

    for incident in incidents.iter_mut() {
        let app = repeated_app_key(&incident.title);
        let verdict = incident
            .findings
            .first()
            .map(|finding| finding.verdict.clone())
            .unwrap_or_default();
        let Some((count, earliest)) = groups.get(&(app, verdict)) else {
            continue;
        };
        incident.repeat_count = *count;
        incident.first_seen = if *count > 1 { Some(*earliest) } else { None };
    }
}
