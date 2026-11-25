use std::path::Path;

use chrono::Local;
use framefault::model::{Analysis, Signal};

fn fixtures() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

#[test]
fn utf16le_wer_is_decoded_and_modules_are_collected() {
    let signals = framefault::sources::wer::scan(&fixtures().join("Report-utf16.wer"));
    assert_eq!(signals.len(), 1, "expected one WER report");
    let signal = &signals[0];
    assert!(signal.detail.contains("LiveKernelEvent"));
    assert!(signal
        .loaded_modules
        .iter()
        .any(|p| p.to_ascii_lowercase().contains("discordhook64.dll")));
    assert!(signal
        .loaded_modules
        .iter()
        .any(|p| p.to_ascii_lowercase().contains("dxgi.dll")));
}

#[test]
fn system32_dxgi_is_not_treated_as_an_overlay() {
    let ruleset = framefault::rules::load();
    let rule = ruleset
        .rules
        .iter()
        .find(|r| r.id == "overlay_hook_in_wer")
        .unwrap();

    let mut clean = Signal::new("wer", Local::now());
    clean.provider = "WER".to_owned();
    clean.loaded_modules = vec![
        r"C:\Windows\System32\dxgi.dll".to_owned(),
        r"C:\Windows\System32\d3d12.dll".to_owned(),
    ];
    assert!(!rule.matches(&clean), "system DXGI/D3D must not trigger");

    let mut dirty = Signal::new("wer", Local::now());
    dirty.provider = "WER".to_owned();
    dirty.loaded_modules = vec![
        r"C:\Windows\System32\dxgi.dll".to_owned(),
        r"D:\Games\Game\dxgi.dll".to_owned(),
    ];
    assert!(rule.matches(&dirty), "non-system dxgi.dll is a proxy");
}

#[test]
fn ue5_lowercase_tags_and_empty_callstack_are_handled() {
    let signals = framefault::sources::ue::scan(&fixtures().join("CrashContext.runtime-xml"));
    assert_eq!(signals.len(), 1);
    let signal = &signals[0];
    assert_eq!(signal.get("bIsOOM"), Some("true"));
    assert!(signal
        .get("ErrorMessage")
        .unwrap()
        .contains("Out of video memory"));
    assert!(signal.get("CallStack").is_none());
}

#[test]
fn event_log_xml_fixture_parses_real_ids_and_decimal_bugcheck() {
    let text = std::fs::read_to_string(fixtures().join("events.txt")).unwrap();
    let signals = framefault::sources::evt::parse_text(&text, "System");
    assert_eq!(signals.len(), 5);
    assert_eq!(signals[0].provider, "nvlddmkm");
    assert_eq!(signals[0].event_id, Some(153));
    assert_eq!(signals[1].provider, "Display");
    assert_eq!(signals[1].event_id, Some(4101));
    assert_eq!(signals[2].event_id, Some(2004));
    assert_eq!(signals[3].event_id, Some(18));
    assert_eq!(signals[4].event_id, Some(41));
    assert!(signals[4].detail.contains("BugcheckCode 159"));
}

#[test]
fn correlation_produces_distinct_verdicts_without_averaging() {
    let f = fixtures();
    let mut signals: Vec<framefault::model::Signal> = framefault::sources::evt::parse_text(
        &std::fs::read_to_string(f.join("events.txt")).unwrap(),
        "System",
    );
    signals.extend(framefault::sources::wer::scan(&f.join("Report-utf16.wer")));
    signals.extend(framefault::sources::ue::scan(&f.join("CrashContext.runtime-xml")));
    signals.extend(framefault::sources::gamelog::scan(&f.join("game.log")));
    signals.extend(framefault::sources::gamelog::scan(&f.join("Player.log")));

    // Fixture mtimes and fixed Event Log timestamps differ; align for correlation.
    for signal in &mut signals {
        signal.t = Local::now();
    }

    let ruleset = framefault::rules::load();
    let nvidia_rule = ruleset.rules.iter().find(|r| r.id == "tdr_nvidia_153").unwrap();
    let event = signals
        .iter()
        .find(|s| s.source == "eventlog" && s.event_id == Some(153))
        .expect("nvlddmkm 153 signal missing");
    let earliest_anchor = signals
        .iter()
        .filter(|s| {
            s.source == "wer"
                || s.source == "ue_xml"
                || s.source == "unity_log"
                || s.source == "game_log"
        })
        .map(|s| s.t)
        .min()
        .unwrap();
    assert!(
        (event.t - earliest_anchor).num_seconds().abs() <= 15,
        "event outside window: {} vs {}",
        event.t,
        earliest_anchor
    );
    assert!(
        nvidia_rule.matches(event),
        "TDR rule did not match: provider={} channel={:?} detail={}",
        event.provider,
        event.get("channel"),
        event.detail
    );

    let analysis = framefault::correlate::run(&signals, &ruleset);
    let Analysis::Results { incidents, .. } = &analysis else {
        panic!("expected incidents, got {analysis:?}");
    };
    assert!(!incidents.is_empty());
    let verdicts: Vec<String> = incidents[0]
        .findings
        .iter()
        .map(|f| f.verdict.clone())
        .collect();
    assert!(
        verdicts.iter().any(|v| v.contains("NVIDIA GPU driver timeout")),
        "verdicts: {verdicts:#?} evidence: {:#?}",
        incidents[0]
            .findings
            .iter()
            .flat_map(|f| f.evidence.clone())
            .collect::<Vec<_>>()
    );
    assert!(verdicts.iter().any(|v| v.contains("overlay/proxy DLL")));
    assert!(verdicts.iter().any(|v| v.contains("out-of-memory")));
    assert!(verdicts.iter().any(|v| v.contains("Low virtual memory")));
}

#[test]
fn redaction_and_self_test_are_silent_about_identity() {
    let report = framefault::report::markdown(&Analysis::Results {
        incidents: vec![framefault::model::Incident {
            title: "Game.exe".to_owned(),
            time: Local::now(),
            findings: vec![framefault::model::Finding {
                verdict: "test".to_owned(),
                score: 1,
                confidence: "High".to_owned(),
                source_count: 1,
                evidence: vec![
                    "C:\\Users\\alice\\saved\\ip 192.168.1.20 sid S-1-5-21-999".to_owned(),
                ],
                next_steps: Vec::new(),
                link: None,
            }],
        }],
        note: None,
    });
    assert!(!report.contains("alice"));
    assert!(!report.contains("192.168"));
    assert!(!report.contains("S-1-5-21"));
    assert!(report.contains("FrameFault"));
    assert!(framefault::self_test().is_ok());
}

#[test]
fn confidence_single_high_source_is_not_lowered() {
    let ruleset = framefault::rules::load();
    let now = Local::now();

    let mut anchor = Signal::new("game_log", now);
    anchor.detail = "Loading level MyMap".to_owned();

    let mut bugcheck = Signal::new("eventlog", now);
    bugcheck.provider = "Microsoft-Windows-WER-SystemErrorReporting".to_owned();
    bugcheck.event_id = Some(1001);
    bugcheck
        .fields
        .insert("channel".to_owned(), "System".to_owned());

    let analysis = framefault::correlate::run(&[anchor, bugcheck], &ruleset);
    let Analysis::Results { incidents, .. } = &analysis else {
        panic!("expected incidents, got {analysis:?}");
    };
    let finding = incidents[0]
        .findings
        .iter()
        .find(|f| f.verdict.contains("BugCheck 1001"))
        .expect("bugcheck finding missing");
    assert_eq!(finding.source_count, 1);
    assert_eq!(finding.confidence, "High");
}

#[test]
fn confidence_two_medium_sources_are_raised_to_high() {
    let ruleset = framefault::rules::load();
    let now = Local::now();

    let mut wer = Signal::new("wer", now);
    wer.provider = "WER".to_owned();
    wer.loaded_modules = vec![r"D:\Games\MyGame\EasyAntiCheat_EOS.sys".to_owned()];

    let mut log = Signal::new("game_log", now);
    log.detail = "BEDaisy.sys crashed".to_owned();

    let analysis = framefault::correlate::run(&[wer, log], &ruleset);
    let Analysis::Results { incidents, .. } = &analysis else {
        panic!("expected incidents, got {analysis:?}");
    };
    let finding = incidents[0]
        .findings
        .iter()
        .find(|f| f.verdict.starts_with("Anti-cheat driver crash"))
        .expect("anti-cheat finding missing");
    assert_eq!(finding.source_count, 2);
    assert_eq!(finding.confidence, "High");
}

#[test]
fn confidence_single_medium_source_stays_medium() {
    let ruleset = framefault::rules::load();
    let now = Local::now();

    let mut log = Signal::new("game_log", now);
    log.detail = "BEDaisy.sys crashed".to_owned();

    let analysis = framefault::correlate::run(&[log], &ruleset);
    let Analysis::Results { incidents, .. } = &analysis else {
        panic!("expected incidents, got {analysis:?}");
    };
    let finding = incidents[0]
        .findings
        .iter()
        .find(|f| f.verdict.starts_with("Anti-cheat driver crash"))
        .expect("anti-cheat finding missing");
    assert_eq!(finding.source_count, 1);
    assert_eq!(finding.confidence, "Medium");
}

#[test]
fn kernel_power_41_verdict_depends_on_bugcheck_code() {
    let ruleset = framefault::rules::load();
    let rule = ruleset
        .rules
        .iter()
        .find(|r| r.id == "kernel_power_41")
        .expect("kernel_power_41 rule missing");
    let now = Local::now();

    let mut with_code = Signal::new("eventlog", now);
    with_code.provider = "Microsoft-Windows-Kernel-Power".to_owned();
    with_code.event_id = Some(41);
    with_code
        .fields
        .insert("channel".to_owned(), "System".to_owned());
    with_code.detail = "BugcheckCode 159".to_owned();
    assert!(rule.matches(&with_code));
    let verdict = rule.verdict_for(&with_code);
    assert!(verdict.contains("0x0000009F"), "verdict: {verdict}");

    let mut zero = with_code.clone();
    zero.detail = "BugcheckCode 0".to_owned();
    assert!(rule.matches(&zero));
    let verdict = rule.verdict_for(&zero);
    assert!(
        verdict.starts_with("Sudden power loss"),
        "verdict: {verdict}"
    );

    let mut absent = with_code.clone();
    absent.detail = "The system has rebooted without cleanly shutting down first.".to_owned();
    let verdict = rule.verdict_for(&absent);
    assert!(
        verdict.starts_with("Sudden power loss"),
        "verdict: {verdict}"
    );
}

