use std::path::Path;

use chrono::{Duration, Local};
use framefault::model::{Analysis, Signal, SystemContext};

fn fixtures() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

#[test]
fn analyze_with_context_uses_the_timestamp_from_the_report() {
    let analysis = framefault::analyze_with_context(
        &fixtures().join("Report-timed.wer"),
        &SystemContext::default(),
    );
    let Analysis::Results { incidents, .. } = &analysis else {
        panic!("expected incidents, got {analysis:?}");
    };

    // The time must come from ReportCreateTimeStamp in the file, not mtime
    // and not Local::now() — even if live WER reports add other incidents.
    let incident = incidents
        .iter()
        .find(|incident| {
            incident
                .findings
                .iter()
                .flat_map(|finding| &finding.evidence)
                .any(|line| line.contains("2026-11-20 10:11:12"))
        })
        .expect("timed WER incident missing");
    assert_eq!(
        incident.time.format("%Y-%m-%d %H:%M:%S").to_string(),
        "2026-11-20 10:11:12"
    );
    assert!(
        incident
            .findings
            .iter()
            .any(|finding| finding.verdict.contains("LiveKernelEvent 141")),
        "findings: {:?}",
        incident.findings
    );
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
fn utf8_report_wer_fixture_is_parsed_without_system_module_noise() {
    let signals = framefault::sources::wer::scan(&fixtures().join("Report.wer"));
    assert_eq!(
        signals.len(),
        1,
        "UTF-8 Report.wer fixture must be readable"
    );
    let signal = &signals[0];
    assert_eq!(signal.provider, "WER");
    assert_eq!(signal.fields.get("Version").map(String::as_str), Some("1"));
    assert!(signal.detail.contains("EventType=ApplicationCrash"));
    assert!(signal.detail.contains("AppVersion=1.41.0"));
    assert!(signal
        .loaded_modules
        .iter()
        .any(|path| path.to_ascii_lowercase().contains(r"\system32\dxgi.dll")));
    assert!(
        !signal.detail.to_ascii_lowercase().contains("dxgi.dll"),
        "system module leaked into evidence: {}",
        signal.detail
    );
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

    let mut other_drive = Signal::new("wer", Local::now());
    other_drive.provider = "WER".to_owned();
    other_drive.loaded_modules = vec![r"D:\Windows\System32\dxgi.dll".to_owned()];
    assert!(
        !rule.matches(&other_drive),
        "System32 on D: is still Windows, not an overlay"
    );
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
fn ue_identity_tags_never_reach_detail() {
    let signals = framefault::sources::ue::scan(&fixtures().join("CrashContext.runtime-xml"));
    assert_eq!(signals.len(), 1);
    let detail = signals[0].detail.to_ascii_lowercase();
    assert!(
        !detail.contains("epicaccountid"),
        "detail: {}",
        signals[0].detail
    );
    assert!(!detail.contains("7656119"), "detail: {}", signals[0].detail);
    assert!(
        detail.contains("errormessage="),
        "detail: {}",
        signals[0].detail
    );
}

#[test]
fn ue_is_ensure_without_bisoom_is_not_oom() {
    let ruleset = framefault::rules::load();
    let now = Local::now();

    let mut ue = Signal::new("ue_xml", now);
    ue.provider = "TestGame".to_owned();
    ue.fields.insert("IsEnsure".to_owned(), "true".to_owned());
    ue.detail = "isensure=true\n".to_owned();

    let oom = ruleset
        .rules
        .iter()
        .find(|rule| rule.id == "ue_oom_flag")
        .expect("ue_oom_flag rule missing");
    assert!(
        !oom.matches(&ue),
        "missing bIsOOM must not fall back to detail"
    );

    let analysis = framefault::correlate::run(&[ue], &ruleset);
    let has_oom = match &analysis {
        Analysis::Results { incidents, .. } => incidents
            .iter()
            .flat_map(|i| &i.findings)
            .any(|f| f.verdict.contains("out-of-memory") || f.verdict.contains("out of memory")),
        _ => false,
    };
    assert!(!has_oom, "unexpected OOM verdict: {analysis:#?}");
}

#[test]
fn non_utf8_game_log_still_finds_markers() {
    let signals = framefault::sources::gamelog::scan(&fixtures().join("Player-invalid.log"));
    assert_eq!(signals.len(), 1);
    assert!(signals[0].detail.contains("DXGI_ERROR_DEVICE_HUNG"));
}

#[test]
fn unity_player_log_dxgi_error_produces_a_verdict() {
    let ruleset = framefault::rules::load();
    let signals = framefault::sources::gamelog::scan(&fixtures().join("Player.log"));
    assert_eq!(signals.len(), 1);
    let signal = &signals[0];
    assert_eq!(signal.source, "unity_log");
    assert!(signal.detail.contains("DXGI_ERROR_DEVICE_HUNG"));

    let rule = ruleset
        .rules
        .iter()
        .find(|r| r.id == "dxgi_device_hung")
        .expect("dxgi_device_hung rule missing");
    assert!(
        rule.matches(signal),
        "unity_log must be accepted via source_any"
    );

    let analysis = framefault::correlate::run(&signals, &ruleset);
    let Analysis::Results { incidents, .. } = &analysis else {
        panic!("expected incidents, got {analysis:?}");
    };
    assert!(
        incidents[0]
            .findings
            .iter()
            .any(|finding| finding.verdict.contains("lost the D3D device")),
        "DXGI verdict missing: {:?}",
        incidents[0].findings
    );
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
    signals.extend(framefault::sources::ue::scan(
        &f.join("CrashContext.runtime-xml"),
    ));
    signals.extend(framefault::sources::gamelog::scan(&f.join("game.log")));
    signals.extend(framefault::sources::gamelog::scan(&f.join("Player.log")));

    // Fixture mtimes and fixed Event Log timestamps differ; align for correlation.
    for signal in &mut signals {
        signal.t = Local::now();
    }

    let ruleset = framefault::rules::load();
    let nvidia_rule = ruleset
        .rules
        .iter()
        .find(|r| r.id == "tdr_nvidia_153")
        .unwrap();
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
        verdicts
            .iter()
            .any(|v| v.contains("NVIDIA GPU driver timeout")),
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
    let report = framefault::report::markdown_with_context(
        &Analysis::Results {
            incidents: vec![framefault::model::Incident {
                title: "Game.exe".to_owned(),
                time: Local::now(),
                findings: vec![framefault::model::Finding {
                    verdict: "test".to_owned(),
                    score: 1,
                    confidence: "High".to_owned(),
                    source_count: 1,
                    evidence: vec![
                        "C:\\Users\\alice\\saved\\ip 192.168.1.20 sid S-1-5-21-999".to_owned()
                    ],
                    next_steps: Vec::new(),
                    link: None,
                    note: None,
                }],
                repeat_count: 1,
                first_seen: None,
            }],
            note: None,
        },
        &SystemContext::default(),
    );
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

#[test]
fn event_1000_bare_exception_code_gets_next_steps() {
    let ruleset = framefault::rules::load();
    let now = Local::now();

    let mut app_error = Signal::new("eventlog", now);
    app_error.provider = "Application Error".to_owned();
    app_error.event_id = Some(1000);
    app_error
        .fields
        .insert("channel".to_owned(), "Application".to_owned());
    app_error
        .fields
        .insert("FaultingApplicationName".to_owned(), "Game.exe".to_owned());
    app_error
        .fields
        .insert("FaultingModuleName".to_owned(), "Game.dll".to_owned());
    app_error
        .fields
        .insert("ExceptionCode".to_owned(), "e06d7363".to_owned());
    app_error.detail = "Faulting application name: Game.exe".to_owned();

    let rule = ruleset
        .rules
        .iter()
        .find(|r| r.id == "application_error_1000")
        .expect("application_error_1000 rule missing");
    assert!(rule.matches(&app_error), "Event 1000 rule did not match");

    let analysis = framefault::correlate::run(&[app_error], &ruleset);
    let Analysis::Results { incidents, .. } = &analysis else {
        panic!("expected incidents, got {analysis:?}");
    };
    assert_eq!(incidents.len(), 1);
    let finding = incidents[0]
        .findings
        .iter()
        .find(|f| f.verdict.contains("CPP_EH_EXCEPTION"))
        .expect("Event 1000 finding missing");
    assert!(
        finding
            .next_steps
            .iter()
            .any(|step| step.contains("Unhandled C++ exception")),
        "next_steps: {:?}",
        finding.next_steps
    );
}

#[test]
fn anchor_group_includes_signals_near_any_anchor() {
    let ruleset = framefault::rules::load();
    let now = Local::now();

    // Two anchors 20s apart form one group (window_sec * 2 = 30s).
    let first = Signal::new("game_log", now);
    let second = Signal::new("game_log", now + Duration::seconds(20));
    // 35s from the first anchor but only 15s from the second: the old
    // first-anchor-only window dropped it into a duplicate incident.
    let mut late = Signal::new("eventlog", now + Duration::seconds(35));
    late.provider = "nvlddmkm".to_owned();
    late.event_id = Some(153);
    late.fields
        .insert("channel".to_owned(), "System".to_owned());
    late.detail = "GPUID 10de:1b06".to_owned();

    let analysis = framefault::correlate::run(&[first, second, late], &ruleset);
    let Analysis::Results { incidents, .. } = &analysis else {
        panic!("expected incidents, got {analysis:?}");
    };
    assert_eq!(
        incidents.len(),
        1,
        "late neighbour must join the existing group: {incidents:#?}"
    );
    assert!(
        incidents[0]
            .findings
            .iter()
            .any(|finding| finding.verdict.contains("NVIDIA GPU driver timeout")),
        "TDR verdict missing: {:?}",
        incidents[0].findings
    );
}

#[test]
fn overlapping_anchor_groups_do_not_duplicate_signals() {
    let ruleset = framefault::rules::load();
    let now = Local::now();

    // 0s and 29s form the first primary group (window = 30s). The WER at 44s
    // is within that group's expanded upper bound and must be consumed there.
    let first = Signal::new("game_log", now);
    let second = Signal::new("game_log", now + Duration::seconds(29));
    let mut wer = Signal::new("wer", now + Duration::seconds(44));
    wer.provider = "WER".to_owned();
    wer.loaded_modules = vec![r"D:\Games\Game\RTSSHooks64.dll".to_owned()];

    let mut tdr = Signal::new("eventlog", now + Duration::seconds(40));
    tdr.provider = "nvlddmkm".to_owned();
    tdr.event_id = Some(153);
    tdr.fields.insert("channel".to_owned(), "System".to_owned());
    tdr.detail = "GPUID 10de:1b06".to_owned();

    let analysis = framefault::correlate::run(&[first, second, wer, tdr], &ruleset);
    let Analysis::Results { incidents, .. } = &analysis else {
        panic!("expected incidents, got {analysis:?}");
    };
    assert_eq!(
        incidents.len(),
        1,
        "overlapping groups must not create a second incident: {incidents:#?}"
    );
    assert_eq!(
        incidents[0]
            .findings
            .iter()
            .filter(|finding| finding.verdict.contains("overlay/proxy DLL"))
            .count(),
        1,
        "the WER signal was duplicated: {:?}",
        incidents[0].findings
    );
    assert_eq!(
        incidents[0].time,
        now + Duration::seconds(29),
        "incident time must be the newest anchor of the group"
    );
}

#[test]
fn equal_score_findings_have_a_stable_order() {
    let ruleset = framefault::rules::load();
    let now = Local::now();

    let mut whea = Signal::new("eventlog", now);
    whea.provider = "Microsoft-Windows-WHEA-Logger".to_owned();
    whea.event_id = Some(18);
    whea.fields
        .insert("channel".to_owned(), "System".to_owned());
    whea.detail = "A fatal hardware error has occurred.".to_owned();

    let mut commit = Signal::new("eventlog", now);
    commit.provider = "Microsoft-Windows-Resource-Exhaustion-Detector".to_owned();
    commit.event_id = Some(2004);
    commit
        .fields
        .insert("channel".to_owned(), "System".to_owned());
    commit.detail = "Windows diagnosed a low virtual memory condition.".to_owned();

    let analysis = framefault::correlate::run(&[whea, commit], &ruleset);
    let Analysis::Results { incidents, .. } = &analysis else {
        panic!("expected incidents, got {analysis:?}");
    };
    let verdicts: Vec<&str> = incidents[0]
        .findings
        .iter()
        .map(|finding| finding.verdict.as_str())
        .collect();
    assert_eq!(verdicts.len(), 2, "{verdicts:#?}");
    assert!(
        verdicts[0].starts_with("Hardware / PCIe") && verdicts[1].starts_with("Low virtual memory"),
        "equal scores must sort by verdict: {verdicts:#?}"
    );
}

#[test]
fn critical_system_events_without_primary_anchor_make_an_incident() {
    let ruleset = framefault::rules::load();
    let now = Local::now();

    let mut nvidia = Signal::new("eventlog", now);
    nvidia.provider = "nvlddmkm".to_owned();
    nvidia.event_id = Some(153);
    nvidia
        .fields
        .insert("channel".to_owned(), "System".to_owned());
    nvidia.detail = "GPUID 10de:1b06".to_owned();

    let mut display = Signal::new("eventlog", now);
    display.provider = "Display".to_owned();
    display.event_id = Some(4101);
    display
        .fields
        .insert("channel".to_owned(), "System".to_owned());

    let analysis = framefault::correlate::run(&[nvidia, display], &ruleset);
    let Analysis::Results { incidents, .. } = &analysis else {
        panic!("expected incidents, got {analysis:?}");
    };
    assert_eq!(incidents.len(), 1, "TDR events must not be hidden");
    assert!(
        incidents[0]
            .findings
            .iter()
            .any(|f| f.verdict.contains("NVIDIA GPU driver timeout")),
        "TDR verdict missing: {:?}",
        incidents[0].findings
    );
}

#[test]
fn live_kernel_141_needs_an_explicit_live_kernel_code() {
    let ruleset = framefault::rules::load();
    let rule = ruleset
        .rules
        .iter()
        .find(|r| r.id == "live_kernel_141")
        .expect("live_kernel_141 rule missing");

    // An ApplicationCrash report with 1.41.0 and \141\ in a path is not a
    // LiveKernelEvent, even though it contains "141" twice.
    let plain = framefault::sources::wer::scan(&fixtures().join("Report.wer"));
    assert_eq!(plain.len(), 1);
    let plain = &plain[0];
    assert!(plain.detail.contains("1.41.0"));
    assert!(plain.detail.contains(r"\141\"));
    assert_eq!(plain.get("LiveKernelCode"), None);
    assert!(!rule.matches(plain), "loose 141 must not trigger VIDEO_TDR");

    // A real LiveKernelEvent with Code=141 does.
    let live = framefault::sources::wer::scan(&fixtures().join("Report-utf16.wer"));
    assert_eq!(live.len(), 1);
    let live = &live[0];
    assert_eq!(live.get("LiveKernelCode"), Some("141"));
    assert!(
        rule.matches(live),
        "explicit LiveKernelEvent 141 must match"
    );
}

#[test]
fn kernel_power_41_prefers_bugcheck_code_over_parameter() {
    let ruleset = framefault::rules::load();
    let now = Local::now();

    let mut event = Signal::new("eventlog", now);
    event.provider = "Microsoft-Windows-Kernel-Power".to_owned();
    event.event_id = Some(41);
    event
        .fields
        .insert("channel".to_owned(), "System".to_owned());
    event
        .fields
        .insert("BugcheckCode".to_owned(), "59".to_owned());
    event.detail = "BugcheckCode=59\nBugcheckParameter1=0xc0000005\n".to_owned();

    let analysis = framefault::correlate::run(&[event], &ruleset);
    let Analysis::Results { incidents, .. } = &analysis else {
        panic!("expected incidents, got {analysis:?}");
    };
    let finding = incidents[0]
        .findings
        .iter()
        .find(|finding| finding.verdict.contains("BSOD 0x0000003B"))
        .unwrap_or_else(|| panic!("wrong bugcheck verdict: {:#?}", incidents[0].findings));
    assert!(
        !finding.verdict.contains("C0000005"),
        "parameter won over BugcheckCode: {}",
        finding.verdict
    );
    assert!(
        finding
            .next_steps
            .iter()
            .any(|step| step.contains("System call fault")),
        "wrong next steps: {:?}",
        finding.next_steps
    );
}

#[test]
fn kernel_power_41_next_steps_follow_the_recorded_bugcheck() {
    let ruleset = framefault::rules::load();
    let now = Local::now();

    let signal = |detail: &str| {
        let mut event = Signal::new("eventlog", now);
        event.provider = "Microsoft-Windows-Kernel-Power".to_owned();
        event.event_id = Some(41);
        event
            .fields
            .insert("channel".to_owned(), "System".to_owned());
        event.detail = detail.to_owned();
        event
    };

    let with_bsod = framefault::correlate::run(&[signal("BugcheckCode 159")], &ruleset);
    let Analysis::Results { incidents, .. } = &with_bsod else {
        panic!("expected incidents, got {with_bsod:?}");
    };
    let finding = &incidents[0].findings[0];
    assert!(
        finding
            .next_steps
            .iter()
            .any(|step| step.contains("Driver failed a power transition")),
        "BSOD advice missing: {:?}",
        finding.next_steps
    );
    assert!(
        !finding
            .next_steps
            .iter()
            .any(|step| step.contains("Check temperatures and PSU under load")),
        "generic power steps leaked into a BSOD: {:?}",
        finding.next_steps
    );

    let plain_power = framefault::correlate::run(&[signal("BugcheckCode 0")], &ruleset);
    let Analysis::Results { incidents, .. } = &plain_power else {
        panic!("expected incidents, got {plain_power:?}");
    };
    let finding = &incidents[0].findings[0];
    assert!(
        finding
            .next_steps
            .iter()
            .any(|step| step.contains("Check temperatures and PSU under load")),
        "power steps missing: {:?}",
        finding.next_steps
    );
    assert!(
        !finding
            .next_steps
            .iter()
            .any(|step| step.contains("Driver failed a power transition")),
        "BSOD advice leaked into a plain power loss: {:?}",
        finding.next_steps
    );
}

#[test]
fn system32_dxgi_in_wer_does_not_make_a_bsod_a_gpu_incident() {
    let ruleset = framefault::rules::load();
    let now = Local::now();

    let mut bugcheck = Signal::new("eventlog", now);
    bugcheck.provider = "Microsoft-Windows-WER-SystemErrorReporting".to_owned();
    bugcheck.event_id = Some(1001);
    bugcheck
        .fields
        .insert("channel".to_owned(), "System".to_owned());
    bugcheck.detail = "The Bug Check was: 0x0000000A (0xffff)".to_owned();

    let mut wer = framefault::sources::wer::scan(&fixtures().join("Report.wer"));
    assert_eq!(wer.len(), 1);
    assert!(wer[0]
        .loaded_modules
        .iter()
        .any(|path| path.to_ascii_lowercase().contains(r"\system32\dxgi.dll")));
    assert!(
        !wer[0].detail.to_ascii_lowercase().contains("dxgi.dll"),
        "system module leaked into evidence: {}",
        wer[0].detail
    );
    wer[0].t = now;

    let mut signals = vec![bugcheck];
    signals.extend(wer);
    let analysis = framefault::correlate::run(&signals, &ruleset);
    let Analysis::Results { incidents, .. } = &analysis else {
        panic!("expected incidents, got {analysis:?}");
    };
    assert!(!incidents.is_empty());
    for incident in incidents {
        assert!(
            incident
                .findings
                .iter()
                .any(|finding| finding.verdict.contains("BugCheck 1001")
                    || finding.verdict.contains("0x0000000A")),
            "bugcheck finding missing: {incident:#?}"
        );
        assert!(
            !framefault::report::incident_has_gpu_context(incident),
            "plain BSOD was classified as GPU/game: {incident:#?}"
        );
    }
    assert!(
        !framefault::report::GPU_CONTEXT_MARKERS.contains(&"d3d"),
        "bare d3d marker must stay out of the shared list"
    );
}

#[test]
fn verdict_and_next_steps_are_redacted_in_report() {
    let incident = framefault::model::Incident {
        title: "Game.exe".to_owned(),
        time: Local::now(),
        findings: vec![framefault::model::Finding {
            verdict: "Game.exe in C:\\Users\\alice\\Game.exe - 0xc0000005".to_owned(),
            score: 1,
            confidence: "High".to_owned(),
            source_count: 1,
            evidence: Vec::new(),
            next_steps: vec!["Remove C:\\Users\\alice\\overlay.dll".to_owned()],
            link: None,
            note: Some("Historical evidence from C:\\Users\\alice\\Report.wer".to_owned()),
        }],
        repeat_count: 1,
        first_seen: None,
    };
    let report =
        framefault::report::markdown_for_incident(&SystemContext::default(), &incident, None);
    assert!(!report.contains("alice"), "unredacted PII: {report}");
    assert!(report.contains("C:\\Users\\%USERPROFILE%"), "{report}");
    assert!(
        report.contains("> Note: Historical evidence from"),
        "rule note missing from report: {report}"
    );
}

#[test]
fn rule_note_reaches_the_finding() {
    let ruleset = framefault::rules::load();
    let now = Local::now();

    let mut wer = Signal::new("wer", now);
    wer.provider = "WER".to_owned();
    wer.loaded_modules = vec![r"D:\Games\Game\RTSSHooks64.dll".to_owned()];

    let analysis = framefault::correlate::run(&[wer], &ruleset);
    let Analysis::Results { incidents, .. } = &analysis else {
        panic!("expected incidents, got {analysis:?}");
    };
    let finding = incidents[0]
        .findings
        .iter()
        .find(|f| f.verdict.contains("overlay/proxy DLL"))
        .expect("overlay finding missing");
    assert_eq!(
        finding.note.as_deref(),
        Some("Historical evidence from Report.wer. System32/SysWOW64 DXGI/D3D DLLs are ignored.")
    );
}

#[test]
fn standalone_bugcheck_1001_makes_a_decoded_incident() {
    let ruleset = framefault::rules::load();
    let now = Local::now();

    let mut bugcheck = Signal::new("eventlog", now);
    bugcheck.provider = "Microsoft-Windows-WER-SystemErrorReporting".to_owned();
    bugcheck.event_id = Some(1001);
    bugcheck
        .fields
        .insert("channel".to_owned(), "System".to_owned());
    bugcheck.detail = "The Bug Check was: 0x00000116 (0xffff)".to_owned();

    let analysis = framefault::correlate::run(&[bugcheck], &ruleset);
    let Analysis::Results { incidents, .. } = &analysis else {
        panic!("expected incidents, got {analysis:?}");
    };
    assert_eq!(incidents.len(), 1);
    assert!(
        incidents[0].title.contains("BSOD 0x00000116"),
        "title: {}",
        incidents[0].title
    );
    assert!(
        incidents[0]
            .findings
            .iter()
            .any(|f| f.verdict.contains("VIDEO_TDR_FAILURE")),
        "findings: {:?}",
        incidents[0].findings
    );
}

fn incident_at(
    title: &str,
    verdict: &str,
    time: chrono::DateTime<Local>,
) -> framefault::model::Incident {
    framefault::model::Incident {
        title: title.to_owned(),
        time,
        findings: vec![framefault::model::Finding {
            verdict: verdict.to_owned(),
            score: 1,
            confidence: "Info".to_owned(),
            source_count: 1,
            evidence: Vec::new(),
            next_steps: Vec::new(),
            link: None,
            note: None,
        }],
        repeat_count: 1,
        first_seen: None,
    }
}

#[test]
fn frequencies_count_repeats_without_merging_the_chronological_rows() {
    let now = Local::now();
    let earliest = now - Duration::days(6);
    let middle = now - Duration::days(2);

    let mut incidents = vec![
        incident_at("Game.exe - Crash in level 3", "GPU driver timeout", now),
        incident_at(
            "Game.exe - Crash in level 1",
            "GPU driver timeout",
            earliest,
        ),
        incident_at("Game.exe - Crash in level 2", "GPU driver timeout", middle),
        incident_at("Other.exe - Crash", "CPU fault", now),
    ];

    framefault::correlate::attach_frequencies(&mut incidents);

    assert_eq!(incidents.len(), 4, "rows must never be merged");
    for repeated in &incidents[..3] {
        assert_eq!(repeated.repeat_count, 3, "{repeated:#?}");
        assert_eq!(repeated.first_seen, Some(earliest), "{repeated:#?}");
    }
    assert_eq!(incidents[3].repeat_count, 1);
    assert_eq!(incidents[3].first_seen, None);

    // Same app, different primary verdict: each verdict is its own one-off.
    let mut mismatched = vec![
        incident_at("Game.exe - Crash A", "GPU driver timeout", now),
        incident_at("Game.exe - Crash B", "CPU fault", now),
    ];
    framefault::correlate::attach_frequencies(&mut mismatched);
    for incident in &mismatched {
        assert_eq!(
            incident.repeat_count, 1,
            "a different primary verdict must not merge: {incident:#?}"
        );
        assert_eq!(incident.first_seen, None, "{incident:#?}");
    }
}

fn mdmp_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn mdmp_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn mdmp_name(out: &mut Vec<u8>, value: &str) {
    let units: Vec<u16> = value.encode_utf16().collect();
    mdmp_u32(out, (units.len() * 2) as u32);
    for unit in units {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    out.extend_from_slice(&0u16.to_le_bytes());
}

fn mdmp_module(out: &mut Vec<u8>, base: u64, size: u32, name_rva: u32) {
    mdmp_u64(out, base);
    mdmp_u32(out, size);
    mdmp_u32(out, 0); // checksum
    mdmp_u32(out, 0); // PE timestamp
    mdmp_u32(out, name_rva);
    out.extend_from_slice(&[0u8; 52]); // VS_FIXEDFILEINFO
    mdmp_u32(out, 0);
    mdmp_u32(out, 0); // CV record
    mdmp_u32(out, 0);
    mdmp_u32(out, 0); // misc record
    out.extend_from_slice(&[0u8; 8]);
    out.extend_from_slice(&[0u8; 8]);
}

/// Minimal user-mode MDMP with one exception stream and two modules.
fn mdmp_bytes() -> Vec<u8> {
    const HEADER: usize = 32;
    const DIRECTORY: usize = 24;
    const EXCEPTION: usize = HEADER + DIRECTORY;
    const EXCEPTION_SIZE: usize = 168;
    const MODULES: usize = EXCEPTION + EXCEPTION_SIZE;
    const MODULE_SIZE: usize = 108;
    const MODULE_LIST_SIZE: usize = 4 + 2 * MODULE_SIZE;
    const NAME1: usize = MODULES + MODULE_LIST_SIZE;

    let game = r"C:\Games\Game\Game.dll";
    let system = r"C:\Windows\System32\kernel32.dll";
    let name1_size = 4 + game.encode_utf16().count() * 2 + 2;
    let name2 = NAME1 + name1_size;

    let mut out = Vec::new();
    mdmp_u32(&mut out, 0x504D_444D);
    mdmp_u32(&mut out, 0x0000_A793);
    mdmp_u32(&mut out, 2);
    mdmp_u32(&mut out, HEADER as u32);
    mdmp_u32(&mut out, 0);
    mdmp_u32(&mut out, 1_765_000_000);
    mdmp_u64(&mut out, 0);

    mdmp_u32(&mut out, 6);
    mdmp_u32(&mut out, EXCEPTION_SIZE as u32);
    mdmp_u32(&mut out, EXCEPTION as u32);
    mdmp_u32(&mut out, 4);
    mdmp_u32(&mut out, MODULE_LIST_SIZE as u32);
    mdmp_u32(&mut out, MODULES as u32);

    mdmp_u32(&mut out, 1); // thread
    mdmp_u32(&mut out, 0);
    mdmp_u32(&mut out, 0xC000_0005); // exception code
    mdmp_u32(&mut out, 0);
    mdmp_u64(&mut out, 0);
    mdmp_u64(&mut out, 0x1000_1234); // crash address inside Game.dll
    mdmp_u32(&mut out, 2);
    mdmp_u32(&mut out, 0);
    for _ in 0..15 {
        mdmp_u64(&mut out, 0);
    }
    mdmp_u32(&mut out, 0);
    mdmp_u32(&mut out, 0); // thread context

    mdmp_u32(&mut out, 2); // module count
    mdmp_module(&mut out, 0x1000_0000, 0x1_0000, NAME1 as u32);
    mdmp_module(&mut out, 0x2000_0000, 0x2_0000, name2 as u32);
    mdmp_name(&mut out, game);
    mdmp_name(&mut out, system);
    out
}

#[test]
fn user_mode_minidump_produces_a_decoded_incident() {
    let unique = format!(
        "framefault-mdmp-{}-{}.dmp",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(unique);
    std::fs::write(&path, mdmp_bytes()).expect("write synthetic minidump");

    let signals = framefault::sources::dmp::scan(&path);
    let _ = std::fs::remove_file(&path);

    assert_eq!(signals.len(), 1, "explicit dump must produce one signal");
    assert_eq!(signals[0].source, "dmp");
    assert_eq!(signals[0].get("ExceptionCode"), Some("0xC0000005"));
    assert_eq!(signals[0].get("FaultingModule"), Some("Game.dll"));
    assert!(
        signals[0]
            .loaded_modules
            .iter()
            .all(|path| !path.to_ascii_lowercase().contains(r"\windows\system32\")),
        "system modules must stay out of loaded_modules: {:?}",
        signals[0].loaded_modules
    );

    let ruleset = framefault::rules::load();
    let analysis = framefault::correlate::run(&signals, &ruleset);
    let Analysis::Results { incidents, .. } = &analysis else {
        panic!("expected incidents, got {analysis:?}");
    };
    let finding = incidents[0]
        .findings
        .iter()
        .find(|finding| finding.verdict.contains("ACCESS_VIOLATION"))
        .unwrap_or_else(|| panic!("decoded dmp verdict missing: {:#?}", incidents[0]));
    assert!(
        finding.verdict.contains("Game.dll"),
        "{:?}",
        finding.verdict
    );
    assert!(
        finding
            .next_steps
            .iter()
            .any(|step| step.contains("Invalid memory access")),
        "decoded exception advice missing: {:?}",
        finding.next_steps
    );
    assert_eq!(incidents[0].time, signals[0].t);
}
