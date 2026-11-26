use crate::model::{Analysis, Incident, SystemContext};

pub fn markdown_with_context(analysis: &Analysis, ctx: &SystemContext) -> String {
    format!(
        "{}\n{}",
        header(ctx, analysis),
        markdown_without_context(analysis)
    )
}

/// MPO and live overlays are useful only next to GPU/display/game evidence.
/// A plain service crash must not be polluted with this context.
fn has_gpu_context(analysis: &Analysis) -> bool {
    match analysis {
        Analysis::Results { incidents, .. } => incidents.iter().any(incident_has_gpu_context),
        _ => false,
    }
}

/// Same GPU/display marker set used by the report header and the UI filter.
pub fn has_gpu_context_text(text: &str) -> bool {
    let cleaned = without_system_modules(text);
    let lower = cleaned.to_ascii_lowercase();
    GPU_CONTEXT_MARKERS
        .iter()
        .any(|marker| lower.contains(marker))
}

/// Drops Windows' own DXGI/D3D DLL paths before marker matching. A plain
/// BugCheck routinely loads System32\dxgi.dll; that is not game evidence.
fn without_system_modules(text: &str) -> String {
    text.split_whitespace()
        .filter(|token| {
            let normalized = token.to_ascii_lowercase().replace('/', "\\");
            let name = normalized
                .rsplit('\\')
                .next()
                .unwrap_or("")
                .trim_end_matches(['.', ',', ';', '"', '\'']);
            let in_system_dir = normalized.contains("\\windows\\system32\\")
                || normalized.contains("\\windows\\syswow64\\");
            !(in_system_dir && crate::sources::wer::is_system_dll_name(name))
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// The single GPU/game marker set, shared by the report header and UI filter.
/// `d3d` is deliberately absent: it matches ordinary system DLL names.
pub const GPU_CONTEXT_MARKERS: &[&str] = &[
    "nvlddmkm",
    "amdkmd",
    "igfx",
    "igdkmd",
    "dxgkrnl",
    "display 4101",
    "display driver",
    "dxgi",
    "vulkan",
    "directx",
    "out of video memory",
    "tdr",
    "gpu",
    "shader",
    "livekernelevent",
    "ue_xml",
    "unity_log",
    "game_log",
    "crashcontext",
    "player.log",
    "igdlh64",
    "rtsshooks",
    "discordhook",
    "specialk",
    "reshade",
    "nvspcap",
];

/// GPU/display/game context of one incident — used by the UI filter and the
/// markdown header so the two can never disagree.
pub fn incident_has_gpu_context(inc: &Incident) -> bool {
    let mut text = inc.title.clone();
    text.push('\n');
    for finding in &inc.findings {
        text.push_str(&finding.verdict);
        text.push('\n');
        for line in &finding.evidence {
            text.push_str(line);
            text.push('\n');
        }
    }
    has_gpu_context_text(&text)
}

/// Human-readable uptime, shared by the report header and the UI header.
pub fn uptime_label(hours: u64) -> String {
    if hours >= 168 {
        format!(
            "{}d {}h (long uptime / Fast Startup?)",
            hours / 24,
            hours % 24
        )
    } else if hours >= 24 {
        format!("{}d {}h", hours / 24, hours % 24)
    } else {
        format!("{hours}h")
    }
}

/// Noisy event fields that add nothing to a pasted report. The GUI Raw Proof
/// stays untouched — only `Copy Clean Report` runs evidence through this.
const REPORT_NOISE_KEYS: &[&str] = &[
    "apptimestamp=",
    "moduletimestamp=",
    "processcreationtime=",
    "processid=",
];

pub fn clean_evidence_for_report(line: &str) -> String {
    line.split_whitespace()
        .filter(|token| {
            let lower = token.to_ascii_lowercase();
            !REPORT_NOISE_KEYS.iter().any(|key| lower.starts_with(key))
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// System Context plus exactly one incident — what `Copy Clean Report` uses.
/// Never pass the whole scan here: one report means one selected incident.
pub fn markdown_for_incident(
    ctx: &SystemContext,
    incident: &Incident,
    note: Option<&str>,
) -> String {
    let analysis = Analysis::Results {
        incidents: vec![incident.clone()],
        note: note.map(str::to_owned),
    };
    markdown_with_context(&analysis, ctx)
}

fn header(ctx: &SystemContext, analysis: &Analysis) -> String {
    let mut out = String::new();
    out.push_str("**FrameFault report** - read-only, no admin, no symbols\n\n");
    out.push_str(&format!("- System: {}\n", redact_safe(&ctx.windows)));
    out.push_str(&format!("- CPU: {}\n", redact_safe(&ctx.cpu)));
    let gpu = redact_safe(&ctx.gpu);
    let gpu = gpu.strip_prefix("GPU: ").unwrap_or(&gpu);
    let driver = redact_safe(&ctx.driver);
    let driver = driver.strip_prefix("driver: ").unwrap_or(&driver);
    out.push_str(&format!("- GPU: {gpu} | {driver}\n"));
    out.push_str(&format!(
        "- RAM: {:.1}/{:.1} GiB | Commit: {:.1}/{:.1} GiB | Pagefile: {}\n",
        ctx.ram_used_gib,
        ctx.ram_total_gib,
        ctx.commit_used_gib,
        ctx.commit_limit_gib,
        redact_safe(&ctx.pagefile)
    ));
    out.push_str(&format!("- Uptime: {}\n", uptime_label(ctx.uptime_hours)));
    if let Some(warning) = &ctx.disk_warn {
        out.push_str(&format!("- Storage warning: {}\n", redact_safe(warning)));
    }
    if has_gpu_context(analysis) {
        out.push_str(&format!("- MPO: {}\n", redact_safe(&ctx.mpo)));
        out.push_str(&format!("- HAGS: {}\n", redact_safe(&ctx.hags)));
        if let Some(note) = &ctx.tdr_note {
            out.push_str(&format!("- TDR override: {}\n", redact_safe(note)));
        }
        if !ctx.overlays_now.is_empty() {
            let overlays = ctx
                .overlays_now
                .iter()
                .map(|name| redact_safe(name))
                .collect::<Vec<_>>()
                .join(", ");
            out.push_str(&format!(
                "- Overlays running now (live state, not crash time): {overlays}\n"
            ));
        }
    }
    out.push('\n');
    out
}

fn markdown_without_context(analysis: &Analysis) -> String {
    let mut out = String::new();
    match analysis {
        Analysis::Results { incidents, note } => {
            if incidents.is_empty() {
                out.push_str("No supported rule matched - no guess was made.\n");
            }
            for (index, incident) in incidents.iter().enumerate() {
                out.push_str(&format!(
                    "## Incident {} - {} - {}\n\n",
                    index + 1,
                    incident.time.format("%Y-%m-%d %H:%M:%S"),
                    crate::redact::redact(&incident.title)
                ));
                for finding in &incident.findings {
                    out.push_str(&format!(
                        "### {} `[{} | {} source(s)]`\n\n",
                        crate::redact::redact(&finding.verdict),
                        finding.confidence,
                        finding.source_count
                    ));
                    out.push_str("Evidence chain:\n\n");
                    for line in &finding.evidence {
                        out.push_str(&format!(
                            "- `{}`\n",
                            crate::redact::redact(&clean_evidence_for_report(line))
                        ));
                    }
                    if let Some(note) = &finding.note {
                        out.push_str(&format!("\n> Note: {}\n", crate::redact::redact(note)));
                    }
                    if !finding.next_steps.is_empty() {
                        out.push_str("\nNext steps:\n\n");
                        for step in &finding.next_steps {
                            out.push_str(&format!("1. {}\n", crate::redact::redact(step)));
                        }
                    }
                    if let Some(link) = &finding.link {
                        out.push_str(&format!("\nReference: {link}\n"));
                    }
                    out.push('\n');
                }
            }
            if let Some(note) = note {
                out.push_str(&format!("> {}\n\n", crate::redact::redact(note)));
            }
        }
        Analysis::NoAnchor { note } => {
            out.push_str("No crash anchor was found. Drop a crash folder, Report.wer or CrashContext.runtime-xml.\n");
            if let Some(note) = note {
                out.push_str(&format!("> {}\n\n", crate::redact::redact(note)));
            }
        }
        Analysis::Empty => out.push_str("Nothing to analyse yet.\n"),
    }
    out.push_str(&format!(
        "---\nGenerated locally by FrameFault v{}. Read-only | 0 Admin | No Drivers.\n",
        env!("CARGO_PKG_VERSION")
    ));
    out
}

fn redact_safe(value: &str) -> String {
    crate::redact::redact(value)
}

#[cfg(test)]
mod tests {
    use chrono::Local;

    use super::*;
    use crate::model::Finding;

    fn incident(title: &str, verdict: &str) -> Incident {
        Incident {
            title: title.to_owned(),
            time: Local::now(),
            findings: vec![Finding {
                verdict: verdict.to_owned(),
                score: 1,
                confidence: "Info".to_owned(),
                source_count: 1,
                evidence: Vec::new(),
                next_steps: Vec::new(),
                link: None,
                note: None,
            }],
        }
    }

    #[test]
    fn copy_report_keeps_context_and_only_the_selected_incident() {
        let ctx = SystemContext {
            windows: "Windows Test".to_owned(),
            cpu: "CPU Test".to_owned(),
            gpu: "GPU Test".to_owned(),
            driver: "driver 1".to_owned(),
            mpo: "Enabled (default)".to_owned(),
            ..Default::default()
        };
        let mut selected = incident("Selected.exe", "selected verdict");
        selected.findings[0]
            .evidence
            .push("2026-11-25 10:00:00 | eventlog | nvlddmkm | GPUID=123".to_owned());
        let other = incident("Other.exe", "other verdict");
        let whole_scan = Analysis::Results {
            incidents: vec![selected.clone(), other],
            note: None,
        };
        assert!(markdown_with_context(&whole_scan, &ctx).contains("Other.exe"));

        let md = markdown_for_incident(&ctx, &selected, Some("scan note"));

        assert!(md.contains("**FrameFault report**"), "{md}");
        assert!(md.contains("- System: Windows Test"), "{md}");
        assert!(md.contains("- CPU: CPU Test"), "{md}");
        assert!(md.contains("- MPO: Enabled (default)"), "{md}");
        assert!(md.contains("Selected.exe"), "{md}");
        assert!(
            !md.contains("Other.exe"),
            "whole scan leaked into report: {md}"
        );
        assert_eq!(md.matches("## Incident").count(), 1, "{md}");
        assert!(md.contains("> scan note"), "{md}");
        assert!(
            md.contains(&format!(
                "Generated locally by FrameFault v{}",
                env!("CARGO_PKG_VERSION")
            )),
            "{md}"
        );
    }

    #[test]
    fn mpo_and_overlays_only_show_with_gpu_context() {
        let ctx = SystemContext {
            cpu: "CPU Test".to_owned(),
            mpo: "Enabled (default)".to_owned(),
            overlays_now: vec!["RTSSHooks64.exe".to_owned()],
            ..Default::default()
        };

        let mut plain = incident("Service.exe", "service crash");
        plain.findings[0].evidence.push(
            "2026-11-25 10:00:00 | eventlog | Application Error | AppName=Service.exe".to_owned(),
        );
        let plain_analysis = Analysis::Results {
            incidents: vec![plain],
            note: None,
        };
        let plain_md = markdown_with_context(&plain_analysis, &ctx);
        assert!(!plain_md.contains("- MPO:"), "{plain_md}");
        assert!(!plain_md.contains("Overlays running now"), "{plain_md}");

        let mut gpu = incident("Game.exe", "GPU driver timeout");
        gpu.findings[0]
            .evidence
            .push("2026-11-25 10:00:00 | game_log | D3D12 | DXGI_ERROR_DEVICE_REMOVED".to_owned());
        let gpu_analysis = Analysis::Results {
            incidents: vec![gpu],
            note: None,
        };
        let gpu_md = markdown_with_context(&gpu_analysis, &ctx);
        assert!(gpu_md.contains("- MPO: Enabled (default)"), "{gpu_md}");
        assert!(gpu_md.contains("Overlays running now"), "{gpu_md}");
        assert!(gpu_md.contains("- HAGS:"), "{gpu_md}");
        assert!(!plain_md.contains("- HAGS:"), "{plain_md}");
    }

    #[test]
    fn gpu_markers_ignore_system_dlls_and_bare_d3d() {
        let bsod = "BSOD 0x0000000A | wer | WER | \
                    LoadedModule[1]=C:\\Windows\\System32\\dxgi.dll \
                    LoadedModule[2]=C:\\Windows\\SysWOW64\\d3d12.dll";
        assert!(
            !has_gpu_context_text(bsod),
            "System32 DLLs are not GPU evidence"
        );
        assert!(!has_gpu_context_text("Direct3D d3d12.dll"));
        assert!(has_gpu_context_text(r"D:\Games\Game\dxgi.dll"));
        assert!(has_gpu_context_text("nvlddmkm GPUID=10de:1b06"));
        assert!(has_gpu_context_text("Intel igdlh64 driver timeout"));
        assert!(!has_gpu_context_text("EasyAntiCheat BEDaisy"));
        assert!(!has_gpu_context_text("Unreal Unity"));
        assert!(!has_gpu_context_text("C:\\Windows\\System32\\dxgi.dll."));
    }

    #[test]
    fn unknown_gpu_prefix_is_not_duplicated() {
        let ctx = SystemContext {
            gpu: "GPU: unknown".to_owned(),
            driver: "driver: unknown".to_owned(),
            ..Default::default()
        };
        let md = markdown_with_context(&Analysis::NoAnchor { note: None }, &ctx);
        assert!(md.contains("- GPU: unknown | unknown"), "{md}");
        assert!(!md.contains("GPU: GPU:"), "{md}");
    }

    #[test]
    fn findings_show_confidence_and_source_count() {
        let mut selected = incident("Game.exe", "GPU driver timeout");
        selected.findings[0].source_count = 3;
        let md = markdown_with_context(
            &Analysis::Results {
                incidents: vec![selected],
                note: None,
            },
            &SystemContext::default(),
        );
        assert!(md.contains("[Info | 3 source(s)]"), "{md}");
    }

    #[test]
    fn markdown_reports_clean_noise_in_every_evidence_line() {
        let mut selected = incident("Game.exe", "GPU driver timeout");
        selected.findings[0].evidence.push(
            "2026-11-25 10:00:00 | eventlog | Application Error | \
             AppName=Game.exe ProcessId=4242"
                .to_owned(),
        );
        let md = markdown_with_context(
            &Analysis::Results {
                incidents: vec![selected],
                note: None,
            },
            &SystemContext::default(),
        );
        assert!(!md.contains("ProcessId="), "{md}");
        assert!(!md.contains("4242"), "{md}");
    }

    #[test]
    fn no_anchor_keeps_the_ring_buffer_note() {
        let md = markdown_with_context(
            &Analysis::NoAnchor {
                note: Some(
                    "Event Log ring buffer: System -> 2026-11-01 10:00 | Application -> 2026-11-02 10:00. If the crash is older than this, absence of events is NOT evidence of absence."
                        .to_owned(),
                ),
            },
            &SystemContext::default(),
        );
        assert!(md.contains("No crash anchor was found"), "{md}");
        assert!(md.contains("Event Log ring buffer:"), "{md}");
    }

    #[test]
    fn clean_evidence_drops_noise_but_keeps_crash_facts() {
        let line = "2026-11-25 10:00:00 | eventlog | Application Error | \
                    AppName=Game.exe AppVersion=1.2 FaultingModuleName=nvlddmkm.sys \
                    ModuleVersion=2.0 ExceptionCode=c0000005 FaultingOffset=0x1234 \
                    AppPath=C:\\Games\\Game.exe ModulePath=C:\\Windows\\System32\\nvlddmkm.sys \
                    AppTimeStamp=12345678 ModuleTimeStamp=87654321 \
                    ProcessCreationTime=2026-11-25T09:59:00Z ProcessId=4242";
        let clean = clean_evidence_for_report(line);
        for kept in [
            "AppName=Game.exe",
            "AppVersion=1.2",
            "FaultingModuleName=nvlddmkm.sys",
            "ModuleVersion=2.0",
            "ExceptionCode=c0000005",
            "FaultingOffset=0x1234",
            "AppPath=",
            "ModulePath=",
        ] {
            assert!(clean.contains(kept), "missing {kept}: {clean}");
        }
        for noise in [
            "AppTimeStamp=",
            "ModuleTimeStamp=",
            "ProcessCreationTime=",
            "ProcessId=",
            "4242",
        ] {
            assert!(!clean.contains(noise), "noise leaked: {clean}");
        }
    }

    #[test]
    fn context_shows_uptime_storage_hags_and_tdr() {
        let ctx = SystemContext {
            cpu: "CPU Test".to_owned(),
            gpu: "GPU Test".to_owned(),
            hags: "Enabled".to_owned(),
            tdr_note: Some("TdrLevel=0 (recovery disabled!)".to_owned()),
            disk_warn: Some("Low free space on E:: 6.4 GiB free".to_owned()),
            uptime_hours: 200,
            ..Default::default()
        };
        let md = markdown_with_context(
            &Analysis::Results {
                incidents: vec![incident("Game.exe", "GPU driver timeout")],
                note: None,
            },
            &ctx,
        );
        assert!(
            md.contains("- Uptime: 8d 8h (long uptime / Fast Startup?)"),
            "{md}"
        );
        assert!(
            md.contains("- Storage warning: Low free space on E:: 6.4 GiB free"),
            "{md}"
        );
        assert!(md.contains("- HAGS: Enabled"), "{md}");
        assert!(
            md.contains("- TDR override: TdrLevel=0 (recovery disabled!)"),
            "{md}"
        );
    }

    #[test]
    fn copy_report_cleans_noisy_evidence() {
        let ctx = SystemContext {
            cpu: "CPU Test".to_owned(),
            ..Default::default()
        };
        let mut selected = incident("Game.exe", "GPU driver timeout");
        selected.findings[0].evidence.push(
            "2026-11-25 10:00:00 | eventlog | Application Error | \
             AppName=Game.exe ExceptionCode=c0000005 ProcessId=4242"
                .to_owned(),
        );
        let md = markdown_for_incident(&ctx, &selected, None);
        assert!(md.contains("AppName=Game.exe"), "{md}");
        assert!(md.contains("ExceptionCode=c0000005"), "{md}");
        assert!(!md.contains("ProcessId="), "{md}");
        assert!(!md.contains("4242"), "{md}");
    }
}
