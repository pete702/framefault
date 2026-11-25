use crate::model::{Analysis, Incident, SystemContext};

pub fn markdown(analysis: &Analysis) -> String {
    let ctx = crate::context();
    format!(
        "{}\n{}",
        header(&ctx, analysis),
        markdown_without_context(analysis)
    )
}

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
    let mut text = String::new();
    if let Analysis::Results { incidents, .. } = analysis {
        for incident in incidents {
            text.push_str(&incident.title);
            text.push('\n');
            for finding in &incident.findings {
                text.push_str(&finding.verdict);
                text.push('\n');
                for line in &finding.evidence {
                    text.push_str(line);
                    text.push('\n');
                }
            }
        }
    }
    let lower = text.to_ascii_lowercase();
    const MARKERS: &[&str] = &[
        "nvlddmkm",
        "amdkmd",
        "igfx",
        "igdkmd",
        "display",
        "dxgkrnl",
        "d3d",
        "dxgi",
        "vulkan",
        "directx",
        "out of video memory",
        "tdr",
        "gpu",
        "shader",
        "game_log",
        "ue_xml",
        "unity_log",
        "unreal",
        "unity",
    ];
    MARKERS.iter().any(|marker| lower.contains(marker))
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
    out.push_str(&format!("- GPU: {} | {}\n", redact_safe(&ctx.gpu), redact_safe(&ctx.driver)));
    out.push_str(&format!(
        "- RAM: {:.1}/{:.1} GiB | Commit: {:.1}/{:.1} GiB | Pagefile: {}\n",
        ctx.ram_used_gib,
        ctx.ram_total_gib,
        ctx.commit_used_gib,
        ctx.commit_limit_gib,
        redact_safe(&ctx.pagefile)
    ));
    if has_gpu_context(analysis) {
        out.push_str(&format!("- MPO: {}\n", ctx.mpo));
        if !ctx.overlays_now.is_empty() {
            out.push_str(&format!(
                "- Overlays running now (live state, not crash time): {}\n",
                ctx.overlays_now.join(", ")
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
                    out.push_str(&format!("### {} `[{}]`\n\n", finding.verdict, finding.confidence));
                    out.push_str("Evidence chain:\n\n");
                    for line in &finding.evidence {
                        out.push_str(&format!("- `{}`\n", crate::redact::redact(line)));
                    }
                    if !finding.next_steps.is_empty() {
                        out.push_str("\nNext steps:\n\n");
                        for step in &finding.next_steps {
                            out.push_str(&format!("1. {step}\n"));
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
        Analysis::NoAnchor => {
            out.push_str("No crash anchor was found. Drop a crash folder, Report.wer or CrashContext.runtime-xml.\n")
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
        assert!(!md.contains("Other.exe"), "whole scan leaked into report: {md}");
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
        gpu.findings[0].evidence.push(
            "2026-11-25 10:00:00 | game_log | D3D12 | DXGI_ERROR_DEVICE_REMOVED".to_owned(),
        );
        let gpu_analysis = Analysis::Results {
            incidents: vec![gpu],
            note: None,
        };
        let gpu_md = markdown_with_context(&gpu_analysis, &ctx);
        assert!(gpu_md.contains("- MPO: Enabled (default)"), "{gpu_md}");
        assert!(gpu_md.contains("Overlays running now"), "{gpu_md}");
    }
}
