use crate::model::{Analysis, SystemContext};

pub fn markdown(analysis: &Analysis) -> String {
    let ctx = crate::context();
    format!("{}\n{}", header(&ctx), markdown_without_context(analysis))
}

pub fn markdown_with_context(analysis: &Analysis, ctx: &SystemContext) -> String {
    format!("{}\n{}", header(ctx), markdown_without_context(analysis))
}

fn header(ctx: &SystemContext) -> String {
    let mut out = String::new();
    out.push_str("**FrameFault report** - read-only, no admin, no symbols\n\n");
    out.push_str(&format!("- System: {}\n", redact_safe(&ctx.windows)));
    out.push_str(&format!("- GPU: {} | {}\n", redact_safe(&ctx.gpu), redact_safe(&ctx.driver)));
    out.push_str(&format!(
        "- RAM: {:.1}/{:.1} GiB | Commit: {:.1}/{:.1} GiB | Pagefile: {}\n",
        ctx.ram_used_gib,
        ctx.ram_total_gib,
        ctx.commit_used_gib,
        ctx.commit_limit_gib,
        redact_safe(&ctx.pagefile)
    ));
    out.push_str(&format!("- MPO: {}\n", ctx.mpo));
    if !ctx.overlays_now.is_empty() {
        out.push_str(&format!(
            "- Overlays running now (live state, not crash time): {}\n",
            ctx.overlays_now.join(", ")
        ));
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
    out.push_str("---\nGenerated locally by FrameFault. Read-only | 0 Admin | No Drivers.\n");
    out
}

fn redact_safe(value: &str) -> String {
    crate::redact::redact(value)
}
