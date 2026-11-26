use chrono::{Duration, Local};
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "framefault", about = "FrameFault headless / CI mode")]
struct Args {
    #[arg(long)]
    self_test: bool,

    #[arg(value_name = "PATH")]
    path: Option<PathBuf>,

    #[arg(long)]
    markdown: bool,

    #[arg(long, default_value_t = 7)]
    days: i64,
}

pub fn maybe_run() -> bool {
    let args = Args::parse();
    if args.self_test {
        match crate::self_test() {
            Ok(()) => {
                println!("SELF-TEST OK: rules, redaction, report");
                std::process::exit(0);
            }
            Err(error) => {
                eprintln!("SELF-TEST FAILED: {error}");
                std::process::exit(1);
            }
        }
    }

    let Some(path) = args.path else { return false };
    let ctx = crate::context();
    let mut analysis = crate::analyze_with_context(&path, &ctx);
    let cutoff = Local::now() - Duration::days(args.days);
    if let crate::model::Analysis::Results { incidents, .. } = &mut analysis {
        incidents.retain(|incident| incident.time >= cutoff);
    }
    if args.markdown {
        println!("{}", crate::report::markdown_with_context(&analysis, &ctx));
    } else {
        println!("{analysis:#?}");
    }
    true
}
