use chrono::{Duration, Local};
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "framefault", about = "FrameFault headless / CI mode", version)]
struct Args {
    #[arg(long, alias = "self_test")]
    self_test: bool,

    #[arg(value_name = "PATH")]
    path: Option<PathBuf>,

    #[arg(long)]
    markdown: bool,

    #[arg(
        long,
        default_value_t = 7,
        value_parser = clap::value_parser!(i64).range(1..=3650)
    )]
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
    let Some(days) = Duration::try_days(args.days) else {
        eprintln!("--days must be between 1 and 3650");
        std::process::exit(2);
    };
    let cutoff = Local::now() - days;
    if let crate::model::Analysis::Results { incidents, .. } = &mut analysis {
        incidents.retain(|incident| incident.time >= cutoff);
        // Count repeats inside the --days window only, before any printing.
        crate::correlate::attach_frequencies(incidents);
    }
    if args.markdown {
        println!("{}", crate::report::markdown_with_context(&analysis, &ctx));
    } else {
        println!("{analysis:#?}");
    }
    true
}
