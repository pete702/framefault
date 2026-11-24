#![cfg_attr(all(windows, not(feature = "cli")), windows_subsystem = "windows")]

fn main() -> eframe::Result<()> {
    #[cfg(feature = "cli")]
    if framefault::cli::maybe_run() {
        return Ok(());
    }

    eframe::run_native(
        "FrameFault",
        framefault::app::native_options(),
        Box::new(|cc| Ok(Box::new(framefault::app::App::new(cc)))),
    )
}
