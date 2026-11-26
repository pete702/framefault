use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver};
use std::sync::Arc;
use std::time::Duration as StdDuration;

use chrono::{Duration, Local};
use eframe::egui::{
    self, Color32, FontData, FontFamily, FontInsert, FontPriority, InsertFontFamily, RichText,
    TextureHandle, Vec2,
};

use crate::model::{Analysis, Incident, SystemContext};

const GITHUB_URL: &str = "https://github.com/pete702/framefault";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum IncidentFilter {
    #[default]
    All,
    GamesAndGpu,
    HardwareAndBsod,
}

fn app_key(title: &str) -> String {
    title
        .split(" - ")
        .next()
        .unwrap_or(title)
        .trim()
        .to_owned()
}

fn short_cpu(cpu: &str) -> String {
    let clean = cpu.split_whitespace().collect::<Vec<_>>().join(" ");
    if clean.chars().count() <= 48 {
        clean
    } else {
        format!("{}…", clean.chars().take(48).collect::<String>())
    }
}

const HARDWARE_MARKERS: &[&str] = &[
    "bugcheck",
    "bsod",
    "blue screen",
    "whea",
    "kernel-power",
    "kernel power",
    "resource-exhaustion",
    "low virtual memory",
    "livekernelevent",
    "live kernel event",
    "2004",
];

fn matches_filter(filter: IncidentFilter, query: &str, inc: &Incident) -> bool {
    let text = App::incident_text(inc);
    let lower = text.to_ascii_lowercase();
    let category = match filter {
        IncidentFilter::All => true,
        // One marker set with the markdown header, in report.rs.
        IncidentFilter::GamesAndGpu => crate::report::incident_has_gpu_context(inc),
        IncidentFilter::HardwareAndBsod => {
            HARDWARE_MARKERS.iter().any(|marker| lower.contains(marker))
        }
    };
    if !category {
        return false;
    }
    let query = query.trim().to_ascii_lowercase();
    query.is_empty() || lower.contains(&query)
}

pub struct App {
    ctx: SystemContext,
    analysis: Analysis,
    selected: usize,
    days: i64,
    path: Option<PathBuf>,
    /// Raw drop slot from egui; consumed once per frame.
    pending: Option<PathBuf>,
    /// A dropped path waiting for the next scan. Kept separate from `path`
    /// so a finishing scan cannot overwrite it with its own older root.
    pending_path: Option<PathBuf>,
    last_scanned: Option<PathBuf>,
    status: String,
    logo: Option<TextureHandle>,
    copied: bool,
    scanning: bool,
    /// A day/Rescan click during a scan is replayed instead of dropped.
    rescan_queued: bool,
    receiver: Option<Receiver<(Analysis, SystemContext, PathBuf)>>,
    hidden_apps: Vec<String>,
    filter: IncidentFilter,
    search_query: String,
}

fn install_system_fonts(ctx: &egui::Context) {
    let candidates: [(&str, &str, FontFamily); 2] = [
        ("SegoeUI", r"C:\Windows\Fonts\segoeui.ttf", FontFamily::Proportional),
        ("Consolas", r"C:\Windows\Fonts\consola.ttf", FontFamily::Monospace),
    ];
    for (name, path, family) in candidates {
        if let Ok(bytes) = std::fs::read(path) {
            ctx.add_font(FontInsert {
                name: name.to_owned(),
                data: FontData::from_owned(bytes),
                families: vec![InsertFontFamily {
                    family,
                    priority: FontPriority::Lowest,
                }],
            });
        }
    }
}

impl App {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        install_system_fonts(&cc.egui_ctx);
        let image = egui::ColorImage::from_rgba_unmultiplied(
            [32, 32],
            include_bytes!("../assets/icon.rgba"),
        );
        let logo = cc
            .egui_ctx
            .load_texture("framefault-logo", image, egui::TextureOptions::NEAREST);

        let mut app = Self {
            // Real context arrives from the background scan; no registry/Event
            // Log reads on the UI thread while the window opens.
            ctx: SystemContext::default(),
            analysis: Analysis::Empty,
            selected: 0,
            days: 7,
            path: None,
            pending: None,
            pending_path: None,
            status: "Drop a crash folder, .wer, .xml or .log to begin.".to_owned(),
            logo: Some(logo),
            copied: false,
            scanning: false,
            rescan_queued: false,
            receiver: None,
            hidden_apps: Vec::new(),
            filter: IncidentFilter::default(),
            search_query: String::new(),
            last_scanned: None,
        };
        app.start_scan();
        app
    }

    /// Root of the next scan: a dropped path wins over the previous root.
    fn next_root(&mut self) -> PathBuf {
        self.pending_path
            .take()
            .or_else(|| self.path.clone())
            .or_else(dirs::data_local_dir)
            .unwrap_or_default()
    }

    /// Launch the read-only scan on a background thread so the window opens instantly.
    fn start_scan(&mut self) {
        if self.scanning {
            self.rescan_queued = true;
            return;
        }
        self.rescan_queued = false;
        let root = self.next_root();
        self.path = Some(root.clone());
        let (tx, rx) = channel();
        self.receiver = Some(rx);
        self.scanning = true;
        self.status = "Scanning...".to_owned();
        self.copied = false;

        std::thread::spawn(move || {
            let ctx = crate::context();
            let analysis = crate::analyze_with_context(&root, &ctx);
            let _ = tx.send((analysis, ctx, root));
        });
    }

    fn finish_scan(&mut self, analysis: Analysis, ctx: SystemContext, root: PathBuf) {
        let queued = self.rescan_queued;
        self.rescan_queued = false;
        let mut analysis = analysis;
        if let Analysis::Results { incidents, .. } = &mut analysis {
            let cutoff = Local::now() - Duration::days(self.days);
            incidents.retain(|incident| incident.time >= cutoff);
        }
        // `self.path` already points at the root of the currently displayed
        // scan; overwriting it here would destroy a path dropped mid-scan.
        self.last_scanned = Some(root);
        self.ctx = ctx;
        self.analysis = analysis;
        self.selected = 0;
        self.scanning = false;
        let count = self.visible_incidents().len();
        self.status = format!("Scanned {count} incident(s) | {}", Local::now().format("%H:%M:%S"));
        if queued {
            self.start_scan();
        }
    }

    fn incident_text(inc: &Incident) -> String {
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
        text
    }

    fn matches_filter(&self, inc: &Incident) -> bool {
        matches_filter(self.filter, &self.search_query, inc)
    }

    fn visible_incidents(&self) -> Vec<crate::model::Incident> {
        match &self.analysis {
            Analysis::Results { incidents, .. } => incidents
                .iter()
                .filter(|incident| !self.hidden_apps.contains(&app_key(&incident.title)))
                .filter(|incident| self.matches_filter(incident))
                .cloned()
                .collect(),
            _ => Vec::new(),
        }
    }

    fn header(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            if let Some(logo) = &self.logo {
                ui.image(egui::load::SizedTexture::new(
                    logo.id(),
                    Vec2::splat(26.0),
                ));
            }
            ui.heading("FrameFault");
            ui.label(RichText::new("one verdict per crash | read-only").small().weak());
            ui.add_space(12.0);

            let overlays = self.ctx.overlays_now.clone();
            ui.menu_button("Overlays now", move |ui| {
                ui.label(RichText::new("LIVE STATE - not crash time").small().italics());
                if overlays.is_empty() {
                    ui.label("none detected");
                }
                for name in &overlays {
                    ui.label(name);
                }
            });

            if ui.button("Rescan").clicked() {
                self.start_scan();
            }
            for days in [7, 14, 30] {
                if ui
                    .selectable_label(self.days == days, format!("{days}d"))
                    .clicked()
                {
                    self.days = days;
                    self.start_scan();
                }
            }
        });

        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new(format!("{} | {}", self.ctx.gpu, self.ctx.driver)).small());
            ui.separator();
            ui.label(RichText::new(format!("CPU {}", short_cpu(&self.ctx.cpu))).small());
            ui.separator();
            ui.label(RichText::new(format!(
                "RAM {:.1}/{:.1} GiB | Commit {:.1}/{:.1} GiB | Pagefile {}",
                self.ctx.ram_used_gib,
                self.ctx.ram_total_gib,
                self.ctx.commit_used_gib,
                self.ctx.commit_limit_gib,
                self.ctx.pagefile
            )).small());
            ui.separator();
            ui.label(RichText::new(format!("MPO: {}", self.ctx.mpo)).small());
            ui.separator();
            ui.label(RichText::new(format!("HAGS: {}", self.ctx.hags)).small());
            ui.separator();
            ui.label(
                RichText::new(format!(
                    "Uptime: {}",
                    crate::report::uptime_label(self.ctx.uptime_hours)
                ))
                .small(),
            );
            if let Some(note) = &self.ctx.tdr_note {
                warning_badge(ui, note, "Non-default TDR registry value (read-only).");
            }
            if let Some(warning) = &self.ctx.disk_warn {
                warning_badge(
                    ui,
                    warning,
                    "Low free space on C: or the pagefile drive.",
                );
            }
        });
    }

    fn incident_list(&mut self, ui: &mut egui::Ui) {
        ui.heading("Incidents");
        ui.label(RichText::new(&self.ctx.log_reach).small().weak());
        ui.horizontal(|ui| {
            for (filter, label) in [
                (IncidentFilter::All, "All"),
                (IncidentFilter::GamesAndGpu, "Games/GPU"),
                (IncidentFilter::HardwareAndBsod, "BSOD/HW"),
            ] {
                if ui.selectable_label(self.filter == filter, label).clicked() {
                    self.filter = filter;
                    self.selected = 0;
                }
            }
        });
        let width = ui.available_width();
        let previous_query = self.search_query.clone();
        ui.add(
            egui::TextEdit::singleline(&mut self.search_query)
                .hint_text("Filter by app or code...")
                .desired_width(width),
        );
        if self.search_query != previous_query {
            self.selected = 0;
        }
        ui.separator();

        let incidents = self.visible_incidents();
        if !self.hidden_apps.is_empty() {
            ui.horizontal(|ui| {
                ui.label(RichText::new(format!("{} hidden", self.hidden_apps.len())).small().weak());
                if ui.small_button("Show all").clicked() {
                    self.hidden_apps.clear();
                    self.start_scan();
                }
            });
        }

        if incidents.is_empty() {
            ui.label("No incidents in the selected period.");
        }
        for (index, incident) in incidents.iter().enumerate() {
            let verdict = incident
                .findings
                .first()
                .map(|finding| finding.verdict.as_str())
                .unwrap_or("no verdict");
            let label = if verdict == incident.title {
                format!("{}  {}", incident.time.format("%m-%d %H:%M:%S"), incident.title)
            } else {
                format!(
                    "{}  {}\n{}",
                    incident.time.format("%m-%d %H:%M:%S"),
                    incident.title,
                    verdict
                )
            };
            if ui
                .selectable_value(&mut self.selected, index, label)
                .clicked()
            {
                // selection is already applied by selectable_value
            }
        }
    }

    fn verdict_card(&mut self, ui: &mut egui::Ui) {
        if self.scanning {
            ui.heading("Scanning...");
            ui.label("Reading Event Log, WER and crash folders read-only...");
            return;
        }
        match &self.analysis {
            Analysis::NoAnchor => {
                ui.heading("No crash anchor found");
                ui.label("Drop a crash folder, Report.wer, CrashContext.runtime-xml or Player.log.");
                return;
            }
            Analysis::Empty => {
                ui.label("Waiting for a crash artifact ...");
                return;
            }
            Analysis::Results { .. } => {}
        }

        let incidents = self.visible_incidents();
        if !incidents.is_empty() && self.selected >= incidents.len() {
            self.selected = 0;
        }
        let Some(incident) = incidents.get(self.selected) else {
            ui.label("Select an incident on the left, or show hidden apps.");
            return;
        };
        let hide_key = app_key(&incident.title);

        ui.heading(incident.time.format("%Y-%m-%d %H:%M:%S").to_string());
        ui.horizontal(|ui| {
            ui.label(RichText::new(&incident.title).weak());
            if ui.small_button("Hide events from this app").clicked() {
                self.hidden_apps.push(hide_key.clone());
                self.selected = 0;
            }
        });
        ui.add_space(8.0);

        for finding in &incident.findings {
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.heading(&finding.verdict);
                badge(
                    ui,
                    &finding.confidence,
                    match finding.confidence.to_ascii_lowercase().as_str() {
                        "high" => Color32::from_rgb(255, 99, 99),
                        "medium" => Color32::from_rgb(255, 184, 77),
                        _ => Color32::from_rgb(120, 170, 220),
                    },
                );
                ui.label(RichText::new(format!("score {}", finding.score)).small().weak());
            });

            let sources = finding.source_count.max(1);
            ui.label(
                RichText::new(format!(
                    "{} - {} independent source{} matched",
                    finding.confidence,
                    sources,
                    if sources == 1 { "" } else { "s" }
                ))
                .small()
                .weak(),
            );
            ui.add_space(4.0);
            egui::CollapsingHeader::new("Raw Proof / Technical Details")
                .id_salt(format!("proof-{}", finding.verdict))
                .show(ui, |ui| {
                    for line in &finding.evidence {
                        ui.add(
                            egui::Label::new(RichText::new(line).monospace().small())
                                .wrap_mode(egui::TextWrapMode::Wrap),
                        );
                    }
                });

            if let Some(note) = &finding.note {
                ui.add_space(4.0);
                ui.label(RichText::new(note.as_str()).small().weak());
            }
            if !finding.next_steps.is_empty() {
                ui.label("Next steps:");
                for step in &finding.next_steps {
                    ui.label(format!("• {step}"));
                }
            }
            if let Some(link) = &finding.link {
                ui.hyperlink_to("Official reference", link);
            }
        }

        ui.add_space(16.0);
        if ui.button("Copy Clean Report").clicked() {
            // One report = System Context + the currently selected incident,
            // never all incidents from the scan.
            let note = match &self.analysis {
                crate::model::Analysis::Results { note, .. } => note.as_deref(),
                _ => None,
            };
            let md = crate::report::markdown_for_incident(&self.ctx, incident, note);
            ui.ctx().copy_text(md);
            self.copied = true;
        }
        if self.copied {
            ui.label(
                RichText::new("Copied - personal identifiers destroyed, not blurred.")
                    .small()
                    .weak(),
            );
        }
    }

    fn status_bar(&mut self, ui: &mut egui::Ui) {
        ui.label(format!(
            "Read-Only | 0 Admin | No Drivers | No .dmp in v{}",
            env!("CARGO_PKG_VERSION")
        ));
        ui.separator();
        ui.label(&self.status);
        ui.separator();
        ui.hyperlink_to("GitHub", GITHUB_URL);
    }
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        ui.ctx().input(|input| {
            for file in &input.raw.dropped_files {
                let path = file.path();
                self.pending = Some(path.to_path_buf());
            }
        });
        if let Some(path) = self.pending.take() {
            // If a scan is in flight, start_scan() only queues; the new path
            // survives in pending_path until that scan finishes.
            self.pending_path = Some(path);
            self.start_scan();
        }

        let received = self
            .receiver
            .as_ref()
            .and_then(|receiver| receiver.try_recv().ok());
        if let Some((analysis, ctx, root)) = received {
            self.receiver = None;
            self.finish_scan(analysis, ctx, root);
        }
        if self.scanning {
            ui.ctx().request_repaint_after(StdDuration::from_millis(120));
        }

        egui::containers::Panel::top("header").show(ui, |ui| {
            self.header(ui);
        });
        egui::containers::Panel::bottom("status").show(ui, |ui| {
            ui.horizontal(|ui| self.status_bar(ui));
        });
        egui::containers::Panel::left("incidents")
            .default_size(300.0)
            .show(ui, |ui| {
                egui::ScrollArea::vertical().show(ui, |ui| self.incident_list(ui));
            });
        egui::containers::CentralPanel::default().show(ui, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| self.verdict_card(ui));
        });
    }
}

fn badge(ui: &mut egui::Ui, text: &str, color: Color32) {
    let (rect, _) = ui.allocate_exact_size(Vec2::new(58.0, 18.0), egui::Sense::hover());
    ui.painter().rect_filled(rect, 4.0, color);
    ui.painter().text(
        rect.center(),
        egui::Align2::CENTER_CENTER,
        text,
        egui::FontId::proportional(11.0),
        Color32::BLACK,
    );
}

fn warning_badge(ui: &mut egui::Ui, text: &str, tooltip: &str) {
    let button = egui::Button::new(
        RichText::new(text)
            .small()
            .strong()
            .color(Color32::from_rgb(70, 45, 0)),
    )
    .small()
    .fill(Color32::from_rgb(255, 184, 77));
    ui.add(button).on_hover_text(tooltip);
}

pub fn native_options() -> eframe::NativeOptions {
    let icon = Arc::new(eframe::egui::IconData {
        rgba: include_bytes!("../assets/icon.rgba").to_vec(),
        width: 32,
        height: 32,
    });
    eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_inner_size([1080.0, 720.0])
            .with_drag_and_drop(true)
            .with_icon(icon),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Finding;

    fn bsod_incident() -> Incident {
        let title = "BSOD 0x0000000A (IRQL_NOT_LESS_OR_EQUAL)".to_owned();
        Incident {
            time: Local::now(),
            title: title.clone(),
            findings: vec![Finding {
                verdict: title,
                score: 20,
                confidence: "High".to_owned(),
                source_count: 1,
                evidence: vec![
                    "2026-11-25 10:00:00 | eventlog | Microsoft-Windows-WER-SystemErrorReporting | The Bug Check was: 0x0000000A (0xffff)"
                        .to_owned(),
                ],
                next_steps: Vec::new(),
                link: None,
                note: None,
            }],
        }
    }

    #[test]
    fn clean_wer_bsod_is_hardware_only() {
        let incident = bsod_incident();
        assert!(!matches_filter(IncidentFilter::GamesAndGpu, "", &incident));
        assert!(matches_filter(
            IncidentFilter::HardwareAndBsod,
            "",
            &incident
        ));
        assert!(matches_filter(IncidentFilter::All, "", &incident));
    }

    #[test]
    fn gpu_marker_incident_passes_games_filter() {
        let mut incident = bsod_incident();
        incident.findings[0].evidence.push(
            "2026-11-25 10:00:05 | eventlog | nvlddmkm | GPUID=10de:1b06".to_owned(),
        );
        assert!(matches_filter(
            IncidentFilter::GamesAndGpu,
            "",
            &incident
        ));
    }

    fn idle_app() -> App {
        App {
            ctx: SystemContext::default(),
            analysis: Analysis::Empty,
            selected: 0,
            days: 7,
            path: None,
            pending: None,
            pending_path: None,
            last_scanned: None,
            status: String::new(),
            logo: None,
            copied: false,
            scanning: false,
            rescan_queued: false,
            receiver: None,
            hidden_apps: Vec::new(),
            filter: IncidentFilter::default(),
            search_query: String::new(),
        }
    }

    #[test]
    fn drop_during_scan_survives_the_old_result() {
        let mut app = idle_app();
        app.path = Some(PathBuf::from("old-root"));
        app.pending_path = Some(PathBuf::from("new-root"));
        app.scanning = true;

        app.start_scan();
        assert!(app.rescan_queued, "the busy click must be queued");
        assert_eq!(app.path, Some(PathBuf::from("old-root")));
        assert_eq!(app.pending_path, Some(PathBuf::from("new-root")));

        // Suppress the automatic replay so this unit test spawns no thread.
        app.rescan_queued = false;
        app.finish_scan(
            Analysis::Empty,
            SystemContext::default(),
            PathBuf::from("old-root"),
        );
        assert_eq!(
            app.path,
            Some(PathBuf::from("old-root")),
            "finish_scan must not overwrite a pending drop"
        );
        assert_eq!(app.next_root(), PathBuf::from("new-root"));
    }
}
