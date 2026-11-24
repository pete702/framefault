use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver};
use std::sync::Arc;
use std::time::Duration as StdDuration;

use chrono::{Duration, Local};
use eframe::egui::{
    self, Color32, FontData, FontFamily, FontInsert, FontPriority, InsertFontFamily, RichText,
    TextureHandle, Vec2,
};

use crate::model::{Analysis, SystemContext};

const GITHUB_URL: &str = "https://github.com/framefault/framefault";

fn app_key(title: &str) -> String {
    title
        .split(" - ")
        .next()
        .unwrap_or(title)
        .trim()
        .to_owned()
}

pub struct App {
    ctx: SystemContext,
    analysis: Analysis,
    selected: usize,
    days: i64,
    path: Option<PathBuf>,
    pending: Option<PathBuf>,
    last_scanned: Option<PathBuf>,
    status: String,
    logo: Option<TextureHandle>,
    copied: bool,
    scanning: bool,
    receiver: Option<Receiver<(Analysis, PathBuf)>>,
    hidden_apps: Vec<String>,
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
            ctx: crate::context(),
            analysis: Analysis::Empty,
            selected: 0,
            days: 7,
            path: None,
            pending: None,
            status: "Drop a crash folder, .wer, .xml or .log to begin.".to_owned(),
            logo: Some(logo),
            copied: false,
            scanning: false,
            receiver: None,
            hidden_apps: Vec::new(),
            last_scanned: None,
        };
        app.start_scan();
        app
    }

    /// Launch the read-only scan on a background thread so the window opens instantly.
    fn start_scan(&mut self) {
        if self.scanning {
            return;
        }
        self.ctx = crate::context();
        let root = self
            .path
            .clone()
            .or_else(dirs::data_local_dir)
            .unwrap_or_default();
        let (tx, rx) = channel();
        self.receiver = Some(rx);
        self.scanning = true;
        self.status = "Scanning...".to_owned();
        self.copied = false;

        std::thread::spawn(move || {
            let analysis = crate::analyze(&root);
            let _ = tx.send((analysis, root));
        });
    }

    fn finish_scan(&mut self, analysis: Analysis, root: PathBuf) {
        let mut analysis = analysis;
        if let Analysis::Results { incidents, .. } = &mut analysis {
            let cutoff = Local::now() - Duration::days(self.days);
            incidents.retain(|incident| incident.time >= cutoff);
        }
        self.path = Some(root.clone());
        self.last_scanned = Some(root);
        self.analysis = analysis;
        self.selected = 0;
        self.scanning = false;
        let count = self.visible_incidents().len();
        self.status = format!("Scanned {count} incident(s) | {}", Local::now().format("%H:%M:%S"));
    }

    fn visible_incidents(&self) -> Vec<crate::model::Incident> {
        match &self.analysis {
            Analysis::Results { incidents, .. } => incidents
                .iter()
                .filter(|incident| !self.hidden_apps.contains(&app_key(&incident.title)))
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
        });
    }

    fn incident_list(&mut self, ui: &mut egui::Ui) {
        ui.heading("Incidents");
        ui.label(RichText::new(&self.ctx.log_reach).small().weak());
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
                        ui.label(RichText::new(line).monospace().small());
                    }
                });

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
            let md = crate::report::markdown_with_context(&self.analysis, &self.ctx);
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
            self.path = Some(path);
            self.start_scan();
        }

        let received = self
            .receiver
            .as_ref()
            .and_then(|receiver| receiver.try_recv().ok());
        if let Some((analysis, root)) = received {
            self.receiver = None;
            self.finish_scan(analysis, root);
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
