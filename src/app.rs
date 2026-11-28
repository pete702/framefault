use std::path::{Path, PathBuf};
use std::sync::mpsc::{channel, Receiver, TryRecvError};
use std::sync::Arc;
use std::time::{Duration as StdDuration, Instant};

use chrono::{Duration, Local};
use eframe::egui::{
    self, Color32, FontData, FontFamily, FontInsert, FontPriority, InsertFontFamily, RichText,
    TextureHandle, Vec2,
};
use notify::{RecommendedWatcher, RecursiveMode, Watcher};
use walkdir::WalkDir;

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
    title.split(" - ").next().unwrap_or(title).trim().to_owned()
}

fn short_cpu(cpu: &str) -> String {
    let clean = cpu.split_whitespace().collect::<Vec<_>>().join(" ");
    if clean.chars().count() <= 48 {
        clean
    } else {
        format!("{}…", clean.chars().take(48).collect::<String>())
    }
}

fn has_component(path: &Path, name: &str) -> bool {
    path.components().any(|component| {
        component
            .as_os_str()
            .to_string_lossy()
            .eq_ignore_ascii_case(name)
    })
}

fn in_saved_crashes(path: &Path) -> bool {
    let parts: Vec<String> = path
        .components()
        .map(|component| component.as_os_str().to_string_lossy().to_ascii_lowercase())
        .collect();
    parts
        .windows(2)
        .any(|pair| pair[0] == "saved" && pair[1] == "crashes")
}

fn is_saved_crashes_dir(path: &Path) -> bool {
    let mut parts = path.components().rev();
    let crashes = parts.next().is_some_and(|part| {
        part.as_os_str()
            .to_string_lossy()
            .eq_ignore_ascii_case("Crashes")
    });
    let saved = parts.next().is_some_and(|part| {
        part.as_os_str()
            .to_string_lossy()
            .eq_ignore_ascii_case("Saved")
    });
    crashes && saved
}

/// Windows stores `ReportArchive\<folder>\Report.wer`, so WER roots must be
/// watched recursively.
fn is_wer_dir(path: &Path) -> bool {
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy())
        .unwrap_or_default();
    let report_dir =
        name.eq_ignore_ascii_case("ReportArchive") || name.eq_ignore_ascii_case("ReportQueue");
    report_dir && has_component(path, "WER")
}

/// Bounded content probe for a generic `.xml` whose name does not already say
/// "crashcontext". Only crash-context XML may wake the app.
fn xml_contains_crash_context(path: &Path) -> bool {
    use std::io::Read;

    const PROBE_BYTES: usize = 4096;
    let Ok(mut file) = std::fs::File::open(path) else {
        return false;
    };
    let mut buffer = [0u8; PROBE_BYTES];
    let Ok(read) = file.read(&mut buffer) else {
        return false;
    };
    String::from_utf8_lossy(&buffer[..read])
        .to_ascii_lowercase()
        .contains("<crashcontext")
}

/// Only a crash artifact may wake the UI. LocalLow is huge and chatty, so it
/// accepts `Player.log` only; everything else is limited to real crash files.
pub(crate) fn is_relevant_watch_path(path: &Path) -> bool {
    let Some(name) = path
        .file_name()
        .map(|name| name.to_string_lossy().to_ascii_lowercase())
    else {
        return false;
    };
    if name.is_empty() {
        return false;
    }

    if has_component(path, "LocalLow") {
        return name == "player.log";
    }
    if has_component(path, "CrashDumps") {
        return name.ends_with(".dmp");
    }

    let xml = name.ends_with(".xml") || name.ends_with(".runtime-xml");
    if in_saved_crashes(path) {
        // UE puts .log/.dmp and CrashContext XML inside its per-crash folder.
        return name.ends_with(".wer") || xml || name.ends_with(".log") || name.ends_with(".dmp");
    }

    name.ends_with(".wer")
        || (xml && (name.contains("crashcontext") || xml_contains_crash_context(path)))
}

/// Exact folders worth watching. Never the whole `%LOCALAPPDATA%`: that would
/// wake the app for browser caches and every unrelated log write.
fn watch_directories() -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = Vec::new();
    let local = dirs::data_local_dir();

    if let Some(local) = &local {
        let wer = local.join("Microsoft").join("Windows").join("WER");
        dirs.push(wer.join("ReportArchive"));
        dirs.push(wer.join("ReportQueue"));
        dirs.push(local.join("CrashDumps"));
        if let Some(appdata) = local.parent() {
            dirs.push(appdata.join("LocalLow"));
        }
        // A UE game keeps its crash dumps in <game>\Saved\Crashes, up to
        // three levels below LocalAppData. The walk itself skips errors.
        for entry in WalkDir::new(local).max_depth(3).into_iter().flatten() {
            if entry.file_type().is_dir() && is_saved_crashes_dir(entry.path()) {
                dirs.push(entry.path().to_path_buf());
            }
        }
    }

    let program_data = std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
    let wer = program_data.join("Microsoft").join("Windows").join("WER");
    dirs.push(wer.join("ReportArchive"));
    dirs.push(wer.join("ReportQueue"));

    let mut seen = std::collections::HashSet::new();
    dirs.retain(|dir| seen.insert(dir.to_string_lossy().to_ascii_lowercase()));
    dirs
}

const HARDWARE_MARKERS: &[&str] = &[
    "bugcheck",
    "bsod",
    "blue screen",
    "whea",
    "kernel-power",
    "kernel power",
    "resource-exhaustion",
    "resource-exhaustion-detector",
    "low virtual memory",
    "livekernelevent",
    "live kernel event",
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
    /// `None` = All days; `Some(n)` = last n days.
    days: Option<i64>,
    path: Option<PathBuf>,
    /// Raw drop slot from egui; consumed once per frame.
    pending: Option<PathBuf>,
    /// A dropped path waiting for the next scan. Kept separate from `path`
    /// so a finishing scan cannot overwrite it with its own older root.
    pending_path: Option<PathBuf>,
    status: String,
    logo: Option<TextureHandle>,
    copied: bool,
    scanning: bool,
    /// A day/Rescan click during a scan is replayed instead of dropped.
    rescan_queued: bool,
    receiver: Option<Receiver<(Analysis, SystemContext)>>,
    /// Filesystem watcher for the exact crash folders in `watch_directories`.
    watcher: Option<RecommendedWatcher>,
    /// Every watcher event, drained on each frame.
    watch_rx: Option<Receiver<notify::Event>>,
    /// Watcher construction runs off the UI thread; the result arrives here.
    watcher_setup: Option<Receiver<(RecommendedWatcher, Receiver<notify::Event>, bool)>>,
    /// Set only by a relevant crash artifact; one rescan after 1.5 s.
    debounce_deadline: Option<Instant>,
    /// True when at least one crash folder is actively watched.
    watching_active: bool,
    hidden_apps: Vec<String>,
    filter: IncidentFilter,
    search_query: String,
    /// Day-filtered, frequency-annotated list. Rebuilt only when its inputs
    /// change, so panels never clone incidents on every frame.
    cached_visible: Vec<Incident>,
    cache_dirty: bool,
}

fn install_system_fonts(ctx: &egui::Context) {
    let fonts_dir = std::env::var_os("WINDIR")
        .map(PathBuf::from)
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"))
        .join("Fonts");
    let candidates: [(&str, PathBuf, FontFamily); 2] = [
        (
            "SegoeUI",
            fonts_dir.join("segoeui.ttf"),
            FontFamily::Proportional,
        ),
        (
            "Consolas",
            fonts_dir.join("consola.ttf"),
            FontFamily::Monospace,
        ),
    ];
    for (name, path, family) in candidates {
        if let Ok(bytes) = std::fs::read(&path) {
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
        let logo =
            cc.egui_ctx
                .load_texture("framefault-logo", image, egui::TextureOptions::NEAREST);

        let mut app = Self {
            // Real context arrives from the background scan; no registry/Event
            // Log reads on the UI thread while the window opens.
            ctx: SystemContext::default(),
            analysis: Analysis::Empty,
            selected: 0,
            days: Some(7),
            path: None,
            pending: None,
            pending_path: None,
            status: "Drop a crash folder, .wer, .xml, .log or user-mode .dmp to begin.".to_owned(),
            logo: Some(logo),
            copied: false,
            scanning: false,
            rescan_queued: false,
            receiver: None,
            watcher: None,
            watch_rx: None,
            watcher_setup: None,
            debounce_deadline: None,
            watching_active: false,
            hidden_apps: Vec::new(),
            filter: IncidentFilter::default(),
            search_query: String::new(),
            cached_visible: Vec::new(),
            cache_dirty: true,
        };
        app.start_watcher(cc.egui_ctx.clone());
        app.start_scan();
        app
    }

    /// Root of the next scan plus whether it came from the user. A local scan
    /// leaves `path` empty so watcher events can still trigger a rescan.
    fn next_root(&mut self) -> (PathBuf, bool) {
        if let Some(dropped) = self.pending_path.take() {
            return (dropped, true);
        }
        if let Some(manual) = self.path.clone() {
            return (manual, true);
        }
        (dirs::data_local_dir().unwrap_or_default(), false)
    }

    /// Launch the read-only scan on a background thread so the window opens instantly.
    fn start_scan(&mut self) {
        if self.scanning {
            self.rescan_queued = true;
            return;
        }
        self.rescan_queued = false;
        let (root, manual) = self.next_root();
        self.path = if manual { Some(root.clone()) } else { None };
        if manual {
            // A manual drop owns the view: kill any watcher-triggered rescan.
            self.debounce_deadline = None;
        }
        let (tx, rx) = channel();
        self.receiver = Some(rx);
        self.scanning = true;
        self.status = "Scanning...".to_owned();
        self.copied = false;

        std::thread::spawn(move || {
            let ctx = crate::context();
            let analysis = crate::analyze_with_context(&root, &ctx);
            let _ = tx.send((analysis, ctx));
        });
    }

    /// Watch only the exact crash folders; missing or denied ones are skipped.
    /// The directory walk and watcher construction happen off the UI thread so
    /// the window paints immediately.
    fn start_watcher(&mut self, repaint: egui::Context) {
        let (setup_tx, setup_rx) = channel();
        self.watcher_setup = Some(setup_rx);
        std::thread::spawn(move || {
            let (tx, rx) = channel::<notify::Event>();
            let Ok(mut watcher) =
                notify::recommended_watcher(move |event: notify::Result<notify::Event>| {
                    if let Ok(event) = event {
                        // Redraw only for crash artifacts, never for cache noise.
                        if event.paths.iter().any(|path| is_relevant_watch_path(path)) {
                            repaint.request_repaint();
                        }
                        let _ = tx.send(event);
                    }
                })
            else {
                // Dropping setup_tx signals failure through the channel.
                return;
            };

            let mut watching_active = false;
            for dir in watch_directories() {
                if !dir.is_dir() {
                    continue;
                }
                let mode = if has_component(&dir, "LocalLow")
                    || is_saved_crashes_dir(&dir)
                    || is_wer_dir(&dir)
                {
                    RecursiveMode::Recursive
                } else {
                    RecursiveMode::NonRecursive
                };
                if watcher.watch(&dir, mode).is_ok() {
                    watching_active = true;
                }
            }

            let _ = setup_tx.send((watcher, rx, watching_active));
        });
    }

    /// Pick up the background watcher exactly once; keep repainting until it
    /// either arrives or reports failure.
    fn poll_watcher_setup(&mut self, ctx: &egui::Context) {
        let received = self
            .watcher_setup
            .as_ref()
            .map(|receiver| receiver.try_recv());
        match received {
            Some(Ok((watcher, watch_rx, watching_active))) => {
                self.watcher = Some(watcher);
                self.watch_rx = Some(watch_rx);
                self.watching_active = watching_active;
                self.watcher_setup = None;
            }
            Some(Err(TryRecvError::Disconnected)) => {
                self.watcher = None;
                self.watch_rx = None;
                self.watching_active = false;
                self.watcher_setup = None;
            }
            Some(Err(TryRecvError::Empty)) => {
                ctx.request_repaint_after(StdDuration::from_millis(100));
            }
            None => {}
        }
    }

    /// Drain every watcher event. Only a relevant artifact in local mode may
    /// arm the debounce; a manually opened crash must never be overwritten.
    fn poll_watcher(&mut self, ctx: &egui::Context) {
        if self.watcher.is_none() {
            return;
        }
        let mut relevant = false;
        if let Some(receiver) = &self.watch_rx {
            while let Ok(event) = receiver.try_recv() {
                if self.path.is_none()
                    && event.paths.iter().any(|path| is_relevant_watch_path(path))
                {
                    relevant = true;
                }
            }
        }

        if relevant {
            self.debounce_deadline = Some(Instant::now() + StdDuration::from_millis(1500));
        }

        if let Some(deadline) = self.debounce_deadline {
            if Instant::now() >= deadline && !self.scanning {
                self.debounce_deadline = None;
                self.start_scan();
            } else {
                // Keep the debounce alive even while a scan is still running.
                ctx.request_repaint_after(StdDuration::from_millis(250));
            }
        }
    }

    fn finish_scan(&mut self, analysis: Analysis, ctx: SystemContext) {
        let queued = self.rescan_queued;
        self.rescan_queued = false;
        self.ctx = ctx;
        self.analysis = analysis;
        self.selected = 0;
        self.copied = false;
        self.scanning = false;
        self.cache_dirty = true;
        let count = self.total_incidents();
        self.status = format!(
            "Scanned {count} incident(s) | {}",
            Local::now().format("%H:%M:%S")
        );
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

    fn total_incidents(&self) -> usize {
        match &self.analysis {
            Analysis::Results { incidents, .. } => incidents.len(),
            _ => 0,
        }
    }

    fn incident_in_period(&self, incident: &Incident) -> bool {
        match self.days {
            None => true,
            Some(days) => incident.time >= Local::now() - Duration::days(days),
        }
    }

    /// Rebuild the visible list only when an input changed. Frequency must
    /// count repeats inside the selected day window, but before hidden apps,
    /// category and search narrow the list.
    fn refresh_visible(&mut self) {
        if !self.cache_dirty {
            return;
        }
        let mut period: Vec<Incident> = match &self.analysis {
            Analysis::Results { incidents, .. } => incidents
                .iter()
                .filter(|incident| self.incident_in_period(incident))
                .cloned()
                .collect(),
            _ => Vec::new(),
        };
        crate::correlate::attach_frequencies(&mut period);
        self.cached_visible = period
            .into_iter()
            .filter(|incident| !self.hidden_apps.contains(&app_key(&incident.title)))
            .filter(|incident| self.matches_filter(incident))
            .collect();
        self.cache_dirty = false;
    }

    fn older_incidents_count(&self) -> usize {
        let Some(days) = self.days else {
            return 0;
        };
        let cutoff = Local::now() - Duration::days(days);
        match &self.analysis {
            Analysis::Results { incidents, .. } => incidents
                .iter()
                .filter(|incident| incident.time < cutoff)
                .filter(|incident| !self.hidden_apps.contains(&app_key(&incident.title)))
                .filter(|incident| self.matches_filter(incident))
                .count(),
            _ => 0,
        }
    }

    fn empty_incidents_message(&self) -> String {
        if self.total_incidents() == 0 {
            return "No incidents found in scanned logs.".to_owned();
        }
        let older = self.older_incidents_count();
        if older > 0 {
            let suggestion = if self.days == Some(30) {
                "try All"
            } else {
                "try 30d or All"
            };
            return format!(
                "No incidents in last {}d ({} older found - {})",
                self.days.unwrap_or(0),
                older,
                suggestion
            );
        }
        "No incidents match the current filter/search.".to_owned()
    }

    fn current_note(&self) -> Option<&str> {
        match &self.analysis {
            Analysis::Results { note, .. } | Analysis::NoAnchor { note } => note.as_deref(),
            Analysis::Empty => None,
        }
    }

    fn header(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            if let Some(logo) = &self.logo {
                ui.image(egui::load::SizedTexture::new(logo.id(), Vec2::splat(26.0)));
            }
            ui.heading("FrameFault");
            ui.label(
                RichText::new("one verdict per crash | read-only")
                    .small()
                    .weak(),
            );
            ui.add_space(12.0);

            let overlays = self.ctx.overlays_now.clone();
            ui.menu_button("Overlays now", move |ui| {
                ui.label(
                    RichText::new("LIVE STATE - not crash time")
                        .small()
                        .italics(),
                );
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
            if self.path.is_some() && ui.button("Return to local PC").clicked() {
                self.path = None;
                self.pending_path = None;
                self.rescan_queued = false;
                self.debounce_deadline = None;
                self.start_scan();
            }
            for (days, label) in [
                (Some(7), "7d"),
                (Some(14), "14d"),
                (Some(30), "30d"),
                (None, "All"),
            ] {
                if ui.selectable_label(self.days == days, label).clicked() {
                    self.days = days;
                    self.selected = 0;
                    self.copied = false;
                    self.cache_dirty = true;
                }
            }
        });

        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new(format!("{} | {}", self.ctx.gpu, self.ctx.driver)).small());
            ui.separator();
            ui.label(RichText::new(format!("CPU {}", short_cpu(&self.ctx.cpu))).small());
            ui.separator();
            ui.label(
                RichText::new(format!(
                    "RAM {:.1}/{:.1} GiB | Commit {:.1}/{:.1} GiB | Pagefile {}",
                    self.ctx.ram_used_gib,
                    self.ctx.ram_total_gib,
                    self.ctx.commit_used_gib,
                    self.ctx.commit_limit_gib,
                    self.ctx.pagefile
                ))
                .small(),
            );
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
                    "Low free space on the system drive or a dynamic pagefile drive.",
                );
            }
        });
    }

    fn incident_list(&mut self, ui: &mut egui::Ui) {
        ui.heading("Incidents");
        if let Some(note) = self.current_note() {
            ui.label(RichText::new(note).small().weak());
        } else {
            ui.label(RichText::new(&self.ctx.log_reach).small().weak());
        }
        ui.horizontal(|ui| {
            for (filter, label) in [
                (IncidentFilter::All, "All"),
                (IncidentFilter::GamesAndGpu, "Games/GPU"),
                (IncidentFilter::HardwareAndBsod, "BSOD/HW"),
            ] {
                if ui.selectable_label(self.filter == filter, label).clicked() {
                    self.filter = filter;
                    self.selected = 0;
                    self.copied = false;
                    self.cache_dirty = true;
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
            self.copied = false;
            self.cache_dirty = true;
        }
        ui.separator();

        self.refresh_visible();
        let incidents = &self.cached_visible;
        if !self.hidden_apps.is_empty() {
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(format!("{} hidden", self.hidden_apps.len()))
                        .small()
                        .weak(),
                );
                if ui.small_button("Show all").clicked() {
                    self.hidden_apps.clear();
                    self.selected = 0;
                    self.copied = false;
                    self.cache_dirty = true;
                }
            });
        }

        if incidents.is_empty() {
            ui.label(self.empty_incidents_message());
        }
        for (index, incident) in incidents.iter().enumerate() {
            let verdict = incident
                .findings
                .first()
                .map(|finding| finding.verdict.as_str())
                .unwrap_or("no verdict");
            let repeat = if incident.repeat_count > 1 {
                format!(" [x{}]", incident.repeat_count)
            } else {
                String::new()
            };
            let label = if verdict == incident.title {
                format!(
                    "{}  {}{}",
                    incident.time.format("%m-%d %H:%M:%S"),
                    incident.title,
                    repeat
                )
            } else {
                format!(
                    "{}  {}{}\n{}",
                    incident.time.format("%m-%d %H:%M:%S"),
                    incident.title,
                    repeat,
                    verdict
                )
            };
            let was_selected = self.selected;
            if ui
                .selectable_value(&mut self.selected, index, label)
                .clicked()
            {
                // selection is already applied by selectable_value
            }
            if self.selected != was_selected {
                self.copied = false;
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
            Analysis::NoAnchor { note } => {
                ui.heading("No crash anchor found");
                ui.label(
                    "Drop a crash folder, Report.wer, CrashContext.runtime-xml, Player.log or a user-mode .dmp.",
                );
                if let Some(note) = note {
                    ui.label(RichText::new(note.as_str()).small().weak());
                }
                return;
            }
            Analysis::Empty => {
                if self.path.is_some() {
                    ui.heading("No incidents found in scanned logs");
                } else {
                    ui.label("Waiting for a crash artifact ...");
                }
                return;
            }
            Analysis::Results { .. } => {}
        }

        let incidents = {
            self.refresh_visible();
            &self.cached_visible
        };
        if incidents.is_empty() {
            ui.label(self.empty_incidents_message());
            return;
        }
        if self.selected >= incidents.len() {
            self.selected = 0;
        }
        let Some(incident) = incidents.get(self.selected) else {
            ui.label("Select an incident on the left, or show hidden apps.");
            return;
        };
        let hide_key = app_key(&incident.title);

        ui.heading(incident.time.format("%Y-%m-%d %H:%M:%S").to_string());
        if let Some(frequency) = crate::report::frequency_label(incident) {
            ui.label(RichText::new(frequency).small().weak());
        }
        ui.horizontal(|ui| {
            ui.label(RichText::new(&incident.title).weak());
            if ui.small_button("Hide events from this app").clicked() {
                if !self.hidden_apps.contains(&hide_key) {
                    self.hidden_apps.push(hide_key.clone());
                }
                self.selected = 0;
                self.copied = false;
                self.cache_dirty = true;
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
                ui.label(
                    RichText::new(format!("score {}", finding.score))
                        .small()
                        .weak(),
                );
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
            "Read-Only | 0 Admin | No Drivers | User-space .dmp | v{}",
            env!("CARGO_PKG_VERSION")
        ));
        ui.separator();
        ui.label(&self.status);
        if self.watching_active && self.path.is_none() {
            ui.separator();
            ui.label(RichText::new("Watching crash folders").small().weak());
        }
        ui.separator();
        ui.label(format!(
            "Showing {} / {} incident(s)",
            self.cached_visible.len(),
            self.total_incidents()
        ));
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

        let received = self.receiver.as_ref().map(|receiver| receiver.try_recv());
        match received {
            Some(Ok((analysis, ctx))) => {
                self.receiver = None;
                self.finish_scan(analysis, ctx);
            }
            Some(Err(TryRecvError::Disconnected)) => {
                self.receiver = None;
                self.scanning = false;
                self.pending_path = None;
                self.rescan_queued = false;
                self.status = "Scan failed: worker thread disconnected".to_owned();
            }
            Some(Err(TryRecvError::Empty)) | None => {}
        }
        self.poll_watcher_setup(ui.ctx());
        self.refresh_visible();
        self.poll_watcher(ui.ctx());
        if self.scanning {
            ui.ctx()
                .request_repaint_after(StdDuration::from_millis(120));
        }

        egui::containers::Panel::top("header").show(ui, |ui| {
            self.header(ui);
        });
        // A day switch in the header must reach the status bar in this frame.
        self.refresh_visible();
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
            repeat_count: 1,
            first_seen: None,
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
        incident.findings[0]
            .evidence
            .push("2026-11-25 10:00:05 | eventlog | nvlddmkm | GPUID=10de:1b06".to_owned());
        assert!(matches_filter(IncidentFilter::GamesAndGpu, "", &incident));
    }

    fn idle_app() -> App {
        App {
            ctx: SystemContext::default(),
            analysis: Analysis::Empty,
            selected: 0,
            days: Some(7),
            path: None,
            pending: None,
            pending_path: None,
            status: String::new(),
            logo: None,
            copied: false,
            scanning: false,
            rescan_queued: false,
            receiver: None,
            watcher: None,
            watch_rx: None,
            watcher_setup: None,
            debounce_deadline: None,
            watching_active: false,
            hidden_apps: Vec::new(),
            filter: IncidentFilter::default(),
            search_query: String::new(),
            cached_visible: Vec::new(),
            cache_dirty: true,
        }
    }

    #[test]
    fn visible_cache_honours_filters_without_recomputing_when_clean() {
        let mut app = idle_app();
        app.analysis = Analysis::Results {
            incidents: vec![bsod_incident()],
            note: None,
        };
        app.refresh_visible();
        assert_eq!(app.cached_visible.len(), 1);
        assert!(!app.cache_dirty);

        // No input changed: the cached list is reused untouched.
        app.refresh_visible();
        assert_eq!(app.cached_visible.len(), 1);

        app.filter = IncidentFilter::GamesAndGpu;
        app.cache_dirty = true;
        app.refresh_visible();
        assert!(
            app.cached_visible.is_empty(),
            "a BSOD must not survive the Games/GPU filter"
        );
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
        app.finish_scan(Analysis::Empty, SystemContext::default());
        assert_eq!(
            app.path,
            Some(PathBuf::from("old-root")),
            "finish_scan must not overwrite a pending drop"
        );
        assert_eq!(
            app.next_root(),
            (PathBuf::from("new-root"), true),
            "a dropped path is a manual root"
        );
    }

    #[test]
    fn watcher_accepts_only_crash_artifacts() {
        for path in [
            r"Local\Microsoft\Windows\WER\ReportArchive\Report.wer",
            r"Local\MyGame\Saved\Crashes\CrashContext.runtime-xml",
            r"LocalLow\Studio\Game\Player.log",
            r"Local\CrashDumps\game.exe.1234.dmp",
        ] {
            assert!(
                is_relevant_watch_path(Path::new(path)),
                "must accept {path}"
            );
        }

        for path in [
            r"Local\Google\Chrome\User Data\Default\Cache\f_000001",
            r"Local\Temp\something.tmp",
            r"Local\Docs\notes.txt",
            r"LocalLow\Studio\other.log",
        ] {
            assert!(
                !is_relevant_watch_path(Path::new(path)),
                "must reject {path}"
            );
        }
    }

    #[test]
    fn crash_context_xml_is_detected_by_content_when_the_name_is_generic() {
        let unique = format!(
            "framefault-watch-{}-{}.xml",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock")
                .as_nanos()
        );
        let path = std::env::temp_dir().join(unique);

        std::fs::write(
            &path,
            "<CrashContext><ErrorMessage>boom</ErrorMessage></CrashContext>",
        )
        .expect("write crash context");
        let accepted = is_relevant_watch_path(&path);

        std::fs::write(&path, "<notes>nothing to see</notes>").expect("write notes");
        let rejected = is_relevant_watch_path(&path);

        let _ = std::fs::remove_file(&path);
        assert!(accepted, "content with <CrashContext> must be accepted");
        assert!(!rejected, "ordinary XML must be rejected");
    }
}
