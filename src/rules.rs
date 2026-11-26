use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct RuleSet {
    pub version: u8,
    pub window_sec: i64,
    pub rules: Vec<Rule>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Rule {
    pub id: String,
    pub source: String,
    /// Also match these sources in addition to `source` (e.g. Unity Player.log).
    pub source_any: Option<Vec<String>>,
    pub channel: Option<String>,
    pub provider: Option<String>,
    pub provider_any: Option<Vec<String>>,
    pub event_id: Option<u16>,
    pub event_id_any: Option<Vec<u16>>,
    pub match_field: Option<String>,
    pub match_value: Option<String>,
    pub match_contains: Option<String>,
    pub match_any: Option<Vec<String>>,
    pub weight: i32,
    pub verdict: String,
    pub confidence: String,
    #[serde(default)]
    pub next_steps: Vec<String>,
    pub link: Option<String>,
    pub note: Option<String>,
}

impl Rule {
    pub fn matches(&self, signal: &crate::model::Signal) -> bool {
        let source_ok = self.source == signal.source
            || self
                .source_any
                .as_ref()
                .is_some_and(|sources| sources.iter().any(|s| s.as_str() == signal.source));
        if !source_ok {
            return false;
        }
        if let Some(channel) = &self.channel {
            if signal.get("channel") != Some(channel.as_str()) {
                return false;
            }
        }
        if let Some(provider) = &self.provider {
            if !signal.provider.eq_ignore_ascii_case(provider) {
                return false;
            }
        }
        if let Some(providers) = &self.provider_any {
            if !providers
                .iter()
                .any(|p| signal.provider.eq_ignore_ascii_case(p))
            {
                return false;
            }
        }
        if let Some(id) = self.event_id {
            if signal.event_id != Some(id) {
                return false;
            }
        }
        if let Some(ids) = &self.event_id_any {
            if signal.event_id.is_none_or(|v| !ids.contains(&v)) {
                return false;
            }
        }

        if self.match_field.as_deref() == Some("LoadedModule") {
            return self.match_loaded_modules(signal);
        }

        // A named field is strict: a missing bIsOOM must not fall back to the
        // whole detail and match an unrelated "IsEnsure=true".
        let haystack = match self.match_field.as_deref() {
            None | Some("detail") => &signal.detail,
            Some(field) => match signal.get(field) {
                Some(value) => value,
                None => return false,
            },
        }
        .to_ascii_lowercase();

        if let Some(value) = &self.match_value {
            if !haystack.contains(&value.to_ascii_lowercase()) {
                return false;
            }
        }
        if let Some(value) = &self.match_contains {
            if !haystack.contains(&value.to_ascii_lowercase()) {
                return false;
            }
        }
        if let Some(values) = &self.match_any {
            if !values
                .iter()
                .any(|v| haystack.contains(&v.to_ascii_lowercase()))
            {
                return false;
            }
        }
        true
    }

    fn match_loaded_modules(&self, signal: &crate::model::Signal) -> bool {
        let Some(names) = &self.match_any else {
            return false;
        };
        signal.loaded_modules.iter().any(|path| {
            let name = path.rsplit(['\\', '/']).next().unwrap_or("");
            if !names.iter().any(|n| n.eq_ignore_ascii_case(name)) {
                return false;
            }
            // CORRECT: system32/SysWOW64 dxgi.dll / d3d*.dll are NOT overlays.
            !(crate::sources::wer::is_system_dll_name(name)
                && crate::sources::wer::is_system_dll_path(path))
        })
    }

    pub fn verdict_for(&self, signal: &crate::model::Signal) -> String {
        if self.id == "application_error_1000" {
            return headline(signal).unwrap_or_else(|| self.verdict.clone());
        }
        // Kernel-Power 41 is a BSOD only when Windows recorded a non-zero
        // bugcheck code. Code 0 (or no code) is a plain sudden power loss
        // and must keep the rule's own verdict.
        if self.id == "kernel_power_41" {
            return match bugcheck_code(signal) {
                Some(code) if code != 0 => {
                    bugcheck_headline(signal).unwrap_or_else(|| self.verdict.clone())
                }
                _ => self.verdict.clone(),
            };
        }
        if self.id == "bugcheck_1001" {
            return bugcheck_headline(signal).unwrap_or_else(|| self.verdict.clone());
        }
        self.verdict.clone()
    }
}

fn detail_field(detail: &str, label: &str) -> Option<String> {
    let from = detail.find(label)? + label.len();
    let rest = detail[from..].trim_start();
    let end = rest.find([',', '\n', '\r', ';']).unwrap_or(rest.len());
    Some(rest[..end].trim().to_owned())
}

/// Short, human headline for Application Error 1000: process, code, module.
pub fn headline(signal: &crate::model::Signal) -> Option<String> {
    let app = signal
        .get("FaultingApplicationName")
        .or_else(|| signal.get("ApplicationName"))
        .or_else(|| signal.get("AppName"))
        .map(str::to_owned)
        .or_else(|| detail_field(&signal.detail, "Faulting application name:"));
    let module = signal
        .get("FaultingModuleName")
        .or_else(|| signal.get("ModuleName"))
        .or_else(|| signal.get("FaultingModule"))
        .map(str::to_owned)
        .or_else(|| detail_field(&signal.detail, "Faulting module name:"));
    let code = signal
        .get("ExceptionCode")
        .map(|value| {
            if value.starts_with("0x") || value.starts_with("0X") {
                value.to_owned()
            } else {
                format!("0x{value}")
            }
        })
        .or_else(|| detail_field(&signal.detail, "Exception code:"));

    if app.is_none() && module.is_none() && code.is_none() {
        return None;
    }
    let process = app.unwrap_or_else(|| "?".to_owned());
    let module = module.unwrap_or_else(|| "?".to_owned());
    if let Some(raw_code) = code {
        if let Some(value) = crate::codes::parse_code(&raw_code) {
            let (name, _) = crate::codes::decode_exception(value);
            return Some(format!("{process} - 0x{value:08X} {name} ({module})"));
        }
        return Some(format!("{process} - {raw_code} ({module})"));
    }
    Some(format!("{process} - ? ({module})"))
}

/// Decimal code after an explicit BugcheckCode label; `=` and `:` are valid
/// separators in Event XML, a space in wevtutil text output.
fn labelled_bugcheck(text: &str) -> Option<u32> {
    ["BugcheckCode", "BugCheckCode", "Bugcheck code"]
        .iter()
        .find_map(|label| {
            let index = text.find(label)?;
            let rest = text[index + label.len()..]
                .trim_start_matches(|c: char| c == '=' || c == ':' || c.is_whitespace());
            let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
            digits.parse::<u32>().ok().filter(|code| *code > 0)
        })
}

/// Short, human headline for a bugcheck: decoded stop code.
pub fn bugcheck_code(signal: &crate::model::Signal) -> Option<u32> {
    // The explicit field is authoritative. BugcheckParameter1=0x... must never
    // win over BugcheckCode=59.
    if let Some(raw) = signal.get("BugcheckCode") {
        let raw = raw.trim();
        return raw
            .parse::<u32>()
            .ok()
            .or_else(|| crate::codes::parse_code(raw))
            .filter(|code| *code > 0);
    }
    if let Some(code) = labelled_bugcheck(&signal.detail) {
        return Some(code);
    }
    crate::codes::parse_code(&signal.detail)
}

pub fn bugcheck_headline(signal: &crate::model::Signal) -> Option<String> {
    bugcheck_code(signal).map(crate::codes::format_bugcheck)
}

pub fn load() -> RuleSet {
    let set: RuleSet =
        toml::from_str(include_str!("../rules.toml")).expect("rules.toml must be valid");
    assert_eq!(set.version, 1, "unsupported rules.toml version");
    set
}
