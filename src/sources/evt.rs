use chrono::{DateTime, Local, NaiveDateTime, TimeZone};

use crate::model::Signal;

const IDS: &str = "EventID=153 or EventID=4101 or EventID=2004 or EventID=1000 \
                   or EventID=1001 or EventID=41 or EventID=17 or EventID=18 or EventID=19";

/// Shortens detail at a word boundary, so Raw Proof and reports never end
/// with half tokens like `F…` or `0…`.
pub const DETAIL_LIMIT: usize = 512;

/// Cap per Event Log channel. A noisy service in Application must not push
/// the System events (TDR, WHEA, BugCheck) out of the scan.
const EVENT_LIMIT: usize = 300;

pub fn excerpt(text: &str, max: usize) -> String {
    let flat: String = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if flat.chars().count() <= max {
        return flat;
    }
    let mut head: String = flat.chars().take(max).collect();
    if let Some(boundary) = head.rfind(' ') {
        head.truncate(boundary);
    }
    format!("{head}…")
}

#[cfg(windows)]
pub fn read_recent() -> Vec<Signal> {
    use windows::core::{HSTRING, PCWSTR};
    use windows::Win32::System::EventLog::{
        EvtClose, EvtNext, EvtQuery, EvtQueryReverseDirection, EVT_HANDLE,
    };

    let xpath = format!("*[System[{IDS}]]");
    let query = HSTRING::from(xpath.as_str());
    let mut out = Vec::new();
    for channel in ["System", "Application"] {
        let channel_name = HSTRING::from(channel);
        let mut per_channel = Vec::new();
        unsafe {
            let handle = match EvtQuery(
                None,
                PCWSTR(channel_name.as_ptr()),
                PCWSTR(query.as_ptr()),
                EvtQueryReverseDirection.0,
            ) {
                Ok(handle) => handle,
                Err(_) => continue,
            };

            let mut batch = [0isize; 64];
            let mut returned = 0u32;
            'events: loop {
                if EvtNext(handle, &mut batch, 0, 0, &mut returned).is_err() {
                    break 'events;
                }
                if returned == 0 {
                    break 'events;
                }
                for (index, event) in batch.iter().take(returned as usize).enumerate() {
                    if let Some(xml) = render_xml(EVT_HANDLE(*event)) {
                        per_channel.extend(parse_xml(&xml, channel));
                    }
                    let _ = EvtClose(EVT_HANDLE(*event));
                    if per_channel.len() >= EVENT_LIMIT {
                        // EvtNext returned a whole batch: close the handles we
                        // never got to before leaving the loop.
                        for pending in batch
                            .iter()
                            .skip(index + 1)
                            .take(returned as usize - index - 1)
                        {
                            let _ = EvtClose(EVT_HANDLE(*pending));
                        }
                        break 'events;
                    }
                }
            }
            let _ = EvtClose(handle);
        }
        out.extend(per_channel.into_iter().take(EVENT_LIMIT));
    }
    out
}

#[cfg(not(windows))]
pub fn read_recent() -> Vec<Signal> {
    Vec::new()
}

/// Event XML stores `2026-11-15T12:58:17.2999703Z`; the header only needs minutes.
fn short_time(raw: &str) -> String {
    let bytes = raw.as_bytes();
    if bytes.len() >= 16
        && bytes.get(4) == Some(&b'-')
        && bytes.get(7) == Some(&b'-')
        && bytes.get(10) == Some(&b'T')
        && bytes[11..13].iter().all(u8::is_ascii_digit)
        && bytes.get(13) == Some(&b':')
        && bytes[14..16].iter().all(u8::is_ascii_digit)
    {
        return format!("{} {}", &raw[..10], &raw[11..16]);
    }
    raw.to_owned()
}

/// Honest ring-buffer depth, read natively (forward direction = oldest first).
pub fn log_reach() -> String {
    #[cfg(windows)]
    {
        use windows::core::{HSTRING, PCWSTR};
        use windows::Win32::System::EventLog::{
            EvtClose, EvtNext, EvtQuery, EvtQueryChannelPath, EvtQueryForwardDirection, EVT_HANDLE,
        };

        let xpath = format!("*[System[{IDS}]]");
        let query = HSTRING::from(xpath.as_str());
        let mut parts = Vec::new();
        for channel in ["System", "Application"] {
            let name = HSTRING::from(channel);
            unsafe {
                let handle = match EvtQuery(
                    None,
                    PCWSTR(name.as_ptr()),
                    PCWSTR(query.as_ptr()),
                    EvtQueryChannelPath.0 | EvtQueryForwardDirection.0,
                ) {
                    Ok(handle) => handle,
                    Err(_) => {
                        parts.push(format!("{channel} -> unavailable"));
                        continue;
                    }
                };
                let mut batch = [0isize; 1];
                let mut returned = 0u32;
                let mut line = format!("{channel} -> unavailable");
                if EvtNext(handle, &mut batch, 0, 0, &mut returned).is_ok() && returned == 1 {
                    if let Some(xml) = render_xml(EVT_HANDLE(batch[0])) {
                        if let Some(time) = attribute(&xml, "<TimeCreated ", "SystemTime=") {
                            line = format!("{channel} -> {}", short_time(&time));
                        }
                    }
                    let _ = EvtClose(EVT_HANDLE(batch[0]));
                }
                let _ = EvtClose(handle);
                parts.push(line);
            }
        }
        parts.join(" | ")
    }
    #[cfg(not(windows))]
    {
        "unavailable".to_owned()
    }
}

#[cfg(windows)]
unsafe fn render_xml(event: windows::Win32::System::EventLog::EVT_HANDLE) -> Option<String> {
    use windows::Win32::System::EventLog::{EvtRender, EvtRenderEventXml};

    let mut used = 0u32;
    let mut count = 0u32;
    // Render directly into a generous buffer. The two-call ""size probe"" was
    // unreliable for the oldest-record query and produced ""unavailable"".
    let mut buffer = vec![0u8; 131_072];
    EvtRender(
        None,
        event,
        EvtRenderEventXml.0,
        buffer.len() as u32,
        Some(buffer.as_mut_ptr() as *mut core::ffi::c_void),
        &mut used,
        &mut count,
    )
    .ok()?;
    buffer.truncate(used as usize);
    let units: Vec<u16> = buffer
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    Some(String::from_utf16_lossy(&units))
}

#[cfg(feature = "evtx")]
pub fn scan_evtx(path: &std::path::Path) -> Vec<Signal> {
    // Optional fallback: exported .evtx files are read through wevtutil /lf:true.
    let xpath = format!("*[System[{}]]", IDS);
    let query = format!("/q:{xpath}");
    let mut command = std::process::Command::new("wevtutil");
    command.args([
        "qe",
        "/lf:true",
        &path.to_string_lossy(),
        "/c:300",
        "/rd:true",
        "/f:text",
        query.as_str(),
    ]);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x0800_0000);
    }
    match command.output() {
        Ok(output) => parse_text(&String::from_utf8_lossy(&output.stdout), "evtx"),
        Err(_) => Vec::new(),
    }
}

/// Index of the tag-closing '>', ignoring '>' inside quoted attribute values.
fn find_tag_end(text: &str) -> Option<usize> {
    let mut quote: Option<char> = None;
    for (index, ch) in text.char_indices() {
        match quote {
            Some(q) if ch == q => quote = None,
            Some(_) => {}
            None if ch == '"' || ch == '\'' => quote = Some(ch),
            None if ch == '>' => return Some(index),
            None => {}
        }
    }
    None
}

fn attribute(xml: &str, start: &str, key: &str) -> Option<String> {
    let from = xml.find(start)? + start.len();
    let rest = &xml[from..];
    // Never read past this tag's '>': an unnamed <Data> must not borrow the
    // Name= attribute of the following tag. A raw '>' inside quotes is legal
    // XML and must not end the tag early.
    let tag_end = find_tag_end(rest)?;
    let segment = &rest[..tag_end];
    let value_start = segment.find(key)? + key.len();
    let rest = &segment[value_start..];
    let quote = rest.chars().next()?;
    if quote != '"' && quote != '\'' {
        return None;
    }
    let end = rest[1..].find(quote)? + 1;
    Some(rest[1..end].to_owned())
}

fn tag_value(xml: &str, tag: &str) -> Option<String> {
    let from = xml.find(tag)? + tag.len();
    let rest = &xml[from..];
    let gt = rest.find('>')? + 1;
    let end = rest[gt..].find("</")? + gt;
    Some(rest[gt..end].trim().to_owned())
}

fn parse_xml(text: &str, channel: &str) -> Vec<Signal> {
    let mut signals = Vec::new();
    let positions: Vec<usize> = text.match_indices("<Event ").map(|(i, _)| i).collect();

    for (index, start) in positions.iter().enumerate() {
        let end = positions.get(index + 1).copied().unwrap_or(text.len());
        let chunk = &text[*start..end];

        let provider = attribute(chunk, "<Provider ", "Name=")
            .unwrap_or_else(|| "Unknown".to_owned());
        let event_id = tag_value(chunk, "<EventID")
            .and_then(|value| value.trim_start_matches('>').parse::<u16>().ok());
        let time = attribute(chunk, "<TimeCreated ", "SystemTime=")
            .and_then(|value| parse_time(&value))
            .unwrap_or_else(Local::now);

        let mut signal = Signal::new("eventlog", time);
        signal.provider = provider;
        signal.event_id = event_id;
        signal
            .fields
            .insert("channel".to_owned(), channel.to_owned());

        let mut detail = String::new();
        for (data_index, (offset, _)) in chunk.match_indices("<Data").enumerate() {
            let rest = &chunk[offset..];
            let Some(gt) = find_tag_end(rest) else { continue };
            let Some(close) = rest[gt + 1..].find("</Data>") else { continue };
            let value = rest[gt + 1..gt + 1 + close].trim().to_owned();
            if value.is_empty() {
                continue;
            }
            let name = attribute(rest, "<Data", "Name=");
            match name {
                Some(name) => {
                    detail.push_str(&format!("{name}={value}\n"));
                    signal.fields.insert(name, value);
                }
                None => detail.push_str(&format!("Data[{}]={}\n", data_index, value)),
            }
        }
        if detail.is_empty() {
            detail = tag_value(chunk, "<EventData>").unwrap_or_default();
        }
        signal.detail = detail;
        signals.push(signal);
    }
    signals
}

/// Kept as a text fallback for fixtures and older captured logs.
pub fn parse_text(text: &str, channel: &str) -> Vec<Signal> {
    let mut signals = Vec::new();
    let mut current: Option<Builder> = None;
    for raw in text.lines() {
        let line = raw.trim();
        if line.starts_with("Event[") {
            if let Some(builder) = current.take() {
                if let Some(signal) = builder.finish() {
                    signals.push(signal);
                }
            }
            current = Some(Builder::new(channel));
            continue;
        }
        if let Some(builder) = current.as_mut() {
            builder.push_line(line);
        }
    }
    if let Some(builder) = current {
        if let Some(signal) = builder.finish() {
            signals.push(signal);
        }
    }
    signals
}

struct Builder {
    signal: Signal,
    time: Option<DateTime<Local>>,
    provider: String,
    event_id: Option<u16>,
    detail: String,
    channel: String,
}

impl Builder {
    fn new(channel: &str) -> Self {
        Self {
            signal: Signal::new("eventlog", Local::now()),
            time: None,
            provider: String::new(),
            event_id: None,
            detail: String::new(),
            channel: channel.to_owned(),
        }
    }

    fn push_line(&mut self, line: &str) {
        self.detail.push_str(line);
        self.detail.push('\n');
        if let Some(value) = line.strip_prefix("Source:") {
            self.provider = value.trim().to_owned();
        } else if let Some(value) = line.strip_prefix("Event ID:") {
            self.event_id = value.trim().parse::<u16>().ok();
        } else if let Some(value) = line.strip_prefix("Date:") {
            self.time = parse_time(value.trim());
        }
    }

    fn finish(mut self) -> Option<Signal> {
        self.signal.t = self.time?;
        self.signal.provider = self.provider;
        self.signal.event_id = self.event_id;
        self.signal.detail = self.detail;
        self.signal
            .fields
            .insert("channel".to_owned(), self.channel);
        Some(self.signal)
    }
}

fn parse_time(value: &str) -> Option<DateTime<Local>> {
    let value = value.trim_end_matches('Z');
    let naive = NaiveDateTime::parse_from_str(value, "%Y-%m-%dT%H:%M:%S%.f").ok()?;
    Local.from_local_datetime(&naive).single()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn excerpt_cuts_on_a_word_boundary() {
        let text = "one two three four five six seven eight nine ten";
        assert_eq!(excerpt(text, 20), "one two three four…");
        assert_eq!(excerpt("short detail", 40), "short detail");
    }

    #[test]
    fn unnamed_data_does_not_borrow_the_next_data_name() {
        let xml = r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System>
<Provider Name="Application Error" />
<EventID>1000</EventID>
<TimeCreated SystemTime="2026-11-20T10:11:12.0000000Z" />
</System>
<EventData>
<Data>Unexpected</Data>
<Data Name="ExceptionCode">e06d7363</Data>
</EventData>
</Event>"#;
        let signals = parse_xml(xml, "Application");
        assert_eq!(signals.len(), 1);
        let signal = &signals[0];
        assert!(
            signal.detail.contains("Data[0]=Unexpected"),
            "detail: {}",
            signal.detail
        );
        assert!(
            !signal.detail.contains("ExceptionCode=Unexpected"),
            "Name leaked backwards: {}",
            signal.detail
        );
        assert_eq!(signal.get("ExceptionCode"), Some("e06d7363"));
    }

    #[test]
    fn greater_than_inside_quoted_attributes_is_not_a_tag_end() {
        let xml = r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System>
<Provider Name="Game > Test" />
<EventID>1000</EventID>
<TimeCreated SystemTime="2026-11-20T10:11:12.0000000Z" />
</System>
<EventData>
<Data Name="Side > Info">value</Data>
</EventData>
</Event>"#;
        let signals = parse_xml(xml, "Application");
        assert_eq!(signals.len(), 1);
        let signal = &signals[0];
        assert_eq!(signal.provider, "Game > Test", "provider: {}", signal.provider);
        assert_eq!(signal.get("Side > Info"), Some("value"));
        assert!(
            signal.detail.contains("Side > Info=value"),
            "detail: {}",
            signal.detail
        );
    }

    #[test]
    fn empty_xml_data_fields_are_not_written_to_detail() {
        let xml = r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System>
<Provider Name="Application Error" />
<EventID>1000</EventID>
<TimeCreated SystemTime="2026-11-20T10:11:12.0000000Z" />
</System>
<EventData>
<Data Name="PackageFullName"></Data>
<Data Name="PackageRelativeAppId">   </Data>
<Data Name="FaultingApplicationName">Game.exe</Data>
<Data Name="ExceptionCode">e06d7363</Data>
</EventData>
</Event>"#;

        let signals = parse_xml(xml, "Application");
        assert_eq!(signals.len(), 1);
        let signal = &signals[0];
        assert!(
            !signal.detail.contains("PackageFullName="),
            "detail: {}",
            signal.detail
        );
        assert!(
            !signal.detail.contains("PackageRelativeAppId="),
            "detail: {}",
            signal.detail
        );
        assert!(!signal.fields.contains_key("PackageFullName"));
        assert!(signal.detail.contains("FaultingApplicationName=Game.exe"));
        assert_eq!(signal.get("ExceptionCode"), Some("e06d7363"));
    }
}
