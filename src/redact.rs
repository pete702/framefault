//! Irreversible redaction for forum posts. Characters are destroyed, not blurred.
//! Hardware facts (game, Windows build, GPU driver, RAM/pagefile, MPO, overlay DLL
//! names) are deliberately kept because they are what makes a report useful.

pub fn redact(input: &str) -> String {
    let mut out = input.to_string();
    out = mask_file_urls(&out);
    out = mask_profile_paths(&out);
    out = mask_emails(&out);
    out = mask_steam_ids(&out);
    out = mask_keyed_ids(&out);
    out = mask_guid(&out);
    out = mask_hex_ids(&out);
    out = mask_mac(&out);
    out = mask_sid(&out);
    out = mask_ipv6(&out);
    out = mask_ipv4(&out);
    out = mask_env_secret(&out, "USERNAME", "[REDACTED-USER]");
    out = mask_env_secret(&out, "COMPUTERNAME", "[REDACTED-HOST]");
    out = mask_serialish(&out);
    out
}

fn is_token_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

fn mask_env_secret(input: &str, var: &str, replacement: &str) -> String {
    let Ok(value) = std::env::var(var) else {
        return input.to_string();
    };
    if value.len() < 3 {
        return input.to_string();
    }
    // Replace the identity only as a standalone token. A blunt substring
    // replace corrupts unrelated handles and URLs (e.g. `pete7` inside
    // `pete702` in a GitHub link).
    let chars: Vec<char> = input.chars().collect();
    let needle: Vec<char> = value.chars().collect();
    let mut out = String::with_capacity(input.len());
    let mut i = 0usize;
    while i < chars.len() {
        if chars[i..].starts_with(&needle) {
            let before_ok = i == 0 || !is_token_char(chars[i - 1]);
            let after = i + needle.len();
            let after_ok = after == chars.len() || !is_token_char(chars[after]);
            if before_ok && after_ok {
                out.push_str(replacement);
                i = after;
                continue;
            }
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

fn find_ascii_ci(haystack: &str, needle: &str, from: usize) -> Option<usize> {
    let slice = haystack.get(from..)?;
    slice
        .to_ascii_lowercase()
        .find(&needle.to_ascii_lowercase())
        .map(|offset| from + offset)
}

fn mask_profile_paths(input: &str) -> String {
    let mut out = mask_unc_servers(input);
    // Windows is case-insensitive: C:\users\alice must be masked too.
    for marker in [
        "\\Users\\",
        "/Users/",
        "\\Documents and Settings\\",
        "/Documents and Settings/",
    ] {
        let mut cursor = 0usize;
        while let Some(relative) = find_ascii_ci(&out, marker, cursor) {
            let name_start = relative + marker.len();
            let end = out[name_start..]
                .find(['\\', '/'])
                .map(|offset| name_start + offset)
                .unwrap_or(out.len());
            out.replace_range(name_start..end, "%USERPROFILE%");
            cursor = name_start + "%USERPROFILE%".len();
        }
    }
    out
}

fn is_path_delimiter(c: char) -> bool {
    c.is_whitespace() || matches!(c, '"' | '\'' | '`' | ',' | ';' | ')' | ']' | '}' | '|')
}

fn mask_file_urls(input: &str) -> String {
    const REPLACEMENT: &str = "[REDACTED-FILE-URL]";
    let lower = input.to_ascii_lowercase();
    let mut out = String::with_capacity(input.len());
    let mut cursor = 0usize;
    while let Some(relative) = lower[cursor..].find("file://") {
        let start = cursor + relative;
        out.push_str(&input[cursor..start]);
        let body_start = start + "file://".len();
        let end = input[body_start..]
            .find(is_path_delimiter)
            .map(|offset| body_start + offset)
            .unwrap_or(input.len());
        out.push_str(REPLACEMENT);
        cursor = end;
    }
    out.push_str(&input[cursor..]);
    out
}

fn is_email_local_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '%' | '+' | '-')
}

fn is_email_trailing_punctuation(c: char) -> bool {
    matches!(c, '.' | ',' | ';' | ':' | ')' | '"' | '\'')
}

fn mask_emails(input: &str) -> String {
    let chars: Vec<char> = input.chars().collect();
    let mut out = String::with_capacity(input.len());
    let mut i = 0usize;
    while i < chars.len() {
        if is_email_local_char(chars[i]) {
            let start = i;
            while i < chars.len() && is_email_local_char(chars[i]) {
                i += 1;
            }
            if i < chars.len() && chars[i] == '@' {
                let mut end = i + 1;
                while end < chars.len()
                    && (chars[end].is_ascii_alphanumeric() || matches!(chars[end], '.' | '-'))
                {
                    end += 1;
                }
                // Sentence punctuation belongs outside the marker, so validate
                // the bare domain and re-emit the suffix afterwards.
                let mut domain_end = end;
                while domain_end > i + 1 && is_email_trailing_punctuation(chars[domain_end - 1]) {
                    domain_end -= 1;
                }
                let domain: String = chars[i + 1..domain_end].iter().collect();
                let suffix: String = chars[domain_end..end].iter().collect();
                let valid = domain.contains('.')
                    && !domain.starts_with('.')
                    && !domain.ends_with('.')
                    && domain.chars().any(|c| c.is_ascii_alphabetic());
                if valid {
                    out.push_str("[REDACTED-EMAIL]");
                    out.push_str(&suffix);
                    i = end;
                    continue;
                }
            }
            out.extend(chars[start..i].iter());
            continue;
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

fn preceded_by_name(chars: &[char], start: usize, key: &str) -> bool {
    let key_chars: Vec<char> = key.chars().collect();
    start >= key_chars.len()
        && chars[start - key_chars.len()..start]
            .iter()
            .collect::<String>()
            .eq_ignore_ascii_case(key)
}

/// 32-char hex IDs (EpicAccountId/MachineId style), but never `0x` offsets,
/// ProcessCreationTime, or dotted version values.
fn mask_hex_ids(input: &str) -> String {
    let chars: Vec<char> = input.chars().collect();
    let mut out = String::with_capacity(input.len());
    let mut i = 0usize;
    while i < chars.len() {
        if chars[i].is_ascii_hexdigit() {
            let start = i;
            while i < chars.len() && chars[i].is_ascii_hexdigit() {
                i += 1;
            }
            let boundary_before = start == 0 || !chars[start - 1].is_ascii_alphanumeric();
            let boundary_after = i == chars.len() || !chars[i].is_ascii_alphanumeric();
            let hex_prefix =
                start >= 2 && chars[start - 2] == '0' && matches!(chars[start - 1], 'x' | 'X');
            let ignored_key = preceded_by_name(&chars, start, "FaultingOffset=")
                || preceded_by_name(&chars, start, "ProcessCreationTime=");
            if i - start == 32 && boundary_before && boundary_after && !hex_prefix && !ignored_key {
                out.push_str("[REDACTED-ID]");
            } else {
                out.extend(chars[start..i].iter());
            }
            continue;
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

/// SteamID64 is always 17 digits and starts with the public universe prefix.
fn mask_steam_ids(input: &str) -> String {
    let chars: Vec<char> = input.chars().collect();
    let mut out = String::with_capacity(input.len());
    let mut i = 0usize;
    while i < chars.len() {
        if chars[i].is_ascii_digit() {
            let start = i;
            while i < chars.len() && chars[i].is_ascii_digit() {
                i += 1;
            }
            let token: String = chars[start..i].iter().collect();
            let boundary_before = start == 0 || !is_token_char(chars[start - 1]);
            let boundary_after = i == chars.len() || !is_token_char(chars[i]);
            if token.len() == 17
                && token.starts_with("7656119")
                && boundary_before
                && boundary_after
            {
                out.push_str("[REDACTED-STEAMID]");
            } else {
                out.push_str(&token);
            }
            continue;
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

/// Account identifiers after a labelled key (`LoginId`, `AccountId`,
/// `SteamId`), whatever their length/format. Whitespace/tabs are allowed
/// before and after `=`.
fn mask_keyed_ids(input: &str) -> String {
    const KEYS: [&str; 3] = ["LoginId", "AccountId", "SteamId"];
    const REPLACEMENT: &str = "[REDACTED-ID]";
    let mut out = input.to_string();
    for key in KEYS {
        let mut cursor = 0usize;
        while let Some(relative) = find_ascii_ci(&out, key, cursor) {
            let boundary_ok = relative == 0
                || !out[..relative]
                    .chars()
                    .next_back()
                    .is_some_and(is_token_char);
            if !boundary_ok {
                cursor = relative + key.len();
                continue;
            }
            let after_key = relative + key.len();
            // Optional spaces/tabs before the `=` sign ("LoginId = abc123").
            let rest = &out[after_key..];
            let before_eq = after_key + (rest.len() - rest.trim_start_matches([' ', '\t']).len());
            if out.as_bytes().get(before_eq) != Some(&b'=') {
                cursor = after_key;
                continue;
            }
            let value_base = before_eq + 1;
            let rest = &out[value_base..];
            let skipped = rest.len() - rest.trim_start_matches([' ', '\t']).len();
            let mut value_start = value_base + skipped;
            if out
                .as_bytes()
                .get(value_start)
                .is_some_and(|byte| matches!(byte, b'"' | b'\''))
            {
                value_start += 1;
            }
            let value_end = out[value_start..]
                .find(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '-' | '_')))
                .map(|offset| value_start + offset)
                .unwrap_or(out.len());
            if value_end == value_start {
                cursor = value_start;
                continue;
            }
            out.replace_range(value_start..value_end, REPLACEMENT);
            cursor = value_start + REPLACEMENT.len();
        }
    }
    out
}

/// An all-digit MAC is only masked when a "MAC"/"Physical" label is nearby;
/// this keeps dates/times such as 26-11-27-10-11-12 intact.
fn has_mac_context(chars: &[char], start: usize, end: usize) -> bool {
    let before_start = start.saturating_sub(32);
    let after_end = (end + 32).min(chars.len());
    let before: String = chars[before_start..start].iter().collect();
    let after: String = chars[end..after_end].iter().collect();
    [before, after].iter().any(|text| {
        text.to_ascii_lowercase()
            .split(|c: char| !c.is_ascii_alphabetic())
            .any(|word| word == "mac" || word == "physical")
    })
}

/// Dash- or colon-separated MAC address (`AA-BB-CC-DD-EE-FF` / `AA:BB:CC:DD:EE:FF`).
fn mask_mac(input: &str) -> String {
    const REPLACEMENT: &str = "[REDACTED-MAC]";
    let chars: Vec<char> = input.chars().collect();
    let mut out = String::with_capacity(input.len());
    let mut i = 0usize;
    while i < chars.len() {
        // Reject mid-sequence starts too: an IPv6 address must never be eaten
        // from its middle as a "MAC".
        let boundary_before =
            i == 0 || (!is_token_char(chars[i - 1]) && !matches!(chars[i - 1], '-' | ':'));
        let candidate = mac_end(&chars, i, '-').or_else(|| mac_end(&chars, i, ':'));
        if let Some(end) = candidate.filter(|_| boundary_before) {
            let has_letter = chars[i..end]
                .iter()
                .any(|character| character.is_ascii_alphabetic());
            let boundary_after = end == chars.len()
                || (!is_token_char(chars[end]) && !matches!(chars[end], '-' | ':'));
            if boundary_after && (has_letter || has_mac_context(&chars, i, end)) {
                out.push_str(REPLACEMENT);
                i = end;
                continue;
            }
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

/// Returns the end index of a six-group, two-hex-digit MAC starting at `start`.
fn mac_end(chars: &[char], start: usize, separator: char) -> Option<usize> {
    let mut i = start;
    for group in 0..6 {
        if group > 0 {
            if chars.get(i) != Some(&separator) {
                return None;
            }
            i += 1;
        }
        let first = *chars.get(i)?;
        let second = *chars.get(i + 1)?;
        if !first.is_ascii_hexdigit() || !second.is_ascii_hexdigit() {
            return None;
        }
        i += 2;
    }
    Some(i)
}

/// Masks the whole UNC path, including every directory and file name after
/// the share — otherwise the last component can still be a username.
fn mask_unc_servers(input: &str) -> String {
    const REPLACEMENT: &str = "[REDACTED-UNC]";
    let mut out = input.to_string();
    for marker in ["\\\\", "//"] {
        let mut cursor = 0usize;
        while let Some(relative) = out[cursor..].find(marker) {
            let start = cursor + relative;
            // `http://` / `https://` are URLs, never UNC paths. A `//` with
            // a colon right before it belongs to a scheme, not a share.
            if start > 0 && out.as_bytes()[start - 1] == b':' {
                cursor = start + marker.len();
                continue;
            }
            let body_start = start + marker.len();
            let mut end = out[body_start..]
                .find(is_path_delimiter)
                .map(|offset| body_start + offset)
                .unwrap_or(out.len());
            // Keep a sentence-final period outside the redaction marker.
            while end > body_start && out.as_bytes()[end - 1] == b'.' {
                end -= 1;
            }
            out.replace_range(start..end, REPLACEMENT);
            cursor = start + REPLACEMENT.len();
        }
    }
    out
}

fn is_ipv6_char(c: char) -> bool {
    c.is_ascii_hexdigit() || c == ':' || c == '.'
}

fn is_hex_group(group: &str) -> bool {
    !group.is_empty() && group.len() <= 4 && group.chars().all(|c| c.is_ascii_hexdigit())
}

fn is_ipv4_tail(group: &str) -> bool {
    let parts: Vec<&str> = group.split('.').collect();
    parts.len() == 4
        && parts.iter().all(|part| {
            !part.is_empty()
                && part.len() <= 3
                && part.chars().all(|c| c.is_ascii_digit())
                && part.parse::<u8>().is_ok()
        })
}

/// Strict IPv6 validation. `HH:MM:SS`, `1.02:03:04` and dash/colon MACs are
/// deliberately rejected; only a real address may be redacted.
fn is_ipv6_address(token: &str) -> bool {
    if token.is_empty() {
        return false;
    }

    if token.contains("::") {
        // Only one `::` compression marker is legal.
        if token.matches("::").count() != 1 {
            return false;
        }
        let Some((left, right)) = token.split_once("::") else {
            return false;
        };
        let left_groups: Vec<&str> = if left.is_empty() {
            Vec::new()
        } else {
            left.split(':').collect()
        };
        let right_groups: Vec<&str> = if right.is_empty() {
            Vec::new()
        } else {
            right.split(':').collect()
        };
        if left_groups.iter().any(|group| group.is_empty())
            || right_groups.iter().any(|group| group.is_empty())
        {
            return false;
        }
        // Keep `E:: 6.4 GiB free` out: a trailing `::` with a single drive
        // letter on the left is a Windows path, not an address. Numeric
        // groups such as `1::` are a valid compressed IPv6.
        if right.is_empty() && !token.starts_with("::") && left_groups.len() == 1 {
            let group = left_groups[0];
            let drive_letter =
                group.len() == 1 && group.chars().all(|c| matches!(c, 'A'..='F' | 'a'..='f'));
            if drive_letter {
                return false;
            }
        }

        let groups: Vec<&str> = left_groups
            .iter()
            .chain(right_groups.iter())
            .copied()
            .collect();
        if groups.is_empty() {
            return true; // "::"
        }

        let mut slots = 0usize;
        for (index, group) in groups.iter().enumerate() {
            let is_last = index + 1 == groups.len();
            if is_last && group.contains('.') {
                // A dotted tail is allowed only as a valid 4-octet IPv4.
                if !is_ipv4_tail(group) {
                    return false;
                }
                slots += 2;
            } else {
                if group.contains('.') || !is_hex_group(group) {
                    return false;
                }
                slots += 1;
            }
        }
        return slots <= 7;
    }

    let groups: Vec<&str> = token.split(':').collect();
    match groups.len() {
        // Eight 1..=4 hex groups.
        8 => groups.iter().all(|group| is_hex_group(group)),
        // Six hex groups plus an IPv4 tail.
        7 => groups[..6].iter().all(|group| is_hex_group(group)) && is_ipv4_tail(groups[6]),
        _ => false,
    }
}

fn mask_ipv6(input: &str) -> String {
    let chars: Vec<char> = input.chars().collect();
    let mut out = String::with_capacity(input.len());
    let mut i = 0usize;
    while i < chars.len() {
        if is_ipv6_char(chars[i]) {
            let start = i;
            while i < chars.len() && is_ipv6_char(chars[i]) {
                i += 1;
            }
            let token: String = chars[start..i].iter().collect();
            // A sentence-final period belongs outside the redaction marker.
            let core = token.trim_end_matches('.');
            let suffix = &token[core.len()..];
            // Never start or end inside an identifier: `std::deque` is a C++
            // type, not an IPv6 address.
            let boundary_before = start == 0 || !is_token_char(chars[start - 1]);
            let boundary_after = i == chars.len() || !is_token_char(chars[i]);
            if boundary_before && boundary_after && is_ipv6_address(core) {
                out.push_str("[REDACTED-IPV6]");
                out.push_str(suffix);
            } else {
                out.push_str(&token);
            }
            continue;
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

/// A dotted quad right after a version label is a version, not an IP address.
/// `AppVersion=1.15.8.0`, `ModuleVersion=1.2.3.4`, `driver 32.0.16.9`, ...
fn is_version_quad(chars: &[char], start: usize) -> bool {
    let lookback = 24.min(start);
    let prefix: String = chars[start - lookback..start].iter().collect();
    let key = prefix
        .trim_end()
        .trim_end_matches('=')
        .trim_end()
        .to_ascii_lowercase();
    const MARKERS: [&str; 6] = [
        "version",
        "appversion",
        "moduleversion",
        "fileversion",
        "productversion",
        "driver",
    ];
    MARKERS.iter().any(|marker| key.ends_with(marker))
}

fn mask_ipv4(input: &str) -> String {
    let chars: Vec<char> = input.chars().collect();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;
    while i < chars.len() {
        if chars[i].is_ascii_digit() && (i == 0 || !chars[i - 1].is_ascii_digit()) {
            let mut j = i;
            let mut groups = 0;
            while j < chars.len() && groups < 4 {
                let start = j;
                while j < chars.len() && chars[j].is_ascii_digit() && j - start < 3 {
                    j += 1;
                }
                if j == start {
                    break;
                }
                let octet: String = chars[start..j].iter().collect();
                if octet.parse::<u32>().map_or(true, |value| value > 255) {
                    break;
                }
                if j < chars.len() && chars[j] == '.' {
                    groups += 1;
                    j += 1;
                } else if j == chars.len() || !chars[j].is_ascii_digit() {
                    // Valid final octet followed by a delimiter or end of input.
                    groups += 1;
                    break;
                } else {
                    // More than three digits — not an IPv4 octet.
                    break;
                }
            }
            // A quad like `AppVersion=1.15.8.0` is a version, not an IP address.
            if groups == 4 && !is_version_quad(&chars, i) {
                out.push_str("[REDACTED-IP]");
                i = j;
                continue;
            }
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

fn mask_sid(input: &str) -> String {
    let chars: Vec<char> = input.chars().collect();
    let prefix: Vec<char> = "S-1-".chars().collect();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;
    while i < chars.len() {
        if chars[i..].starts_with(&prefix) {
            let mut j = i + prefix.len();
            while j < chars.len() && (chars[j].is_ascii_digit() || chars[j] == '-') {
                j += 1;
            }
            out.push_str("[REDACTED-SID]");
            i = j;
            continue;
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

fn mask_guid(input: &str) -> String {
    let chars: Vec<char> = input.chars().collect();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;
    while i < chars.len() {
        if is_hex(chars[i]) && i + 36 <= chars.len() {
            let candidate: String = chars[i..i + 36].iter().collect();
            let c = candidate.as_bytes();
            if c[8] == b'-'
                && c[13] == b'-'
                && c[18] == b'-'
                && c[23] == b'-'
                && c[..8].iter().all(|b| b.is_ascii_hexdigit())
                && c[9..13].iter().all(|b| b.is_ascii_hexdigit())
                && c[14..18].iter().all(|b| b.is_ascii_hexdigit())
                && c[19..23].iter().all(|b| b.is_ascii_hexdigit())
                && c[24..].iter().all(|b| b.is_ascii_hexdigit())
            {
                out.push_str("[REDACTED-GUID]");
                i += 36;
                continue;
            }
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

fn mask_serialish(input: &str) -> String {
    let chars: Vec<char> = input.chars().collect();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;
    while i < chars.len() {
        if chars[i].is_ascii_uppercase() || chars[i].is_ascii_digit() {
            let start = i;
            while i < chars.len() && (chars[i].is_ascii_uppercase() || chars[i].is_ascii_digit()) {
                i += 1;
            }
            let token: String = chars[start..i].iter().collect();
            let digits = token.chars().filter(|c| c.is_ascii_digit()).count();
            let letters = token.chars().filter(|c| c.is_ascii_alphabetic()).count();
            if token.len() >= 20 && digits >= 4 && letters >= 4 {
                out.push_str("[REDACTED-SERIAL]");
            } else {
                out.push_str(&token);
            }
            continue;
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

fn is_hex(c: char) -> bool {
    c.is_ascii_hexdigit()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn destroys_personal_markers() {
        let sample = "C:\\Users\\alice\\Saved\\ip 192.168.1.20 sid S-1-5-21-1234 \
                      guid {a0e9b465-b939-57d7-b27d-95d8e925ff57} serial AB12CD34EF56GH78IJ90KL12";
        let out = redact(sample);
        assert!(!out.contains("alice"));
        assert!(!out.contains("192.168"));
        assert!(!out.contains("S-1-5-21"));
        assert!(!out.contains("a0e9b465"));
        assert!(out.contains("[REDACTED-SERIAL]"));
    }

    #[test]
    fn masks_any_drive_and_unc_paths() {
        let out = redact(r"D:\Users\bob\Saved\file.txt and \\nas01\profiles\alice\crash.log");
        assert!(out.contains(r"D:\Users\%USERPROFILE%\Saved"));
        assert!(!out.contains("nas01"));
        assert!(!out.contains("profiles"));
        assert!(!out.contains("alice"), "UNC tail leaked: {out}");
        assert!(out.contains("[REDACTED-UNC]"), "{out}");
    }

    #[test]
    fn every_unc_path_is_masked_but_urls_and_times_are_untouched() {
        let out =
            redact(r"\\nas01\profiles\alice\crash.log and \\other\share\bob\dump.dmp at 17:17:46");
        assert_eq!(out.matches("[REDACTED-UNC]").count(), 2, "{out}");
        for leaked in ["nas01", "alice", "other", "share", "bob", "dump.dmp"] {
            assert!(!out.contains(leaked), "{leaked} leaked: {out}");
        }
        assert!(out.contains("17:17:46"), "time was destroyed: {out}");

        let url = "https://github.com/pete702/framefault";
        assert_eq!(redact(url), url);
    }

    #[test]
    fn ipv6_addresses_are_masked_without_breaking_times_or_windows_paths() {
        let out =
            redact("client fe80::1%eth0 fd00::1234 ::1 2001:0db8:85a3:0000:0000:8a2e:0370:7334");
        assert_eq!(out.matches("[REDACTED-IPV6]").count(), 4, "{out}");
        for leaked in ["fe80", "fd00", "2001", "0db8", "0370"] {
            assert!(!out.contains(leaked), "{leaked} leaked: {out}");
        }

        let keep = "2026-11-25 17:17:46 | C:\\Windows\\System32\\dxgi.dll | \
                    0x00000116 | Low free space on E:: 6.4 GiB free";
        assert_eq!(redact(keep), keep, "non-IP tokens must survive: {out}");
    }

    #[test]
    fn durations_and_times_survive_but_colon_macs_still_mask() {
        assert_eq!(redact("1.02:03:04"), "1.02:03:04");
        assert_eq!(redact("17:17:46"), "17:17:46");
        assert_eq!(redact("AA:BB:CC:DD:EE:FF"), "[REDACTED-MAC]");
        assert_eq!(redact("00:1a:2b:3c:4d:5e"), "[REDACTED-MAC]");
        assert_eq!(redact("MAC 11:22:33:44:55:66"), "MAC [REDACTED-MAC]");

        // Full IPv6 still masks; a sentence-final period stays outside.
        assert_eq!(redact("fe80::1."), "[REDACTED-IPV6].");
    }

    #[test]
    fn email_punctuation_ipv6_boundaries_and_spaced_keys_are_handled() {
        // M1: a sentence-final period stays outside the marker.
        assert_eq!(redact("alice@example.com."), "[REDACTED-EMAIL].");
        assert_eq!(redact("mail alice@example.com,"), "mail [REDACTED-EMAIL],");

        // L1: C++ identifiers are not IPv6 addresses.
        for code in ["std::deque", "std::detail", "std::default_delete"] {
            assert_eq!(redact(code), code, "{code} must stay intact");
        }

        // L2: optional spaces/tabs before the `=`.
        assert_eq!(redact("LoginId = abc123"), "LoginId = [REDACTED-ID]");
        assert_eq!(redact("AccountId\t=\t42"), "AccountId\t=\t[REDACTED-ID]");
        assert_eq!(
            redact("SteamId = 76561198012345678"),
            "SteamId = [REDACTED-STEAMID]"
        );

        // L3: `1::` is a valid IPv6 address, `E::` is a drive letter.
        assert_eq!(redact("1::"), "[REDACTED-IPV6]");
        assert_eq!(redact("E::"), "E::");
        assert_eq!(redact("1.02:03:04"), "1.02:03:04");
    }

    #[test]
    fn keeps_hardware_facts() {
        let out = redact("AppVersion=2026.4.0.0 ModuleVersion=10.0.26100.10068");
        assert!(
            !out.contains("[REDACTED-IP]"),
            "versions must stay readable: {out}"
        );
        let out = redact("GPU NVIDIA 32.0.15.6094 | RAM 32 GB | MPO 5 | RTSSHooks64.dll");
        assert!(out.contains("RTSSHooks64.dll"));
        assert!(out.contains("32.0.15.6094"));
        assert!(out.contains("MPO 5"));
    }

    #[test]
    fn keeps_small_version_quads_but_masks_real_ips() {
        let versions = "AppVersion=1.15.8.0 ModuleVersion=1.2.3.4 \
                        FileVersion=0.9.8.1 driver 32.0.16.9";
        let out = redact(versions);
        assert_eq!(out, versions, "version quads must survive verbatim: {out}");

        let out = redact("client ip 192.168.1.20");
        assert!(
            out.contains("[REDACTED-IP]"),
            "real IPs must still be masked: {out}"
        );
    }

    #[test]
    fn profile_paths_are_case_insensitive_and_documents_is_masked() {
        let out = redact(r"C:\users\alice\AppData\Local\file.txt");
        assert!(!out.contains("alice"), "{out}");
        assert!(out.contains("%USERPROFILE%"), "{out}");

        let out = redact(r"D:\Documents and Settings\bob\ntuser.dat");
        assert!(!out.contains("bob"), "{out}");
        assert!(out.contains("%USERPROFILE%"), "{out}");
    }

    #[test]
    fn emails_file_urls_and_hex_ids_are_masked() {
        let out = redact("contact alice@example.com");
        assert!(out.contains("[REDACTED-EMAIL]"), "{out}");
        assert!(!out.contains("alice"), "{out}");
        assert!(!out.contains("example.com"), "{out}");

        let out = redact("file:///C:/Users/alice/crash.dmp");
        assert!(out.contains("[REDACTED-FILE-URL]"), "{out}");
        assert!(!out.contains("alice"), "{out}");

        let out = redact("EpicAccountId deadbeefcafebabe0011223344556677");
        assert!(out.contains("[REDACTED-ID]"), "{out}");
        assert!(!out.contains("deadbeef"), "{out}");

        let offset = "FaultingOffset=deadbeefcafebabe0011223344556677";
        assert_eq!(redact(offset), offset);
        let created = "ProcessCreationTime=20261120101112000000000000000000";
        assert_eq!(redact(created), created);
    }

    #[test]
    fn unc_trailing_period_stays_outside_the_marker() {
        assert_eq!(redact(r"\\srv\share\file.log."), "[REDACTED-UNC].");
        assert_eq!(redact(r"\\srv\share\file.log,"), "[REDACTED-UNC],");
        assert_eq!(redact(r"\\srv\share\file.log;"), "[REDACTED-UNC];");
    }

    #[test]
    fn urls_are_not_unc_paths() {
        for url in [
            "https://github.com/pete702/framefault",
            "http://example.com/path/to/file",
        ] {
            let out = redact(url);
            assert_eq!(out, url, "URL must stay intact: {out}");
            assert!(
                !out.contains("[REDACTED-UNC]"),
                "URL must not be masked: {out}"
            );
        }

        let out = redact(r"\\NAS\share\user");
        assert_eq!(out, "[REDACTED-UNC]");
        assert!(!out.contains("NAS"), "UNC server must be destroyed: {out}");
        assert!(!out.contains("user"), "UNC tail must be destroyed: {out}");
    }

    #[test]
    fn steam_ids_and_keyed_accounts_are_masked() {
        let out = redact("76561198012345678");
        assert_eq!(out, "[REDACTED-STEAMID]");

        let out = redact("SteamId=76561198012345678 LoginId=abc123 AccountId=42");
        assert!(out.contains("SteamId=[REDACTED-STEAMID]"), "{out}");
        assert!(out.contains("LoginId=[REDACTED-ID]"), "{out}");
        assert!(out.contains("AccountId=[REDACTED-ID]"), "{out}");
        assert!(!out.contains("7656119"), "{out}");
        assert!(!out.contains("abc123"), "{out}");

        // A 17-digit number without the Steam prefix is not a SteamID64.
        let other = "12345678901234567";
        assert_eq!(redact(other), other);
    }

    #[test]
    fn quoted_and_spaced_keyed_ids_are_masked() {
        let out = redact("LoginId=\"abc123\" AccountId= 42 SteamId='76561198012345678'");
        assert!(out.contains("LoginId=\"[REDACTED-ID]\""), "{out}");
        assert!(out.contains("AccountId= [REDACTED-ID]"), "{out}");
        assert!(out.contains("SteamId='[REDACTED-STEAMID]'"), "{out}");
        assert!(!out.contains("abc123"), "{out}");
    }

    #[test]
    fn dash_separated_mac_addresses_are_masked() {
        let out = redact("MAC AA-BB-CC-DD-EE-FF and 00-1a-2b-3c-4d-5e");
        assert_eq!(out.matches("[REDACTED-MAC]").count(), 2, "{out}");
        for leaked in ["AA-BB", "00-1a"] {
            assert!(!out.contains(leaked), "{leaked} leaked: {out}");
        }

        let keep = "2026-11-20 17:17:46 | 1234-5678 | driver 1.2.3.4";
        assert_eq!(redact(keep), keep, "dates/versions must survive: {out}");
    }

    #[test]
    fn numeric_dates_are_not_mistaken_for_macs() {
        let date = "26-11-27-10-11-12";
        assert_eq!(redact(date), date);

        assert_eq!(redact("MAC 11-22-33-44-55-66"), "MAC [REDACTED-MAC]");
        assert_eq!(
            redact("Physical Address: 11-22-33-44-55-66"),
            "Physical Address: [REDACTED-MAC]"
        );
    }
}
