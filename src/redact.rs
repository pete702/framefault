//! Irreversible redaction for forum posts. Characters are destroyed, not blurred.
//! Hardware facts (game, Windows build, GPU driver, RAM/pagefile, MPO, overlay DLL
//! names) are deliberately kept because they are what makes a report useful.

pub fn redact(input: &str) -> String {
    let mut out = input.to_string();
    out = mask_file_urls(&out);
    out = mask_profile_paths(&out);
    out = mask_emails(&out);
    out = mask_guid(&out);
    out = mask_hex_ids(&out);
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
                let domain: String = chars[i + 1..end].iter().collect();
                let valid = domain.contains('.')
                    && !domain.starts_with('.')
                    && !domain.ends_with('.')
                    && domain.chars().any(|c| c.is_ascii_alphabetic());
                if valid {
                    out.push_str("[REDACTED-EMAIL]");
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

/// `HH:MM:SS` and `C:\...` have too few colons; a MAC-like `10de:1b06` has
/// one. Real IPv6 has `::` or at least three colons plus hex groups.
fn is_ipv6_address(token: &str) -> bool {
    let colons = token.chars().filter(|&c| c == ':').count();
    if !(token.contains("::") || colons >= 3) || !token.chars().any(|c| c.is_ascii_hexdigit()) {
        return false;
    }
    // A doubled colon after a drive letter ("E:: 6.4 GiB free") is not an
    // address: require real groups on both sides of `::` (or a leading `::`).
    if let Some(pos) = token.find("::") {
        let right = &token[pos + 2..];
        if right.is_empty() && !token.starts_with("::") {
            return false;
        }
    }
    true
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
            if is_ipv6_address(&token) {
                out.push_str("[REDACTED-IPV6]");
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
}
