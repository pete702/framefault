//! Irreversible redaction for forum posts. Characters are destroyed, not blurred.
//! Hardware facts (game, Windows build, GPU driver, RAM/pagefile, MPO, overlay DLL
//! names) are deliberately kept because they are what makes a report useful.

pub fn redact(input: &str) -> String {
    let mut out = input.to_string();
    out = mask_profile_paths(&out);
    out = mask_guid(&out);
    out = mask_sid(&out);
    out = mask_ipv4(&out);
    out = mask_env_secret(&out, "USERNAME", "[REDACTED-USER]");
    out = mask_env_secret(&out, "COMPUTERNAME", "[REDACTED-HOST]");
    out = mask_serialish(&out);
    out
}

/// Context lines are built from hardware facts only; still scrubbed defensively.
pub fn context_line(label: &str, value: &str) -> String {
    format!("- {label}: {}", redact(value))
}

fn mask_env_secret(input: &str, var: &str, replacement: &str) -> String {
    let Ok(value) = std::env::var(var) else {
        return input.to_string();
    };
    if value.len() < 3 {
        return input.to_string();
    }
    input.replace(&value, replacement)
}

fn mask_profile_paths(input: &str) -> String {
    let mut out = mask_unc_servers(input);
    // Any drive letter, forward or back slashes: C:\Users\<name>, D:/Users/<name>, ...
    for marker in ["\\Users\\", "/Users/"] {
        let mut cursor = 0usize;
        while let Some(relative) = out[cursor..].find(marker) {
            let name_start = cursor + relative + marker.len();
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

fn mask_unc_servers(input: &str) -> String {
    let mut out = input.to_string();
    for marker in ["\\\\", "//"] {
        let mut cursor = 0usize;
        while let Some(relative) = out[cursor..].find(marker) {
            let start = cursor + relative;
            let body_start = start + marker.len();
            let Some(server_end) = out[body_start..].find(['\\', '/']) else {
                break;
            };
            let share_start = body_start + server_end + 1;
            let Some(share_end) = out[share_start..].find(['\\', '/']) else {
                break;
            };
            let end = share_start + share_end;
            let replacement = format!("{marker}%UNC%");
            out.replace_range(start..end, &replacement);
            cursor = start + replacement.len();
        }
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
    }

    #[test]
    fn keeps_hardware_facts() {
        let out = redact("AppVersion=2026.4.0.0 ModuleVersion=10.0.26100.10068");
        assert!(!out.contains("[REDACTED-IP]"), "versions must stay readable: {out}");
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
        assert!(out.contains("[REDACTED-IP]"), "real IPs must still be masked: {out}");
    }
}
