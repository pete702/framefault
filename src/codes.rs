//! Plain-language decoding for the most common bugcheck codes.
//! No symbols required: these are documented Windows stop codes.

const TABLE: &[(u32, &str, &str)] = &[
    (0x0000_0116, "VIDEO_TDR_FAILURE", "GPU driver stopped responding: check GPU OC/undervolt, driver version, overlays, MPO."),
    (0x0000_0117, "VIDEO_TDR_TIMEOUT_DETECTED", "GPU adapter timeout: same checks as 0x116, plus power/PCIe."),
    (0x0000_0141, "VIDEO_ENGINE_TIMEOUT_DETECTED", "GPU engine timeout (LiveKernelEvent 141): often driver or OC."),
    (0x0000_0124, "WHEA_UNCORRECTABLE_ERROR", "Hardware/PCIe error: remove OC, reseat GPU/RAM, check temps and PSU."),
    (0x0000_0133, "DPC_WATCHDOG_VIOLATION", "A driver blocked the CPU too long: update storage/NIC/AV drivers."),
    (0x0000_000A, "IRQL_NOT_LESS_OR_EQUAL", "Driver touched invalid memory at high IRQL: usually a third-party driver."),
    (0x0000_003B, "SYSTEM_SERVICE_EXCEPTION", "System call fault: note the faulting module in the report."),
    (0x0000_001E, "KMODE_EXCEPTION_NOT_HANDLED", "Kernel-mode exception: note the faulting driver/module."),
    (0x0000_0050, "PAGE_FAULT_IN_NONPAGED_AREA", "Invalid memory access: RAM, pagefile or a buggy driver."),
    (0x0000_001A, "MEMORY_MANAGEMENT", "Memory corruption: RAM, pagefile, or driver."),
    (0x0000_00D1, "DRIVER_IRQL_NOT_LESS_OR_EQUAL", "Driver touched invalid memory at raised IRQL: commonly GPU/NIC/USB/AV filter drivers."),
    (0x0000_000D, "DRIVER_IRQL_NOT_LESS_OR_EQUAL", "Bad driver IRQL: commonly NIC/USB/AV filter drivers."),
    (0x0000_004E, "PFN_LIST_CORRUPT", "Memory manager page-frame corruption: unstable RAM/XMP or a driver leak."),
    (0x0000_0001, "APC_INDEX_MISMATCH", "Driver called an invalid API at the wrong IRQL."),
    (0x0000_0139, "KERNEL_SECURITY_CHECK_FAILURE", "Kernel structure corruption: driver or memory."),
    (0x0000_007E, "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED", "System thread fault: note the faulting module."),
    (0x0000_007B, "INACCESSIBLE_BOOT_DEVICE", "Boot storage/driver problem; not usually game-related."),
    (0x0000_0024, "NTFS_FILE_SYSTEM", "Filesystem/storage driver problem."),
    (0x0000_0023, "FAT_FILE_SYSTEM", "Filesystem/storage driver problem."),
    (0x0000_00ED, "UNMOUNTABLE_BOOT_VOLUME", "Boot volume/storage problem."),
    (0x0000_009C, "MACHINE_CHECK_EXCEPTION", "CPU/hardware machine check: disable OC, check temps/PSU."),
    (0x0000_0101, "CLOCK_WATCHDOG_TIMEOUT", "A CPU core stopped responding: OC/thermals/hardware."),
    (0x0000_009F, "DRIVER_POWER_STATE_FAILURE", "Driver failed a power transition: GPU/USB drivers, fast startup."),
    (0x0000_00EF, "CRITICAL_PROCESS_DIED", "Critical system process terminated; check the faulting module."),
    (0x0000_00C2, "BAD_POOL_CALLER", "Driver corrupted the memory pool."),
    (0x0000_0019, "BAD_POOL_HEADER", "Pool header corruption: driver or RAM."),
    (0x0000_00A0, "INTERNAL_POWER_ERROR", "Power transition failure: drivers/BIOS."),
];

/// Exception codes seen in Application Error (Event 1000) and DXGI game logs.
/// Names follow Microsoft's NTSTATUS / DXGI documentation.
const EXCEPTIONS: &[(u32, &str, &str)] = &[
    (0xC000_0005, "ACCESS_VIOLATION", "Invalid memory access: mod, overlay, driver or corrupted install."),
    (0xC000_0409, "STACK_BUFFER_OVERRUN", "Stack corruption: usually a native plugin/mod or VC++ runtime."),
    (0xE06D_7363, "CPP_EH_EXCEPTION", "Unhandled C++ exception from the faulting module: often a game/plugin bug."),
    (0x8000_0003, "STATUS_BREAKPOINT", "Breakpoint/assert inside the app: often an internal error or memory pressure in Chromium/Electron apps; also debug builds and launchers."),
    (0xC000_00FD, "STACK_OVERFLOW", "Guard page could not be created: recursion or deep call chain."),
    (0x887A_0005, "DXGI_ERROR_DEVICE_REMOVED", "GPU device removed: driver timeout, TDR, or VRAM exhaustion."),
    (0x887A_0006, "DXGI_ERROR_DEVICE_HUNG", "GPU stopped responding (0x887A0006): check driver, OC and overlays."),
    (0xC000_0006, "IN_PAGE_ERROR", "Could not read a page from disk: storage or pagefile problem."),
    (0xC000_001D, "ILLEGAL_INSTRUCTION", "CPU executed an invalid instruction: bad mod or CPU/OC issue."),
    (0xC000_0094, "INTEGER_DIVIDE_BY_ZERO", "Division by zero in native code."),
    (0xC000_00B0, "INTEGER_OVERFLOW", "Integer arithmetic overflow in native code."),
    (0xC000_0135, "DLL_NOT_FOUND", "Required DLL missing: verify game files / VC++ redist."),
    (0xC000_0142, "DLL_INIT_FAILED", "DLL initialization failed: conflicting mod or runtime."),
    (0xE043_4352, "CLR_EXCEPTION", "Unhandled .NET exception from the faulting module."),
    (0xC000_0025, "NONCONTINUABLE_EXCEPTION", "Exception handler tried to continue after a fatal exception."),
];

pub fn decode_exception(code: u32) -> (&'static str, &'static str) {
    EXCEPTIONS
        .iter()
        .find(|(value, _, _)| *value == code)
        .map(|(_, name, advice)| (*name, *advice))
        .unwrap_or(("UNKNOWN_EXCEPTION", "Check the faulting module in Raw Proof."))
}

pub fn decode(code: u32) -> (&'static str, &'static str) {
    TABLE
        .iter()
        .find(|(value, _, _)| *value == code)
        .map(|(_, name, advice)| (*name, *advice))
        .unwrap_or(("UNKNOWN_STOP_CODE", "Check the faulting module and driver versions in Raw Proof."))
}

pub fn format_bugcheck(code: u32) -> String {
    let (name, _) = decode(code);
    format!("BSOD 0x{code:08X} ({name})")
}

/// Extracts a bugcheck code from decimal (Kernel-Power 41) or hex (BugCheck 1001).
pub fn parse_code(text: &str) -> Option<u32> {
    for token in text.split(|c: char| !c.is_ascii_alphanumeric() && c != 'x') {
        if let Some(hex) = token.strip_prefix("0x").or_else(|| token.strip_prefix("0X")) {
            if let Ok(code) = u32::from_str_radix(hex, 16) {
                if code > 0 {
                    return Some(code);
                }
            }
        }
    }
    // Decimal form is only trustworthy when explicitly labelled (Kernel-Power 41).
    for label in ["BugcheckCode", "BugCheckCode", "Bugcheck code"] {
        if let Some(index) = text.find(label) {
            let rest = text[index + label.len()..].trim_start();
            let token = rest
                .split(|c: char| !c.is_ascii_digit())
                .next()
                .unwrap_or("");
            if let Ok(code) = token.parse::<u32>() {
                if code > 0 {
                    return Some(code);
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_known_codes() {
        assert_eq!(decode(0x116).0, "VIDEO_TDR_FAILURE");
        assert_eq!(decode(0x124).0, "WHEA_UNCORRECTABLE_ERROR");
    }

    #[test]
    fn decodes_application_exceptions() {
        assert_eq!(decode_exception(0xC000_0005).0, "ACCESS_VIOLATION");
        assert_eq!(decode_exception(0xE06D_7363).0, "CPP_EH_EXCEPTION");
        assert_eq!(decode_exception(0x887A_0006).0, "DXGI_ERROR_DEVICE_HUNG");
    }

    #[test]
    fn parses_hex_and_decimal() {
        assert_eq!(parse_code("The Bug Check was: 0x00000116 (0xffff)"), Some(0x116));
        assert_eq!(parse_code("BugcheckCode 159"), Some(159));
    }
}
