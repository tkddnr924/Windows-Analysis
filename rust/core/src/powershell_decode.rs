//! Decode explicit PowerShell EncodedCommand arguments without executing them.
//! Original command lines remain in the parent record; decoded text is not recursed.
//! Switch rules: PowerShell CommandLineParameterParser.cs, GetSwitchKey/MatchSwitch.
//! Windows PowerShell 5.1 about_PowerShell_exe defines UTF-16LE and -Version's value.
//! Unlike Convert.FromBase64String, strict base64 0.22 STANDARD rejects whitespace
//! and noncanonical padding/bits. Invalid UTF-16 is never replaced lossily.

use base64::Engine as _;
use std::borrow::Cow;

/// `DecodedCommand::source_field` values — the row field the command line came from.
const SOURCE_COMMAND: &str = "command";
const SOURCE_HOST_APPLICATION: &str = "host_application";

/// Only decoding method implemented: Base64 of UTF-16LE.
const METHOD_BASE64_UTF16LE: &str = "base64_utf16le";

/// Stable `decode_status` values.
const STATUS_SUCCESS: &str = "success";
const STATUS_MISSING_PAYLOAD: &str = "missing_payload";
const STATUS_INVALID_BASE64: &str = "invalid_base64";
const STATUS_INVALID_UTF16: &str = "invalid_utf16";
const STATUS_AMBIGUOUS: &str = "ambiguous_command_line";

/// One `-EncodedCommand` occurrence found in one source field. The caller keeps
/// the raw command line itself; this only carries the switch payload and the
/// decode outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DecodedCommand {
    pub source_field: &'static str,
    pub encoded_command: String,
    pub decoded_command: Option<String>,
    pub decode_method: &'static str,
    pub decode_status: &'static str,
    pub decode_error: Option<String>,
}

/// Extracts every `-EncodedCommand` payload from the two recorded command-line
/// fields and decodes it. Order is `command` first, then `host_application`;
/// the caller assigns the stored ordinal. Returns an empty vector when neither
/// field is an explicit PowerShell invocation carrying the switch.
pub(crate) fn decode_commands(command: &str, host_application: &str) -> Vec<DecodedCommand> {
    let mut out = Vec::new();
    scan_command_line(SOURCE_COMMAND, command, &mut out);
    scan_command_line(SOURCE_HOST_APPLICATION, host_application, &mut out);
    out
}

/// What the parser does with a recognized switch, as far as finding further
/// `-EncodedCommand` switches is concerned.
enum SwitchKind {
    /// Takes no argument; parsing continues.
    Flag,
    /// Consumes the next argument as its value.
    Value,
    /// `-EncodedCommand` / `-e` / `-ec` and the other prefixes.
    Encoded,
    /// Parsing of further switches ends here (`-Command`, `-File`,
    /// `-CommandWithArgs`, `-Version`, `-Help`, or anything unrecognized —
    /// the host treats the first unrecognized token as the script file and
    /// hands the rest to the script).
    Stop,
}

fn scan_command_line(source_field: &'static str, mut line: &str, out: &mut Vec<DecodedCommand>) {
    let shell_text = source_field == SOURCE_COMMAND;
    if shell_text {
        line = line.trim_start();
        if let Some(invocation) = line.strip_prefix('&') {
            line = invocation.trim_start();
        } else if line.starts_with(['"', '\'']) {
            return;
        }
    }
    let Some(exe) = next_arg(&mut line, true, shell_text) else {
        return;
    };
    if !is_powershell_executable(&exe) {
        return;
    }
    let windows_powershell = exe.rsplit(['\\', '/']).next().is_some_and(|name|
        name.eq_ignore_ascii_case("powershell") || name.eq_ignore_ascii_case("powershell.exe"));
    let mut command_specified = false;
    while let Some(arg) = next_arg(&mut line, false, shell_text) {
        let Some(key) = switch_key(&arg) else {
            break;
        };
        let kind = if windows_powershell && matches(key, "version", "v") {
            SwitchKind::Value
        } else {
            classify_switch(key)
        };
        match kind {
            SwitchKind::Flag => {}
            SwitchKind::Value => {
                if next_arg(&mut line, false, shell_text).is_none() {
                    break;
                }
            }
            SwitchKind::Encoded => {
                let payload = next_arg(&mut line, false, shell_text);
                out.push(encoded_record(source_field, payload.as_deref(), command_specified));
                command_specified = true;
                if payload.is_none() {
                    break;
                }
            }
            SwitchKind::Stop => break,
        }
    }
}

/// Duplicate command specifications are flagged, not treated as execution proof.
fn encoded_record(
    source_field: &'static str,
    payload: Option<&str>,
    already_specified: bool,
) -> DecodedCommand {
    let payload = payload.unwrap_or_default();
    let (decoded, status, error) = decode_payload(payload);
    let (status, error) = if already_specified {
        let mut message = String::from(
            "multiple EncodedCommand arguments; decoded text does not establish execution",
        );
        if let Some(error) = error {
            message.push_str("; ");
            message.push_str(&error);
        }
        (STATUS_AMBIGUOUS, Some(message))
    } else {
        (status, error)
    };
    DecodedCommand {
        source_field,
        encoded_command: payload.to_string(),
        decoded_command: decoded,
        decode_method: METHOD_BASE64_UTF16LE,
        decode_status: status,
        decode_error: error,
    }
}

/// Strict Base64 → strict UTF-16LE. No lossy replacement, no trimming, no
/// unescaping: either the exact decoded text or a reason why not.
fn decode_payload(payload: &str) -> (Option<String>, &'static str, Option<String>) {
    if payload.is_empty() {
        return (
            None,
            STATUS_MISSING_PAYLOAD,
            Some("-EncodedCommand has no payload argument".to_string()),
        );
    }
    let bytes = match base64::engine::general_purpose::STANDARD.decode(payload) {
        Ok(bytes) => bytes,
        Err(e) => {
            return (
                None,
                STATUS_INVALID_BASE64,
                Some(format!("invalid base64 payload: {e}")),
            )
        }
    };
    if !bytes.len().is_multiple_of(2) {
        return (
            None,
            STATUS_INVALID_UTF16,
            Some(format!(
                "decoded payload is {} bytes, not a whole number of UTF-16LE units",
                bytes.len()
            )),
        );
    }
    let units = bytes.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]]));
    match char::decode_utf16(units).collect::<Result<String, _>>() {
        Ok(text) => (Some(text), STATUS_SUCCESS, None),
        Err(e) => (
            None,
            STATUS_INVALID_UTF16,
            Some(format!(
                "invalid UTF-16LE payload: unpaired surrogate U+{:04X}",
                e.unpaired_surrogate()
            )),
        ),
    }
}

/// `-`, en dash, em dash and horizontal bar all start a switch (CharTraits.cs).
fn is_dash(c: char) -> bool {
    c == '-' || c == '\u{2013}' || c == '\u{2014}' || c == '\u{2015}'
}

/// Strip the host's switch prefix without modifying the evidence.
fn switch_key(arg: &str) -> Option<&str> {
    let arg = arg.trim();
    let mut chars = arg.chars();
    let first = chars.next()?;
    if !is_dash(first) && first != '/' {
        return None;
    }
    let rest = chars.as_str();
    let rest = match rest.chars().next() {
        Some(second) if is_dash(first) && second == first => &rest[second.len_utf8()..],
        _ => rest,
    };
    Some(rest)
}

/// Match the accepted case-insensitive prefix or alias.
fn matches(key: &str, full: &str, smallest_unambiguous: &str) -> bool {
    key.len() >= smallest_unambiguous.len()
        && full.get(..key.len()).is_some_and(|prefix| prefix.eq_ignore_ascii_case(key))
}

/// Same order as ParseHelper's if/else chain — the order decides which switch a
/// short prefix like `e`, `c` or `s` belongs to. The DEBUG-only `-isswait` and
/// anything else unknown falls through to "stop" like the host's file handling.
fn classify_switch(key: &str) -> SwitchKind {
    if matches(key, "version", "v") || matches(key, "help", "h") || matches(key, "?", "?") {
        return SwitchKind::Stop;
    }
    if matches(key, "login", "l")
        || matches(key, "noexit", "noe")
        || matches(key, "noprofile", "nop")
        || matches(key, "nologo", "nol")
        || matches(key, "noninteractive", "noni")
        || matches(key, "socketservermode", "so")
        || matches(key, "v2socketservermode", "v2so")
        || matches(key, "servermode", "s")
        || matches(key, "namedpipeservermode", "nam")
        || matches(key, "sshservermode", "sshs")
        || matches(key, "noprofileloadtime", "noprofileloadtime")
        || matches(key, "interactive", "i")
    {
        return SwitchKind::Flag;
    }
    if matches(key, "configurationfile", "configurationfile")
        || matches(key, "configurationname", "config")
        || matches(key, "custompipename", "cus")
    {
        return SwitchKind::Value;
    }
    // -CommandWithArgs, -Command and -File take the rest of the command line.
    if matches(key, "commandwithargs", "commandwithargs")
        || matches(key, "cwa", "cwa")
        || matches(key, "command", "c")
    {
        return SwitchKind::Stop;
    }
    if matches(key, "windowstyle", "w") {
        return SwitchKind::Value;
    }
    if matches(key, "file", "f") {
        return SwitchKind::Stop;
    }
    if matches(key, "outputformat", "o")
        || matches(key, "of", "o")
        || matches(key, "inputformat", "inp")
        || matches(key, "if", "if")
        || matches(key, "executionpolicy", "ex")
        || matches(key, "ep", "ep")
    {
        return SwitchKind::Value;
    }
    if matches(key, "encodedcommand", "e") || matches(key, "ec", "e") {
        return SwitchKind::Encoded;
    }
    if matches(key, "encodedarguments", "encodeda")
        || matches(key, "ea", "ea")
        || matches(key, "settingsfile", "settings")
    {
        return SwitchKind::Value;
    }
    if matches(key, "sta", "sta") || matches(key, "mta", "mta") {
        return SwitchKind::Flag;
    }
    if matches(key, "workingdirectory", "wo") || matches(key, "wd", "wd") {
        return SwitchKind::Value;
    }
    if matches(
        key,
        "removeworkingdirectorytrailingcharacter",
        "removeworkingdirectorytrailingcharacter",
    ) {
        return SwitchKind::Flag;
    }
    if matches(key, "token", "to") || matches(key, "utctimestamp", "utc") {
        return SwitchKind::Value;
    }
    SwitchKind::Stop
}

/// Only an explicit PowerShell executable counts; `cmd.exe /c powershell ...`,
/// wrapper scripts and `powershell_ise.exe` are deliberately not recognized.
fn is_powershell_executable(arg0: &str) -> bool {
    let name = arg0.rsplit(['\\', '/']).next().unwrap_or_default();
    ["powershell", "powershell.exe", "pwsh", "pwsh.exe"]
        .iter().any(|exe| name.eq_ignore_ascii_case(exe))
}

/// Read only the next argv token; unquoted text borrows the original line.
fn next_arg<'a>(remaining: &mut &'a str, program: bool, shell_text: bool) -> Option<Cow<'a, str>> {
    let line = remaining.trim_start_matches([' ', '\t']);
    if line.is_empty() {
        return None;
    }
    let bytes = line.as_bytes();
    let (mut i, mut start, mut quote) = (0, 0, 0);
    let mut output: Option<String> = None;
    while i < bytes.len() {
        if quote == 0 && matches!(bytes[i], b' ' | b'\t') {
            break;
        }
        if bytes[i] == b'"' && quote != b'\''
            || shell_text && bytes[i] == b'\'' && quote != b'"'
        {
            let out = output.get_or_insert_with(String::new);
            out.push_str(&line[start..i]);
            if quote == b'\'' && bytes.get(i + 1) == Some(&b'\'') {
                out.push('\'');
                i += 2;
                start = i;
                continue;
            }
            quote = if quote == 0 { bytes[i] } else { 0 };
            i += 1;
            start = i;
        } else if !program && !shell_text && bytes[i] == b'\\' {
            let slash_start = i;
            while i < bytes.len() && bytes[i] == b'\\' {
                i += 1;
            }
            if i < bytes.len() && bytes[i] == b'"' {
                let out = output.get_or_insert_with(String::new);
                out.push_str(&line[start..slash_start]);
                let count = i - slash_start;
                out.extend(std::iter::repeat_n('\\', count / 2));
                if count % 2 == 1 {
                    out.push('"');
                } else {
                    quote = if quote == 0 { b'"' } else { 0 };
                }
                i += 1;
                start = i;
            }
        } else {
            i += 1;
        }
    }
    *remaining = &line[i..];
    Some(match output {
        Some(mut out) => {
            out.push_str(&line[start..i]);
            Cow::Owned(out)
        }
        None => Cow::Borrowed(&line[..i]),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const PS51: &str = r"C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe";

    fn encode(text: &str) -> String {
        let bytes: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    fn only(command: &str, host_application: &str) -> DecodedCommand {
        let mut rows = decode_commands(command, host_application);
        assert_eq!(rows.len(), 1, "expected one row for {host_application:?}");
        rows.remove(0)
    }

    fn host(line: &str) -> DecodedCommand {
        only("", line)
    }

    #[test]
    fn baseline_shaped_command_line_decodes_korean_and_multiline_text() {
        // Same shape as the real host's 400/403 records.
        let script = "Write-Host '한글 테스트'\r\n$x = 1\nGet-Date";
        let payload = encode(script);
        let row = host(&format!(
            "{PS51} -NoProfile -NonInteractive -NoLogo -EncodedCommand {payload}"
        ));
        assert_eq!(row.source_field, "host_application");
        assert_eq!(row.encoded_command, payload);
        assert_eq!(row.decoded_command.as_deref(), Some(script));
        assert_eq!(row.decode_method, "base64_utf16le");
        assert_eq!(row.decode_status, "success");
        assert_eq!(row.decode_error, None);
    }

    #[test]
    fn decoded_text_is_not_trimmed_unescaped_or_re_decoded() {
        // Nested encoded text inside the payload stays text: only the outer
        // switch is decoded, exactly once.
        let inner = encode("whoami");
        let script = format!("\u{feff}$c = '-EncodedCommand {inner}'  ");
        let row = host(&format!("powershell.exe -enc {}", encode(&script)));
        assert_eq!(row.decoded_command.as_deref(), Some(script.as_str()));
        assert_eq!(decode_commands("", &script).len(), 0);
    }

    #[test]
    fn documented_abbreviations_cases_and_prefixes_are_recognized() {
        let payload = encode("Get-Date");
        for switch in [
            "-e",
            "-ec",
            "-eC",
            "-en",
            "-enc",
            "-EncodedCommand",
            "-ENCODEDCOMMAND",
            "-encodedcomman",
            "--enc",
            "/enc",
            "/EncodedCommand",
            "\u{2013}enc",
            "\u{2014}e",
            "\u{2015}ec",
        ] {
            let row = host(&format!("pwsh.exe {switch} {payload}"));
            assert_eq!(row.decode_status, "success", "switch {switch}");
            assert_eq!(row.decoded_command.as_deref(), Some("Get-Date"));
        }
    }

    #[test]
    fn switch_key_is_trimmed_like_the_host() {
        let payload = encode("Get-Date");
        let row = host(&format!("powershell.exe \" -enc \" {payload}"));
        assert_eq!(row.decode_status, "success");
    }

    #[test]
    fn quoted_payload_and_quoted_executable_path_are_handled() {
        let payload = encode("Get-Process");
        let row = host(&format!(
            "\"C:\\Program Files\\PowerShell\\7\\pwsh.exe\" -NoLogo -EncodedCommand \"{payload}\""
        ));
        assert_eq!(row.encoded_command, payload);
        assert_eq!(row.decoded_command.as_deref(), Some("Get-Process"));
    }

    #[test]
    fn value_switches_consume_their_argument() {
        let payload = encode("hi");
        let row = host(&format!(
            "{PS51} -ExecutionPolicy Bypass -WindowStyle Hidden -NoProfile -enc {payload}"
        ));
        assert_eq!(row.decode_status, "success");
        // -ep eats the next token, so what follows is no longer a switch.
        assert!(decode_commands("", &format!("powershell.exe -ep -enc {payload}")).is_empty());
    }

    #[test]
    fn encoded_arguments_are_not_encoded_commands() {
        let payload = encode("Get-Date");
        for line in [
            format!("powershell.exe -EncodedArguments {payload} -NoLogo"),
            format!("powershell.exe -ea {payload}"),
            format!("powershell.exe -encodeda {payload}"),
        ] {
            assert!(decode_commands("", &line).is_empty(), "line {line}");
        }
    }

    #[test]
    fn command_body_mentioning_encodedcommand_is_never_decoded() {
        let payload = encode("Get-Date");
        for line in [
            format!("powershell.exe -NoProfile -Command \"Write-Host '-EncodedCommand {payload}'\""),
            format!("powershell.exe -c Get-Thing -EncodedCommand {payload}"),
            format!("powershell.exe -cwa -Command Get-Thing -enc {payload}"),
            format!("powershell.exe -commandwithargs -command x -enc {payload}"),
        ] {
            assert!(decode_commands("", &line).is_empty(), "line {line}");
        }
    }

    #[test]
    fn file_positional_and_unknown_switches_stop_parsing() {
        let payload = encode("Get-Date");
        for line in [
            format!("powershell.exe -File C:\\tools\\run.ps1 -EncodedCommand {payload}"),
            format!("powershell.exe -f run.ps1 -enc {payload}"),
            format!("powershell.exe run.ps1 -enc {payload}"),
            format!("powershell.exe -Bogus -enc {payload}"),
            format!("pwsh.exe -Version -enc {payload}"),
            format!("powershell.exe -? -enc {payload}"),
        ] {
            assert!(decode_commands("", &line).is_empty(), "line {line}");
        }
    }

    #[test]
    fn windows_powershell_version_consumes_a_value_before_encoded_command() {
        let payload = encode("Get-Date");
        let row = host(&format!("powershell.exe -Version 5.1 -enc {payload}"));
        assert_eq!(row.decoded_command.as_deref(), Some("Get-Date"));
    }

    #[test]
    fn only_explicit_powershell_invocations_are_inspected() {
        let payload = encode("Get-Date");
        for line in [
            format!("cmd.exe /c powershell.exe -enc {payload}"),
            format!("C:\\Windows\\System32\\cmd.exe /c \"powershell -enc {payload}\""),
            format!("powershell_ise.exe -enc {payload}"),
            format!("notpowershell.exe -enc {payload}"),
            format!("wscript.exe run.vbs -enc {payload}"),
            format!("-enc {payload}"),
            format!("Write-Host; {payload}"),
            format!("CommandInvocation(Invoke-Expression): payload {payload}"),
        ] {
            assert!(decode_commands("", &line).is_empty(), "line {line}");
        }
        assert!(decode_commands("", "").is_empty());
        assert!(decode_commands("", "   ").is_empty());
    }

    #[test]
    fn console_invocations_respect_single_quotes_and_call_operator() {
        let payload = encode("Write-Output '한글'");
        for command in [
            format!("powershell -enc '{payload}'"),
            format!("& 'C:\\Windows\\powershell.exe' -enc '{payload}'"),
        ] {
            let row = only(&command, "");
            assert_eq!(row.decoded_command.as_deref(), Some("Write-Output '한글'"));
        }
        for command in [
            format!("'powershell -enc {payload}'"),
            format!("\"powershell.exe\" -enc {payload}"),
        ] {
            assert!(decode_commands(&command, "").is_empty());
        }
        let row = host(&format!("powershell -enc '{payload}'"));
        assert_eq!(row.decode_status, "invalid_base64");
    }

    #[test]
    fn missing_or_empty_payload_is_reported_not_guessed() {
        for line in ["powershell.exe -NoLogo -EncodedCommand", "pwsh -enc \"\""] {
            let row = host(line);
            assert_eq!(row.decode_status, "missing_payload", "line {line}");
            assert_eq!(row.encoded_command, "");
            assert_eq!(row.decoded_command, None);
            assert!(row.decode_error.is_some());
        }
    }

    #[test]
    fn malformed_base64_is_reported_with_the_payload_kept() {
        for payload in [
            "not*base64!",
            "QQA",     // padding stripped
            "QQA==",   // non-canonical padding
            "QQ A=",   // embedded white space
            "-NoLogo", // next token consumed verbatim
        ] {
            let row = host(&format!("powershell.exe -enc \"{payload}\""));
            assert_eq!(row.decode_status, "invalid_base64", "payload {payload}");
            assert_eq!(row.encoded_command, payload);
            assert_eq!(row.decoded_command, None);
            assert!(row.decode_error.is_some());
        }
    }

    #[test]
    fn odd_byte_count_and_unpaired_surrogate_are_invalid_utf16() {
        let odd = base64::engine::general_purpose::STANDARD.encode([0x41u8, 0x00, 0x42]);
        let row = host(&format!("powershell.exe -enc {odd}"));
        assert_eq!(row.decode_status, "invalid_utf16");
        assert!(row.decode_error.unwrap().contains("3 bytes"));

        let lone = base64::engine::general_purpose::STANDARD.encode([0x41u8, 0x00, 0x00, 0xD8]);
        let row = host(&format!("powershell.exe -enc {lone}"));
        assert_eq!(row.decode_status, "invalid_utf16");
        assert_eq!(row.decoded_command, None);
        assert!(row.decode_error.unwrap().contains("D800"));
    }

    #[test]
    fn second_encoded_command_is_ambiguous_and_still_preserved() {
        let first = encode("Get-Date");
        let second = encode("whoami");
        let rows = decode_commands("", &format!("powershell.exe -enc {first} -enc {second}"));
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].decode_status, "success");
        assert_eq!(rows[0].decoded_command.as_deref(), Some("Get-Date"));
        assert_eq!(rows[1].decode_status, "ambiguous_command_line");
        assert_eq!(rows[1].encoded_command, second);
        assert_eq!(rows[1].decoded_command.as_deref(), Some("whoami"));
        assert!(rows[1].decode_error.is_some());
    }

    #[test]
    fn both_source_fields_are_scanned_in_order() {
        let from_command = encode("Get-Date");
        let from_host = encode("whoami");
        let rows = decode_commands(
            &format!("powershell.exe -enc {from_command}"),
            &format!("{PS51} -NoProfile -enc {from_host}"),
        );
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].source_field, "command");
        assert_eq!(rows[0].decoded_command.as_deref(), Some("Get-Date"));
        assert_eq!(rows[1].source_field, "host_application");
        assert_eq!(rows[1].decoded_command.as_deref(), Some("whoami"));
    }

}
