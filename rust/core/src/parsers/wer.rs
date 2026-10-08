//! Windows Error Reporting (Report.wer) parser. Each .wer is a UTF-16LE
//! key=value text file. One row per report: a few promoted scalar columns +
//! the whole report as ONE json "report" column (scalars, then indexed
//! families like LoadedModule[0..N] collapsed to arrays), byte-identical to the
//! Python parser's json.dumps output. Pure text parsing — very fast in Rust.
use std::path::Path;

use anyhow::Result;
use rayon::prelude::*;
use serde::Serialize;
use serde_json::{Map, Value};

use crate::sqlite::Row;
use crate::time::fmt_filetime;

pub const WER_TABLE: &str = "WER_Reports";
/// Facts columns. The first seven keep the original promoted scalars and the
/// whole-report JSON; the rest preserve the complete input text, every raw
/// key occurrence with its original array index, the decoding result and the
/// read status. Results written before these columns need a WER reparse.
pub const WER_FIELD_ORDER: &[&str] = &[
    "timestamp",
    "EventType",
    "AppName",
    "AppPath",
    "TargetAppId",
    "ReportIdentifier",
    "report",
    "report_text",
    "entries_json",
    "encoding",
    "decode_status",
    "decode_error",
    "byte_size",
    "line_count",
    "entry_count",
    "unparsed_line_count",
    "_status",
    "_error",
    "_source_file",
];

// json.dumps(x, ensure_ascii=False): compact with a space after ',' and ':'.
struct PyFmt;
impl serde_json::ser::Formatter for PyFmt {
    fn begin_array_value<W: ?Sized + std::io::Write>(
        &mut self,
        w: &mut W,
        first: bool,
    ) -> std::io::Result<()> {
        if first {
            Ok(())
        } else {
            w.write_all(b", ")
        }
    }
    fn begin_object_key<W: ?Sized + std::io::Write>(
        &mut self,
        w: &mut W,
        first: bool,
    ) -> std::io::Result<()> {
        if first {
            Ok(())
        } else {
            w.write_all(b", ")
        }
    }
    fn begin_object_value<W: ?Sized + std::io::Write>(&mut self, w: &mut W) -> std::io::Result<()> {
        w.write_all(b": ")
    }
}
fn py_json(v: &Value) -> String {
    let mut buf = Vec::new();
    let mut ser = serde_json::Serializer::with_formatter(&mut buf, PyFmt);
    v.serialize(&mut ser).ok();
    String::from_utf8(buf).unwrap_or_default()
}

fn key_valid(k: &str) -> bool {
    !k.is_empty()
        && k.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '[' || c == ']')
}
fn ident_ok(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
}
/// Matches the Python _INDEX_RE: family[idx] or family[idx].sub (whole key).
fn parse_index(key: &str) -> Option<(String, usize, Option<String>)> {
    let lb = key.find('[')?;
    let family = &key[..lb];
    if !ident_ok(family) {
        return None;
    }
    let after = &key[lb + 1..];
    let rb = after.find(']')?;
    let idx_str = &after[..rb];
    if idx_str.is_empty() || !idx_str.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let idx: usize = idx_str.parse().ok()?;
    let rest = &after[rb + 1..];
    let sub = if rest.is_empty() {
        None
    } else {
        let s = rest.strip_prefix('.')?;
        if !ident_ok(s) {
            return None;
        }
        Some(s.to_string())
    };
    Some((family, idx, sub).into_tuple())
}
trait IntoTuple {
    fn into_tuple(self) -> (String, usize, Option<String>);
}
impl IntoTuple for (&str, usize, Option<String>) {
    fn into_tuple(self) -> (String, usize, Option<String>) {
        (self.0.to_string(), self.1, self.2)
    }
}

/// Decoded report text with the evidence needed to judge the decoding itself.
#[derive(Debug)]
pub(crate) struct Decoded {
    pub text: String,
    pub encoding: &'static str,
    pub status: &'static str,
    pub error: Option<String>,
}

/// Decode UTF-16LE, reporting damage instead of hiding it: an odd trailing
/// byte and unpaired surrogates are both evidence about the source file.
fn utf16le_detailed(data: &[u8]) -> (String, Vec<String>) {
    let mut notes = Vec::new();
    if !data.len().is_multiple_of(2) {
        notes.push("utf-16le: dropped 1 odd trailing byte".to_string());
    }
    let units = data.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]]));
    let mut text = String::with_capacity(data.len() / 2);
    let mut unpaired = 0usize;
    for unit in char::decode_utf16(units) {
        match unit {
            Ok(c) => text.push(c),
            Err(_) => {
                unpaired += 1;
                text.push(char::REPLACEMENT_CHARACTER);
            }
        }
    }
    if unpaired > 0 {
        notes.push(format!("utf-16le: replaced {unpaired} unpaired surrogate(s)"));
    }
    (text, notes)
}

/// Windows writes some Report.wer files as UTF-16LE with no BOM. The report
/// text is ASCII-heavy, so such a file has a NUL in nearly every odd byte —
/// use that to tell it apart from UTF-8.
fn looks_utf16le(data: &[u8]) -> bool {
    if data.len() < 4 {
        return false;
    }
    let sample = &data[..data.len().min(256)];
    let odd_nuls = sample.iter().skip(1).step_by(2).filter(|&&b| b == 0).count();
    odd_nuls * 3 > sample.len() / 2
}

pub(crate) fn decode_detailed(data: &[u8]) -> Decoded {
    let utf16_bom = data.len() >= 2 && data[0] == 0xFF && data[1] == 0xFE;
    let utf8_bom = data.starts_with(&[0xEF, 0xBB, 0xBF]);
    let (mut text, encoding, notes) = if utf16_bom {
        let (text, notes) = utf16le_detailed(&data[2..]);
        (text, "utf-16le-bom", notes)
    } else if !utf8_bom && looks_utf16le(data) {
        let (text, notes) = utf16le_detailed(data);
        (text, "utf-16le", notes)
    } else {
        let mut notes = Vec::new();
        if std::str::from_utf8(data).is_err() {
            notes.push("utf-8: replaced invalid byte sequence(s)".to_string());
        }
        (
            String::from_utf8_lossy(data).into_owned(),
            if utf8_bom { "utf-8-bom" } else { "utf-8" },
            notes,
        )
    };
    if text.starts_with('\u{feff}') {
        let prefix = text.len() - text.trim_start_matches('\u{feff}').len();
        text.drain(..prefix);
    }
    let status = if notes.is_empty() { "ok" } else { "replaced" };
    let error = (!notes.is_empty()).then(|| notes.join("; "));
    Decoded {
        text,
        encoding,
        status,
        error,
    }
}

/// One parsed source line, kept with its file position, original key text and
/// untrimmed value. Repeated keys and original array indices survive here even
/// though the `report` JSON keeps one slot per key and renumbers arrays.
fn raw_entry(line_no: usize, key: &str, raw_value: &str) -> Value {
    let mut entry = Map::new();
    entry.insert("line".into(), Value::from(line_no as u64));
    entry.insert("key".into(), Value::String(key.to_string()));
    if let Some((family, index, sub)) = parse_index(key) {
        entry.insert("family".into(), Value::String(family));
        entry.insert("index".into(), Value::from(index as u64));
        if let Some(sub) = sub {
            entry.insert("sub".into(), Value::String(sub));
        }
    }
    entry.insert("value".into(), Value::String(raw_value.to_string()));
    Value::Object(entry)
}

fn skipped_entry(line_no: usize, line: &str, reason: &str) -> Value {
    let mut entry = Map::new();
    entry.insert("line".into(), Value::from(line_no as u64));
    entry.insert("skipped".into(), Value::String(reason.to_string()));
    entry.insert("raw".into(), Value::String(line.to_string()));
    Value::Object(entry)
}

fn parse_report(path: &Path) -> Row {
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            let mut r = Row::new();
            r.insert("timestamp".into(), String::new());
            r.insert("_source_file".into(), path.to_string_lossy().into());
            r.insert("_status".into(), "unreadable_file".into());
            r.insert("_error".into(), e.to_string());
            return r;
        }
    };
    let decoded = decode_detailed(&data);
    let text = decoded.text;

    // scalars in file order (dedup-update keeps first position, like a dict);
    // families in first-seen order, each a sorted-by-index map of Value.
    let mut scalars: Map<String, Value> = Map::new();
    let mut fam_order: Vec<String> = Vec::new();
    let mut families: std::collections::HashMap<String, std::collections::BTreeMap<usize, Value>> =
        std::collections::HashMap::new();
    let mut entries: Vec<Value> = Vec::new();
    let mut lines = 0usize;
    let mut unparsed = 0usize;

    for (offset, line) in text.lines().enumerate() {
        let line_no = offset + 1;
        lines = line_no;
        let Some(eq) = line.find('=') else {
            unparsed += 1;
            entries.push(skipped_entry(line_no, line, "no_separator"));
            continue;
        };
        let key = line[..eq].trim();
        if !key_valid(key) {
            unparsed += 1;
            entries.push(skipped_entry(line_no, line, "invalid_key"));
            continue;
        }
        let raw_value = &line[eq + 1..];
        entries.push(raw_entry(line_no, key, raw_value));
        let value = raw_value.trim().to_string();
        if let Some((fam, idx, sub)) = parse_index(key) {
            if !families.contains_key(&fam) {
                fam_order.push(fam.clone());
            }
            let bucket = families.entry(fam).or_default();
            match sub {
                Some(sk) => {
                    let slot = bucket
                        .entry(idx)
                        .or_insert_with(|| Value::Object(Map::new()));
                    if !slot.is_object() {
                        *slot = Value::Object(Map::new());
                    }
                    if let Value::Object(m) = slot {
                        m.insert(sk, Value::String(value));
                    }
                }
                None => {
                    bucket.insert(idx, Value::String(value));
                }
            }
        } else {
            scalars.insert(key.to_string(), Value::String(value));
        }
    }

    let timestamp = match scalars
        .get("EventTime")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<i64>().ok())
    {
        Some(t) if t > 0 => fmt_filetime(t),
        _ => String::new(),
    };
    let get = |k: &str| {
        scalars
            .get(k)
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string()
    };

    // full = scalars (in order) then families (first-seen order) as arrays.
    let mut full: Map<String, Value> = Map::new();
    for (k, v) in &scalars {
        full.insert(k.clone(), v.clone());
    }
    for fam in &fam_order {
        let bucket = &families[fam];
        let arr: Vec<Value> = bucket.values().cloned().collect();
        full.insert(fam.clone(), Value::Array(arr));
    }

    let mut r = Row::new();
    r.insert("timestamp".into(), timestamp);
    r.insert("EventType".into(), get("EventType"));
    r.insert("AppName".into(), get("AppName"));
    r.insert("AppPath".into(), get("AppPath"));
    r.insert("TargetAppId".into(), get("TargetAppId"));
    r.insert("ReportIdentifier".into(), get("ReportIdentifier"));
    r.insert("report".into(), py_json(&Value::Object(full)));
    r.insert("report_text".into(), text);
    r.insert("entry_count".into(), entries.len().to_string());
    r.insert(
        "entries_json".into(),
        serde_json::to_string(&Value::Array(entries)).unwrap_or_default(),
    );
    r.insert("encoding".into(), decoded.encoding.into());
    r.insert("decode_status".into(), decoded.status.into());
    if let Some(error) = decoded.error {
        r.insert("decode_error".into(), error);
    }
    r.insert("byte_size".into(), data.len().to_string());
    r.insert("line_count".into(), lines.to_string());
    r.insert("unparsed_line_count".into(), unparsed.to_string());
    r.insert("_status".into(), "parsed".into());
    r.insert("_source_file".into(), path.to_string_lossy().into());
    r
}

pub fn wer_sources(root: &Path) -> crate::finder::Found {
    let (files, errors) = crate::finder::walk_files(root);
    let mut paths: Vec<_> = files
        .into_iter()
        .filter(|p| {
            p.extension()
                .map(|e| e.eq_ignore_ascii_case("wer"))
                .unwrap_or(false)
        })
        .collect();
    paths.sort();
    crate::finder::Found { paths, errors }
}

/// Parse already-discovered Report.wer files.
pub fn parse_wer_from(paths: &[std::path::PathBuf]) -> Vec<Row> {
    // Reports are independent. Parallel decoding/parsing leaves every report
    // represented, while indexed parallel collection keeps discovery order.
    paths.par_iter().map(|path| parse_report(path)).collect()
}

pub fn parse_wer_with_sources(root: &Path) -> Result<(Vec<std::path::PathBuf>, Vec<Row>)> {
    let paths = wer_sources(root).paths;
    let rows = parse_wer_from(&paths);
    Ok((paths, rows))
}

pub fn parse_wer(root: &Path) -> Result<Vec<Row>> {
    Ok(parse_wer_with_sources(root)?.1)
}

#[cfg(test)]
mod tests {
    use super::{decode_detailed, parse_report, WER_FIELD_ORDER};
    use serde_json::Value;

    fn utf16le_bytes(s: &str, bom: bool) -> Vec<u8> {
        let mut out = Vec::new();
        if bom {
            out.extend_from_slice(&[0xFF, 0xFE]);
        }
        for u in s.encode_utf16() {
            out.extend_from_slice(&u.to_le_bytes());
        }
        out
    }

    fn write(name: &str, bytes: &[u8]) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("wina-wer-facts-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(name);
        std::fs::write(&path, bytes).unwrap();
        path
    }

    #[test]
    fn decode_utf16le_with_bom() {
        let text = "Version=1\r\nEventType=APPCRASH\r\nAppName=foo.exe\r\n";
        assert_eq!(decode_detailed(&utf16le_bytes(text, true)).text, text);
    }

    #[test]
    fn decode_utf16le_without_bom() {
        // Windows writes some Report.wer files as BOM-less UTF-16LE.
        let text = "Version=1\r\nEventType=APPCRASH\r\nAppName=foo.exe\r\n";
        assert_eq!(decode_detailed(&utf16le_bytes(text, false)).text, text);
    }

    #[test]
    fn decode_utf8_stays_utf8() {
        let text = "Version=1\r\nEventType=APPCRASH\r\n";
        assert_eq!(decode_detailed(text.as_bytes()).text, text);
    }

    /// R16: encoding and decoding damage are evidence, not silent repairs.
    #[test]
    fn decode_reports_encoding_and_replacement() {
        let text = "EventType=APPCRASH\r\n";
        let clean = decode_detailed(&utf16le_bytes(text, true));
        assert_eq!((clean.encoding, clean.status), ("utf-16le-bom", "ok"));
        assert!(clean.error.is_none());
        let plain = decode_detailed(text.as_bytes());
        assert_eq!((plain.encoding, plain.status), ("utf-8", "ok"));
        let mut bom8 = vec![0xEF, 0xBB, 0xBF];
        bom8.extend_from_slice(text.as_bytes());
        assert_eq!(decode_detailed(&bom8).encoding, "utf-8-bom");
        let mut lone = utf16le_bytes("A=1\r\n", true);
        lone.extend_from_slice(&0xD800u16.to_le_bytes());
        let broken = decode_detailed(&lone);
        assert_eq!(broken.status, "replaced");
        assert!(broken.error.as_deref().unwrap().contains("surrogate"));
        let mut odd_bytes = utf16le_bytes("A=1\r\n", false);
        odd_bytes.push(0x41);
        let odd = decode_detailed(&odd_bytes);
        assert!(odd.error.as_deref().unwrap_or_default().contains("odd"));
        let invalid = decode_detailed(&[0x41, 0x3D, 0xFF, 0x0A]);
        assert_eq!(invalid.encoding, "utf-8");
        assert_eq!(invalid.status, "replaced");
    }

    /// R03/R04: original keys, repeated fields and original array indices
    /// survive next to the existing report JSON.
    #[test]
    fn facts_preserve_raw_entries_duplicates_and_original_indices() {
        let text = "Version=1\r\nEventType=AppHangB1\r\nEventTime=134350754916815872\r\n\
                    Sig[0].Name=Application Name\r\nSig[0].Value=app.exe\r\n\
                    DynamicSig[1].Name=OS Version\r\nDynamicSig[1].Value=10.0\r\n\
                    DynamicSig[2].Name=Locale ID\r\nDynamicSig[2].Value=1042\r\n\
                    OsInfo[30].Key=buildflightid\r\n\
                    Consent=1\r\nConsent=2\r\n\
                    LoadedModule[1]= C:\\a.dll \r\n\
                    not a pair\r\nbad key!=1\r\n";
        let path = write("Report.wer", &utf16le_bytes(text, true));
        let row = parse_report(&path);
        assert_eq!(row.get("_status").map(String::as_str), Some("parsed"));
        assert_eq!(row.get("encoding").map(String::as_str), Some("utf-16le-bom"));
        let size = std::fs::metadata(&path).unwrap().len().to_string();
        assert_eq!(row.get("byte_size"), Some(&size));
        assert_eq!(row.get("line_count").map(String::as_str), Some("15"));
        assert_eq!(row.get("unparsed_line_count").map(String::as_str), Some("2"));
        // The complete decoded input is kept, not just the parsed pairs.
        assert_eq!(row.get("report_text").map(String::as_str), Some(text));
        let entries: Value = serde_json::from_str(row.get("entries_json").unwrap()).unwrap();
        let entries = entries.as_array().unwrap();
        assert_eq!(entries.len(), 15);
        // Repeated scalar keys keep both occurrences in file order.
        let consents: Vec<&Value> = entries
            .iter()
            .filter(|e| e.get("key").and_then(Value::as_str) == Some("Consent"))
            .collect();
        assert_eq!(consents.len(), 2);
        assert_eq!(consents[1]["value"], Value::String("2".into()));
        // Original index 1/2 is preserved although the JSON array starts at 0.
        let dynamic: Vec<(i64, String)> = entries
            .iter()
            .filter(|e| e.get("family").and_then(Value::as_str) == Some("DynamicSig"))
            .map(|e| {
                (
                    e["index"].as_i64().unwrap(),
                    e["sub"].as_str().unwrap_or_default().to_string(),
                )
            })
            .collect();
        assert_eq!(
            dynamic,
            vec![
                (1, "Name".to_string()),
                (1, "Value".to_string()),
                (2, "Name".to_string()),
                (2, "Value".to_string())
            ]
        );
        assert_eq!(entries[9]["index"].as_i64(), Some(30));
        // Untrimmed raw values stay available next to the trimmed report JSON.
        let module = entries
            .iter()
            .find(|e| e.get("family").and_then(Value::as_str) == Some("LoadedModule"))
            .unwrap();
        assert_eq!(module["value"], Value::String(" C:\\a.dll ".into()));
        let report: Value = serde_json::from_str(row.get("report").unwrap()).unwrap();
        assert_eq!(report["LoadedModule"][0], Value::String("C:\\a.dll".into()));
        // Skipped lines are recorded with their reason, never dropped silently.
        let skipped: Vec<&str> = entries
            .iter()
            .filter_map(|e| e.get("skipped").and_then(Value::as_str))
            .collect();
        assert_eq!(skipped, vec!["no_separator", "invalid_key"]);
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    /// R16: an unreadable report keeps its failure row and no invented values.
    #[test]
    fn unreadable_report_keeps_failure_status() {
        let dir = std::env::temp_dir().join(format!("wina-wer-missing-{}", uuid::Uuid::new_v4()));
        let row = parse_report(&dir.join("Report.wer"));
        assert_eq!(row.get("_status").map(String::as_str), Some("unreadable_file"));
        assert!(!row.get("_error").unwrap().is_empty());
        assert_eq!(row.get("report"), None);
        assert_eq!(row.get("report_text"), None);
        assert_eq!(row.get("entries_json"), None);
        // Both failure columns are declared so every result can be queried.
        assert!(WER_FIELD_ORDER.contains(&"_status") && WER_FIELD_ORDER.contains(&"_error"));
    }
}
