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
pub const WER_FIELD_ORDER: &[&str] = &[
    "timestamp",
    "EventType",
    "AppName",
    "AppPath",
    "TargetAppId",
    "ReportIdentifier",
    "report",
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

fn utf16le(data: &[u8]) -> String {
    let u: Vec<u16> = data
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&u)
}

/// Windows writes some Report.wer files as UTF-16LE with no BOM. The report
/// text is ASCII-heavy, so such a file has a NUL in nearly every odd byte —
/// use that to tell it apart from UTF-8.
fn looks_utf16le(data: &[u8]) -> bool {
    if data.len() < 4 || !data.len().is_multiple_of(2) {
        return false;
    }
    let sample = &data[..data.len().min(256)];
    let odd_nuls = sample.iter().skip(1).step_by(2).filter(|&&b| b == 0).count();
    odd_nuls * 3 > sample.len() / 2
}

fn decode(data: &[u8]) -> String {
    let s = if data.len() >= 2 && data[0] == 0xFF && data[1] == 0xFE {
        utf16le(&data[2..])
    } else if looks_utf16le(data) {
        utf16le(data)
    } else {
        String::from_utf8_lossy(data).into_owned()
    };
    s.trim_start_matches('\u{feff}').to_string()
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
    let text = decode(&data);

    // scalars in file order (dedup-update keeps first position, like a dict);
    // families in first-seen order, each a sorted-by-index map of Value.
    let mut scalars: Map<String, Value> = Map::new();
    let mut fam_order: Vec<String> = Vec::new();
    let mut families: std::collections::HashMap<String, std::collections::BTreeMap<usize, Value>> =
        std::collections::HashMap::new();

    for line in text.lines() {
        let Some(eq) = line.find('=') else { continue };
        let key = line[..eq].trim();
        if !key_valid(key) {
            continue;
        }
        let value = line[eq + 1..].trim().to_string();
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
    use super::decode;

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

    #[test]
    fn decode_utf16le_with_bom() {
        let text = "Version=1\r\nEventType=APPCRASH\r\nAppName=foo.exe\r\n";
        assert_eq!(decode(&utf16le_bytes(text, true)), text);
    }

    #[test]
    fn decode_utf16le_without_bom() {
        // Windows writes some Report.wer files as BOM-less UTF-16LE.
        let text = "Version=1\r\nEventType=APPCRASH\r\nAppName=foo.exe\r\n";
        assert_eq!(decode(&utf16le_bytes(text, false)), text);
    }

    #[test]
    fn decode_utf8_stays_utf8() {
        let text = "Version=1\r\nEventType=APPCRASH\r\n";
        assert_eq!(decode(text.as_bytes()), text);
    }
}
