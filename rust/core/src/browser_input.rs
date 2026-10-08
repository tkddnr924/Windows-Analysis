//! Original browser input identity, independent of output naming.
use anyhow::{Context, Result};
use rusqlite::Connection;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct BrowserInput {
    pub source_file: Option<String>,
    pub browser: Option<String>,
    pub profile: Option<String>,
    pub account_label: Option<String>,
    pub input_kind: String,
}

impl BrowserInput {
    pub fn from_source(path: &Path, kind: &str, browser_hint: Option<&str>) -> Self {
        let source = path.to_string_lossy().into_owned();
        let normalized = source.replace('\\', "/");
        let parts: Vec<_> = normalized.split('/').filter(|s| !s.is_empty()).collect();
        // A collected account outranks the examiner's home-directory name.
        let collection = parts
            .windows(2)
            .position(|p| p[0].eq_ignore_ascii_case("BROWSER"));
        let native_profile = parts.windows(3).position(|p| {
            p[0].eq_ignore_ascii_case("Users") && p[2].eq_ignore_ascii_case("AppData")
        });
        let account_position = collection.or(native_profile);
        let account_label = account_position.map(|i| parts[i + 1].to_string());
        let browser_part = parts
            .iter()
            .enumerate()
            .skip(account_position.map_or(0, |i| i + 2))
            .find(|(_, p)| {
                ["Chrome", "Edge", "Whale"]
                    .iter()
                    .any(|b| p.eq_ignore_ascii_case(b))
            })
            .map(|(i, _)| i);
        let browser = browser_part
            .map(|i| {
                if parts[i].eq_ignore_ascii_case("Chrome") {
                    "Chrome"
                } else if parts[i].eq_ignore_ascii_case("Edge") {
                    "Edge"
                } else {
                    "Whale"
                }
                .to_string()
            })
            .or_else(|| browser_hint.map(str::to_string))
            .or_else(|| kind.starts_with("ie_").then(|| "IE".to_string()));
        let profile = browser_part.and_then(|i| {
            let mut next = i + 1;
            if parts
                .get(next)
                .is_some_and(|p| p.eq_ignore_ascii_case("User Data"))
            {
                next += 1;
            }
            parts
                .get(next)
                .filter(|p| {
                    next + 1 < parts.len()
                        && !p.eq_ignore_ascii_case("Cache")
                        && !p.eq_ignore_ascii_case("Cache_Data")
                })
                .map(|p| p.to_string())
        });
        Self {
            source_file: Some(source),
            browser,
            profile,
            account_label,
            input_kind: kind.to_string(),
        }
    }
}

pub fn write_input(path: &Path, input: &BrowserInput) -> Result<()> {
    let mut conn = Connection::open(path)?;
    let tx = conn.transaction()?;
    tx.execute_batch(
        "DROP TABLE IF EXISTS _wina_browser_input;
        CREATE TABLE _wina_browser_input (
            source_file TEXT, browser TEXT, profile TEXT, account_label TEXT,
            input_kind TEXT NOT NULL);",
    )?;
    tx.execute(
        "INSERT INTO _wina_browser_input VALUES (?1,?2,?3,?4,?5)",
        rusqlite::params![
            input.source_file,
            input.browser,
            input.profile,
            input.account_label,
            input.input_kind
        ],
    )?;
    tx.commit()?;
    Ok(())
}

pub fn read_input(conn: &Connection) -> Result<BrowserInput> {
    conn.query_row(
        "SELECT source_file,browser,profile,account_label,input_kind
        FROM _wina_browser_input",
        [],
        |row| {
            Ok(BrowserInput {
                source_file: row.get(0)?,
                browser: row.get(1)?,
                profile: row.get(2)?,
                account_label: row.get(3)?,
                input_kind: row.get(4)?,
            })
        },
    )
    .context("browser input identity missing; reparse the browser artifact")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collected_identity_wins_over_examiner_home_and_browser_directories() {
        let input = BrowserInput::from_source(
            Path::new(
                "/Users/examiner/Chrome/collection/BROWSER/Administrator/EDGE/Default/History",
            ),
            "history",
            Some("Chrome"),
        );
        assert_eq!(input.account_label.as_deref(), Some("Administrator"));
        assert_eq!(input.browser.as_deref(), Some("Edge"));
        assert_eq!(input.profile.as_deref(), Some("Default"));
        let unknown = BrowserInput::from_source(
            Path::new("/Users/examiner/Documents/History"),
            "history",
            None,
        );
        assert_eq!(unknown.account_label, None);
    }

    #[test]
    fn separates_profile_and_collected_label_without_filename_guessing() {
        let input = BrowserInput::from_source(
            Path::new("/evidence/BROWSER/analyst_2/CHROME/Profile 3/Cache/Cache_Data/index"),
            "cache",
            None,
        );
        assert_eq!(input.account_label.as_deref(), Some("analyst_2"));
        assert_eq!(input.browser.as_deref(), Some("Chrome"));
        assert_eq!(input.profile.as_deref(), Some("Profile 3"));
        let unknown =
            BrowserInput::from_source(Path::new("/evidence/cache_2/index"), "cache", None);
        assert_eq!(unknown.account_label, None);
        assert_eq!(unknown.browser, None);
        assert_eq!(unknown.profile, None);
    }

    #[test]
    fn preserves_original_paths_and_native_profile_layout() {
        let source =
            Path::new(r"C:\Users\Analyst\AppData\Local\Microsoft\Edge\User Data\Default\History");
        let input = BrowserInput::from_source(source, "history", Some("Edge"));
        assert_eq!(input.source_file.as_deref(), source.to_str());
        assert_eq!(input.account_label.as_deref(), Some("Analyst"));
        assert_eq!(input.profile.as_deref(), Some("Default"));
        let conn = Connection::open_in_memory().unwrap();
        assert!(read_input(&conn).is_err());
    }
}
