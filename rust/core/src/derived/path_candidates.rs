//! Path-based candidate links from path references to MFT file entries.
//! Every stored row is a candidate only: an equal path never proves the same
//! file, and a volume key never proves the same physical volume. Candidates are
//! generated after FileSystemEntries streaming, from the two derived databases.
use std::path::Path;

use anyhow::{Context as _, Result};
use rusqlite::{Connection, OpenFlags};

/// Child table of PathReferences holding one row per candidate file entry.
const CANDIDATES_TABLE: &str = "PathReferenceCandidates";

// Accept "C" or "C:" and keep anything else unknown; NULL stays NULL.
fn drive_expr(column: &str) -> String {
    format!(
        "CASE WHEN substr(trim({column}),1,1) GLOB '[A-Za-z]' \
           AND (length(trim({column})) = 1 OR (length(trim({column})) = 2 AND substr(trim({column}),2,1) = ':')) \
          THEN upper(substr(trim({column}),1,1)) END"
    )
}

// Stream the join straight into the child table: no MFT record or BLOB is
// loaded into memory, and the ordinal is assigned by a deterministic window.
fn insert_sql() -> String {
    let ref_drive = drive_expr("target_drive_letter");
    let file_drive = drive_expr("drive_letter");
    format!(
        "WITH refs AS (
           SELECT record_id, host_id, dataset_id, path, {ref_drive} AS drive
           FROM main.\"PathReferences\"
           WHERE path_kind IN ('drive_absolute','volume_relative')
             AND path IS NOT NULL AND path <> ''
         ),
         files AS (
           SELECT record_id, host_id, dataset_id, path_key, volume_id, entry, seq,
                  {file_drive} AS drive
           FROM entries.\"FileSystemEntries\"
           -- Only fully resolved paths are comparable, and a candidate without a
           -- volume identity cannot be recorded.
           WHERE path_status = 'complete'
             AND path_key IS NOT NULL AND path_key <> ''
             AND volume_id IS NOT NULL
         ),
         matched AS (
           SELECT r.record_id AS record_id,
                  f.record_id AS file_record_id,
                  f.volume_id AS volume_id,
                  f.entry AS entry,
                  f.seq AS seq,
                  CASE WHEN r.drive IS NOT NULL AND f.drive IS NOT NULL
                       THEN 'path_and_drive' ELSE 'path' END AS match_basis
           FROM refs r
           JOIN files f
             ON f.path_key = r.path
            AND f.host_id = r.host_id
            AND f.dataset_id = r.dataset_id
           -- Two confirmed and different drive letters rule the file out.
           WHERE r.drive IS NULL OR f.drive IS NULL OR r.drive = f.drive
         )
         INSERT INTO \"{CANDIDATES_TABLE}\"(record_id, ordinal, file_record_id, volume_id, match_basis)
         SELECT record_id,
                ROW_NUMBER() OVER (
                  PARTITION BY record_id
                  ORDER BY volume_id, entry, seq, file_record_id
                ) - 1,
                file_record_id, volume_id, match_basis
         FROM matched"
    )
}

/// Record path candidates for every reference of this host and generation.
pub(super) fn build(ctx: &super::Ctx) -> Result<()> {
    build_in(&ctx.overview_dir()).map(|_| ())
}

// Takes the _OVERVIEW folder so tests can drive the real SQL directly.
fn build_in(overview_dir: &Path) -> Result<usize> {
    let references = overview_dir.join("PathReferences.sqlite");
    let entries = overview_dir.join("FileSystemEntries.sqlite");
    if !entries.is_file() {
        anyhow::bail!("파일 시스템 DB가 없습니다: {}", entries.display());
    }
    // Both databases are generated before this step; never create them here.
    let conn = Connection::open_with_flags(&references, OpenFlags::SQLITE_OPEN_READ_WRITE)
        .with_context(|| format!("경로 참조 DB 열기: {}", references.display()))?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.execute(
        "ATTACH DATABASE ?1 AS entries",
        [entries.to_string_lossy().as_ref()],
    )
    .with_context(|| format!("파일 시스템 DB 연결: {}", entries.display()))?;

    conn.execute_batch("BEGIN IMMEDIATE")?;
    // Regenerate from scratch so a repeated run keeps the same rows.
    conn.execute(&format!("DELETE FROM \"{CANDIDATES_TABLE}\""), [])?;
    let rows = conn
        .execute(&insert_sql(), [])
        .context("경로 참조 후보 저장")?;
    conn.execute_batch("COMMIT")?;
    conn.execute_batch("DETACH DATABASE entries")?;
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::params;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static SEQ: AtomicUsize = AtomicUsize::new(0);

    struct Fixture {
        dir: PathBuf,
        references: Connection,
        entries: Connection,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    impl Fixture {
        fn new(name: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "wina-path-candidates-{}-{}-{}",
                name,
                std::process::id(),
                SEQ.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = std::fs::remove_dir_all(&dir);
            let references = super::super::create_database(&dir, "PathReferences").unwrap();
            let entries = super::super::create_database(&dir, "FileSystemEntries").unwrap();
            Self {
                dir,
                references,
                entries,
            }
        }

        fn reference(
            &self,
            record_id: &str,
            host: &str,
            dataset: &str,
            path: &str,
            path_kind: &str,
            drive: Option<&str>,
        ) {
            self.references
                .execute(
                    "INSERT INTO PathReferences(record_id,host_id,dataset_id,overview_name,path,path_kind,target_drive_letter)
                     VALUES (?1,?2,?3,'PathReferences',?4,?5,?6)",
                    params![record_id, host, dataset, path, path_kind, drive],
                )
                .unwrap();
        }

        #[allow(clippy::too_many_arguments)]
        fn entry(
            &self,
            record_id: &str,
            host: &str,
            dataset: &str,
            path_key: &str,
            path_status: &str,
            volume_id: &str,
            volume_label: Option<&str>,
            drive: Option<&str>,
            entry: i64,
            seq: i64,
            data: Option<&[u8]>,
        ) {
            self.entries
                .execute(
                    "INSERT INTO FileSystemEntries(record_id,host_id,dataset_id,overview_name,path,path_key,path_status,volume_id,volume_label,drive_letter,entry,seq,data)
                     VALUES (?1,?2,?3,'FileSystemEntries',?4,?4,?5,?6,?7,?8,?9,?10,?11)",
                    params![record_id, host, dataset, path_key, path_status, volume_id, volume_label, drive, entry, seq, data],
                )
                .unwrap();
        }

        fn build(&self) -> usize {
            build_in(&self.dir).unwrap()
        }

        fn candidates(&self) -> Vec<(String, i64, String, String, String)> {
            let mut stmt = self
                .references
                .prepare(
                    "SELECT record_id, ordinal, file_record_id, volume_id, match_basis
                     FROM PathReferenceCandidates ORDER BY record_id, ordinal",
                )
                .unwrap();
            let rows = stmt
                .query_map([], |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                })
                .unwrap();
            rows.collect::<rusqlite::Result<Vec<_>>>().unwrap()
        }
    }

    #[test]
    fn two_inputs_with_the_same_path_stay_separate_candidates() {
        let fx = Fixture::new("two-inputs");
        fx.reference("ref", "host", "gen", "\\users\\alice\\a.txt", "drive_absolute", None);
        // Equal labels and equal paths, different inputs and different bodies.
        fx.entry("file-b", "host", "gen", "\\users\\alice\\a.txt", "complete", "vol-b", Some("DATA"), None, 70, 1, Some(b"second"));
        fx.entry("file-a", "host", "gen", "\\users\\alice\\a.txt", "complete", "vol-a", Some("DATA"), None, 90, 2, Some(b"first"));

        assert_eq!(fx.build(), 2);
        assert_eq!(
            fx.candidates(),
            vec![
                ("ref".into(), 0, "file-a".into(), "vol-a".into(), "path".into()),
                ("ref".into(), 1, "file-b".into(), "vol-b".into(), "path".into()),
            ]
        );
    }

    #[test]
    fn a_known_and_different_drive_letter_excludes_the_file() {
        let fx = Fixture::new("drive-mismatch");
        fx.reference("ref", "host", "gen", "\\tools\\run.exe", "drive_absolute", Some("C"));
        fx.entry("same", "host", "gen", "\\tools\\run.exe", "complete", "vol-c", None, Some("C:"), 11, 1, None);
        fx.entry("other", "host", "gen", "\\tools\\run.exe", "complete", "vol-d", None, Some("D"), 12, 1, None);
        fx.entry("unknown", "host", "gen", "\\tools\\run.exe", "complete", "vol-e", None, None, 13, 1, None);
        fx.entry("malformed", "host", "gen", "\\tools\\run.exe", "complete", "vol-f", None, Some("C:folder"), 14, 1, None);

        assert_eq!(fx.build(), 3);
        assert_eq!(
            fx.candidates(),
            vec![
                ("ref".into(), 0, "same".into(), "vol-c".into(), "path_and_drive".into()),
                ("ref".into(), 1, "unknown".into(), "vol-e".into(), "path".into()),
                ("ref".into(), 2, "malformed".into(), "vol-f".into(), "path".into()),
            ]
        );
    }

    #[test]
    fn incomplete_paths_and_non_local_kinds_are_excluded() {
        let fx = Fixture::new("excluded");
        fx.reference("abs", "host", "gen", "\\users\\alice\\a.txt", "drive_absolute", None);
        for (id, kind, path) in [
            ("unc", "unc", "\\\\server\\share\\users\\alice\\a.txt"),
            ("rel", "relative", "\\users\\alice\\a.txt"),
            ("drv", "drive_relative", "\\users\\alice\\a.txt"),
            ("shell", "shell_namespace", "\\users\\alice\\a.txt"),
        ] {
            fx.reference(id, "host", "gen", path, kind, None);
        }
        // Only fully resolved MFT paths may be compared.
        fx.entry("mismatch", "host", "gen", "\\users\\alice\\a.txt", "sequence_mismatch", "vol-a", None, None, 40, 1, None);
        fx.entry("orphan", "host", "gen", "\\users\\alice\\a.txt", "orphan", "vol-b", None, None, 41, 1, None);
        fx.entry("unknown", "host", "gen", "\\users\\alice\\a.txt", "unknown", "vol-c", None, None, 42, 1, None);

        assert_eq!(fx.build(), 0);
        assert!(fx.candidates().is_empty());
    }

    #[test]
    fn other_hosts_and_generations_are_not_joined() {
        let fx = Fixture::new("host-dataset");
        fx.reference("ref", "host", "gen", "\\windows\\notepad.exe", "volume_relative", None);
        fx.entry("same", "host", "gen", "\\windows\\notepad.exe", "complete", "vol-a", None, None, 20, 1, None);
        fx.entry("other-host", "host2", "gen", "\\windows\\notepad.exe", "complete", "vol-b", None, None, 21, 1, None);
        fx.entry("other-gen", "host", "gen2", "\\windows\\notepad.exe", "complete", "vol-c", None, None, 22, 1, None);

        assert_eq!(fx.build(), 1);
        assert_eq!(
            fx.candidates(),
            vec![("ref".into(), 0, "same".into(), "vol-a".into(), "path".into())]
        );
    }

    #[test]
    fn duplicate_paths_inside_one_volume_keep_both_entries() {
        let fx = Fixture::new("duplicates");
        fx.reference("ref", "host", "gen", "\\temp\\x.dat", "drive_absolute", Some("C"));
        fx.entry("reused", "host", "gen", "\\temp\\x.dat", "complete", "vol-a", None, Some("C"), 55, 7, None);
        fx.entry("original", "host", "gen", "\\temp\\x.dat", "complete", "vol-a", None, Some("C"), 55, 3, None);
        fx.entry("newer", "host", "gen", "\\temp\\x.dat", "complete", "vol-a", None, Some("C"), 56, 1, None);

        assert_eq!(fx.build(), 3);
        assert_eq!(
            fx.candidates(),
            vec![
                ("ref".into(), 0, "original".into(), "vol-a".into(), "path_and_drive".into()),
                ("ref".into(), 1, "reused".into(), "vol-a".into(), "path_and_drive".into()),
                ("ref".into(), 2, "newer".into(), "vol-a".into(), "path_and_drive".into()),
            ]
        );
    }

    #[test]
    fn each_reference_gets_its_own_ordinals() {
        let fx = Fixture::new("per-reference");
        fx.reference("ref-1", "host", "gen", "\\a.txt", "drive_absolute", None);
        fx.reference("ref-2", "host", "gen", "\\a.txt", "drive_absolute", None);
        fx.entry("file-a", "host", "gen", "\\a.txt", "complete", "vol-a", None, None, 30, 1, None);
        fx.entry("file-b", "host", "gen", "\\a.txt", "complete", "vol-b", None, None, 31, 1, None);

        assert_eq!(fx.build(), 4);
        assert_eq!(
            fx.candidates(),
            vec![
                ("ref-1".into(), 0, "file-a".into(), "vol-a".into(), "path".into()),
                ("ref-1".into(), 1, "file-b".into(), "vol-b".into(), "path".into()),
                ("ref-2".into(), 0, "file-a".into(), "vol-a".into(), "path".into()),
                ("ref-2".into(), 1, "file-b".into(), "vol-b".into(), "path".into()),
            ]
        );
    }

    #[test]
    fn missing_data_produces_no_candidates() {
        let fx = Fixture::new("empty");
        assert_eq!(fx.build(), 0);
        assert!(fx.candidates().is_empty());
    }

    #[test]
    fn candidates_are_removed_with_their_reference() {
        let fx = Fixture::new("cascade");
        fx.reference("ref", "host", "gen", "\\a.txt", "drive_absolute", None);
        fx.entry("file-a", "host", "gen", "\\a.txt", "complete", "vol-a", None, None, 30, 1, None);
        assert_eq!(fx.build(), 1);

        fx.references
            .pragma_update(None, "foreign_keys", "ON")
            .unwrap();
        fx.references
            .execute("DELETE FROM PathReferences WHERE record_id='ref'", [])
            .unwrap();
        assert!(fx.candidates().is_empty());
    }
}
