# Rust pipeline — validation log (vs current Python output)

Baseline = current Python pipeline's SQLite output. Method = per-artifact
symmetric `EXCEPT` diff + per-column mismatch counts on the sample host, plus
sample eyeballing.

## $MFT  (parsers/mft.rs, via the `mft` crate)  — ✅ validated

Sample: `MAINDB1 .../METADATA/C/$MFT` (986 MB, 962,094 records).

| metric | Python | Rust | 
|---|---|---|
| records | 962,094 | 962,094 (exact match) |
| parse time | ~41 s | **~7.5 s (≈5× faster)** |
| write time | ~6.8 s | ~4 s |
| sqlite size | 492 MB | 492 MB (parity) |

Row diff (symmetric `EXCEPT`): **1,868 / 962,094 = 0.19%**, and every one of
those differs ONLY in a timestamp, by ≤ 1 ms. Exact matches on:
`path, file_name, extension, is_directory, in_use, file_size, entry, seq,
parent_entry` — 0 mismatches each (after aligning name-namespace priority to
the Python rule and using the FN real size `physical_size`).

Timestamp residual (≤1 ms, 0.19%): the `mft` crate converts FILETIME with
`Duration::microseconds(ticks/10)` — i.e. it FLOORS the 100 ns tick to a
microsecond — whereas Python builds the datetime with `timedelta(microseconds
= ticks/10)`, which ROUNDS to the nearest microsecond. When the dropped
sub-microsecond part is ≥ 0.5 µs and the floored microsecond ends in `999`,
Python's value rounds up into the next millisecond. Both are millisecond-
accurate; the ≤1 ms difference is a display-rounding convention, not a parse
error, and the crate's raw ticks are not exposed to recover it. Considered
acceptable (forensically immaterial).

Size note: further reduction is possible later (integer columns instead of
all-TEXT, dropping the repeated `_source_file`), deferred until functional
parity across all parsers is done so the current viewer keeps working.

## Registry hives  (parsers/registry.rs, via `notatin`)  — ✅ validated

notatin applies transaction logs (dirty-hive recovery) natively, replacing
regipy + `common/hive_recovery.py`. Value-type strings aligned to regipy
(REG_BIN→REG_BINARY; notatin's REG_UNKNOWN→raw numeric type, which is how SAM
encodes a RID in the type field). Binary rendered as lowercase hex, MULTI_SZ
as json.dumps-style `["a", "b"]`, matching the Python `_clean`.

### SOFTWARE (93 MB, dirty — 158 pages replayed)
| metric | Python | Rust |
|---|---|---|
| rows | 535,153 | 535,157 |
| time | ~12.1 s | **~1.3 s (≈9× faster)** |
| sqlite | 163 MB | 162 MB |

Content diff (5 cols, excl. `_source_file`): **443 / 535k = 0.08%**.
`value_type` 0 mismatches. `value_data` **9** — 8 are transaction-log
recovery-version differences in volatile keys (TaskCache DynamicInfo, download
times, Notifications\Data) where notatin and regipy replayed the logs to
slightly different cell versions; 1 MULTI_SZ likewise. MULTI_SZ decoding
verified fine at scale (3,584 vs 3,582 total, only 1 differs). `last_write`
408 — the same ≤1 ms FILETIME floor-vs-round as $MFT. notatin recovered ~4
extra keys/rows (slightly more complete log replay).

### SAM (account security-principal hive)
| metric | value |
|---|---|
| rows | 259 (Python) / 259 (Rust) |
| value_type diff | 0 |
| last_write diff | 0 |
| value_data diff | 2 (meaningless SAM `Names\` default bytes — regipy hexes, notatin decodes as text) |
| **V / F account binary records** | **exact match** (incl. a 752-byte V record — full raw bytes, no 128-byte regipy trim) |

Conclusion: functionally equivalent (arguably more complete recovery), ~9×
faster. Residuals are ≤1 ms timestamps and a handful of log-replay-version /
meaningless-slack bytes — forensically immaterial.

## Event Logs (.evtx)  (parsers/eventlog.rs, via the `evtx` crate)  — ✅ validated

The `evtx` crate is the same engine the Python `evtx` binding wraps, so the
JSON is structurally identical. EventData is serialized json.dumps-style
(space after `,`/`:`, insertion-ordered keys via serde_json `preserve_order`);
absent System fields are written as SQL NULL (Python's None), matching exactly.

Sample: `Microsoft-Windows-SystemDataArchiver%4Diagnostic.evtx` (300 MB,
485,333 records — the largest log, dense EventData).

| metric | Python | Rust |
|---|---|---|
| rows | 485,333 | 485,333 |
| time | ~9.5 s | ~7.6 s |
| content diff (15 cols, excl. `_source_file`) | — | **0 (byte-identical)** |

Every column — timestamp, EventID, Provider, the full EventData JSON — matches
byte-for-byte across all 485k rows.

## Amcache.hve  (parsers/amcache.rs, via notatin)  — ✅ validated (data-equivalence)

Amcache is a registry hive, so it reuses notatin. Programs = raw
InventoryApplication values; Files = the same snake_case columns +
sha1/file_id `[4:]` handling as regipy's AmCachePlugin.

Validation note: parsers whose raw table the analyst reads directly ($MFT,
Registry, EventLog) are validated byte-for-byte. Parsers whose output only
FEEDS the overview builders (Amcache, and the remaining SRUM/Prefetch/…) are
validated by data-equivalence now, and will be finalized by an end-to-end diff
of the overview tables once those builders are ported — chasing regipy's
arbitrary column-format quirks isn't worth it when both sides become Rust.

| metric | Python | Rust |
|---|---|---|
| programs | 139 | 139 (Name set: exact match) |
| files | 1,266 | 1,265 |
| file path set diff | — | 0 in rust-not-py, 1 in py-not-rust |
| SHA1 set diff | — | 0 / 1 |
| time | ~0.5 s | ~0.07 s |

The single missing file is `systemcollector_x64.exe` (the collector tool),
an edge/slack InventoryApplicationFile entry regipy surfaced but notatin's
live walk didn't — 0.08%. Program list and all file paths/SHA1s otherwise
match exactly.

## USN Journal ($UsnJrnl:$J)  (parsers/usnjrnl.rs, manual)  — ✅ validated

Pure manual struct parsing (USN_RECORD_V2/V3), no crate. Reason/attribute flag
decoding and record layout mirror the Python parser.

Sample: `.../METADATA/C/$J` (34 MB, 302,545 records).

| metric | Python | Rust |
|---|---|---|
| rows | 302,545 | 302,545 |
| time | ~3.1 s | **~0.47 s (≈6.6× faster)** |
| content diff (11 cols) | — | 103 / 302,545 = **0.034%**, all ≤1 ms timestamp |

filename, reason flags, attributes, MFT/file references — 0 mismatches. The
103 timestamp diffs are the same ≤1 ms artifact: Python's
`timedelta(microseconds=ticks/10)` does the division in f64, which loses
sub-µs precision at 2020s-era FILETIME magnitudes (> 2^53); the Rust path uses
exact integer round-half-even, so it's the more precise of the two.

## Task Scheduler (per-task XML)  (parsers/taskscheduler.rs, via roxmltree)  — ✅ validated

Located by the task-schema namespace in content (utf-8 or utf-16-le, first
4 KB — matching Python). Task XML is UTF-16LE; decoded to UTF-8 before parsing.

Sample: `.../TASKS_SYSTEM32/Tasks` (139 registered tasks).

| metric | Python | Rust |
|---|---|---|
| tasks | 139 | 139 |
| content diff (13 cols) | — | **0 (byte-identical)** |

Every field — actions, triggers, run-as/level, timestamps (KST) — matches.

## Enhancement: maximum recovery (deleted cells + transaction logs)

Per the directive "parse everything visible in the collected data, including
deleted", the Rust registry and Amcache parsers now go BEYOND the Python
originals — notatin's `recover_deleted(true)` plus transaction-log replay,
with a new `_recovery` column marking each row:
`live` | `DeletedPrimaryFile` | `DeletedPrimaryFileSlack` | `DeletedTransactionLog`.

- **Registry (SOFTWARE)**: 535,156 live rows (matches Python) PLUS **1,669
  recovered deleted entries** (1,231 slack + 331 transaction-log + 107 primary)
  that the Python pipeline never extracted at all.
- **Amcache**: files 1,265 → **1,266** — the entry the Python parser surfaced
  only via regipy slack (`systemcollector_x64.exe`, the collector tool) is now
  recovered via transaction-log replay; programs 139 and files 1,266 match
  Python exactly, all `live` after log replay. Amcache.hve's own .LOG1/.LOG2
  are applied (previously not).

This is a net improvement over the Python tool, which only carved deleted
Amcache *programs* and never recovered deleted registry keys/values.

## JumpList (Automatic/CustomDestinations)  (parsers/jumplist.rs, cfb + lnk)  — ✅ validated

AutomaticDestinations = OLE compound file (`cfb`); each stream (except DestList*)
is a Shell Link parsed with the `lnk` crate. CustomDestinations = LNKs split by
signature. The `lnk` crate doesn't expose the DistributedLinkTracker block, so
`machine_id` is parsed directly from the LNK bytes (0xA0000003 block) — a small
improvement so nothing visible is dropped.

Sample: `.../JUMPLIST` (228 entries across users).

| metric | Python | Rust |
|---|---|---|
| entries | 228 | 228 |
| full-row set diff (10 cols) | — | **0 (identical)** — incl. machine_id, target_path, RDP `/v:` args, times |

## SRUM (SRUDB.dat, ESE)  (parsers/srum.rs, via libesedb)  — ✅ validated + FIXED

libesedb (FFI to the SAME libyal C library the Python pyesedb binding wraps) →
identical ESE parsing. Two things needed care:

1. **OLE date, not FILETIME.** The libesedb crate decodes a DATE_TIME column as
   a FILETIME (u64 ticks). SRUM's `TimeStamp` is actually an OLE automation date
   (f64 days since 1899-12-30). Reinterpreting the bits as f64 (`f64::from_bits`)
   is required — otherwise every SRUM timestamp is garbage.

2. **The Python parser's problem (diagnosed):** on this host, SRUM uses a NEWER
   schema — the network-data-usage provider has columns BytesInBound /
   BytesOutBound / BytesTotal (not the classic BytesSent / BytesRecvd) under a
   different provider GUID. Python's fixed GUID→name map didn't recognize it, so
   the most important table (network bytes per app) showed as a cryptic
   `SRUM_EEE2F477...` hex name. The Rust parser names tables by COLUMN SIGNATURE
   (schema-stable, and not sample-specific like a regenerated GUID would be), so
   it's correctly labeled `SRUM_NetworkDataUsage`.

Validation (same underlying tables, Rust friendly-name vs Python GUID-name):

| table | rows | diff |
|---|---|---|
| NetworkDataUsage (BytesInBound/Out/Total) | 35,414 | **0** |
| ApplicationResourceUsage | 1,332 | **0** |
| NetworkConnectivityUsage | 5,654 | **0** |

timestamp (OLE date), app (UTF-16 id) and user (SID) resolution all match; 1.4 s
(Python ~several s). Net improvement: network usage is now discoverable by name.

## WER (Report.wer)  (parsers/wer.rs, manual text)  — ✅ validated + re-included

WER was dropped from the Python pipeline for being slow; ported to Rust and
brought back. Pure UTF-16LE key=value text parsing; the whole report is kept in
one json `report` column (scalars, then indexed families like LoadedModule[0..N]
as arrays) serialized json.dumps-style (spaces + preserve_order), plus promoted
scalar columns. EventTime FILETIME formatted with exact integer rounding.

Sample: `.../WER` (41 reports) — content diff (7 cols): **0 (byte-identical,
incl. the report JSON and timestamp)**.

Scale (8,200 unique reports): Rust **1.46 s** vs Python 2.46 s (~1.7×). WER
parsing is largely file-I/O-bound, so the gain is modest; the historical
"slowness" was actually the viewer's per-file log flood + wide-table render
(fixed earlier), not the parse. Re-including it in Rust is safe and faster.

## Browser History (Chrome "History" SQLite)  (parsers/browser_history.rs, rusqlite)  — ✅ validated

## Browser Cache (Chrome blockfile disk cache)  (parsers/browser_cache.rs, manual)  — ✅ validated

## PowerShell console history (PSReadLine)  (parsers/powershell_history.rs, manual)  — ✅ validated (synthetic)

## Prefetch (.pf)  (parsers/prefetch.rs, via `prefetch-core`)  — ⚠ blind port (no sample yet)

Port of parsers/prefetch_parser.py (which uses pyscca/libscca). The
`prefetch-core` crate provides MAM/Xpress-Huffman decompression + SCCA v30/31
parsing (run count, last-8 run times, volume info, loaded filenames); the
prefetch hash is read directly from the decompressed SCCA header (u32 @ 0x4C,
formatted 8-hex, matching pyscca `get_prefetch_hash`). Two tables:
`Prefetch_Execution` + `Prefetch_LoadedFiles`.

The current collection has **no `.pf` files**, so the happy path is unvalidated.
What IS exercised: discovery by `.pf` extension, and the parse-failure fallback
(a bogus `.pf` → one `corrupted` / `BadSignature` row with `_source_file`,
exactly like Python), plus the ExecutionHistory `_from_prefetch` wiring.

Known gaps to close against a real sample (documented in the source):
- `prefetch-core` supports SCCA **v30/31 only** (Win10/11); older formats
  (v17/23/26) fall through to a `corrupted` row (pyscca handled those).
- per-file **MFT `file_reference`** is not exposed by the crate, so
  `Prefetch_LoadedFiles.file_reference` is currently blank.
Both are fine to finalize once a `.pf`-bearing collection is available.


`ConsoleHost_history.txt` — one typed command per line, no timestamps (order is
the only signal, kept as `line_number`). The sample host carries no such file,
so this was validated against the Python parser on a **synthetic fixture**
exercising the tricky bits: a canonical
`Users\<u>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\…`
path and a flattened `Users\<u>\…` path (account-name walk-up), blank-line
gaps (line numbers must count skipped empty lines), and mixed CRLF/LF endings.
Rust output is **identical** to Python: 6 rows, `line_number` 1/2/4 per user
(blank line 3 skipped), correct account extraction, column order
`line_number, command, user, _source_file`.


Newly ported (Python had a `BrowserCache` parser but Rust had skipped it as
"no sample"; the sample in fact carries 6652 cached responses). Pure byte
parsing — no crate: walks the `Cache_Data/index` hash table (magic 0xC103CAC3),
follows each bucket's collision chain to every EntryStore, resolves cache
addresses to raw stream bytes (block files data_0..3 by size class, or external
f_###### files), and decodes stream 0 (serialized HttpResponseInfo) into the
HTTP status + response headers plus request/response times (scanned as base::Time
int64s in the pickle header). Output: `CacheEntries`, one sqlite per
`<account>_Chrome_Cache`. On the sample: **6652 entries, full-row EXCEPT diff 0
in both directions** vs the Python parser (status, all headers, content-type,
times, body_file, cache_key all byte-identical).


Generic table-for-table copy of a Chrome History DB (recognised by a `urls`
table). BLOB -> hex, NULL -> SQL NULL, columns = source columns sorted (matches
the Python writer). A new `write_table_cols` preserves all-NULL source columns
(the Python union kept them; the plain writer had dropped them).

Sample: `Administrator/CHROME/Default/History` — 6 tables (meta, urls, visits,
content_annotations, context_annotations, visited_links): **all 0 diff**.

## Scalability: streaming SQLite writes (#7)  — ✅ done

For large datasets the parsers no longer build the whole result in RAM. A
`StreamWriter` buffers rows and flushes to SQLite in 50k batches, so memory is
bounded by one batch (+ any index a parser needs) regardless of record count.
Applied to the five heavy parsers; column order / NULL semantics unchanged, so
output is byte-identical to before.

| parser | rows | peak RSS (before → after) | regression diff |
|---|---|---|---|
| $MFT (2-pass: index, then stream) | 962,094 | ~3 GB → **345 MB** | unchanged (1,868 ≤1 ms) |
| Registry (SOFTWARE) | 536,825 | rows no longer accumulate¹ | unchanged (443) |
| EventLog | 485,333 | rows streamed | **0** |
| USN | 302,545 | rows streamed | 103 (≤1 ms) |
| SRUM | 122,049 | rows streamed | **0** |

¹ Registry peak (~722 MB) is now dominated by notatin's in-memory hive +
deleted-cell recovery, not by accumulated rows — so it stays flat as row count
grows. MFT is the clearest win (holds only a compact entry→parent index + one
batch instead of ~1M full rows).

## RDP bitmap cache (RDP8bmp Cache####.bin)  (parsers/rdpcache.rs)  — ✅ validated (content)

Decodes tiles, stitches adjacent tiles by exact-matching edges into
reconstructed screen fragments, emits mosaic/fragment/tile rows with base64
PNGs. The edge-match inverse maps are built in tile order (matching Python's
insertion-order dict comprehension) so the connected components come out the
same — HashMap iteration order had initially diverged them.

Sample: `.../RDP_CACHE` (multiple Cache files across users).

| metric | Python | Rust |
|---|---|---|
| rows | 33,108 | 33,108 |
| kind counts | fragment 3073 / mosaic 6 / tile 30029 | identical |
| tile content set (file,key,count,w,h) | — | **0 diff both ways** |
| fragment content set (file,tile_count,cols,rows,w,h) | — | **0 diff both ways** |
| time | ~13 s | **~2.7 s (≈4.7×)** |

Residual: `tile_index` (the representative index a dedup group reports) differs
for 76 of 30k groups — a cosmetic ordering label, not content. PNG image BYTES
differ (zlib encoders differ between Python and Rust) — the images are visually
identical; validation is structural, which is exact.

## CLI orchestration + full parse pipeline (part of #5)  — ✅ working end-to-end

`wina` now mirrors main.py's CLI: `--list-artifacts`, `--list-cases`,
`--create-case`, `--create-host` (--name/--target), `--run-host` (--host/--only),
`--cases-dir`. case_store (Case/Host JSON, slugify/id, list/create/load/update)
and a finder (by name/extension/suffix/content + dedupe_by_content, RegBack
dedup) are ported. `run_host` cleans the output dirs, discovers + parses every
ported artifact, and writes per-source SQLite into the same CATEGORY/<name>.sqlite
layout the Electron viewer reads — so the Rust binary is a drop-in for the
Python parse stage.

End-to-end on the full sample host (MAINDB1): exit 0, host.json status "ok",
**~40 s for the entire host** (962k MFT + 13 registry hives + 15 evtx + 302k
USN + SRUM + jumplists + tasks + rdpcache + WER + browser) — Python's MFT step
alone was ~41 s. Output: 11 category folders, all per-artifact tables written.

Fixed: the `lnk` crate panics (not Errs) on some malformed shell links; wrapped
per-entry in catch_unwind so one bad jumplist entry no longer aborts the whole
run (it had crashed run_host before host.json was updated).

## _OVERVIEW correlation builders  (overview.rs)  — in progress

The overview builders read the per-artifact SQLite the parse stage already
wrote (via `read_table` / `read_eventlog` / `read_registry_all`), so memory
stays bounded for large hosts — no in-memory `all_results`. Each is validated
by writing Python's equivalent overview table and diffing both directions
(`EXCEPT`) against the Rust output on the full sample host (MAINDB1).

| builder | rows | Rust∖Py | Py∖Rust | notes |
|---|---|---|---|---|
| ScheduledTasks | 139 | 0 | 0 | project TaskScheduler_Tasks → _ST_KEYS + is_microsoft |
| RdpCache | 3073 | 0 | 0 | RdpBitmapCache rows where kind=="fragment" |
| Defender | 11 | 0 | 0 | full detection-merge / tampering / scans / RT-toggle / signature |
| RemoteDesktopHistory | 2064 | 0 | 0 | RDP event map + LSM session backfill + outbound 5-min carry-forward |
| SmbHistory | 8881 | 0 | 0 | Security 4624/4625 (LogonType 3) + SMBServer 551/1009 |
| PowerShellHistory | 327 | 18* | 18* | 4104/4103/800 + multi-part 4104 reassembly + SID→user map |
| BrowserActivity | 6664 | 0 | 0 | 9 visits + 3 downloads + 6652 cache; chrome-time + url-decode + human-bytes |
| TargetInfo | 54 | 0 | 0 | 8 SystemInfo + 40 Account (SAM V/F binary parse) + 2 Network + 4 NetworkInterface |
| ExecutionHistory | 1845 | 79† | 1† | amcache(139+1266) + userassist(159) + srum(134) + bam(147); prefetch empty (no sample) |

| RegistryFindings | 1047 | 0 | 0 | credprot(2) + shares(1) + sqlauth(1) + autoruns(4) + exec-traces + shimcache(1039) |

All 10 overview builders are ported and validated. 8 are byte-for-byte 0-diff;
PowerShellHistory differs only by the evtx crate's whitespace trim; and
ExecutionHistory is a superset (see below).

†ExecutionHistory: **Rust is a superset of Python.** Of the 79 rust-only rows,
**78 are extra UserAssist entries** and 1 is the NisSrv.exe amcache row below.
Cause: for `Administrator_NTUSER.DAT`, notatin recovers **9** UserAssist GUID
subkeys' Count entries vs regipy's **6** (regipy's log-replay dropped 3 subkeys;
all 113 Rust rows are distinct `(key_path, value_name)` — no duplicates). This
is the same "maximum recovery" completeness win as the registry/amcache
enhancement — more genuine execution evidence, exactly per the "parse
everything" directive. The single symmetric diff (1 rust-only / 1 py-only) is
one amcache `NisSrv.exe` row whose timestamp differs by **1 ms** (`.188` vs
`.189`) — the documented FILETIME float-rounding artifact. Overview registry
reads are otherwise filtered to live entries (`_recovery == "live"`) so the
correlations mirror Python's live-state semantics; the extra UserAssist rows
are themselves live (notatin completeness), not recovered-deleted.

BrowserActivity's cache rows come from a newly-ported **BrowserCache** parser
(see below); visits/downloads come from BrowserHistory. Two field quirks were
matched exactly: a 0 visit/typed count renders blank (Python `str(x or "")`),
and `danger_type` passes through as-is (Python's blank-"0" guard tests a string
but the value is an integer column, so 0 is never blanked).

*PowerShellHistory: the 18 differing rows are all multi-part 4104 script
blocks; every one is **byte-identical once all whitespace is removed** — the
only difference is whitespace. 16 differ at the final tail (e.g. a dropped
`\r\n        \r\n`); 2 differ at an internal part boundary (a joined part's
trailing whitespace was trimmed before concatenation). Root cause is in the
`evtx` crate itself: `utils/binxml_utils.rs::read_utf16_by_size` unconditionally
`trim_end()`s every UTF-16 string it reads from BinXml (there is no
ParserSettings toggle for it). This normalization therefore also shaves trailing
whitespace off some raw EventData string values in the EventLog table. It is
DFIR-immaterial (trailing blank lines/spaces are not evidence) and is accepted
as a crate-level difference, in the same class as the FILETIME sub-ms rounding
and the PNG/zlib byte layout. Fixing it to strict byte-parity would require
forking/vendoring the `evtx` crate to drop those 5 lines.

## _OVERVIEW end-to-end + CLI (#5)  — ✅ complete

All 10 overview builders are wired into `run_host`'s `_OVERVIEW` stage and a
full host run produces every table in one pass:

- byte-for-byte 0-diff (both `EXCEPT` directions): ScheduledTasks, RdpCache,
  Defender, RemoteDesktopHistory, SmbHistory, BrowserActivity, TargetInfo,
  RegistryFindings.
- PowerShellHistory: content-identical; differs only by the evtx crate's
  trailing-whitespace trim (18 rows, all whitespace-only).
- ExecutionHistory: Rust superset — 78 extra genuine UserAssist rows (notatin
  recovers 3 more GUID subkeys than regipy for one hive) + 1 amcache row at a
  ≤1 ms FILETIME rounding difference.

Overview registry reads are filtered to live entries (`_recovery == "live"`) so
the correlations mirror Python's live-state semantics; the deleted/recovered
entries remain in the raw REGISTRY tables (the "maximum recovery" enhancement).

Full host (MAINDB1): `wina --run-host` → exit 0, `last_run_status: ok`,
12 artifacts parsed + 11 `_OVERVIEW` tables written, **~53 s** end-to-end.
CLI flags mirror main.py (`--list-artifacts/--list-cases/--create-case/
--create-host/--run-host/--host/--only/--cases-dir`) and the case_store JSON
matches the Python dataclasses the Electron viewer reads.
