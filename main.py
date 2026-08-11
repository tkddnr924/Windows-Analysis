"""Windows artifact triage entry point.

1. Register a case (target folder + a name) — fast, no parsing. Creates
   cases/<name>_<time>/.
2. Run a registered case: locate collected artifact files under its target
   folder (matched by filename/extension/content, not an assumed directory
   structure), run each artifact's parser, write each artifact output as
   its own .sqlite file under cases/<name>_<time>/CATEGORY/subfolder/ —
   the same layout the project's CSV output used, just one file per result
   instead of one shared database.
"""
import argparse
import datetime as dt
import json
import shutil
import sys
import traceback
from dataclasses import asdict
from pathlib import Path

# On a Korean (or any non-UTF-8) Windows, Python's stdout/stderr default to the
# locale ANSI code page (e.g. cp949) — especially when the streams are pipes,
# as they are when the Electron viewer spawns this process. The viewer always
# decodes that output as UTF-8, so Korean case names and file paths printed
# here come out as mojibake ("이상한 글씨"). Force UTF-8 on both streams so the
# bytes on the wire match what the viewer expects. Guard with hasattr because a
# windowed/frozen build can have stdout/stderr set to None.
for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8")

from common import case_store, correlate, processing
from common.finder import dedupe_by_content
from common.registry import ARTIFACTS
from common.sqlite_writer import write_rows_to_sqlite

def run_host(case_id: str, host_id: str, cases_dir: Path, only: set[str] | None = None) -> None:
    host = case_store.load_host(case_id, host_id, cases_dir)
    case_output_dir = case_store.host_dir(cases_dir, case_id, host_id)
    target_dir = Path(host.target_dir)

    # On a full re-parse, wipe previous output first so renamed or removed
    # artifacts (e.g. an overview table that changed name, or an artifact no
    # longer in the registry) don't leave stale .sqlite files behind. Only the
    # per-CATEGORY output folders and _OVERVIEW are removed — case.json and
    # bookmarks.json live in the case root and are preserved. A partial
    # (--only) run leaves the untouched artifacts' output in place.
    if only is None:
        for child in case_output_dir.iterdir():
            if child.is_dir():
                shutil.rmtree(child, ignore_errors=True)

    artifacts_run = []
    had_error = False
    all_results: dict[str, dict[str, list[dict]]] = {}

    for artifact in ARTIFACTS:
        if only is not None and artifact.name not in only:
            continue

        print(f"=== {artifact.name} ===")

        try:
            paths = dedupe_by_content(artifact.find_paths(target_dir))
            if not paths:
                print("[!] no matching files found")
                artifacts_run.append(artifact.name)
                continue

            for path in paths:
                print(f"[*] found: {path}")

            results = artifact.parse(paths)
        except Exception:
            print(f"[!] {artifact.name} failed:\n{traceback.format_exc()}")
            had_error = True
            artifacts_run.append(artifact.name)
            continue

        all_results[artifact.name] = results

        artifact_dir = case_output_dir / artifact.category.upper() / artifact.subfolder
        for output_name, content in results.items():
            sqlite_path = artifact_dir / f"{output_name}.sqlite"
            if isinstance(content, dict):
                # One sqlite per source file, one TABLE per structure inside it
                # (e.g. SOFTWARE.sqlite -> Registry_Run, Registry_InstalledPrograms,
                # ...) — keeps the parsed output 1:1 with the source hive/file.
                for table_name, rows in content.items():
                    write_rows_to_sqlite(rows, sqlite_path, table_name, artifact.field_order.get(table_name, []))
                    print(f"[+] {len(rows)} rows -> {sqlite_path} [{table_name}]")
            else:
                write_rows_to_sqlite(content, sqlite_path, output_name, artifact.field_order.get(output_name, []))
                print(f"[+] {len(content)} rows -> {sqlite_path}")

        artifacts_run.append(artifact.name)

    print("=== _OVERVIEW ===")
    overview_dir = case_output_dir / "_OVERVIEW"
    overview_builders = {
        "TargetInfo": processing.build_target_info,
        "ExecutionHistory": processing.build_execution_history,
        "Defender": processing.build_defender,
        "RegistryFindings": processing.build_registry_findings,
        "BrowserActivity": processing.build_browser_history,
        "RemoteDesktopHistory": correlate.build_remote_desktop_history,
        # "SmbHistory": correlate.build_smb_history,  # deferred — needs a sample with SMB logon data
        "PowerShellHistory": correlate.build_powershell_history,
    }
    for output_name, builder in overview_builders.items():
        rows = builder(all_results)
        sqlite_path = overview_dir / f"{output_name}.sqlite"
        write_rows_to_sqlite(rows, sqlite_path, output_name, [])
        print(f"[+] {len(rows)} rows -> {sqlite_path}")

    case_store.update_host_status(
        case_id,
        host_id,
        cases_dir,
        run_at=dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        status="error" if had_error else "ok",
        artifacts_run=artifacts_run,
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--create-case", metavar="NAME", help="Register a new (empty) case; holds hosts")
    parser.add_argument("--create-host", metavar="CASE_ID", help="Register a new host under a case (needs --name, --target)")
    parser.add_argument("--name", help="Host name for --create-host")
    parser.add_argument("--target", help="Target folder for --create-host")
    parser.add_argument("--run-host", metavar="CASE_ID", help="Parse a host (needs --host); use with --only to re-run part")
    parser.add_argument("--host", help="Host id for --run-host")
    parser.add_argument("--only", default=None, help="Comma-separated artifact names to run (default: all)")
    parser.add_argument("--list-cases", action="store_true", help="Print registered cases (with their hosts) as JSON and exit")
    parser.add_argument(
        "--list-artifacts",
        action="store_true",
        help="Print known artifact names as a JSON array and exit (used by the viewer GUI to build the run screen)",
    )
    parser.add_argument(
        "--cases-dir",
        required=True,
        help="Folder holding one subfolder per case — chosen by the caller (the viewer GUI), since a "
        "frozen/packaged build has no meaningful project-relative default.",
    )
    args = parser.parse_args()
    cases_dir = Path(args.cases_dir).resolve()

    if args.list_artifacts:
        print(json.dumps([artifact.name for artifact in ARTIFACTS]))
        return

    if args.list_cases:
        cases = case_store.list_cases(cases_dir)
        print(json.dumps([asdict(c) for c in cases], ensure_ascii=False))
        return

    if args.create_case:
        created_at = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        case = case_store.create_case(args.create_case, created_at, cases_dir)
        print(json.dumps(asdict(case), ensure_ascii=False))
        return

    if args.create_host:
        if not args.name or not args.target:
            parser.error("--create-host requires --name and --target")
        created_at = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        host = case_store.create_host(
            args.create_host, args.name, str(Path(args.target).resolve()), created_at, cases_dir
        )
        print(json.dumps(asdict(host), ensure_ascii=False))
        return

    if args.run_host:
        if not args.host:
            parser.error("--run-host requires --host")
        only = set(args.only.split(",")) if args.only else None
        run_host(args.run_host, args.host, cases_dir, only=only)
        return

    parser.error("one of --create-case, --create-host, --run-host, --list-cases, --list-artifacts is required")


if __name__ == "__main__":
    main()
