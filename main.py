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
import traceback
from dataclasses import asdict
from pathlib import Path

from common import case_store, correlate
from common.finder import dedupe_by_content
from common.registry import ARTIFACTS
from common.sqlite_writer import write_rows_to_sqlite

PROJECT_ROOT = Path(__file__).resolve().parent


def run_case(case_id: str, only: set[str] | None = None) -> None:
    case = case_store.load_case(case_id)
    target_dir = Path(case.target_dir)

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

        artifact_dir = case.dir / artifact.category.upper() / artifact.subfolder
        for output_name, rows in results.items():
            sqlite_path = artifact_dir / f"{output_name}.sqlite"
            write_rows_to_sqlite(rows, sqlite_path, output_name, artifact.field_order.get(output_name, []))
            print(f"[+] {len(rows)} rows -> {sqlite_path}")

        artifacts_run.append(artifact.name)

    print("=== _OVERVIEW ===")
    overview_dir = case.dir / "_OVERVIEW"
    overview_builders = {
        "TargetInfo": correlate.build_target_info,
        "ExecutionHistory": correlate.build_execution_history,
        "RemoteAccessHistory": correlate.build_remote_access_history,
        "BrowserTimeline": correlate.build_browser_timeline,
    }
    for output_name, builder in overview_builders.items():
        rows = builder(all_results)
        sqlite_path = overview_dir / f"{output_name}.sqlite"
        write_rows_to_sqlite(rows, sqlite_path, output_name, [])
        print(f"[+] {len(rows)} rows -> {sqlite_path}")

    case_store.update_case_status(
        case_id,
        run_at=dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        status="error" if had_error else "ok",
        artifacts_run=artifacts_run,
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--create-case", metavar="NAME", help="Register a new case (does not parse)")
    parser.add_argument("--target", help="Target folder for --create-case")
    parser.add_argument("--run-case", metavar="CASE_ID", help="Parse a previously registered case")
    parser.add_argument("--only", default=None, help="Comma-separated artifact names to run (default: all)")
    parser.add_argument("--list-cases", action="store_true", help="Print registered cases as JSON and exit")
    parser.add_argument(
        "--list-artifacts",
        action="store_true",
        help="Print known artifact names as a JSON array and exit (used by the viewer GUI to build the run screen)",
    )
    args = parser.parse_args()

    if args.list_artifacts:
        print(json.dumps([artifact.name for artifact in ARTIFACTS]))
        return

    if args.list_cases:
        cases = case_store.list_cases()
        print(json.dumps([asdict(c) for c in cases], ensure_ascii=False))
        return

    if args.create_case:
        if not args.target:
            parser.error("--create-case requires --target")
        created_at = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        case = case_store.create_case(args.create_case, str(Path(args.target).resolve()), created_at)
        print(json.dumps(asdict(case), ensure_ascii=False))
        return

    if args.run_case:
        only = set(args.only.split(",")) if args.only else None
        run_case(args.run_case, only=only)
        return

    parser.error("one of --create-case, --run-case, --list-cases, --list-artifacts is required")


if __name__ == "__main__":
    main()
