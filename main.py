"""Windows artifact triage entry point.

1. Locate collected artifact files under the target folder (matched by
   filename, not by an assumed directory structure).
2. Run each artifact's parser against the located paths.
3. Write the parsed results to CSV under the result folder.
"""
import argparse
from pathlib import Path

from common.csv_writer import write_dicts_to_csv
from common.finder import dedupe_by_content
from common.registry import ARTIFACTS

PROJECT_ROOT = Path(__file__).resolve().parent


def run(target_dir: Path, output_dir: Path) -> None:
    for artifact in ARTIFACTS:
        print(f"=== {artifact.name} ===")

        paths = dedupe_by_content(artifact.find_paths(target_dir))
        if not paths:
            print("[!] no matching files found")
            continue

        for path in paths:
            print(f"[*] found: {path}")

        results = artifact.parse(paths)

        artifact_dir = output_dir / artifact.category.upper() / artifact.subfolder
        for output_name, rows in results.items():
            csv_path = artifact_dir / f"{output_name}.csv"
            write_dicts_to_csv(rows, csv_path, artifact.field_order.get(output_name, []))
            print(f"[+] {len(rows)} rows -> {csv_path}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", default="target", help="Root folder of collected artifacts")
    parser.add_argument("--output", default="result", help="Folder to write CSV output")
    args = parser.parse_args()

    run(PROJECT_ROOT / args.target, PROJECT_ROOT / args.output)


if __name__ == "__main__":
    main()
