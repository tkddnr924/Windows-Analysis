"""Write a list of flat dicts to CSV, tolerating rows with different keys."""
import csv
from pathlib import Path


def write_dicts_to_csv(rows: list[dict], output_path: Path, preferred_order: list[str] | None = None) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)

    if not rows:
        output_path.write_text("", encoding="utf-8-sig")
        return

    all_keys = set()
    for row in rows:
        all_keys.update(row.keys())

    preferred_order = preferred_order or []
    ordered_fields = [f for f in preferred_order if f in all_keys]
    ordered_fields += sorted(all_keys - set(ordered_fields))

    with output_path.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=ordered_fields, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
