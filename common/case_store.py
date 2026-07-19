"""Case registry: one case = one target folder + one <cases_dir>/<id>/ output
folder. Parsing results land inside that folder as one .sqlite file per
artifact output (mirroring the project's original CATEGORY/subfolder/
output_name.csv layout, just with .sqlite instead of .csv), not one shared
database.

Splits "register a case" (fast, just remembers where the evidence is) from
"run parsing for a case" (slow, actually extracts and writes data) so a case
can be created ahead of time and parsed later, or re-parsed after
touching `--only`. Mirrors the target/output split main.py already had, but
persists it under <cases_dir>/<id>/ instead of requiring both to be re-typed
every run.

cases_dir is passed in explicitly rather than hardcoded relative to this
file — a PyInstaller-frozen build has no meaningful "project root" next to
the executable, so the caller (main.py, driven by --cases-dir) decides where
case data actually lives.
"""
from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path


@dataclass
class Case:
    id: str
    name: str
    target_dir: str
    created_at: str
    last_run_at: str | None = None
    last_run_status: str | None = None  # "ok" | "error" | None (never run)
    artifacts_run: list[str] = field(default_factory=list)


def case_dir(cases_dir: Path, case: Case) -> Path:
    return cases_dir / case.id


def case_meta_path(cases_dir: Path, case: Case) -> Path:
    return case_dir(cases_dir, case) / "case.json"


def _slugify(name: str) -> str:
    slug = re.sub(r"[^\w.-]+", "_", name.strip(), flags=re.UNICODE).strip("_")
    return slug or "case"


def create_case(name: str, target_dir: str, created_at: str, cases_dir: Path) -> Case:
    """Register a new case. Does not parse anything."""
    compact_time = created_at.replace(":", "").replace("-", "").replace(" ", "_")
    case_id = f"{_slugify(name)}_{compact_time}"

    case = Case(id=case_id, name=name, target_dir=target_dir, created_at=created_at)
    case_dir(cases_dir, case).mkdir(parents=True, exist_ok=True)
    _save(cases_dir, case)
    return case


def list_cases(cases_dir: Path) -> list[Case]:
    if not cases_dir.exists():
        return []

    cases = []
    for entry in sorted(cases_dir.iterdir()):
        meta_path = entry / "case.json"
        if meta_path.exists():
            cases.append(_load_from_path(meta_path))
    return sorted(cases, key=lambda c: c.created_at, reverse=True)


def load_case(case_id: str, cases_dir: Path) -> Case:
    meta_path = cases_dir / case_id / "case.json"
    if not meta_path.exists():
        raise FileNotFoundError(f"No such case: {case_id}")
    return _load_from_path(meta_path)


def update_case_status(
    case_id: str, cases_dir: Path, *, run_at: str, status: str, artifacts_run: list[str]
) -> Case:
    case = load_case(case_id, cases_dir)
    case.last_run_at = run_at
    case.last_run_status = status
    case.artifacts_run = artifacts_run
    _save(cases_dir, case)
    return case


def _save(cases_dir: Path, case: Case) -> None:
    case_meta_path(cases_dir, case).write_text(
        json.dumps(asdict(case), ensure_ascii=False, indent=2), encoding="utf-8"
    )


def _load_from_path(meta_path: Path) -> Case:
    data = json.loads(meta_path.read_text(encoding="utf-8"))
    return Case(**data)
