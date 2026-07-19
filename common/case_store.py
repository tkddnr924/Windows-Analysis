"""Case registry: one case = one target folder + one cases/<name>_<time>/
output folder. Parsing results land inside that folder as one .sqlite file
per artifact output (mirroring the project's original CATEGORY/subfolder/
output_name.csv layout, just with .sqlite instead of .csv), not one shared
database.

Splits "register a case" (fast, just remembers where the evidence is) from
"run parsing for a case" (slow, actually extracts and writes data) so a case
can be created ahead of time and parsed later, or re-parsed after
touching `--only`. Mirrors the target/output split main.py already had, but
persists it under cases/<id>/ instead of requiring both to be re-typed
every run.
"""
from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CASES_DIR = PROJECT_ROOT / "cases"


@dataclass
class Case:
    id: str
    name: str
    target_dir: str
    created_at: str
    last_run_at: str | None = None
    last_run_status: str | None = None  # "ok" | "error" | None (never run)
    artifacts_run: list[str] = field(default_factory=list)

    @property
    def dir(self) -> Path:
        return CASES_DIR / self.id

    @property
    def meta_path(self) -> Path:
        return self.dir / "case.json"


def _slugify(name: str) -> str:
    slug = re.sub(r"[^\w.-]+", "_", name.strip(), flags=re.UNICODE).strip("_")
    return slug or "case"


def create_case(name: str, target_dir: str, created_at: str) -> Case:
    """Register a new case. Does not parse anything."""
    compact_time = created_at.replace(":", "").replace("-", "").replace(" ", "_")
    case_id = f"{_slugify(name)}_{compact_time}"

    case = Case(id=case_id, name=name, target_dir=target_dir, created_at=created_at)
    case.dir.mkdir(parents=True, exist_ok=True)
    _save(case)
    return case


def list_cases() -> list[Case]:
    if not CASES_DIR.exists():
        return []

    cases = []
    for entry in sorted(CASES_DIR.iterdir()):
        meta_path = entry / "case.json"
        if meta_path.exists():
            cases.append(_load_from_path(meta_path))
    return sorted(cases, key=lambda c: c.created_at, reverse=True)


def load_case(case_id: str) -> Case:
    meta_path = CASES_DIR / case_id / "case.json"
    if not meta_path.exists():
        raise FileNotFoundError(f"No such case: {case_id}")
    return _load_from_path(meta_path)


def update_case_status(case_id: str, *, run_at: str, status: str, artifacts_run: list[str]) -> Case:
    case = load_case(case_id)
    case.last_run_at = run_at
    case.last_run_status = status
    case.artifacts_run = artifacts_run
    _save(case)
    return case


def _save(case: Case) -> None:
    case.meta_path.write_text(json.dumps(asdict(case), ensure_ascii=False, indent=2), encoding="utf-8")


def _load_from_path(meta_path: Path) -> Case:
    data = json.loads(meta_path.read_text(encoding="utf-8"))
    return Case(**data)
