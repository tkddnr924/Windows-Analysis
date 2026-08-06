"""Case/host registry. Two levels:

    <cases_dir>/<case_id>/case.json                     ← a case (an incident)
    <cases_dir>/<case_id>/<host_id>/host.json           ← one collected machine
    <cases_dir>/<case_id>/<host_id>/<CATEGORY>/...       ← that host's parsed .sqlite
    <cases_dir>/<case_id>/<host_id>/bookmarks.json

A CASE groups the machines involved in one incident; a HOST is a single
collected machine (a target folder + its parsed output). One case holds many
hosts so an analyst can pivot between them within the same investigation.

Registering (fast — just remembers where evidence is) stays split from parsing
(slow — extracts and writes), so a host can be created ahead of time and parsed
later, or re-parsed with `--only`.

cases_dir is passed in explicitly rather than hardcoded relative to this file —
a PyInstaller-frozen build has no meaningful "project root" next to the
executable, so the caller (main.py, driven by --cases-dir) decides where case
data actually lives.
"""
from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path


@dataclass
class Host:
    id: str
    name: str
    target_dir: str
    created_at: str
    last_run_at: str | None = None
    last_run_status: str | None = None  # "ok" | "error" | None (never run)
    artifacts_run: list[str] = field(default_factory=list)


@dataclass
class Case:
    id: str
    name: str
    created_at: str
    # Populated on list/load from the host subfolders; not stored in case.json.
    hosts: list[Host] = field(default_factory=list)


# --- paths ---

def case_dir(cases_dir: Path, case_id: str) -> Path:
    return cases_dir / case_id


def case_meta_path(cases_dir: Path, case_id: str) -> Path:
    return case_dir(cases_dir, case_id) / "case.json"


def host_dir(cases_dir: Path, case_id: str, host_id: str) -> Path:
    return case_dir(cases_dir, case_id) / host_id


def host_meta_path(cases_dir: Path, case_id: str, host_id: str) -> Path:
    return host_dir(cases_dir, case_id, host_id) / "host.json"


def _slugify(name: str) -> str:
    slug = re.sub(r"[^\w.-]+", "_", name.strip(), flags=re.UNICODE).strip("_")
    return slug or "item"


def _id_for(name: str, created_at: str) -> str:
    compact_time = created_at.replace(":", "").replace("-", "").replace(" ", "_")
    return f"{_slugify(name)}_{compact_time}"


# --- cases ---

def create_case(name: str, created_at: str, cases_dir: Path) -> Case:
    """Register a new (empty) case. Holds hosts; parses nothing itself."""
    case_id = _id_for(name, created_at)
    case = Case(id=case_id, name=name, created_at=created_at)
    case_dir(cases_dir, case_id).mkdir(parents=True, exist_ok=True)
    case_meta_path(cases_dir, case_id).write_text(
        json.dumps({"id": case.id, "name": case.name, "created_at": case.created_at}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return case


def list_cases(cases_dir: Path) -> list[Case]:
    if not cases_dir.exists():
        return []
    cases = []
    for entry in sorted(cases_dir.iterdir()):
        meta_path = entry / "case.json"
        if meta_path.exists():
            cases.append(_load_case_from_path(meta_path, cases_dir))
    return sorted(cases, key=lambda c: c.created_at, reverse=True)


def load_case(case_id: str, cases_dir: Path) -> Case:
    meta_path = case_meta_path(cases_dir, case_id)
    if not meta_path.exists():
        raise FileNotFoundError(f"No such case: {case_id}")
    return _load_case_from_path(meta_path, cases_dir)


# --- hosts ---

def create_host(case_id: str, name: str, target_dir: str, created_at: str, cases_dir: Path) -> Host:
    """Register a new host under an existing case. Does not parse anything."""
    if not case_meta_path(cases_dir, case_id).exists():
        raise FileNotFoundError(f"No such case: {case_id}")
    host_id = _id_for(name, created_at)
    host = Host(id=host_id, name=name, target_dir=target_dir, created_at=created_at)
    host_dir(cases_dir, case_id, host_id).mkdir(parents=True, exist_ok=True)
    _save_host(cases_dir, case_id, host)
    return host


def load_host(case_id: str, host_id: str, cases_dir: Path) -> Host:
    meta_path = host_meta_path(cases_dir, case_id, host_id)
    if not meta_path.exists():
        raise FileNotFoundError(f"No such host: {case_id}/{host_id}")
    return Host(**json.loads(meta_path.read_text(encoding="utf-8")))


def update_host_status(
    case_id: str, host_id: str, cases_dir: Path, *, run_at: str, status: str, artifacts_run: list[str]
) -> Host:
    host = load_host(case_id, host_id, cases_dir)
    host.last_run_at = run_at
    host.last_run_status = status
    host.artifacts_run = artifacts_run
    _save_host(cases_dir, case_id, host)
    return host


# --- internals ---

def _save_host(cases_dir: Path, case_id: str, host: Host) -> None:
    host_meta_path(cases_dir, case_id, host.id).write_text(
        json.dumps(asdict(host), ensure_ascii=False, indent=2), encoding="utf-8"
    )


def _load_case_from_path(meta_path: Path, cases_dir: Path) -> Case:
    data = json.loads(meta_path.read_text(encoding="utf-8"))
    case_folder = meta_path.parent
    hosts = []
    for entry in sorted(case_folder.iterdir()):
        hmeta = entry / "host.json"
        if hmeta.exists():
            hosts.append(Host(**json.loads(hmeta.read_text(encoding="utf-8"))))
    hosts.sort(key=lambda h: h.created_at, reverse=True)
    return Case(id=data["id"], name=data["name"], created_at=data["created_at"], hosts=hosts)
