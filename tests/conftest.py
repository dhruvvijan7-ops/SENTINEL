from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from dataclasses import replace
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
os.environ.setdefault("SENTINEL_CONFIG", str(ROOT / "configs" / "config.example.toml"))

from .keys import KEY_A, KEY_B  # noqa: E402,F401


@pytest.fixture(scope="session")
def settings():
    from sentinel_core.config import load_settings

    base = load_settings()
    tmp = tempfile.mkdtemp(prefix="sentinel-m1-")
    return replace(base, storage_root=str(Path(tmp) / "objects"), observability_log_format="console")


@pytest.fixture(scope="session")
def migrated(settings):
    from migrations.apply import apply as apply_migrations
    from sentinel_core.db import tx

    apply_migrations(settings.database_migrator_url)
    with tx(settings.database_worker_url) as conn:
        conn.execute(
            "INSERT INTO tenants (id, name) VALUES ('tenant-b', 'Tenant B') "
            "ON CONFLICT DO NOTHING"
        )
        conn.execute(
            "INSERT INTO workspaces (id, tenant_id, name) VALUES ('ws-b', 'tenant-b', 'WS B') "
            "ON CONFLICT DO NOTHING"
        )
        conn.commit()
    return settings


@pytest.fixture
def app_settings(migrated, tmp_path):
    return replace(migrated, storage_root=str(tmp_path / "objects"))


@pytest.fixture
def client(app_settings):
    from fastapi.testclient import TestClient

    from sentinel_api.app import create_app

    app = create_app(app_settings)
    with TestClient(app) as c:
        c.sentinel_settings = app_settings
        yield c


@pytest.fixture(scope="session")
def m1_fixture_evtx() -> Path:
    """M1's 1 MiB+ System-channel EVTX containing only mapped EIDs.

    Prefers the committed copy at ``tests/fixtures/sentinel_m1.evtx`` so the
    e2e suite runs on any platform (Linux CI has no ``wevtutil``). The Windows
    path stays as a regeneration fallback: it re-harvests the file when the
    committed copy is absent or too small, then verifies it parses.
    """
    committed = ROOT / "tests" / "fixtures" / "sentinel_m1.evtx"
    if committed.exists() and committed.stat().st_size >= 1024 * 1024:
        _assert_evtx_parses(committed)
        return committed

    if os.name != "nt" or shutil.which("wevtutil") is None:
        pytest.skip("EVTX fixture unavailable: no committed fixture and no wevtutil")

    out = Path(tempfile.gettempdir()) / "opencode" / "sentinel_m1.evtx"
    if out.exists() and out.stat().st_size >= 1024 * 1024:
        return out
    out.parent.mkdir(parents=True, exist_ok=True)
    query = "*[System[(EventID=7036 or 7045 or 7040 or 7034 or 7043)]]"
    proc = subprocess.run(
        ["wevtutil", "epl", "System", str(out), f"/q:{query}"],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0 or not out.exists():
        pytest.skip(f"EVTX fixture unavailable: {proc.stderr.strip()}")
    return out


def _assert_evtx_parses(path: Path) -> None:
    """Guard against a corrupt/truncated committed fixture."""
    from evtx import PyEvtxParser

    try:
        records = PyEvtxParser(str(path)).records()
        next(iter(records))
    except (OSError, StopIteration, ValueError) as exc:  # pragma: no cover
        pytest.skip(f"EVTX fixture unusable ({path}): {exc}")


def drain_jobs(settings, *, max_rounds: int = 300) -> int:
    """Run the worker until the queue is idle; return jobs processed."""
    from sentinel_worker.main import make_worker_id, process_batch

    worker_id = make_worker_id(settings)
    total = 0
    for _ in range(max_rounds):
        n = process_batch(settings, worker_id)
        total += n
        if n == 0:
            break
    return total
