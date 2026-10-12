from __future__ import annotations

import os
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

    The fixture is committed at ``tests/fixtures/sentinel_m1.evtx`` and the
    suite refuses to run without it: M1 exit ① is defined against a 1 MiB
    upload, so a missing or corrupt fixture is a hard failure, not a skip.
    """
    committed = ROOT / "tests" / "fixtures" / "sentinel_m1.evtx"
    if not committed.exists():
        pytest.fail(f"M1 EVTX fixture is missing: {committed}")
    if committed.stat().st_size < 1024 * 1024:
        pytest.fail(
            f"M1 EVTX fixture is {committed.stat().st_size} bytes; "
            "exit ① requires at least 1 MiB"
        )
    _assert_evtx_parses(committed)
    return committed


def _assert_evtx_parses(path: Path) -> None:
    """Guard against a corrupt/truncated committed fixture."""
    from evtx import PyEvtxParser

    try:
        records = PyEvtxParser(str(path)).records()
        next(iter(records))
    except (OSError, StopIteration, ValueError) as exc:
        pytest.fail(f"M1 EVTX fixture is unusable ({path}): {exc}")


def drain_jobs(settings, *, max_rounds: int = 300) -> int:
    """Run the M1 pipeline worker until the queue is idle; return jobs processed."""
    from sentinel_worker.main import PIPELINE_JOB_TYPES, make_worker_id, process_batch

    worker_id = make_worker_id(settings)
    total = 0
    for _ in range(max_rounds):
        n = process_batch(settings, worker_id, job_types=PIPELINE_JOB_TYPES)
        total += n
        if n == 0:
            break
    return total
