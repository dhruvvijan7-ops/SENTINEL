"""M1 exit ④ and Stage-6 §5.4: /ready reports database, object store and
queue, degrades on a stale queue without a skip, and flips on DB stop/start.

The DB stop/start test is the last thing in the suite to run: it disturbs the
shared database that every other integration test depends on.
"""
from __future__ import annotations

import re
import subprocess
import time
import uuid

import pytest

from sentinel_core.db import tx


def _db_port(settings) -> int:
    m = re.search(r"@[^/:]+:(\d+)/", settings.database_url or "")
    assert m, f"cannot parse a port out of {settings.database_url!r}"
    return int(m.group(1))


def _container_publishing(port: int) -> str | None:
    """Find the container publishing `port`, whatever its compose project
    named it (the dev topology is `sentinel-db`, but the port is the contract)."""
    try:
        r = subprocess.run(
            ["docker", "ps", "--format", "{{.Names}}\t{{.Ports}}"],
            capture_output=True,
            text=True,
            timeout=20,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if r.returncode != 0:
        return None
    needle = f":{port}->"
    for line in r.stdout.splitlines():
        name, _, ports = line.partition("\t")
        if needle in ports and name.strip():
            return name.strip()
    return None


def test_ready_reports_the_three_spec_5_4_checks(client, migrated, settings):
    r = client.get("/ready")
    assert r.status_code in (200, 503), r.text
    body = r.json()
    assert set(body) == {"status", "checks"}
    assert set(body["checks"]) == {"database", "object_store", "queue"}
    assert body["status"] in ("ok", "degraded")
    for name, state in body["checks"].items():
        assert state in ("ok", "degraded"), f"{name} -> {state}"
    # the integration suite only runs with a live database
    assert body["checks"]["database"] == "ok", body


def test_ready_degrades_when_the_queue_goes_stale(client, migrated):
    """§5.4: oldest-queued-job age > 15 min flips readiness to degraded.
    No skip: the degradation is manufactured here, so it always executes."""
    dsn = migrated.database_worker_url
    key = f"ready-probe:{uuid.uuid4().hex}"

    # Measured before anything is touched: the test must restore *this* value.
    baseline = client.get("/ready").json()["checks"]["queue"]

    with tx(dsn) as conn:
        snapshot = conn.execute(
            "SELECT job_id, created_at FROM jobs WHERE status = 'queued'"
        ).fetchall()
        conn.execute(
            """
            INSERT INTO jobs (tenant_id, workspace_id, job_type, payload, idempotency_key)
            VALUES ('default', 'default', 'noop', '{}'::jsonb, %s)
            """,
            (key,),
        )
        conn.execute(
            "UPDATE jobs SET created_at = now() - interval '30 minutes' "
            "WHERE status = 'queued'"
        )
        conn.commit()
    try:
        r = client.get("/ready")
        assert r.status_code == 503, r.text
        assert r.json()["checks"]["queue"] == "degraded", r.json()
        assert r.json()["status"] == "degraded"
    finally:
        with tx(dsn) as conn:
            for job_id, created_at in snapshot:
                conn.execute(
                    "UPDATE jobs SET created_at = %s WHERE job_id = %s",
                    (created_at, job_id),
                )
            conn.execute("DELETE FROM jobs WHERE idempotency_key = %s", (key,))
            conn.commit()

    r = client.get("/ready")
    assert r.json()["checks"]["queue"] == baseline, (
        "queue check did not return to its pre-test state after restore"
    )


@pytest.mark.slow
def test_readiness_flips_on_db_stop_start(client, migrated, settings):
    """M1 exit ④: readiness flips when the database goes away and comes back.

    Only skipped when there is genuinely no database process to stop: the
    flip is defined against a live server, and stopping a remote/shared
    server would take every other test down with it.

    Queue ages are normalized for the duration of this test and restored
    after, so the §5.4 queue check (an independent signal) cannot mask the
    database flip this test exists to observe.
    """
    port = _db_port(settings)
    container = _container_publishing(port)
    if container is None:
        pytest.skip(
            f"no docker container is publishing Postgres port {port}; "
            "stopping and restarting a live database is the only way to "
            "exercise the readiness flip, and this host has no such "
            "container to disturb"
        )

    dsn = migrated.database_worker_url
    with tx(dsn) as conn:
        ages = conn.execute(
            "SELECT job_id, created_at FROM jobs WHERE status = 'queued'"
        ).fetchall()
        conn.execute(
            "UPDATE jobs SET created_at = now() WHERE status = 'queued'"
        )
        conn.commit()

    try:
        # baseline: database check is ok
        r = client.get("/ready")
        assert r.status_code == 200, r.text
        assert r.json()["checks"]["database"] == "ok", r.text
        assert r.json()["status"] == "ok", r.text

        subprocess.run(["docker", "stop", container], check=True, timeout=60)
        try:
            deadline = time.monotonic() + 30
            degraded = None
            while time.monotonic() < deadline:
                r = client.get("/ready")
                if r.status_code == 503:
                    degraded = r
                    break
                time.sleep(1)
            assert degraded is not None, "readiness never degraded after DB stop"
            body = degraded.json()
            assert body["status"] == "degraded"
            assert body["checks"]["database"] == "degraded", body
        finally:
            subprocess.run(["docker", "start", container], check=True, timeout=60)

        deadline = time.monotonic() + 90
        ok = None
        while time.monotonic() < deadline:
            r = client.get("/ready")
            if r.status_code == 200 and r.json()["checks"]["database"] == "ok":
                ok = r
                break
            time.sleep(1)
        assert ok is not None, "readiness never recovered after DB start"
        assert ok.json()["checks"]["database"] == "ok"
        assert ok.json()["status"] == "ok", (
            f"database recovered but readiness stayed degraded: {ok.json()}"
        )
    finally:
        with tx(dsn) as conn:
            for job_id, created_at in ages:
                conn.execute(
                    "UPDATE jobs SET created_at = %s WHERE job_id = %s",
                    (created_at, job_id),
                )
            conn.commit()
