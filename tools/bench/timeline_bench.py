#!/usr/bin/env python3
"""M2 exit ③ — timeline render budget (spec §9 + §6.6 measurement protocol).

Exit criterion, verbatim: *timeline: findings ∪ events for a host over a time
window render in < PROPOSED 2 s p95 for 10⁵ events (§6.6 method)*.

What this measures
------------------
``sentinel_storage.repos_timeline.query_timeline`` — the union of ``findings``
and ``events`` for one host over one half-open window — executed exactly the
way the HTTP layer would run it: a fresh connection per pass, the app role,
RLS tenant/workspace GUCs set.  The window is sized so the *whole* union is
materialised and ordered (no LIMIT short-circuit: paging past the budget would
be gaming the number).

Protocol (§6.6): one warm-up pass discarded, then 5 measured passes; the
nearest-rank p95 of those samples must stay under the budget.  The environment
is pinned into the JSON artifact alongside the number, because §6.6 requires
every shipped figure to be MEASURED-with-environment.

Usage
-----
    python tools/bench/timeline_bench.py --seed 100000
    python tools/bench/timeline_bench.py --no-seed          # re-use seeded data
    python tools/bench/timeline_bench.py --keep             # skip cleanup

Exit status is 0 when p95 < budget, 1 otherwise, so CI can gate on it.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import psycopg

from sentinel_core.db import tx

ROOT = Path(__file__).resolve().parents[2]
OUT_PATH = ROOT / "research" / "work" / "_stage6_work" / "bench" / "timeline_m2.json"

BUDGET_MS = 2000.0
WARMUP_PASSES = 1
MEASURED_PASSES = 5

BENCH_HOST = "bench-timeline-host"
BENCH_TENANT = "default"
BENCH_WORKSPACE = "default"
_EVENT_TYPE = "process_create"


def _percentile_nearest_rank(samples: list[float], pct: float) -> float:
    if not samples:
        return 0.0
    ordered = sorted(samples)
    rank = max(1, int(round(pct / 100.0 * len(ordered))))
    return ordered[min(rank, len(ordered)) - 1]


def _environment() -> dict[str, Any]:
    ram = _total_ram_bytes()
    return {
        "os": platform.platform(),
        "machine": platform.machine(),
        "cpu": platform.processor() or platform.machine(),
        "cpu_count": os.cpu_count(),
        "ram_bytes": ram,
        "python": platform.python_version(),
    }


def _total_ram_bytes() -> int | None:
    try:
        return int(os.sysconf("SC_PAGE_SIZE")) * int(os.sysconf("SC_PHYS_PAGES"))
    except (AttributeError, ValueError, OSError):
        pass
    if sys.platform == "win32":
        # GetPhysicallyInstalledSystemMemory reports installed RAM in KB and
        # needs a real out-parameter — a NULL pointer simply returns 0.
        try:
            import ctypes

            kib = ctypes.c_uint32(0)
            ok = ctypes.windll.kernel32.GetPhysicallyInstalledSystemMemory(
                ctypes.byref(kib)
            )
            if ok and kib.value:
                return int(kib.value) * 1024
        except Exception:
            pass
    return None


def _config_hash() -> str | None:
    """Same inputs ``run_detection`` records on the run row (§4.2)."""
    try:
        import hashlib

        from sentinel_detect.sigma_import import default_manifest, pack_config_bytes
        from sentinel_detect.store import ENGINE_VERSION

        manifest = default_manifest()
        if manifest is None:
            return None
        return hashlib.sha256(pack_config_bytes(manifest, ENGINE_VERSION)).hexdigest()
    except Exception:
        return None


def seed(
    conn: psycopg.Connection,
    *,
    events: int,
    findings: int,
    hosts: int,
    window_seconds: float,
    run_id: str,
    since: datetime,
) -> dict[str, Any]:
    """Plant a synthetic host timeline.  Committed, so the bench measures the
    same on-disk index the API would read."""
    artifact_id = uuid.uuid4()
    sha = uuid.uuid5(uuid.NAMESPACE_URL, f"sentinel/timeline-bench/{run_id}").bytes

    conn.execute(
        "INSERT INTO raw_objects (sha256, size, refcount, storage_uri, state, "
        "retention_until, legal_hold) VALUES (%s, 12, 1, 'file:///bench', 'hot', "
        "now() + interval '90 days', false) ON CONFLICT DO NOTHING",
        (sha,),
    )
    conn.execute(
        "INSERT INTO uploads (artifact_id, tenant_id, workspace_id, run_id, sha256, "
        "size, original_filename, display_name, received_at, triage_state) "
        "VALUES (%s, %s, %s, %s, %s, 12, 'bench.evtx', 'bench.evtx', now(), 'done')",
        (artifact_id, BENCH_TENANT, BENCH_WORKSPACE, run_id, sha),
    )

    # One host carries the whole window by default (the conservative reading of
    # "10⁵ events"); --hosts spreads them so the host predicate stays selective.
    conn.execute(
        """
        INSERT INTO events (
            tenant_id, workspace_id, run_id, artifact_id, event_time_utc,
            event_time_state, event_category, event_type, event_action,
            event_outcome, event_severity, event_derived_by, classification,
            host_hostname, user_name, source_format, source_parser,
            source_record_type, document
        )
        SELECT %(tenant)s, %(ws)s, %(run)s, %(artifact)s,
               %(since)s + make_interval(secs => g * %(span)s::float8 / %(n)s),
               'ok', 'process', %(etype)s, 'created', 'success', 'low', 'source',
               'internal',
               %(host)s || CASE WHEN %(hosts)s = 1 THEN '' ELSE '-' || (g %% %(hosts)s) END,
               'bench-user', 'evtx', 'sysmon', '1',
               jsonb_build_object(
                   'schema_version', 'canonical-event/v1',
                   'event', jsonb_build_object('type', %(etype)s::text, 'action', 'created')
               )
          FROM generate_series(0, %(n)s - 1) g
        """,
        {
            "tenant": BENCH_TENANT,
            "ws": BENCH_WORKSPACE,
            "run": run_id,
            "artifact": artifact_id,
            "since": since,
            "span": window_seconds,
            "n": events,
            "host": BENCH_HOST,
            "hosts": hosts,
            "etype": _EVENT_TYPE,
        },
    )
    conn.execute(
        """
        INSERT INTO findings (
            tenant_id, workspace_id, run_id, rule_id, rule_name, author, kind,
            severity, level_original, time_utc, host_hostname, user_name,
            detection_path, reason_codes, fingerprint, event_uids,
            evidence_snapshot
        )
        SELECT %(tenant)s, %(ws)s, %(run)s::uuid, %(rule)s::text::uuid,
               'Timeline bench rule',
               'sentinel', 'sigma', 'MEDIUM', 'medium',
               %(since)s + make_interval(secs => g * %(span)s::float8 / %(n)s),
               %(host)s, 'bench-user', 'sql', '{}',
               digest(%(rule)s::text || ':' || g::text, 'sha256'), '{}',
               jsonb_build_object('schema_version', 'sentinel-evidence/v1')
          FROM generate_series(0, %(n)s - 1) g
        """,
        {
            "tenant": BENCH_TENANT,
            "ws": BENCH_WORKSPACE,
            "run": str(uuid.uuid5(uuid.NAMESPACE_URL, f"timeline-bench/{run_id}")),
            "rule": str(uuid.uuid5(uuid.NAMESPACE_URL, "timeline-bench/rule")),
            "since": since,
            "span": window_seconds,
            "n": findings,
            "host": BENCH_HOST,
        },
    )
    conn.commit()
    return {
        "artifact_id": str(artifact_id),
        "raw_sha256": sha.hex(),
        "events": events,
        "findings": findings,
        "hosts": hosts,
        "window_seconds": window_seconds,
        "since": since.isoformat(),
        "until": (since + timedelta(seconds=window_seconds)).isoformat(),
    }


def purge(conn: psycopg.Connection, *, run_id: str) -> dict[str, int]:
    removed = {}
    for table, sql in (
        ("events", "DELETE FROM events WHERE tenant_id = %s AND workspace_id = %s AND run_id = %s"),
        ("uploads", "DELETE FROM uploads WHERE tenant_id = %s AND workspace_id = %s AND run_id = %s"),
    ):
        removed[table] = conn.execute(sql, (BENCH_TENANT, BENCH_WORKSPACE, run_id)).rowcount
    removed["findings"] = conn.execute(
        "DELETE FROM findings WHERE tenant_id = %s AND workspace_id = %s AND run_id = %s::uuid",
        (BENCH_TENANT, BENCH_WORKSPACE, str(uuid.uuid5(uuid.NAMESPACE_URL, f"timeline-bench/{run_id}"))),
    ).rowcount
    conn.execute(
        "DELETE FROM raw_objects WHERE sha256 = %s",
        (uuid.uuid5(uuid.NAMESPACE_URL, f"sentinel/timeline-bench/{run_id}").bytes,),
    )
    conn.commit()
    return removed


def measure(
    *,
    database_url: str,
    since: datetime,
    until: datetime,
    limit: int,
    passes: int,
) -> tuple[list[float], int]:
    from sentinel_core.rls import set_rls
    from sentinel_storage.repos_timeline import query_timeline

    # warm-up (§6.6 step 2) — discarded
    with tx(database_url) as conn:
        set_rls(conn, BENCH_TENANT, BENCH_WORKSPACE)
        warm = query_timeline(
            conn,
            tenant_id=BENCH_TENANT,
            workspace_id=BENCH_WORKSPACE,
            host=BENCH_HOST,
            since=since,
            until=until,
            limit=limit,
        )
    samples: list[float] = []
    for _ in range(passes):
        with tx(database_url) as conn:
            set_rls(conn, BENCH_TENANT, BENCH_WORKSPACE)
            started = time.perf_counter()
            rows = query_timeline(
                conn,
                tenant_id=BENCH_TENANT,
                workspace_id=BENCH_WORKSPACE,
                host=BENCH_HOST,
                since=since,
                until=until,
                limit=limit,
            )
            samples.append((time.perf_counter() - started) * 1000.0)
    return samples, len(warm)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=100_000, help="events to plant (0 = skip seeding)")
    parser.add_argument("--findings", type=int, default=1_000)
    parser.add_argument("--hosts", type=int, default=1, help="hosts to spread the events over")
    parser.add_argument("--window-seconds", type=float, default=3600.0)
    parser.add_argument("--limit", type=int, default=None, help="query LIMIT (default: untruncated)")
    parser.add_argument("--passes", type=int, default=MEASURED_PASSES)
    parser.add_argument("--out", type=Path, default=OUT_PATH)
    parser.add_argument("--no-seed", action="store_true", help="measure existing data only")
    parser.add_argument("--keep", action="store_true", help="skip cleanup after the run")
    args = parser.parse_args(argv)

    from sentinel_core.config import load_settings

    settings = load_settings()
    run_id = f"bench-timeline-{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}-{uuid.uuid4().hex[:8]}"
    since = datetime.now(timezone.utc) - timedelta(seconds=args.window_seconds)
    until = since + timedelta(seconds=args.window_seconds)
    limit = args.limit if args.limit is not None else args.seed + args.findings + 1000

    planted: dict[str, Any] | None = None
    removed: dict[str, int] | None = None
    seeded = not args.no_seed and args.seed > 0
    try:
        if seeded:
            # the worker role is BYPASSRLS: seeding is bench plumbing, not an
            # API call — the *measurement* below deliberately goes through the
            # app role with RLS GUCs, exactly as a request would.
            with tx(settings.database_worker_url) as conn:
                planted = seed(
                    conn,
                    events=args.seed,
                    findings=args.findings,
                    hosts=max(1, args.hosts),
                    window_seconds=args.window_seconds,
                    run_id=run_id,
                    since=since,
                )
        with tx(settings.database_url) as conn:
            server_version = conn.execute("SELECT version()").fetchone()[0]
        samples, rows = measure(
            database_url=settings.database_url,
            since=since,
            until=until,
            limit=limit,
            passes=args.passes,
        )
    finally:
        if seeded and not args.keep:
            with tx(settings.database_worker_url) as conn:
                removed = purge(conn, run_id=run_id)

    p50 = _percentile_nearest_rank(samples, 50)
    p95 = _percentile_nearest_rank(samples, 95)
    result = {
        "benchmark": "m2-timeline",
        "criterion": "M2 exit ③ — findings ∪ events for a host, p95 < 2 s @ 10^5 events",
        "protocol": (
            f"{WARMUP_PASSES} warm-up pass discarded, then {len(samples)} measured "
            "passes; nearest-rank percentiles (spec §6.6)"
        ),
        "environment": _environment(),
        "database": {"server_version": server_version, "config_hash": _config_hash()},
        "query": {
            "since": since.isoformat(),
            "until": until.isoformat(),
            "host": BENCH_HOST,
            "limit": limit,
        },
        "scale": planted,
        "rows_rendered": rows,
        "samples_ms": [round(s, 3) for s in samples],
        "p50_ms": round(p50, 3),
        "p95_ms": round(p95, 3),
        "max_ms": round(max(samples), 3),
        "budget_ms": BUDGET_MS,
        "pass": bool(p95 < BUDGET_MS),
        "cleanup": removed,
        "measured_at": datetime.now(timezone.utc).isoformat(),
    }

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print(f"rows={rows} p50={p50:.1f}ms p95={p95:.1f}ms max={max(samples):.1f}ms "
          f"budget={BUDGET_MS:.0f}ms -> {'PASS' if result['pass'] else 'FAIL'}")
    print(f"wrote {args.out}")
    return 0 if result["pass"] else 1


if __name__ == "__main__":
    sys.exit(main())
