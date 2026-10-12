"""The M2 planted-finding drill: real ingest, pinned event uid, real detect.

M2 exit ① (spec §9) requires a committed EVTX containing a known-bad process
creation that a pinned SigmaHQ rule matches, "with expected ``fingerprint``
recorded in the fixture manifest" (§6.3).  ``events.event_uid`` defaults to a
random uuid7, and the fingerprint hashes ``event_uids``, so the golden
fingerprint can only be stable when the drill pins the planted event's uid —
which is done here, between ingest and detect, and documented in
``tests/planted/manifest.json``.

Both consumers run exactly this code so the golden values and the assertions
cannot drift apart:

* ``tests/integration/test_m2_exit.py`` — the M2 exit gates;
* ``python -m tests.m2_drill`` — regenerates the ``expected`` block of
  ``tests/planted/manifest.json`` (never hand-edited).
"""
from __future__ import annotations

import hashlib
import json
import uuid
from pathlib import Path
from typing import Any

from .conftest import drain_jobs
from .keys import KEY_B

ROOT = Path(__file__).resolve().parents[1]
PLANTED_DIR = ROOT / "tests" / "planted"
PLANTED_EVTX = PLANTED_DIR / "sysmon_planted.evtx"
PACK_PATH = PLANTED_DIR / "pack.json"
MANIFEST_PATH = PLANTED_DIR / "manifest.json"

#: The drill owns one workspace so it can never disturb ``default`` (whose
#: empty pack ``tests/e2e/test_upload_flow.py`` pins) or the ``rule_rls``
#: seed rows.
TENANT_ID = "tenant-b"
WORKSPACE_ID = "ws-b"
PACK_ID = "sentinel-m2-planted"

#: The record ``tools/plant_fixture.py`` rewrites, and the command line it
#: writes into it.
PLANT_RECORD_ID = 1742
PLANTED_CMDLINE = "ping.exe whoami /priv"

PIN_NS_URL = "https://sentinel.local/m2-planted"


def planted_event_uid() -> uuid.UUID:
    """Stable uid for the planted event (uuid5 over the record id)."""
    return uuid.uuid5(uuid.NAMESPACE_URL, f"{PIN_NS_URL}/{PLANT_RECORD_ID}")


def load_manifest() -> dict[str, Any]:
    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


def planted_sha256_bytes() -> bytes:
    return hashlib.sha256(PLANTED_EVTX.read_bytes()).digest()


def purge(settings: Any) -> None:
    """Remove every row this drill can create (children before parents)."""
    from sentinel_core.db import tx

    scope = (TENANT_ID, WORKSPACE_ID)
    with tx(settings.database_worker_url) as conn:
        conn.execute(
            "DELETE FROM findings WHERE tenant_id = %s AND workspace_id = %s", scope
        )
        conn.execute(
            "DELETE FROM rule_run WHERE run_id IN ("
            "  SELECT run_id FROM detection_runs"
            "   WHERE tenant_id = %s AND workspace_id = %s)",
            scope,
        )
        conn.execute(
            "DELETE FROM rule_baseline WHERE tenant_id = %s AND workspace_id = %s",
            scope,
        )
        conn.execute(
            "DELETE FROM events WHERE tenant_id = %s AND workspace_id = %s", scope
        )
        conn.execute(
            "DELETE FROM job_attempts WHERE job_id IN ("
            "  SELECT job_id FROM jobs WHERE tenant_id = %s AND workspace_id = %s)",
            scope,
        )
        conn.execute(
            "DELETE FROM jobs WHERE tenant_id = %s AND workspace_id = %s", scope
        )
        conn.execute(
            "DELETE FROM detection_runs WHERE tenant_id = %s AND workspace_id = %s",
            scope,
        )
        conn.execute(
            "DELETE FROM uploads WHERE tenant_id = %s AND workspace_id = %s", scope
        )
        conn.execute(
            "DELETE FROM raw_objects WHERE sha256 = %s"
            "   AND NOT EXISTS (SELECT 1 FROM uploads u WHERE u.sha256 = raw_objects.sha256)",
            (planted_sha256_bytes(),),
        )
        conn.execute(
            "DELETE FROM rule_source WHERE tenant_id = %s AND workspace_id = %s"
            "   AND rule_id IN (SELECT rule_id FROM rules"
            "                    WHERE tenant_id = %s AND workspace_id = %s"
            "                      AND provenance ->> 'pack_id' = %s)",
            (*scope, *scope, PACK_ID),
        )
        conn.execute(
            "DELETE FROM rules WHERE tenant_id = %s AND workspace_id = %s"
            "   AND provenance ->> 'pack_id' = %s",
            (*scope, PACK_ID),
        )
        conn.commit()


def import_planted_pack(settings: Any) -> dict[str, Any]:
    """Load the one committed SigmaHQ rule into the drill workspace."""
    from sentinel_core.db import tx
    from sentinel_detect.sigma_import import import_pack, load_pack_manifest

    manifest = load_pack_manifest(PACK_PATH)
    with tx(settings.database_worker_url) as conn:
        summary = import_pack(
            conn,
            manifest,
            tenant_id=TENANT_ID,
            workspace_id=WORKSPACE_ID,
            pack_root=PLANTED_DIR,
            retire_missing=False,
        )
        conn.commit()
    return summary.counts


def pin_event_uid(settings: Any, run_id: str) -> uuid.UUID:
    """Rewrite the planted event's uid to the manifest's pinned constant."""
    from sentinel_core.db import tx

    pinned = planted_event_uid()
    with tx(settings.database_worker_url) as conn:
        rows = conn.execute(
            "SELECT event_uid FROM events"
            " WHERE run_id = %s"
            "   AND document #>> '{source,record,record_id}' = %s",
            (run_id, str(PLANT_RECORD_ID)),
        ).fetchall()
        if len(rows) != 1:
            raise RuntimeError(
                f"expected exactly 1 event for record {PLANT_RECORD_ID}, got {len(rows)}"
            )
        previous = rows[0][0]
        if previous != pinned:
            conn.execute(
                "UPDATE events SET event_uid = %s WHERE event_uid = %s",
                (pinned, previous),
            )
        conn.commit()
    return pinned


def _event_count(settings: Any, run_id: str) -> int:
    from sentinel_core.db import tx

    with tx(settings.database_worker_url) as conn:
        row = conn.execute(
            "SELECT count(*) FROM events WHERE run_id = %s", (run_id,)
        ).fetchone()
    return int(row[0])


def fetch_findings(settings: Any) -> list[dict[str, Any]]:
    """Every finding in the drill workspace, normalised for assertions."""
    from datetime import datetime

    from sentinel_core.db import tx

    sql = (
        "SELECT finding_uid, rule_id, rule_name, author, kind, severity,"
        "       level_original, time_utc, host_hostname, user_name,"
        "       detection_path, reason_codes, fingerprint, event_uids,"
        "       occurrence_count, triage_state, evidence_snapshot, run_id"
        "  FROM findings WHERE tenant_id = %s AND workspace_id = %s"
        " ORDER BY time_utc, finding_uid"
    )
    with tx(settings.database_worker_url) as conn:
        rows = conn.execute(sql, (TENANT_ID, WORKSPACE_ID)).fetchall()
    out = []
    for row in rows:
        out.append(
            {
                "finding_uid": str(row[0]),
                "rule_id": str(row[1]),
                "rule_name": row[2],
                "author": row[3],
                "kind": row[4],
                "severity": row[5],
                "level_original": row[6],
                "time_utc": row[7].isoformat() if isinstance(row[7], datetime) else row[7],
                "host_hostname": row[8],
                "user_name": row[9],
                "detection_path": row[10],
                "reason_codes": list(row[11] or []),
                "fingerprint": bytes(row[12]).hex(),
                "event_uids": [str(u) for u in (row[13] or [])],
                "occurrence_count": int(row[14]),
                "triage_state": row[15],
                "evidence_snapshot": row[16],
                "run_id": str(row[17]) if row[17] else None,
            }
        )
    return out


def run_drill(settings: Any, client: Any) -> dict[str, Any]:
    """purge → import the planted rule → upload → ingest → pin → detect.

    Returns the artifact/run ids plus the single finding the pack must raise.
    """
    from sentinel_worker.main import make_worker_id, process_batch

    purge(settings)
    counts = import_planted_pack(settings)

    data = PLANTED_EVTX.read_bytes()
    response = client.post(
        f"/v1/workspaces/{WORKSPACE_ID}/uploads",
        files={"file": ("sysmon_planted.evtx", data, "application/octet-stream")},
        data={"collection_kind": "harvest"},
        headers={"X-API-Key": KEY_B},
    )
    if response.status_code != 202:
        raise RuntimeError(f"upload failed: {response.status_code} {response.text}")
    artifact_id = response.json()["artifact_id"]
    run_id = response.json()["run_id"]

    worker_id = make_worker_id(settings)
    # The queue is shared: other suites' (or a previous session's) jobs may
    # claim the batch first, so keep draining until *this* upload has landed.
    for _ in range(60):
        process_batch(settings, worker_id, job_types=("ingest_file",))
        if _event_count(settings, run_id):
            break
    else:
        raise RuntimeError("planted EVTX never reached the events table")

    event_uid = pin_event_uid(settings, run_id)

    if drain_jobs(settings) < 1:
        raise RuntimeError("chained detect_run job did not run")

    findings = fetch_findings(settings)
    if len(findings) != 1:
        raise RuntimeError(f"expected exactly 1 finding, got {len(findings)}")

    detect_run_id = findings[0]["run_id"]
    with _worker_conn(settings) as conn:
        row = conn.execute(
            "SELECT config_hash FROM detection_runs WHERE run_id = %s",
            (detect_run_id,),
        ).fetchone()
    config_hash = bytes(row[0]).hex() if row else None

    return {
        "artifact_id": artifact_id,
        "run_id": run_id,
        "detect_run_id": detect_run_id,
        "event_uid": str(event_uid),
        "pack_counts": counts,
        "config_hash": config_hash,
        "finding": findings[0],
    }


class _worker_conn:
    """Context manager over the BYPASSRLS worker connection (read-only use)."""

    def __init__(self, settings: Any) -> None:
        from sentinel_core.db import tx

        self._cm = tx(settings.database_worker_url)

    def __enter__(self):
        return self._cm.__enter__()

    def __exit__(self, *exc):
        return self._cm.__exit__(*exc)


def expected_block(result: dict[str, Any]) -> dict[str, Any]:
    """The ``expected`` stanza recorded in the fixture manifest.

    Only *reproducible* values land here.  ``rule_document_sha256`` and the
    per-event digests are deliberately excluded: the rule document embeds
    ``provenance.imported_at`` and the event document embeds the (random)
    harvest ``run_id`` and artifact id, so both change on every re-import.
    ``tests/integration/test_m2_exit.py`` recomputes those two digests from
    the stored rows instead, which is the check that actually matters.
    """
    finding = result["finding"]
    snapshot = finding["evidence_snapshot"] or {}
    rule = snapshot.get("rule") or {}
    return {
        "tenant_id": TENANT_ID,
        "workspace_id": WORKSPACE_ID,
        "rule_id": finding["rule_id"],
        "detection_path": finding["detection_path"],
        "severity": finding["severity"],
        "level_original": finding["level_original"],
        "time_utc": finding["time_utc"],
        "host_hostname": finding["host_hostname"],
        "user_name": finding["user_name"],
        "occurrence_count": finding["occurrence_count"],
        "reason_codes": finding["reason_codes"],
        "event_uids": finding["event_uids"],
        "fingerprint": finding["fingerprint"],
        "config_hash": result["config_hash"],
        "rule_source_sha256": rule.get("source_sha256"),
        "evidence_schema_version": snapshot.get("schema_version"),
    }


def main(argv: list[str] | None = None) -> int:
    """Run the drill and rewrite the ``expected`` block of the manifest."""
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--keep", action="store_true", help="skip the teardown purge")
    args = parser.parse_args(argv)

    from fastapi.testclient import TestClient

    from sentinel_api.app import create_app
    from sentinel_core.config import load_settings

    settings = load_settings()
    app = create_app(settings)
    with TestClient(app) as client:
        result = run_drill(settings, client)
    if not args.keep:
        purge(settings)

    manifest = load_manifest()
    manifest["expected"] = expected_block(result)
    MANIFEST_PATH.write_text(
        json.dumps(manifest, indent=2, ensure_ascii=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(manifest["expected"], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
