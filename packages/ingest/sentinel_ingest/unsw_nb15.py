"""UNSW-NB15 flow CSV -> canonical-event/v1 ``network_connection`` (spec Â§6.3a).

The two published CSVs (``UNSW_NB15_training-set.csv`` /
``UNSW_NB15_testing-set.csv``) carry 45 columns and **no** addresses or ports,
so the mapping is deliberately partial:

======================  ==========================================
CSV column              canonical home
======================  ==========================================
``proto``               ``network.protocol``
``state``               ``network.state``
``sbytes``              ``network.bytes_sent``   (int)
``dbytes``              ``network.bytes_recv``... -> ``bytes_received``
``dur``                 ``network.duration``     (float, seconds)
``service``, ``spkts``, ``dpkts``, ``sttl``, ``dttl``, ``rate``,
``ct_*``, ...           ``unmapped[]`` under the source column name
``id``                  ``source.record.row``
``label``, ``attack_cat`` **ground truth â€” never written into the document**
======================  ==========================================

Why ground truth stays out of the document: a rule that could match the
label would score itself. The scoring harness reads ``label``/``attack_cat``
straight from the CSV row (``FlowRecord.label`` / ``.attack_cat``), and
``tests/scoring/test_unsw_nb15_pack.py`` fails the pack if any rule's
detection or logsource mentions them (or ``raw``, which is the verbatim row).

Licence: UNSW-NB15 is free for academic research, commercial use prohibited
(spec Â§6.2/Â§6.3a, VERIFIED 2026-10-12; V-6-035). The CSVs themselves are
**never committed** â€” they live in the gitignored ``.corpus/unsw-nb15/`` and
are fetched by ``tools/corpus_fetch.py`` with a pinned sha256. Citation lives
in the fetch manifest and is checked by the gate.

Zero-drop contract (M2 exit â‘¥): every data row yields exactly one schema-valid
document. A row that cannot be interpreted raises :class:`UnswRowError` â€” the
caller counts it as a drop and the gate fails; rows are never silently skipped.
"""
from __future__ import annotations

import csv
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator, Mapping

from .envelope import SCHEMA_VERSION, state_invalid, state_null

PARSER_NAME = "unsw-nb15"
PARSER_VERSION = "1.0.0"
DATASET = "UNSW-NB15"

#: Columns that carry ground truth. Excluded from every document (see module
#: docstring) and readable only through :func:`ground_truth`.
GROUND_TRUTH_COLUMNS = ("label", "attack_cat")

#: Flow id column â€” folded into source.record.row, not into the payload.
ID_COLUMN = "id"

#: CSV column -> canonical ``network.*`` property (canonical_event_v1 Â§$defs/network).
NETWORK_FIELDS: dict[str, str] = {
    "proto": "protocol",
    "state": "state",
    "sbytes": "bytes_sent",
    "dbytes": "bytes_received",
    "dur": "duration",
}

#: Canonical network properties that must be integers / floats.
_INT_FIELDS = frozenset({"bytes_sent", "bytes_received"})

#: Feature columns that are neither ground truth nor canonical network fields:
#: they keep their source name in ``unmapped[]``. The full set is asserted
#: against the CSV header so a different UNSW variant (one carrying IPs, say)
#: is rejected instead of being mapped as if it were this dataset.
FEATURE_COLUMNS = (
    "service", "spkts", "dpkts", "sttl", "dttl", "rate", "sload", "dload",
    "sloss", "dloss", "sinpkt", "dinpkt", "sjit", "djit", "swin", "stcpb",
    "dtcpb", "dwin", "tcprtt", "synack", "ackdat", "smean", "dmean",
    "trans_depth", "response_body_len", "ct_srv_src", "ct_state_ttl",
    "ct_dst_ltm", "ct_src_dport_ltm", "ct_dst_sport_ltm", "ct_dst_src_ltm",
    "is_ftp_login", "ct_ftp_cmd", "ct_flw_http_mthd", "ct_src_ltm",
    "ct_srv_dst", "is_sm_ips_ports",
)

#: The header both published CSVs carry, in order (45 columns). The parser
#: refuses any other header: a different UNSW variant (one carrying srcip/
#: dstip/sport/dsport, say) must not be mapped as if it were this dataset.
EXPECTED_COLUMNS = (
    "id", "dur", "proto", "service", "state", "spkts", "dpkts", "sbytes",
    "dbytes", "rate", "sttl", "dttl", "sload", "dload", "sloss", "dloss",
    "sinpkt", "dinpkt", "sjit", "djit", "swin", "stcpb", "dtcpb", "dwin",
    "tcprtt", "synack", "ackdat", "smean", "dmean", "trans_depth",
    "response_body_len", "ct_srv_src", "ct_state_ttl", "ct_dst_ltm",
    "ct_src_dport_ltm", "ct_dst_sport_ltm", "ct_dst_src_ltm",
    "is_ftp_login", "ct_ftp_cmd", "ct_flw_http_mthd", "ct_src_ltm",
    "ct_srv_dst", "is_sm_ips_ports", "attack_cat", "label",
)


class UnswRowError(ValueError):
    """A CSV row could not be turned into a document â€” counted as a drop."""


@dataclass(frozen=True)
class FlowRecord:
    """One CSV row: the document plus the ground truth kept beside it."""

    row: int
    document: dict[str, Any]
    label: int
    attack_cat: str


def ground_truth(row: Mapping[str, str]) -> tuple[int, str]:
    """``(label, attack_cat)`` straight from the source row.

    ``label`` is 1 for any attack, 0 for ``Normal``; a row that disagrees with
    its own ``attack_cat`` is a corpus defect, not something to paper over.
    """
    raw_label = (row.get("label") or "").strip()
    if raw_label not in ("0", "1"):
        raise UnswRowError(f"label column is {raw_label!r}, expected 0 or 1")
    label = int(raw_label)
    category = (row.get("attack_cat") or "").strip() or "Normal"
    if label == 0 and category != "Normal":
        raise UnswRowError(f"label 0 with attack_cat {category!r}")
    if label == 1 and category == "Normal":
        raise UnswRowError("label 1 with attack_cat Normal")
    return label, category


def _canonical_value(raw: str | None, path: str) -> Any:
    """Source text -> canonical scalar (state objects for empty/invalid)."""
    if raw is None:
        return state_null("")
    text = raw.strip()
    if text == "" or text == "-":
        return state_null(raw)
    if path in _INT_FIELDS:
        try:
            return int(text)
        except ValueError:
            try:
                value = float(text)
            except ValueError:
                return state_invalid(raw, "not a number")
            # float("NaN") parses: a non-finite value is not JSON, so it would
            # poison the document (json.dumps emits `NaN`, PostgreSQL rejects
            # it). Treat it exactly like any other unparseable number.
            return value if math.isfinite(value) else state_invalid(raw, "not a number")
    if path == "duration":
        try:
            value = float(text)
        except ValueError:
            return state_invalid(raw, "not a number")
        return value if math.isfinite(value) else state_invalid(raw, "not a number")
    return raw


def row_to_document(
    row: Mapping[str, str],
    *,
    row_number: int,
    tenant_id: str,
    workspace_id: str,
    run_id: str,
    file_id: str,
    file_sha256: str | None = None,
) -> dict[str, Any]:
    """One CSV row -> a canonical-event/v1 document (schema-valid by design)."""
    flow_id = (row.get(ID_COLUMN) or "").strip()
    if not flow_id:
        raise UnswRowError(f"row {row_number}: missing {ID_COLUMN}")
    for column in NETWORK_FIELDS:
        if column not in row:
            raise UnswRowError(f"row {row_number}: missing column {column}")

    network: dict[str, Any] = {}
    for column, path in NETWORK_FIELDS.items():
        network[path] = _canonical_value(row.get(column), path)

    unmapped: list[dict[str, Any]] = [
        {"name": column, "value": row[column]}
        for column in row
        if column not in NETWORK_FIELDS
        and column not in GROUND_TRUTH_COLUMNS
        and column != ID_COLUMN
        and column in row
    ]

    source: dict[str, Any] = {
        "file_id": file_id,
        "format": "csv",
        "parser": PARSER_NAME,
        "parser_version": PARSER_VERSION,
        "record": {"type": "row", "row": int(flow_id) if flow_id.isdigit() else row_number},
    }
    if file_sha256:
        source["sha256"] = file_sha256

    document: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "event": {
            "category": "network",
            "type": "network_connection",
            "action": "connect",
            "outcome": "unknown",
            "severity": "informational",
            # Sentinel classifies the record (the source has no taxonomy).
            "derived_by": "sentinel",
        },
        "tenant_id": tenant_id,
        "workspace_id": workspace_id,
        "run_id": run_id,
        # The published CSVs carry no timestamps: utc null + state unknown is
        # exactly what the schema's time.allOf requires in that case.
        "time": {
            "utc": None,
            "original": None,
            "original_timezone": None,
            "timezone_source": "none",
            "precision": "unknown",
            "state": "unknown",
        },
        "host": {},
        "user": {},
        "source": source,
        "classification": "public",
        # Verbatim source row, lossless â€” label/attack_cat travel here and
        # nowhere else, which is why no rule may read `raw`.
        "raw": dict(row),
        "network": network,
        "unmapped": unmapped,
    }
    return document


def read_flows(
    path: Path | str,
    *,
    tenant_id: str,
    workspace_id: str,
    run_id: str,
    file_id: str,
    file_sha256: str | None = None,
) -> Iterator[FlowRecord]:
    """Yield exactly one :class:`FlowRecord` per CSV data row.

    ``utf-8-sig`` strips the BOM the published files carry on the ``id``
    header. Structurally unusable rows raise :class:`UnswRowError` instead of
    being skipped, so "zero dropped rows" is a count, not a hope.
    """
    path = Path(path)
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames is None:
            raise UnswRowError(f"{path}: empty CSV")
        if tuple(reader.fieldnames) != EXPECTED_COLUMNS:
            raise UnswRowError(
                f"{path}: header is not the pinned UNSW-NB15 45-column header "
                f"(got {tuple(reader.fieldnames)!r})"
            )
        for index, row in enumerate(reader, start=1):
            if None in row:  # stray extra field: ragged row, not a silent skip
                raise UnswRowError(f"{path} row {index}: ragged (extra columns)")
            label, category = ground_truth(row)
            document = row_to_document(
                row,
                row_number=index,
                tenant_id=tenant_id,
                workspace_id=workspace_id,
                run_id=run_id,
                file_id=file_id,
                file_sha256=file_sha256,
            )
            yield FlowRecord(row=index, document=document, label=label, attack_cat=category)


def count_rows(path: Path | str) -> int:
    """Data-row count (excludes the header), for the fetch-manifest check."""
    with Path(path).open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.reader(handle)
        try:
            next(reader)
        except StopIteration:
            return 0
        return sum(1 for _ in reader)
