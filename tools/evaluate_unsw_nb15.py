#!/usr/bin/env python3
"""Score the Sentinel network rule pack against UNSW-NB15 (spec §6.3a, M2 exit ⑥).

Pipeline per split (train / test):

  1. locate the CSV under ``.corpus/unsw-nb15/`` and verify the **pinned**
     sha256 + row count (drift fails the run — the dataset is never committed,
     so the pin is what makes the run reproducible);
  2. require the fetch manifest's citation line (attribution is part of the
     gate, §6.3a);
  3. map every row to a canonical ``network_connection`` document
     (``sentinel_ingest.unsw_nb15``) — a row that cannot be mapped is counted
     as a **drop and fails the run** (zero-drop contract);
  4. validate every document against ``canonical_event_v1.schema.json``
     (fastjsonschema, the same rules as the jsonschema gate — see
     ``tests/scoring/test_unsw_nb15_mapping.py`` for the agreement check);
  5. evaluate ``tests/scoring/rules/*.yml`` on the native path and report
     precision / recall / F1 / FPR against ``label`` plus per-category recall
     against ``attack_cat``.

The JSON report is written to ``research/work/_stage6_work/bench/`` (numbers
only, no corpus rows — §6.6 artefact discipline).

Usage::

    python tools/evaluate_unsw_nb15.py                 # both splits
    python tools/evaluate_unsw_nb15.py --split test    # one split
    python tools/evaluate_unsw_nb15.py --json out.json --no-validate
"""
from __future__ import annotations

import argparse
import hashlib
import json
import platform
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sentinel_detect.compile import CompileError, plan  # noqa: E402
from sentinel_detect.evaluate import evaluate  # noqa: E402
from sentinel_detect.normalize import normalize_rule  # noqa: E402
from sentinel_ingest.unsw_nb15 import (  # noqa: E402
    DATASET,
    UnswRowError,
    read_flows,
)

CORPUS_DIR = ROOT / ".corpus" / "unsw-nb15"
MANIFEST = CORPUS_DIR / "manifest.json"
PACK_DIR = ROOT / "tests" / "scoring" / "rules"
SCHEMA_PATH = ROOT / "canonical_event_v1.schema.json"
DEFAULT_REPORT = ROOT / "research" / "work" / "_stage6_work" / "bench" / "unsw_nb15_scoring.json"
CITATION_TOKEN = "Moustafa"
#: Mandatory attribution for UNSW-NB15 (V-6-035): the fetch manifest carries
#: this line, and a run whose manifest lacks it fails (§6.3a "citation is
#: part of the gate"). tools/corpus_fetch.py writes the manifest with it.
CITATION = (
    "Moustafa, N. and Slay, J. (2015). UNSW-NB15: a comprehensive data set "
    "for network intrusion detection systems (UNSW-NB15 network data set). "
    "Military Communications and Information Systems Conference (MilCIS), "
    "pp. 492-497. IEEE. Academic use only; commercial use prohibited "
    "(UNSW terms, VERIFIED 2026-10-12)."
)

#: URL + sha256 + data-row count for both published CSVs. Recorded from the
#: first fetch (tools/corpus_fetch.py prints the digest); drift fails the run.
PINNED: dict[str, dict[str, Any]] = {
    "UNSW_NB15_training-set.csv": {
        "rows": 175341,
        "bytes": 32293018,
        "sha256": "bec7dd5ec88dc2a0ccc7a07879d338395ed7421750f675fd0339e07dfe0648fa",
        "url": "https://huggingface.co/datasets/Mouwiya/UNSW-NB15/resolve/main/"
               "UNSW_NB15_training-set.csv",
    },
    "UNSW_NB15_testing-set.csv": {
        "rows": 82332,
        "bytes": 15380800,
        "sha256": "734fe6642edf758f7c94d7d9149426b49d202fe8e7bf0bef47392489c3c0a559",
        "url": "https://raw.githubusercontent.com/Nir-J/ML-Projects/master/"
               "UNSW-Network_Packet_Classification/UNSW_NB15_testing-set.csv",
    },
}

SPLITS = {"train": "UNSW_NB15_training-set.csv", "test": "UNSW_NB15_testing-set.csv"}

BATCH = 10_000
#: Document keys that would leak ground truth into detection. Belt and braces
#: next to the pack lint in tests/scoring/test_unsw_nb15_pack.py.
FORBIDDEN_DOCUMENT_KEYS = ("label", "attack_cat")


class ScoringError(RuntimeError):
    """A gate condition failed: pin, manifest, mapping, validation or pack."""


# ---------------------------------------------------------------------------
# corpus
# ---------------------------------------------------------------------------
def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_corpus(split: str) -> tuple[Path, dict[str, Any]]:
    name = SPLITS[split]
    path = CORPUS_DIR / name
    if not path.exists():
        raise ScoringError(
            f"{path} is missing — fetch it first: python tools/corpus_fetch.py "
            "(the dataset itself is never committed, D6-009)"
        )
    expected = PINNED[name]
    digest = sha256_file(path)
    if digest != expected["sha256"]:
        raise ScoringError(f"{name}: sha256 {digest} != pinned {expected['sha256']}")
    if path.stat().st_size != expected["bytes"]:
        raise ScoringError(
            f"{name}: {path.stat().st_size} bytes != pinned {expected['bytes']}"
        )
    if MANIFEST.exists():
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        citation = str(manifest.get("citation") or "")
        if CITATION_TOKEN not in citation:
            raise ScoringError("fetch manifest carries no citation line (§6.3a gate)")
        entry = (manifest.get("files") or {}).get(name) or {}
        if entry.get("sha256") not in (None, expected["sha256"]):
            raise ScoringError(f"{name}: manifest sha256 disagrees with the pin")
    else:
        raise ScoringError(f"{MANIFEST} is missing — attribution is part of the gate")
    return path, expected


# ---------------------------------------------------------------------------
# pack
# ---------------------------------------------------------------------------
def load_pack(pack_dir: Path = PACK_DIR) -> list[tuple[str, dict[str, Any], list[dict[str, str]]]]:
    """``[(source_id, normalized document, reason codes)]`` for every rule."""
    import yaml

    out: list[tuple[str, dict[str, Any], list[dict[str, str]]]] = []
    for path in sorted(pack_dir.glob("*.yml")):
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ScoringError(f"{path}: rule is not a mapping")
        normalized = normalize_rule(raw, source_ref=f"tests/scoring/rules/{path.name}")
        if normalized.fatal:
            raise ScoringError(
                f"{path.name}: fatal normalize codes "
                f"{[u['code'] for u in normalized.unsupported]}"
            )
        codes = list(normalized.unsupported)
        # Every scoring rule must be SQL-compilable: the product runs the SQL
        # path in front of the native one, and a rule that cannot compile is a
        # different rule at runtime. plan() raises CompileError on failure and
        # only ever appends non-fatal codes (UNMAPPED_FIELD for the feature
        # columns that have no canonical home) to ``unsupported``.
        try:
            plan(normalized.document, unsupported=codes)
        except CompileError as exc:
            raise ScoringError(f"{path.name}: SQL compile failed: {exc}") from exc
        out.append((normalized.document["source_id"], normalized.document, codes))
    if not out:
        raise ScoringError(f"no rules found in {pack_dir}")
    return out


# ---------------------------------------------------------------------------
# scoring
# ---------------------------------------------------------------------------
def _validator():
    import fastjsonschema

    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    # fastjsonschema's newest dialect is draft 2019-09; this schema uses only
    # features both dialects share ($defs pointers, if/then, oneOf, const,
    # additionalProperties). tests/scoring/test_unsw_nb15_mapping.py asserts
    # the two validators accept and reject the same documents, so the faster
    # one can be used for the 257k-row run without weakening the check.
    dialect = dict(schema)
    dialect["$schema"] = "http://json-schema.org/draft-07/schema#"
    return fastjsonschema.compile(dialect)


def _ratio(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else 0.0


def score_split(
    split: str,
    rules: list[tuple[str, dict[str, Any], list[dict[str, str]]]],
    *,
    validate: bool = True,
) -> dict[str, Any]:
    path, expected = verify_corpus(split)
    started = time.time()

    validate_doc = _validator() if validate else None
    tenant_id, workspace_id, run_id = "tenant-b", "ws-b", f"unsw-{split}"

    rows = dropped = invalid = 0
    first_error: str | None = None
    tp = fp = fn = tn = 0
    category_total: Counter[str] = Counter()
    category_hits: Counter[str] = Counter()
    rule_fires: Counter[str] = Counter()
    #: per-rule attribution: how often each rule was the (only) reason a row
    #: was flagged, plus how many of its fires were on attack vs normal rows.
    rule_on_attack: Counter[str] = Counter()
    rule_on_normal: Counter[str] = Counter()
    leak_rows = 0

    batch: list[tuple[str, dict[str, Any], str, str, Any]] = []
    labels: dict[str, tuple[int, str]] = {}

    def flush() -> None:
        nonlocal tp, fp, fn, tn
        if not batch:
            return
        hits: dict[str, list[str]] = {}
        for source_id, document, _codes in rules:
            for match in evaluate(document, batch):
                hits.setdefault(match.event_uid, []).append(source_id)
        for uid, _doc, _host, _user, _when in batch:
            row_label, category = labels[uid]
            fired = hits.get(uid, [])
            for source_id in fired:
                rule_fires[source_id] += 1
                if row_label == 1:
                    rule_on_attack[source_id] += 1
                else:
                    rule_on_normal[source_id] += 1
            if row_label == 1:
                if fired:
                    tp += 1
                    category_hits[category] += 1
                else:
                    fn += 1
            elif fired:
                fp += 1
            else:
                tn += 1
        batch.clear()

    try:
        for record in read_flows(
            path,
            tenant_id=tenant_id,
            workspace_id=workspace_id,
            run_id=run_id,
            file_id=path.name,
            file_sha256=expected["sha256"],
        ):
            rows += 1
            document = record.document
            # Ground truth must not be reachable from the payload except in
            # `raw` (the verbatim source row), which no rule may read.
            names = {entry["name"] for entry in document.get("unmapped", [])}
            if names & set(FORBIDDEN_DOCUMENT_KEYS):
                leak_rows += 1
            if validate_doc is not None:
                try:
                    validate_doc(document)
                except Exception as exc:  # noqa: BLE001 - counted, then failed
                    invalid += 1
                    if first_error is None:
                        first_error = f"row {record.row}: {exc}"
            labels[str(record.row)] = (record.label, record.attack_cat)
            category_total[record.attack_cat] += 1
            batch.append((str(record.row), document, "", "", None))
            if len(batch) >= BATCH:
                flush()
    except UnswRowError as exc:
        dropped += 1
        raise ScoringError(f"{path.name}: row dropped while mapping: {exc}") from exc
    flush()

    if rows != expected["rows"]:
        raise ScoringError(f"{path.name}: read {rows} rows, pinned {expected['rows']}")
    if invalid:
        raise ScoringError(f"{path.name}: {invalid} documents failed the schema: {first_error}")
    if leak_rows:
        raise ScoringError(f"{path.name}: {leak_rows} rows leak ground truth into the document")

    precision = _ratio(tp, tp + fp)
    recall = _ratio(tp, tp + fn)
    f1 = _ratio(2 * precision * recall, precision + recall)
    return {
        "file": path.name,
        "sha256": expected["sha256"],
        "rows": rows,
        "documents": rows - dropped,
        "dropped": dropped,
        "invalid_documents": invalid,
        "binary": {
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "tn": tn,
            "precision": round(precision, 6),
            "recall": round(recall, 6),
            "f1": round(f1, 6),
            "fpr": round(_ratio(fp, fp + tn), 6),
        },
        "per_category_recall": {
            category: round(_ratio(category_hits[category], total), 6)
            for category, total in sorted(category_total.items())
            if category != "Normal"
        },
        "normal_rows": category_total.get("Normal", 0),
        "per_rule_fires": dict(sorted(rule_fires.items())),
        "per_rule_attack_vs_normal": {
            source_id: {
                "on_attack": rule_on_attack[source_id],
                "on_normal": rule_on_normal[source_id],
            }
            for source_id in sorted(rule_fires)
        },
        "seconds": round(time.time() - started, 2),
    }


def run(
    *,
    splits: Iterable[str] = ("train", "test"),
    validate: bool = True,
    pack_dir: Path = PACK_DIR,
    report: Path = DEFAULT_REPORT,
) -> dict[str, Any]:
    rules = load_pack(pack_dir)
    results = {split: score_split(split, rules, validate=validate) for split in splits}
    payload: dict[str, Any] = {
        "dataset": DATASET,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "citation": json.loads(MANIFEST.read_text(encoding="utf-8"))["citation"]
        if MANIFEST.exists()
        else None,
        "schema": "canonical-event/v1",
        "validator": "fastjsonschema" if validate else "none (--no-validate)",
        "pack": {
            "dir": str(pack_dir.relative_to(ROOT)).replace("\\", "/"),
            "rules": [source_id for source_id, _doc, _codes in rules],
            "rule_count": len(rules),
        },
        "splits": results,
        "environment": {
            "python": platform.python_version(),
            "platform": platform.platform(),
        },
    }
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--split", choices=("train", "test", "both"), default="both")
    parser.add_argument("--json", type=Path, default=DEFAULT_REPORT, help="report path")
    parser.add_argument("--no-validate", action="store_true", help="skip schema validation")
    parser.add_argument("--pack", type=Path, default=PACK_DIR, help="rule pack directory")
    args = parser.parse_args(argv)

    splits = ("train", "test") if args.split == "both" else (args.split,)
    try:
        payload = run(
            splits=splits,
            validate=not args.no_validate,
            pack_dir=args.pack,
            report=args.json,
        )
    except ScoringError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 2

    for split, result in payload["splits"].items():
        binary = result["binary"]
        print(
            f"[{split}] rows={result['rows']} dropped={result['dropped']} "
            f"invalid={result['invalid_documents']} "
            f"precision={binary['precision']:.4f} recall={binary['recall']:.4f} "
            f"f1={binary['f1']:.4f} fpr={binary['fpr']:.4f} "
            f"({result['seconds']}s)"
        )
        print("        per-category recall: " + ", ".join(
            f"{k}={v:.3f}" for k, v in result["per_category_recall"].items()
        ))
    print(f"report: {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
