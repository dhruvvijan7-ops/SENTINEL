"""Dual-path conformance oracle (Stage-5 12.1, tier T-C).

The compiled **SQL** detection path and the **native** evaluator are two
implementations of one specification, so the native evaluator is the oracle
for the SQL path: over the same rule corpus and the same events both must
emit the same finding set, rule for rule.  A rule where they disagree is an
*unexplained divergence* and fails the run.

Two classes of difference are expected and are recorded, never counted as
divergences:

* **native-only rules** - the rule uses a construct PostgreSQL cannot be asked
  to decide (``re``, ``fieldref``, ``cidr``, bare keywords).  The compiler
  deliberately emits no predicate for them, so the comparison would be
  meaningless; the oracle checks instead that the fallback carries one of the
  registered reason codes.
* **over-budget SQL** - ``COST_BUDGET_EXCEEDED``: the statement exists and is
  complete, the engine just runs the native path (M2-A1).

Modes
-----
    python tools/conformance_oracle.py
        committed corpus (``tests/conformance/``) - what CI gates on.

    python tools/conformance_oracle.py --sigma-rules research/work/_stage1_work/sigma-rules
        broad run over an out-of-tree SigmaHQ checkout (D6-009 fetch).

    python tools/conformance_oracle.py --evtx .corpus/evtx-rs/sysmon.evtx
        add a real EVTX's events to the corpus (needs the gitignored sample).

    python tools/conformance_oracle.py --write-expected
        regenerate tests/conformance/expected.json after a deliberate change.

Everything runs inside one database transaction and rolls back, so the oracle
never leaves rows behind.
"""
from __future__ import annotations

import argparse
import copy
import glob
import importlib.util
import json
import os
import sys
import uuid
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

ROOT = Path(__file__).resolve().parents[1]
COMMITTED_RULES = ROOT / "tests" / "conformance" / "rules"
COMMITTED_EXPECTED = ROOT / "tests" / "conformance" / "expected.json"
FIXTURE_EVENTS = ROOT / "tests" / "fixtures" / "canonical_events"

#: Fallback reasons that still carry a complete SQL predicate, i.e. the two
#: paths are comparable (M2-A1 keeps the statement even when the engine runs
#: native for cost reasons).
COMPARABLE_REASONS = (None, "COST_BUDGET_EXCEEDED")

#: Registered native-only reasons (``compile._fallback_reason``).  Anything
#: else is not a known, explained difference.
KNOWN_NATIVE_REASONS = frozenset(
    {"REGEX_NATIVE_ONLY", "FIELDREF_NATIVE_ONLY", "KEYWORD_NATIVE_ONLY", "NATIVE_BY_COMPILE"}
)

NOMATCH = "__conformance_no_match__"

# The rule corpus is compared over these committed canonical-event fixtures;
# they are already schema-gated by tests/contract/test_fixture_corpora.py.
_FIXTURES_BY_CATEGORY: dict[str, list[Path]] | None = None


def _detect_packages() -> None:
    """Importable when the tree is not pip-installed (matches other tools)."""
    for pkg in ("detect", "ingest", "storage", "core"):
        path = ROOT / "packages" / pkg
        if str(path) not in sys.path:
            sys.path.insert(0, str(path))


_detect_packages()


# ---------------------------------------------------------------------------
# corpus loading
# ---------------------------------------------------------------------------
class RuleCorpus:
    """One normalized + compiled rule."""

    __slots__ = ("name", "source_ref", "document", "block", "unsupported")

    def __init__(
        self,
        name: str,
        source_ref: str,
        document: Mapping[str, Any],
        block: Mapping[str, Any],
        unsupported: Sequence[Mapping[str, str]],
    ) -> None:
        self.name = name
        self.source_ref = source_ref
        self.document = document
        self.block = block
        self.unsupported = list(unsupported)

    @property
    def reason(self) -> str | None:
        return self.block.get("fallback_reason")

    @property
    def comparable(self) -> bool:
        return self.reason in COMPARABLE_REASONS

    @property
    def detection_path(self) -> str:
        return str(self.block.get("detection_path"))

    @property
    def selector(self) -> dict[str, Any]:
        from sentinel_detect.compile import _pipeline_selector

        return dict(_pipeline_selector(self.document))


def _load_rule_file(path: Path, *, source_ref: str) -> RuleCorpus:
    import yaml

    from sentinel_detect.compile import plan
    from sentinel_detect.normalize import normalize_rule

    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or "detection" not in raw:
        raise ValueError(f"{source_ref}: not a rule document")
    normalized = normalize_rule(raw, source_ref=source_ref)
    block, _codes = plan(normalized.document, unsupported=normalized.unsupported)
    return RuleCorpus(path.stem, source_ref, normalized.document, block, normalized.unsupported)


def load_corpus(rules_dir: Path | None = None) -> list[RuleCorpus]:
    """Committed corpus, or every rule below ``rules_dir`` for a broad run."""
    root = Path(rules_dir) if rules_dir else COMMITTED_RULES
    files = sorted(root.rglob("*.yml")) + sorted(root.rglob("*.yaml"))
    if not files:
        raise SystemExit(f"no rule files under {root}")
    return [_load_rule_file(p, source_ref=str(p.relative_to(root))) for p in files]


# ---------------------------------------------------------------------------
# event corpus
# ---------------------------------------------------------------------------
def _fixture_paths() -> list[Path]:
    return sorted(FIXTURE_EVENTS.glob("*.yaml"))


def _load_fixtures() -> list[dict[str, Any]]:
    import yaml

    return [
        yaml.safe_load(p.read_text(encoding="utf-8"))
        for p in _fixture_paths()
    ]


def _select_base(selector: Mapping[str, Any], fixtures: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Pick a committed fixture that satisfies the pipeline selector.

    A rule that logs to ``image_load`` must be replayed over image_load
    events, otherwise the selector excludes every row and the comparison is
    vacuous.  Fixtures are matched on the selector's own columns; the first
    full match wins, then a category-only match, then a deterministic default.
    """

    def value(doc: Mapping[str, Any], dotted: str) -> Any:
        cur: Any = doc
        for part in dotted.split("."):
            if not isinstance(cur, Mapping) or part not in cur:
                return None
            cur = cur[part]
        return cur

    def matches(doc: Mapping[str, Any], keys: Iterable[str]) -> bool:
        for key in keys:
            want = selector[key]
            options = {str(o) for o in (want if isinstance(want, list) else [want])}
            got = value(doc, key)
            observed = {str(g) for g in (got if isinstance(got, list) else [got])}
            if not options & observed:
                return False
        return True

    keys = list(selector)
    for doc in fixtures:
        if matches(doc, keys):
            return dict(doc)
    narrow = [k for k in keys if k.startswith("event.category")]
    for doc in fixtures:
        if narrow and matches(doc, narrow):
            return dict(doc)
    return dict(fixtures[0])


def _write(doc: dict[str, Any], dotted: str, value: Any) -> None:
    from sentinel_detect.normalize import UNMAPPED_ROOT

    if dotted == UNMAPPED_ROOT or dotted.startswith(UNMAPPED_ROOT + "."):
        # Canonical unmapped shape: a list of {"name": SigmaField, "value": v}.
        name = dotted.split(".", 1)[1]
        entries = doc.get(UNMAPPED_ROOT)
        kept = (
            [
                e
                for e in entries
                if not (isinstance(e, Mapping) and e.get("name") == name)
            ]
            if isinstance(entries, list)
            else []
        )
        kept.append({"name": name, "value": value})
        doc[UNMAPPED_ROOT] = kept
        return
    parts = dotted.split(".")
    cur: Any = doc
    for part in parts[:-1]:
        nxt = cur.get(part)
        if not isinstance(nxt, dict):
            nxt = {}
            cur[part] = nxt
        cur = nxt
    cur[parts[-1]] = value


def _satisfy(key: str, values: Any) -> Any | None:
    """A scalar for the *numeric* / ``neq`` requirements (see ``_joint``)."""
    mods = key.split("|")[1:]
    items = [i for i in (list(values) if isinstance(values, list) else [values]) if i is not None]
    if not items:
        return None
    strings = [str(i) for i in items]
    if "gt" in mods or "gte" in mods:
        try:
            return max(float(s) for s in strings) + (1.0 if "gt" in mods else 0.0)
        except ValueError:
            return None
    if "lt" in mods or "lte" in mods:
        try:
            return min(float(s) for s in strings) - (1.0 if "lt" in mods else 0.0)
        except ValueError:
            return None
    if "neq" in mods:
        return NOMATCH if NOMATCH not in strings else NOMATCH + "x"
    if "exists" in mods:
        return strings[0]
    return items[0]


def _current(doc: Mapping[str, Any], dotted: str) -> Any:
    from sentinel_detect.evaluate import field_value

    present, value = field_value(doc, dotted)
    return value if present else None


def _joint(items: Sequence[tuple[str, Any]], current: Any) -> Any:
    """One value for a field that satisfies *every* requirement on it.

    A rule rarely reads a field once: ``selection`` and ``selection_2`` may
    both write ``process.command_line``, and ``unmapped.name`` may be asked
    for ``contains`` in one identifier and ``endswith`` in another.  Writing
    them one after the other (last one wins) silently drops requirements, so
    the requirements are collected first and folded into a single value:
    exact equality anchors the value, ``contains`` appends, ``startswith``
    prepends, ``endswith`` appends, numeric comparisons replace it.
    """
    hard: str | None = None
    contains: list[tuple[list[str], bool]] = []
    prefixes: list[tuple[list[str], bool]] = []
    suffixes: list[tuple[list[str], bool]] = []
    numeric: Any = None
    neq: list[str] = []
    keep_present = False
    for key, values in items:
        mods = key.split("|")[1:]
        raw = list(values) if isinstance(values, list) else [values]
        raw = [v for v in raw if v is not None]
        if not raw:
            continue
        strings = [str(v) for v in raw]
        if "re" in mods:
            continue  # native-only; nothing to satisfy on the SQL path
        if "exists" in mods:
            keep_present = True
            continue
        if set(mods) & {"gt", "gte", "lt", "lte"}:
            numeric = _satisfy(key, raw)
            continue
        if "neq" in mods:
            neq.extend(strings)
            continue
        cased = "cased" in mods
        if "startswith" in mods:
            prefixes.append((strings, cased))
            continue
        if "endswith" in mods:
            suffixes.append((strings, cased))
            continue
        if "all" in mods or "contains" in mods:
            contains.append((strings, cased))
            continue
        hard = strings[0]  # exact equality; the last one wins

    if numeric is not None:
        return int(numeric) if isinstance(numeric, float) and numeric.is_integer() else numeric

    out = "" if current is None else (current if isinstance(current, str) else str(current))
    if hard is not None:
        out = hard
    for strings, cased in contains:
        hay = out if cased else out.lower()
        for needle in strings:
            probe = needle if cased else needle.lower()
            if probe not in hay:
                out = out + needle
                hay = out if cased else out.lower()
    for strings, cased in prefixes:
        ok = any(out.startswith(s if cased else s.lower()) for s in strings) if cased else any(
            out.lower().startswith(s.lower()) for s in strings
        )
        if not ok:
            out = strings[0] + out
    for strings, cased in suffixes:
        ok = any(out.endswith(s if cased else s.lower()) for s in strings) if cased else any(
            out.lower().endswith(s.lower()) for s in strings
        )
        if not ok:
            out = out + strings[0]
    if out == "" and keep_present:
        out = "true"
    if neq and out in neq:
        out = NOMATCH if NOMATCH not in neq else NOMATCH + "x"
    return out


def _negated_identifiers(document: Mapping[str, Any]) -> set[str]:
    from sentinel_detect.condition import parse_condition

    detection = document.get("detection") or {}
    if not isinstance(detection, Mapping) or "condition" not in detection:
        return set()

    def walk(node: Any, negated: bool) -> set[str]:
        kind = node[0]
        if kind == "ident":
            return {node[1]} if negated else set()
        if kind == "not":
            return walk(node[1], not negated)
        if kind in ("and", "or"):
            return walk(node[1], negated) | walk(node[2], negated)
        if kind == "of":
            # ``not 1 of filter_*`` only matches when *every* member of the
            # pattern is false, so all of them are negative requirements.  A
            # positive ``1 of`` is carried by the positive event as-is.
            if not negated:
                return set()
            _, _count, pattern = node
            import fnmatch

            if pattern in ("them", "*", "all"):
                return {k for k in detection if k != "condition"}
            return {k for k in detection if fnmatch.fnmatchcase(k, pattern)}
        return set()

    return walk(parse_condition(detection["condition"]), False)


def synthesize_events(
    document: Mapping[str, Any],
    *,
    selector: Mapping[str, Any],
    fixtures: Sequence[Mapping[str, Any]],
    scope: Mapping[str, Any],
    tag: str,
) -> list[dict[str, Any]]:
    """Deterministic events built from the rule's own selections.

    Two per rule: one that satisfies every positive selection while
    *defeating* every negated one (``selection and not 1 of filter_*``), and
    one that satisfies both (the control that must NOT match).  Every event is
    a committed fixture in disguise - only the fields the rule actually reads
    are rewritten - so the corpus stays schema-valid and the pipeline
    selector still admits it.
    """
    detection = document.get("detection") or {}
    negated = _negated_identifiers(document)
    idents = {k: v for k, v in detection.items() if k != "condition"}
    pos: dict[str, list[tuple[str, Any]]] = {}
    neg: dict[str, list[tuple[str, Any]]] = {}
    pos_kw: list[str] = []
    neg_kw: list[str] = []
    for name, spec in idents.items():
        fields, keywords = (neg, neg_kw) if name in negated else (pos, pos_kw)
        for item in spec if isinstance(spec, list) else [spec]:
            if isinstance(item, str):
                keywords.append(item)
                continue
            if not isinstance(item, Mapping):
                continue
            for key, value in item.items():
                if key == "|all":
                    continue
                fields.setdefault(key.split("|", 1)[0], []).append((key, value))
    if not pos and not neg and not pos_kw and not neg_kw:
        return []

    out: list[dict[str, Any]] = []
    for variant in ("positive", "negated"):
        base = _select_base(selector, fixtures)
        base.update(dict(scope))
        base["event"]["type"] = base["event"].get("type") or "process_create"
        words = list(pos_kw) + (list(neg_kw) if variant == "negated" else [])
        base["raw"] = (
            f"<Event synthetic-conformance tag='{tag}' variant='{variant}'/>"
            + ("" if not words else " " + " ".join(words))
        )
        for dotted, reqs in pos.items():
            _write(base, dotted, _joint(reqs, _current(base, dotted)))
        if variant == "negated":
            for dotted, reqs in neg.items():
                _write(base, dotted, _joint(reqs, _current(base, dotted)))
        else:
            _defeat(base, idents=idents, negated=negated, pos=pos)
        base["source"] = dict(base.get("source") or {})
        base["source"]["record"] = dict(base["source"].get("record") or {})
        base["source"]["record"]["record_id"] = 900000 + len(out)
        base["source"]["record"]["type"] = base["source"]["record"].get("type", "event_record")
        base["run_id"] = str(base.get("run_id") or "")
        out.append(base)
    return out


def _defeat(
    base: dict[str, Any],
    *,
    idents: Mapping[str, Any],
    negated: set[str],
    pos: Mapping[str, Sequence[tuple[str, Any]]],
) -> None:
    """Make every negated identifier false, without touching positive fields."""
    from sentinel_detect.evaluate import _eval

    for name in sorted(negated):
        spec = idents.get(name)
        if spec is None:
            continue
        try:
            if not _eval(("ident", name), idents, base):
                continue
        except (KeyError, ValueError):
            continue
        for item in spec if isinstance(spec, list) else [spec]:
            if not isinstance(item, Mapping):
                continue
            for key in item:
                dotted = key.split("|", 1)[0]
                if dotted in pos:
                    continue  # a positive requirement owns this field
                _write(base, dotted, NOMATCH)


def build_event_corpus(
    rules: Sequence[RuleCorpus],
    *,
    scope: Mapping[str, Any],
    with_fixtures: bool = True,
) -> list[dict[str, Any]]:
    """Committed fixtures + one synthesized pair per rule."""
    fixtures = _load_fixtures()
    events: list[dict[str, Any]] = []
    if with_fixtures:
        for doc in fixtures:
            event = copy.deepcopy(doc)
            event.update(dict(scope))
            events.append(event)
    for rule in rules:
        from sentinel_detect.compile import _pipeline_selector

        selector = _pipeline_selector(rule.document)
        events.extend(
            synthesize_events(
                rule.document,
                selector=selector,
                fixtures=fixtures,
                scope=scope,
                tag=rule.name,
            )
        )
    return events


# ---------------------------------------------------------------------------
# the comparison
# ---------------------------------------------------------------------------
def _run_sql(rule: RuleCorpus, *, tenant: str, workspace: str, run_ids: list[str]) -> set[Any]:
    from sentinel_detect.compile import bind_params

    params = bind_params(rule.document, tenant, workspace, run_ids)
    rows = execute(rule.block["sql"], params)
    return {row[0] for row in rows}


def _run_native(rule: RuleCorpus, *, tenant: str, workspace: str, run_ids: list[str]) -> set[Any]:
    from sentinel_detect.compile import _pipeline_selector, _selector_sql
    from sentinel_detect.evaluate import evaluate

    sel_params: list[Any] = []
    sel_sql, _entries = _selector_sql(_pipeline_selector(rule.document), sel_params)
    sql = (
        "SELECT e.event_uid, e.document, e.host_hostname, e.user_name,"
        " COALESCE(e.event_time_utc, e.ingest_time) AS finding_time FROM events e"
        " WHERE e.tenant_id = %s AND e.workspace_id = %s AND e.run_id = ANY(%s)"
    ) + sel_sql
    rows = execute(sql, [tenant, workspace, run_ids, *sel_params])
    return {m.event_uid for m in evaluate(rule.document, rows)}


_CONN: Any = None


def execute(sql: str, params: Sequence[Any]) -> Sequence[Sequence[Any]]:
    if _CONN is None:
        raise RuntimeError("oracle has no open connection")
    return _CONN.execute(sql, list(params)).fetchall()


def compare(
    rules: Sequence[RuleCorpus],
    *,
    tenant: str,
    workspace: str,
    run_id: str,
) -> dict[str, Any]:
    """Run both paths over one run id and return the oracle report."""
    run_ids = [run_id]
    divergences: list[dict[str, Any]] = []
    intentional: list[dict[str, Any]] = []
    per_rule: list[dict[str, Any]] = []
    fired = {"sql": 0, "native": 0}
    pairs = 0
    for rule in rules:
        if not rule.comparable:
            reason = rule.reason
            if reason not in KNOWN_NATIVE_REASONS:
                divergences.append(
                    {
                        "rule": rule.name,
                        "kind": "unknown-fallback-reason",
                        "reason": reason,
                        "detail": "fallback reason is not one of the registered codes",
                    }
                )
            else:
                native_hits = _run_native(
                    rule, tenant=tenant, workspace=workspace, run_ids=run_ids
                )
                fired["native"] += 1 if native_hits else 0
                intentional.append(
                    {
                        "rule": rule.name,
                        "source_ref": rule.source_ref,
                        "reason": reason,
                        "detection_path": rule.detection_path,
                        "matched": len(native_hits),
                    }
                )
            continue
        sql_hits = _run_sql(rule, tenant=tenant, workspace=workspace, run_ids=run_ids)
        nat_hits = _run_native(rule, tenant=tenant, workspace=workspace, run_ids=run_ids)
        fired["sql"] += 1 if sql_hits else 0
        fired["native"] += 1 if nat_hits else 0
        pairs += min(len(sql_hits), len(nat_hits))
        per_rule.append(
            {
                "rule": rule.name,
                "source_ref": rule.source_ref,
                "sql": len(sql_hits),
                "native": len(nat_hits),
                "selector": rule.selector,
                "fallback_reason": rule.reason,
            }
        )
        if sql_hits != nat_hits:
            divergences.append(
                {
                    "rule": rule.name,
                    "kind": "path-divergence",
                    "reason": rule.reason,
                    "sql_only": sorted(str(u) for u in (sql_hits - nat_hits))[:5],
                    "native_only": sorted(str(u) for u in (nat_hits - sql_hits))[:5],
                    "sql": len(sql_hits),
                    "native": len(nat_hits),
                }
            )
    return {
        "rules": len(rules),
        "comparable": sum(1 for r in rules if r.comparable),
        "native_only": sum(1 for r in rules if not r.comparable),
        "fired": fired,
        "matched_pairs": pairs,
        "divergences": divergences,
        "intentional": sorted(intentional, key=lambda i: i["rule"]),
        "per_rule": sorted(per_rule, key=lambda i: i["rule"]),
    }


# ---------------------------------------------------------------------------
# expected-classification manifest (drift detection for the committed corpus)
# ---------------------------------------------------------------------------
def expected_manifest(rules: Sequence[RuleCorpus]) -> dict[str, Any]:
    import hashlib

    entries = {}
    for rule in sorted(rules, key=lambda r: r.name):
        path = COMMITTED_RULES / (rule.source_ref)
        entries[rule.name] = {
            "source_ref": rule.source_ref,
            "sha256": hashlib.sha256(Path(path).read_bytes()).hexdigest(),
            "detection_path": rule.detection_path,
            "comparable": rule.comparable,
            "fallback_reason": rule.reason,
            "title": str((rule.document.get("title") or ""))[:120],
            "author": str(rule.document.get("author") or ""),
            "kind": str(rule.document.get("kind") or ""),
            "license": str(rule.document.get("license") or rule.document.get("status") or ""),
        }
    return {
        "schema": "sentinel-conformance-expectation/v1",
        "rules": entries,
        "count": len(entries),
    }


def write_expected(rules: Sequence[RuleCorpus]) -> dict[str, Any]:
    manifest = expected_manifest(rules)
    COMMITTED_EXPECTED.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return manifest


def load_expected() -> dict[str, Any]:
    return json.loads(COMMITTED_EXPECTED.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# database plumbing
# ---------------------------------------------------------------------------
def _scope(tenant: str, workspace: str, run_id: str) -> dict[str, Any]:
    return {"tenant_id": tenant, "workspace_id": workspace, "run_id": run_id}


def insert_events(
    conn: Any,
    events: Sequence[Mapping[str, Any]],
    *,
    tenant: str,
    workspace: str,
    run_id: str,
    artifact_id: uuid.UUID,
) -> int:
    _detect_packages()
    from sentinel_ingest.worker_handlers import _event_row
    from sentinel_storage.repos_events import bulk_insert

    # events.artifact_id -> uploads.artifact_id (FK); the oracle owns a throw
    # away raw object + upload row and rolls them back with the transaction.
    digest = uuid.uuid4().bytes + uuid.uuid4().bytes
    conn.execute(
        "INSERT INTO raw_objects (sha256, size, refcount, storage_uri, state,"
        " retention_until, legal_hold, created_at)"
        " VALUES (%s, %s, 1, %s, 'hot', now() + interval '90 days', false, now())",
        [digest, len(events), f"file:///conformance/{run_id}"],
    )
    conn.execute(
        "INSERT INTO uploads (artifact_id, tenant_id, workspace_id, run_id, sha256,"
        " size, original_filename, display_name, received_at, triage_state)"
        " VALUES (%s, %s, %s, %s, %s, %s, %s, %s, now(), 'done')",
        [
            artifact_id,
            tenant,
            workspace,
            run_id,
            digest,
            len(events),
            "conformance.json",
            f"conformance {run_id}",
        ],
    )
    rows = [
        _event_row(
            dict(event),
            tenant_id=tenant,
            workspace_id=workspace,
            artifact_id=artifact_id,
            harvest_run_id=run_id,
        )
        for event in events
    ]
    return bulk_insert(conn, rows)


def _settings():
    os.environ.setdefault("SENTINEL_CONFIG", str(ROOT / "configs" / "config.example.toml"))
    from sentinel_core.config import load_settings

    return load_settings()


def run_oracle(
    conn: Any,
    *,
    rules: Sequence[RuleCorpus] | None = None,
    events: Sequence[Mapping[str, Any]] | None = None,
    tenant: str = "default",
    workspace: str = "default",
    run_id: str | None = None,
) -> dict[str, Any]:
    """Compare both paths on ``conn``; the caller owns the transaction."""
    global _CONN
    rules = list(rules) if rules is not None else load_corpus()
    run_id = run_id or f"conformance-{uuid.uuid4().hex[:12]}"
    artifact_id = uuid.uuid4()
    if events is None:
        events = build_event_corpus(rules, scope=_scope(tenant, workspace, run_id))
    else:
        events = [dict(e) for e in events]
        for event in events:
            event.update(_scope(tenant, workspace, run_id))
    _CONN = conn
    try:
        inserted = insert_events(
            conn,
            events,
            tenant=tenant,
            workspace=workspace,
            run_id=run_id,
            artifact_id=artifact_id,
        )
        report = compare(rules, tenant=tenant, workspace=workspace, run_id=run_id)
    finally:
        _CONN = None
    report["events"] = inserted
    report["run_id"] = run_id
    report["pass"] = not report["divergences"]
    return report


# ---------------------------------------------------------------------------
# optional extras for the broad run
# ---------------------------------------------------------------------------
def envelopes_from_evtx(path: Path, *, tenant: str, workspace: str, run_id: str) -> list[dict]:
    _detect_packages()
    from sentinel_ingest.evtx_parser import ParseStats, iter_envelopes

    stats = ParseStats()
    return list(
        iter_envelopes(
            str(path),
            tenant_id=tenant,
            workspace_id=workspace,
            run_id=run_id,
            file_id=str(uuid.uuid4()),
            file_sha256="0" * 64,
            stats=stats,
        )
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sigma-rules", type=Path, help="out-of-tree rule checkout (broad run)")
    parser.add_argument("--evtx", type=Path, help="add this EVTX's events to the corpus")
    parser.add_argument("--write-expected", action="store_true", help="rewrite expected.json")
    parser.add_argument("--json", type=Path, help="write the report to this file")
    parser.add_argument("--keep", action="store_true", help="commit instead of rolling back")
    args = parser.parse_args(argv)

    settings = _settings()
    from sentinel_core.db import tx

    rules = load_corpus(args.sigma_rules)
    if args.write_expected:
        if args.sigma_rules:
            raise SystemExit("--write-expected only makes sense for the committed corpus")
        manifest = write_expected(rules)
        print(f"wrote {COMMITTED_EXPECTED.relative_to(ROOT)} ({manifest['count']} rules)")
        return 0

    run_id = f"conformance-{uuid.uuid4().hex[:12]}"
    events: list[dict[str, Any]] | None = None
    if args.evtx:
        events = build_event_corpus(
            rules, scope=_scope("default", "default", run_id)
        ) + envelopes_from_evtx(
            args.evtx, tenant="default", workspace="default", run_id=run_id
        )

    with tx(settings.database_worker_url) as conn:
        report = run_oracle(conn, rules=rules, events=events, run_id=run_id)
        if args.keep:
            conn.commit()

    print(
        f"rules={report['rules']} comparable={report['comparable']} "
        f"native_only={report['native_only']} events={report['events']}"
    )
    print(f"fired sql={report['fired']['sql']} native={report['fired']['native']}")
    print(f"matched_pairs={report['matched_pairs']}")
    for item in report["intentional"]:
        print(
            f"  INTENTIONAL {item['rule']}: {item['reason']} "
            f"(native matched {item['matched']})"
        )
    for row in report.get("per_rule", []):
        print(
            f"  RULE {row['rule']}: sql={row['sql']} native={row['native']} "
            f"selector={json.dumps(row['selector'], sort_keys=True)}"
        )
    for bad in report["divergences"]:
        print(f"  DIVERGENCE {bad}")
    print(f"divergences={len(report['divergences'])} -> {'PASS' if report['pass'] else 'FAIL'}")
    if args.json:
        args.json.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    return 0 if report["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
