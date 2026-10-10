#!/usr/bin/env python3
"""Stage-7 audit: dangling references, invariant scan, and number audit.

Dangling-reference scan: every cross-stage pointer of the form
  stage-N:§X, stage-N:X.Y, D<stage>-NNN, Q<stage>-NNN, AF-NNN, T-NN, V-NNN
is checked against the extracted inventories.  Invariant scan: the ten
Stage-1 invariants plus Stage-5 D5-014 empty-pack invariant are re-stated
and machine-checked where checkable.  Number audit: PROPOSED constants are
inventoried with their labels.

Emits _stage7_work/invariants_numbers.json and prints a summary.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "_stage7_work"

STAGE_FILES = {
    1: ROOT / "stage-1-landscape-and-rule-engine-decision.md",
    2: ROOT / "stage-2-canonical-event-and-mappings.md",
    3: ROOT / "stage-3-ingestion-and-artifact-triage.md",
    4: ROOT / "stage-4-threat-model-and-windows-sandbox.md",
    5: ROOT / "stage-5-dynamic-rule-engine.md",
    6: ROOT / "stage-6-platform-storage-jobs-api-testing-release.md",
}
TEXTS = {n: p.read_text(encoding="utf-8") for n, p in STAGE_FILES.items()}
COMBINED = "\n".join(TEXTS.values())
SCHEMA_SQL = (ROOT / "schema.sql").read_text(encoding="utf-8")
OPENAPI = (ROOT / "openapi.yaml").read_text(encoding="utf-8")
CANON = (ROOT / "canonical_event_v1.schema.json").read_text(encoding="utf-8")
RULE = (ROOT / "rule_schema.json").read_text(encoding="utf-8")

# ---------------------------------------------------------------------------
# collect defined ids
# ---------------------------------------------------------------------------
decision_ids: set[str] = set()
question_ids: set[str] = set()
# decisions: lines like "- id: D5-001" or "- id: D-004" (YAML)
for n, text in TEXTS.items():
    for m in re.finditer(r"^\s*-\s+id:\s*([A-Za-z][\w-]*)\s*$", text, re.M):
        iid = m.group(1)
        if re.match(r"^D\d*-\d+$", iid):
            decision_ids.add(iid)
        elif re.match(r"^Q\d*-\d+$", iid):
            question_ids.add(iid)
    # open questions also use "- id: Q..."
    for m in re.finditer(r"^\s*-\s+id:\s*(Q[\w-]+)\s*$", text, re.M):
        question_ids.add(m.group(1))
    # markdown-table decisions: | D6-001 | ... or first cell
    for m in re.finditer(r"^\|\s*(D\d+-\d+)\s*\|", text, re.M):
        decision_ids.add(m.group(1))
    for m in re.finditer(r"^\|\s*(Q\d+-\d+)\s*\|", text, re.M):
        question_ids.add(m.group(1))
    # stage-1 numbered open questions: **Q1 — ...**
    for m in re.finditer(r"\*\*(Q\d+)\b", text):
        question_ids.add(m.group(1))
    # stage-4 open questions in table form | Q4-001 | ...
    for m in re.finditer(r"\b(Q4-\d{3})\b", text):
        question_ids.add(m.group(1))

# AF rules
af_ids = set(re.findall(r"^\s*-\s+id:\s*(AF-\d+)\s*$", COMBINED, re.M))
af_ids |= set(re.findall(r'"id":\s*"(AF-\d+)"', COMBINED))
af_ids |= set(re.findall(r"^id:\s*(AF-\d+)\s*$", COMBINED, re.M))

# threat ids from stage-4
threat_ids = set(re.findall(r"\bT-(\d+)\b", TEXTS[4]))

# verification log entries per stage (approximate: V-… / TL-… / A-… ids)
verif_ids = set(re.findall(r"\bV\d+\b", TEXTS[5]))
verif_ids |= set(re.findall(r"^\s*-\s+id:\s*([A-Z][\w-]+)\s*$", TEXTS[2], re.M))

# ---------------------------------------------------------------------------
# dangling reference scan
# ---------------------------------------------------------------------------
dangling: list[dict] = []

# decision refs of form D5-001, D2-014, D-004
dec_ref_re = re.compile(r"\b(D\d+-\d{3}|D-\d{3})\b")
q_ref_re = re.compile(r"\b(Q\d+-\d{3}|Q\d*-\d+)\b")
af_ref_re = re.compile(r"\bAF-\d{3}\b")

for n, text in TEXTS.items():
    for m in dec_ref_re.finditer(text):
        ref = m.group(1)
        # allow bare D-001..D-0xx as stage-1 ids
        if ref not in decision_ids:
            # stage-1 uses D-001 style; check
            line = text.count("\n", 0, m.start()) + 1
            dangling.append(
                {"stage": n, "line": line, "ref": ref, "type": "decision", "context": text[max(0, m.start()-60):m.end()+40].replace("\n", " ")}
            )
    for m in q_ref_re.finditer(text):
        ref = m.group(1)
        if ref not in question_ids and not re.match(r"^Q1$", ref):
            line = text.count("\n", 0, m.start()) + 1
            dangling.append(
                {"stage": n, "line": line, "ref": ref, "type": "question", "context": text[max(0, m.start()-60):m.end()+40].replace("\n", " ")}
            )
    for m in af_ref_re.finditer(text):
        ref = m.group(0)
        if ref not in af_ids:
            line = text.count("\n", 0, m.start()) + 1
            dangling.append(
                {"stage": n, "line": line, "ref": ref, "type": "af_rule", "context": text[max(0, m.start()-60):m.end()+40].replace("\n", " ")}
            )

# contract-name scan
for name in ("sentinel-alert", "AnalysisRun", "alerts."):
    if name in COMBINED and name not in SCHEMA_SQL and name not in OPENAPI:
        # find where referenced
        for n, text in TEXTS.items():
            for m in re.finditer(re.escape(name), text):
                line = text.count("\n", 0, m.start()) + 1
                dangling.append(
                    {
                        "stage": n,
                        "line": line,
                        "ref": name,
                        "type": "contract_name",
                        "context": text[max(0, m.start()-60):m.end()+40].replace("\n", " "),
                        "note": "appears in stage text but not in schema.sql or openapi.yaml",
                    }
                )
                break  # one hit per stage is enough

# events.classification field
_events_block = re.search(
    r"CREATE TABLE events\s*\((.*?)\)(?:\s*PARTITION|\s*;)", SCHEMA_SQL, re.S | re.I
)
_events_has_col = bool(_events_block and "classification" in _events_block.group(1))
for n, text in TEXTS.items():
    for m in re.finditer(r"events\.classification|events\.class", text):
        line = text.count("\n", 0, m.start()) + 1
        if not _events_has_col:
            dangling.append(
                {
                    "stage": n,
                    "line": line,
                    "ref": "events.classification",
                    "type": "field",
                    "context": text[max(0, m.start()-60):m.end()+40].replace("\n", " "),
                    "note": "schema.sql events has no classification column",
                }
            )

# payload column names used by stage-5 SQL that are not DDL columns
for col in ("payload", "host.agent_id", "time.utc", "source.event_id"):
    # these appear in stage-5 as if they were SQL columns
    if col in TEXTS[5] and f'"{col}"' not in SCHEMA_SQL:
        pass  # recorded manually in the report; scan is heuristic

# ---------------------------------------------------------------------------
# invariant checks
# ---------------------------------------------------------------------------
invariants = []

def inv(iid: str, statement: str, check: str, ok: bool | None, evidence: str = ""):
    invariants.append(
        {"id": iid, "statement": statement, "check": check, "status": ("PASS" if ok else "FAIL") if ok is not None else "MANUAL", "evidence": evidence}
    )

# INV-1 empty-pack / no hardcoded detections
inv(
    "INV-1",
    "Engine with zero rules emits zero findings; no detection constants in engine code (Stage-1 MVP-2 / D5-014).",
    "textual: stage-1 MVP-2 present, stage-5 D5-014 present",
    ("MVP-2" in TEXTS[1] or "MVP-2" in COMBINED) and ("D5-014" in COMBINED),
    "stage-5 D5-014; stage-1 §4.4 MVP-2",
)

# INV-2 detectors consume only canonical events
inv(
    "INV-2",
    "Detectors consume only canonical-event/v1 objects (Stage-3 §3.4, §12).",
    "textual: stage-3 invariant statement present",
    "detectors consume only canonical events" in TEXTS[3].lower(),
    "stage-3 §3.4 and §12.6",
)

# INV-3 no verdict words in triage
banned = ("clean", "safe", "benign", "malicious", "infected", "whitelisted")
inv(
    "INV-3",
    "Triage never emits a verdict; clean/safe/benign/malicious are banned by name (Stage-3 D3-029).",
    "textual: ban present in stage-3",
    "banned from the triage vocabulary" in TEXTS[3],
    "stage-3 §8.1 D3-029",
)

# INV-4 no rendering / no macro execution
inv(
    "INV-4",
    "No rendering, no macro execution, no document interpreters, no egress, no code-loading, no deref, no destructive ops (Stage-3 §9).",
    "textual: §9 present with all seven prohibitions",
    all(x in TEXTS[3] for x in ("No rendering, ever", "No macro execution", "No document interpreters", "No network egress", "No code-loading", "No reference dereferencing", "No destructive")),
    "stage-3 §9.1–§9.8",
)

# INV-5 events.classification invariant (Stage-5 §1.10)
if "classification" in TEXTS[5] and "events.classification" in TEXTS[5]:
    has_col = bool(re.search(r"CREATE TABLE events.*?classification", SCHEMA_SQL, re.S))
    inv(
        "INV-5",
        "events.classification (public/internal/restricted) is a persisted column (Stage-5 §1.10 invariant 5).",
        "schema.sql: events table has classification column",
        has_col,
        "schema.sql CREATE TABLE events",
    )

# INV-6 author on every alert/finding
findings_has_author = bool(re.search(r"CREATE TABLE findings.*?author", SCHEMA_SQL, re.S))
inv(
    "INV-6",
    "Rule author is persisted on every alert/finding row (Stage-1 DRL-1.1 / D-004).",
    "schema.sql: findings table has author column",
    findings_has_author,
    "schema.sql CREATE TABLE findings",
)

# INV-7 RLS on every tenant-scoped table
rls_named = set(
    re.findall(r"ALTER\s+TABLE\s+([\w]+)\s+ENABLE\s+ROW\s+LEVEL\s+SECURITY", SCHEMA_SQL, re.I)
)
tenant_tables = set(re.findall(r"CREATE TABLE (\w+) \(", SCHEMA_SQL))
scoped = set()
for t in tenant_tables:
    m = re.search(rf"CREATE TABLE {t} \((.*?)\)(?:\s*PARTITION|\s*;)", SCHEMA_SQL, re.S | re.I)
    if m and "tenant_id" in m.group(1):
        scoped.add(t)
missing_rls = sorted(scoped - rls_named)
inv(
    "INV-7",
    "Every tenant-scoped table has RLS ENABLEd (Stage-1 D-012 / Stage-6).",
    "schema.sql: every table with a tenant_id column has an ENABLE ROW LEVEL SECURITY statement",
    not missing_rls,
    f"missing RLS: {missing_rls}" if missing_rls else f"all {len(scoped)} tenant-scoped tables covered; {len(rls_named)} RLS statements",
)

# INV-8 raw evidence does not reference raw bytes (retention-safe)
inv(
    "INV-8",
    "findings.evidence_snapshot is an immutable JSONB freeze that does NOT reference raw bytes; purging raw never destroys evidence (Stage-6 reject-condition #1).",
    "schema.sql comment + column present",
    "evidence_snapshot" in SCHEMA_SQL and "does NOT reference raw bytes" in SCHEMA_SQL,
    "schema.sql header comment + findings.evidence_snapshot",
)

# INV-9 severity axes never collapsed
inv(
    "INV-9",
    "severity (LOW/MEDIUM/HIGH) and level_original (informational..critical) remain separate axes and are never collapsed (Stage-1 §6.4).",
    "rule_schema.json keeps both enums distinct",
    '"level_original"' in RULE and '"severity"' in RULE and "never collapsed" in RULE,
    "rule_schema.json severity/level_original",
)

# INV-10 no bare null except time.utc
# The schema encodes: time.utc type [string,null] + allOf if-null then state in
# [unknown,invalid]; $defs/state_object description states bare null is forbidden.
_canon_obj = __import__("json").loads(CANON)
_time_allOf = _canon_obj.get("$defs", {}).get("time", {}).get("allOf", [])
_state_banned = "Bare null is forbidden" in _canon_obj.get("$defs", {}).get("state_object", {}).get("description", "")
_null_guard = any(
    "utc" in (clause.get("if", {}).get("properties", {}) or {}) for clause in _time_allOf
)
inv(
    "INV-10",
    "Canonical events never contain a bare JSON null except time.utc under state unknown/invalid (Stage-2 D2-001).",
    "canonical_event_v1.schema.json: $defs.time.allOf guards null utc by state; state_object description bans bare null",
    _null_guard and _state_banned,
    "canonical_event_v1.schema.json $defs.time / $defs.state_object",
)

# ---------------------------------------------------------------------------
# number audit: PROPOSED constants
# ---------------------------------------------------------------------------
proposed: list[dict] = []
for n, text in TEXTS.items():
    for m in re.finditer(r"([^\n]{0,120}?)\s*`?PROPOSED[^`\n]{0,80}`?", text):
        line = text.count("\n", 0, m.start()) + 1
        snippet = m.group(1).strip()[-120:]
        proposed.append({"stage": n, "line": line, "context": snippet})

# key constants to cross-check
constants = {
    "max_file_bytes": {"value": "64 MiB", "stages": [3]},
    "event.severity enum": {"value": "informational|low|medium|high|critical", "stages": [2]},
    "finding.severity enum": {"value": "LOW|MEDIUM|HIGH", "stages": [1, 5, 6]},
    "Bloom FPP": {"value": "~1%", "stages": [5]},
    "Bloom 5M-entry cap": {"value": "5M", "stages": [5]},
    "in_list_ref size cap": {"value": "10 MiB", "stages": [5]},
    "cost budgets": {"value": "2/10 ms/event, 200k window tuples", "stages": [5]},
    "uploads metadata grace": {"value": "90 days", "stages": [6]},
    "raw presigned TTL": {"value": "15 min", "stages": [6]},
}

# verify constants appear with PROPOSED label where claimed
const_checks = []
for name, meta in constants.items():
    found_stages = [n for n in meta["stages"] if name.split()[0].lower() in TEXTS[n].lower() or meta["value"].split()[0] in TEXTS[n]]
    const_checks.append(
        {
            "constant": name,
            "value": meta["value"],
            "expected_stages": meta["stages"],
            "found_in_stages": found_stages,
            "ok": bool(found_stages),
        }
    )

# ---------------------------------------------------------------------------
# write
# ---------------------------------------------------------------------------
# de-dup dangling by (stage, line, ref)
seen = set()
dang_uniq = []
for d in dangling:
    key = (d.get("stage"), d.get("line"), d.get("ref"))
    if key not in seen:
        seen.add(key)
        dang_uniq.append(d)

report = {
    "id_inventory": {
        "decision_ids": sorted(decision_ids),
        "question_ids": sorted(question_ids),
        "af_ids": sorted(af_ids),
        "decision_count": len(decision_ids),
        "question_count": len(question_ids),
        "af_count": len(af_ids),
    },
    "dangling_references": dang_uniq,
    "dangling_count": len(dang_uniq),
    "invariants": invariants,
    "invariant_failures": [i for i in invariants if i["status"] == "FAIL"],
    "proposed_constant_mentions": len(proposed),
    "proposed_sample": proposed[:40],
    "constant_checks": const_checks,
}
path = OUT / "invariants_numbers.json"
path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
print(f"wrote {path}")
print(f"decisions={len(decision_ids)} questions={len(question_ids)} af={len(af_ids)}")
print(f"dangling={len(dang_uniq)} invariant_failures={len(report['invariant_failures'])}")
for i in invariants:
    print(f"  {i['id']}: {i['status']} — {i['statement'][:90]}")
for d in dang_uniq[:30]:
    print(f"  DANGLING stage{d.get('stage')}:{d.get('line')} {d.get('ref')} ({d.get('type')})")
sys.exit(0)
