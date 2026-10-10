#!/usr/bin/env python3
"""Stage-7 audit: extract Stage-2 §5 example canonical events (YAML blocks
under '## 5. Example canonical events') and validate each against
canonical_event_v1.schema.json.  Also re-run Stage-5 §11 rule validation
(reusing _stage5_work/validate_examples.py logic).  Emits
_stage7_work/example_validation.json."""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "_stage7_work"

# ---------------------------------------------------------------------------
# Stage-2 examples
# ---------------------------------------------------------------------------
s2 = (ROOT / "stage-2-canonical-event-and-mappings.md").read_text(encoding="utf-8")
m = re.search(r"## 5\. Example canonical events.*?(?=\n## DECISIONS)", s2, re.S)
assert m, "stage-2 §5 not found"
sec5 = m.group(0)
# examples are fenced json (or yaml) blocks that contain schema_version
blocks = []
for fb in re.finditer(r"```(?:json|yaml)\n(.*?)```", sec5, re.S):
    body = fb.group(1)
    if "schema_version" in body and "canonical-event/v1" in body:
        blocks.append(body)

canon = json.loads((ROOT / "canonical_event_v1.schema.json").read_text(encoding="utf-8"))
Draft202012Validator.check_schema(canon)
cv = Draft202012Validator(canon)

s2_results = []
s2_fail = 0
for i, b in enumerate(blocks, 1):
    try:
        obj = yaml.safe_load(b)
    except Exception:
        try:
            obj = json.loads(b)
        except Exception as exc:  # noqa: BLE001
            s2_results.append({"index": i, "ok": False, "error": f"parse: {exc}"})
            s2_fail += 1
            continue
    errs = sorted(cv.iter_errors(obj), key=lambda e: list(e.path))
    if errs:
        s2_fail += 1
        s2_results.append(
            {
                "index": i,
                "ok": False,
                "category": (obj or {}).get("event", {}).get("category"),
                "type": (obj or {}).get("event", {}).get("type"),
                "errors": [
                    {"path": "/".join(map(str, e.path)), "msg": e.message[:200]}
                    for e in errs[:8]
                ],
            }
        )
    else:
        s2_results.append(
            {
                "index": i,
                "ok": True,
                "category": obj.get("event", {}).get("category"),
                "type": obj.get("event", {}).get("type"),
            }
        )

# ---------------------------------------------------------------------------
# Stage-5 rule examples (reuse the Stage-5 validator logic)
# ---------------------------------------------------------------------------
s5 = (ROOT / "stage-5-dynamic-rule-engine.md").read_text(encoding="utf-8")
m5 = re.search(r"## 11\. Worked Rule Examples.*?(?=\n---\n\n## 12\.)", s5, re.S)
s5_results = []
s5_fail = 0
if not m5:
    # try alternate heading
    m5 = re.search(r"## 11\..*?(?=\n## 12\.)", s5, re.S)
assert m5, "stage-5 §11 not found"
rule_blocks = re.findall(r"```yaml\n(.*?)```", m5.group(0), re.S)
rschema = json.loads((ROOT / "rule_schema.json").read_text(encoding="utf-8"))
Draft202012Validator.check_schema(rschema)
rv = Draft202012Validator(rschema)
for i, b in enumerate(rule_blocks, 1):
    try:
        obj = yaml.safe_load(b)
    except Exception as exc:  # noqa: BLE001
        s5_results.append({"index": i, "ok": False, "error": f"yaml: {exc}"})
        s5_fail += 1
        continue
    errs = sorted(rv.iter_errors(obj), key=lambda e: list(e.path))
    if errs:
        s5_fail += 1
        s5_results.append(
            {
                "index": i,
                "ok": False,
                "id": (obj or {}).get("id"),
                "kind": (obj or {}).get("kind"),
                "errors": [
                    {"path": "/".join(map(str, e.path)), "msg": e.message[:200]}
                    for e in errs[:8]
                ],
            }
        )
    else:
        s5_results.append(
            {"index": i, "ok": True, "id": obj.get("id"), "kind": obj.get("kind")}
        )

# ---------------------------------------------------------------------------
# Stage-3 AF rules embedded in §12.4 (YAML under artifact_finding_rules.yaml)
# ---------------------------------------------------------------------------
s3 = (ROOT / "stage-3-ingestion-and-artifact-triage.md").read_text(encoding="utf-8")
m3 = re.search(r"### 12\.4 Fact-to-finding rules.*?(?=\n### 12\.5)", s3, re.S)
af_results = []
af_fail = 0
if m3:
    af_block = re.search(r"```yaml\n(.*?)```", m3.group(0), re.S)
    if af_block:
        try:
            af_doc = yaml.safe_load(af_block.group(1))
            rules = (af_doc or {}).get("rules", [])
            # wrap each in sentinel-rule/v1 shape to validate against rule_schema
            for r in rules:
                wrapped = {
                    "schema": "sentinel-rule/v1",
                    "id": r.get("id"),
                    "kind": "artifact",
                    "source": "native",
                    "title": r.get("title", ""),
                    "severity": "LOW",
                    "enabled": True,
                    **{k: v for k, v in r.items() if k in ("when", "emit", "severity_hint", "attribution")},
                }
                errs = sorted(rv.iter_errors(wrapped), key=lambda e: list(e.path))
                if errs:
                    af_fail += 1
                    af_results.append(
                        {
                            "id": r.get("id"),
                            "ok": False,
                            "errors": [
                                {"path": "/".join(map(str, e.path)), "msg": e.message[:200]}
                                for e in errs[:6]
                            ],
                        }
                    )
                else:
                    af_results.append({"id": r.get("id"), "ok": True})
        except Exception as exc:  # noqa: BLE001
            af_results.append({"ok": False, "error": str(exc)})
            af_fail += 1

report = {
    "stage2_examples": {
        "total": len(blocks),
        "fail": s2_fail,
        "results": s2_results,
    },
    "stage5_rules": {
        "total": len(rule_blocks),
        "fail": s5_fail,
        "results": s5_results,
    },
    "stage3_af_rules": {
        "total": len(af_results),
        "fail": af_fail,
        "results": af_results,
    },
}
path = OUT / "example_validation.json"
path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
print(f"wrote {path}")
print(
    f"stage2: {len(blocks)-s2_fail}/{len(blocks)} ok | "
    f"stage5: {len(rule_blocks)-s5_fail}/{len(rule_blocks)} ok | "
    f"stage3 AF: {len(af_results)-af_fail}/{len(af_results)} ok"
)
for r in s2_results:
    if not r.get("ok"):
        print("  S2 FAIL", r)
for r in s5_results:
    if not r.get("ok"):
        print("  S5 FAIL", r)
for r in af_results:
    if not r.get("ok"):
        print("  S3 FAIL", r)
sys.exit(0)
