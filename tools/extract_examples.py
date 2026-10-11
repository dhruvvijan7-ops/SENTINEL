#!/usr/bin/env python3
"""Extract the committed example corpora from the authored stage documents.

Produces (idempotent, re-runnable):

  tests/fixtures/canonical_events/*.yaml   — Stage-2 §5 canonical-event/v1 examples
  tests/fixtures/rules/stage5/*.yaml       — Stage-5 §11 worked sentinel-rule/v1 rules
  tests/fixtures/rules/stage3_af/*.yaml    — Stage-3 §12.4 AF rules (wrapped in sentinel-rule/v1)
  tests/fixtures/manifest.json             — counts, source sha256, per-file provenance

Adapted from research/work/_stage7_work/validate_examples.py; that script stays
as authoring tooling, this one is the writer behind the contract-test gate.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"

FENCE = re.compile(r"```(json|yaml)\n(.*?)```", re.S)
YAML_FENCE = re.compile(r"```yaml\n(.*?)```", re.S)

EXPECTED_COUNTS = {"canonical_events": 121, "stage5_rules": 25, "stage3_af_rules": 5}

WRITE = True


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _slug(value: str) -> str:
    value = re.sub(r"[^0-9A-Za-z]+", "_", value).strip("_").lower()
    return value[:60] or "unnamed"


def _dump(path: Path, obj: object) -> None:
    if not WRITE:
        return
    text = yaml.safe_dump(obj, sort_keys=False, allow_unicode=True, width=100)
    path.write_text(text, encoding="utf-8", newline="\n")


# ---------------------------------------------------------------------------
# Stage-2 §5 canonical events
# ---------------------------------------------------------------------------
def extract_canonical_events() -> tuple[list[dict], dict]:
    src = ROOT / "research" / "stage-2-canonical-event-and-mappings.md"
    text = src.read_text(encoding="utf-8")
    m = re.search(r"## 5\. Example canonical events.*?(?=\n## DECISIONS)", text, re.S)
    if not m:
        raise SystemExit("stage-2 §5 'Example canonical events' not found")
    section_start = _line_of(text, m.start())
    section_end = _line_of(text, m.end())
    outdir = FIXTURES / "canonical_events"
    outdir.mkdir(parents=True, exist_ok=True)
    files: list[dict] = []
    seen: set[str] = set()
    for i, fb in enumerate(FENCE.finditer(m.group(0)), 1):
        body = fb.group(2)
        if "schema_version" not in body or "canonical-event/v1" not in body:
            continue
        obj = yaml.safe_load(body)
        event = (obj or {}).get("event") or {}
        base = f"{len(files) + 1:03d}_{_slug(event.get('category', 'na'))}_{_slug(event.get('type', 'na'))}"
        name = base
        n = 2
        while name in seen:
            name = f"{base}_{n}"
            n += 1
        seen.add(name)
        path = outdir / f"{name}.yaml"
        _dump(path, obj)
        files.append(
            {
                "file": f"canonical_events/{name}.yaml",
                "source_line_start": _line_of(text, m.start() + fb.start()),
                "source_line_end": _line_of(text, m.start() + fb.end()),
                "category": event.get("category"),
                "type": event.get("type"),
            }
        )
    manifest = {
        "corpus": "canonical_events",
        "count": len(files),
        "source_doc": "research/stage-2-canonical-event-and-mappings.md",
        "source_sha256": _sha256(src),
        "source_section": "## 5. Example canonical events",
        "source_section_line_start": section_start,
        "source_section_line_end": section_end,
        "schema": "canonical_event_v1.schema.json",
        "files": files,
    }
    return files, manifest


# ---------------------------------------------------------------------------
# Stage-5 §11 worked rules
# ---------------------------------------------------------------------------
def extract_stage5_rules() -> tuple[list[dict], dict]:
    src = ROOT / "research" / "stage-5-dynamic-rule-engine.md"
    text = src.read_text(encoding="utf-8")
    m = re.search(r"## 11\. Worked Rule Examples.*?(?=\n---\n\n## 12\.)", text, re.S)
    if not m:
        m = re.search(r"## 11\..*?(?=\n## 12\.)", text, re.S)
    if not m:
        raise SystemExit("stage-5 §11 'Worked Rule Examples' not found")
    section_start = _line_of(text, m.start())
    section_end = _line_of(text, m.end())
    outdir = FIXTURES / "rules" / "stage5"
    outdir.mkdir(parents=True, exist_ok=True)
    files: list[dict] = []
    seen: set[str] = set()
    for fb in YAML_FENCE.finditer(m.group(0)):
        obj = yaml.safe_load(fb.group(1))
        rule_id = str((obj or {}).get("id") or f"rule_{len(files) + 1:03d}")
        name = _slug(rule_id)
        base = name
        n = 2
        while name in seen:
            name = f"{base}_{n}"
            n += 1
        seen.add(name)
        path = outdir / f"{name}.yaml"
        _dump(path, obj)
        files.append(
            {
                "file": f"rules/stage5/{name}.yaml",
                "source_line_start": _line_of(text, m.start() + fb.start()),
                "source_line_end": _line_of(text, m.start() + fb.end()),
                "id": obj.get("id"),
                "kind": obj.get("kind"),
            }
        )
    manifest = {
        "corpus": "stage5_rules",
        "count": len(files),
        "source_doc": "research/stage-5-dynamic-rule-engine.md",
        "source_sha256": _sha256(src),
        "source_section": "## 11. Worked Rule Examples",
        "source_section_line_start": section_start,
        "source_section_line_end": section_end,
        "schema": "rule_schema.json",
        "files": files,
    }
    return files, manifest


# ---------------------------------------------------------------------------
# Stage-3 §12.4 AF rules (wrapped into sentinel-rule/v1 exactly as
# research/work/_stage7_work/validate_examples.py wraps them)
# ---------------------------------------------------------------------------
def wrap_af_rule(rule: dict) -> dict:
    return {
        "schema": "sentinel-rule/v1",
        "id": rule.get("id"),
        "kind": "artifact",
        "source": "native",
        "title": rule.get("title", ""),
        "severity": "LOW",
        "enabled": True,
        **{k: v for k, v in rule.items() if k in ("when", "emit", "severity_hint", "attribution")},
    }


def extract_stage3_af_rules() -> tuple[list[dict], dict]:
    src = ROOT / "research" / "stage-3-ingestion-and-artifact-triage.md"
    text = src.read_text(encoding="utf-8")
    m = re.search(r"### 12\.4 Fact-to-finding rules.*?(?=\n### 12\.5)", text, re.S)
    if not m:
        raise SystemExit("stage-3 §12.4 'Fact-to-finding rules' not found")
    section_start = _line_of(text, m.start())
    section_end = _line_of(text, m.end())
    fb = YAML_FENCE.search(m.group(0))
    if not fb:
        raise SystemExit("stage-3 §12.4 has no yaml block")
    af_doc = yaml.safe_load(fb.group(1)) or {}
    rules = af_doc.get("rules", [])
    outdir = FIXTURES / "rules" / "stage3_af"
    outdir.mkdir(parents=True, exist_ok=True)
    files: list[dict] = []
    seen: set[str] = set()
    block_line = _line_of(text, m.start() + fb.start())
    for rule in rules:
        wrapped = wrap_af_rule(rule)
        rule_id = str(rule.get("id") or f"af_{len(files) + 1:03d}")
        name = _slug(rule_id)
        base = name
        n = 2
        while name in seen:
            name = f"{base}_{n}"
            n += 1
        seen.add(name)
        path = outdir / f"{name}.yaml"
        _dump(path, wrapped)
        files.append(
            {
                "file": f"rules/stage3_af/{name}.yaml",
                "source_line_start": block_line,
                "source_line_end": block_line,
                "id": rule.get("id"),
                "kind": "artifact",
                "wrapped_from": "stage-3 §12.4 artifact_finding_rules.yaml",
            }
        )
    manifest = {
        "corpus": "stage3_af_rules",
        "count": len(files),
        "source_doc": "research/stage-3-ingestion-and-artifact-triage.md",
        "source_sha256": _sha256(src),
        "source_section": "### 12.4 Fact-to-finding rules",
        "source_section_line_start": section_start,
        "source_section_line_end": section_end,
        "schema": "rule_schema.json",
        "files": files,
    }
    return files, manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="do not write; exit non-zero if committed fixtures are stale",
    )
    args = parser.parse_args(argv)

    global WRITE
    WRITE = not args.check

    corpora = {
        "canonical_events": extract_canonical_events(),
        "stage5_rules": extract_stage5_rules(),
        "stage3_af_rules": extract_stage3_af_rules(),
    }

    # prune fixtures that no longer correspond to a source block
    keep_by_dir: dict[str, set[str]] = {}
    for _, man in corpora.values():
        for f in man["files"]:
            d, _, base = f["file"].partition("/")
            keep_by_dir.setdefault(d, set()).add(base)
    for d, keep in keep_by_dir.items():
        outdir = FIXTURES / d
        if not outdir.is_dir():
            continue
        for existing in sorted(outdir.glob("*.yaml")):
            if existing.name not in keep:
                if args.check:
                    print(f"STALE: {existing} has no source block", file=sys.stderr)
                    return 1
                existing.unlink()

    manifest = {
        "version": 1,
        "generated_by": "tools/extract_examples.py",
        "corpora": {name: man for name, (_, man) in corpora.items()},
    }
    manifest_path = FIXTURES / "manifest.json"
    new_manifest = json.dumps(manifest, indent=2, ensure_ascii=False) + "\n"

    drift: list[str] = []
    for name, (files, man) in corpora.items():
        if man["count"] != EXPECTED_COUNTS[name]:
            drift.append(
                f"{name}: extracted {man['count']} fixtures, expected {EXPECTED_COUNTS[name]}"
            )
        for f in files:
            p = FIXTURES / f["file"]
            if not p.exists():
                drift.append(f"{name}: missing {f['file']}")
    if args.check:
        current = (
            manifest_path.read_text(encoding="utf-8") if manifest_path.exists() else ""
        )
        if current != new_manifest:
            drift.append("tests/fixtures/manifest.json is stale")
        for d, keep in keep_by_dir.items():
            outdir = FIXTURES / d
            if outdir.is_dir():
                for existing in sorted(outdir.glob("*.yaml")):
                    if existing.name not in keep:
                        drift.append(f"{d}/{existing.name} is orphaned")
        if drift:
            for line in drift:
                print(f"STALE: {line}", file=sys.stderr)
            print("re-run: python tools/extract_examples.py", file=sys.stderr)
            return 1
        print("fixtures are up to date")
        return 0

    manifest_path.write_text(new_manifest, encoding="utf-8", newline="\n")
    for name, (files, man) in corpora.items():
        print(f"{name}: {man['count']} fixtures (source sha256 {man['source_sha256'][:12]}…)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
