#!/usr/bin/env python3
"""Stage-7 audit: extract DECISIONS / OPEN_QUESTIONS / NOT_VERIFIED from all
stage documents, detect id collisions and status conflicts, and emit a
machine-readable inventory under _stage7_work/.

Tolerant of informal YAML (unquoted colons in titles, backtick-quoted
scalars) by falling back to a line-oriented parser when safe_load fails.
NOT_VERIFIED may be a YAML block OR a markdown table — both are counted.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "_stage7_work"

STAGE_FILES = {
    "stage-1": ROOT / "stage-1-landscape-and-rule-engine-decision.md",
    "stage-2": ROOT / "stage-2-canonical-event-and-mappings.md",
    "stage-3": ROOT / "stage-3-ingestion-and-artifact-triage.md",
    "stage-4": ROOT / "stage-4-threat-model-and-windows-sandbox.md",
    "stage-5": ROOT / "stage-5-dynamic-rule-engine.md",
    "stage-6": ROOT / "stage-6-platform-storage-jobs-api-testing-release.md",
}

DECISION_HEADING = re.compile(r"^#{2,3}\s*(?:[\d.]+\s+)?DECISIONS?\b.*$", re.M)
OPEN_HEADING = re.compile(r"^#{2,3}\s*(?:[\d.]+\s+)?OPEN[_ ]QUESTIONS?\b.*$", re.M)
NV_HEADING = re.compile(r"^#{2,3}\s*(?:[\d.]+\s+)?NOT[_ ]VERIFIED\b.*$", re.M)
YAML_FENCE = re.compile(r"```yaml\n(.*?)```", re.S)


def next_fence(text: str, pos: int) -> tuple[str | None, int]:
    """Return (yaml_body, end_pos) of the next fenced yaml block after pos."""
    fence = YAML_FENCE.search(text, pos)
    if not fence:
        return None, pos
    # ensure it's the *next* content, not far away (allow prose in between)
    return fence.group(1), fence.end()


def tolerant_items(block: str) -> list[dict]:
    """Parse a YAML list of dicts, tolerating informal YAML.

    Strategy: try safe_load; on failure, split on top-level '- id:' items and
    parse each item independently after backtick-stripping and colon-quoting
    of the first ': ' in unquoted scalar lines.
    """
    def attempt(s: str):
        return yaml.safe_load(s)

    try:
        data = attempt(block)
        if isinstance(data, dict):
            key = next(iter(data))
            items = data[key] or []
            if isinstance(items, list):
                return [i if isinstance(i, dict) else {"value": i} for i in items]
        return []
    except Exception:  # noqa: BLE001
        pass

    # fallback: line-oriented split on "- id:"
    items: list[dict] = []
    lines = block.splitlines()
    current: list[str] = []
    for line in lines:
        if re.match(r"^\s*-\s+id:\s*", line):
            if current:
                items.append(_parse_item(current))
            current = [line]
        elif current:
            current.append(line)
    if current:
        items.append(_parse_item(current))
    return items


def _parse_item(lines: list[str]) -> dict:
    """Very small key: value parser for one decision/question item."""
    out: dict = {}
    # de-indent to a common base
    stripped = [re.sub(r"^\s+", "", l) for l in lines]
    for i, line in enumerate(stripped):
        if line.startswith("- "):
            line = line[2:]
        m = re.match(r"^([A-Za-z_][\w-]*):\s*(.*)$", line)
        if not m:
            continue
        key, val = m.group(1), m.group(2).strip()
        if val in (">-", "|", ">", "|-"):
            # folded/literal scalar: gather following indented lines
            body = []
            for j in range(i + 1, len(stripped)):
                if re.match(r"^[A-Za-z_][\w-]*:\s*", stripped[j]) or stripped[j].startswith("- "):
                    break
                body.append(stripped[j])
            out[key] = " ".join(x.strip() for x in body if x.strip())
        elif val.startswith("[") and val.endswith("]"):
            inner = val[1:-1].strip()
            out[key] = [x.strip().strip("'\"") for x in inner.split(",") if x.strip()] if inner else []
        else:
            out[key] = val.strip("'\"`")
    return out


def count_markdown_rows(text_after_heading: str) -> tuple[int, list[str]]:
    """Count markdown table data rows. Returns (row_count, non_numeric_first_cells).

    A markdown table's first `|` row is always the header (its first cell may
    be 'Id', 'ID', '#', ...). We skip it plus the `|---|` separator row, so
    header rows are never counted as items (D8-08 fix).
    """
    row_count = 0
    ids: list[str] = []
    in_table = False
    header_skipped = False
    for line in text_after_heading.splitlines():
        if not line.startswith("|"):
            if in_table and line.strip():
                break  # table ended
            continue
        in_table = True
        if re.match(r"^\|\s*-+", line):
            continue  # separator
        if not header_skipped:
            header_skipped = True
            continue  # first row is the header (whatever its label)
        if re.match(r"^\|\s*#\s*\|", line):
            continue  # numbered header (legacy guard)
        row_count += 1
        cells = [c.strip() for c in line.strip("|").split("|")]
        if cells and cells[0] and cells[0] != "#" and not cells[0].isdigit():
            ids.append(cells[0])
    return row_count, ids


def main() -> int:
    inventory: dict[str, dict] = {}
    all_ids: dict[str, list[str]] = {}
    parse_errors: list[str] = []

    for stage, path in STAGE_FILES.items():
        text = path.read_text(encoding="utf-8")
        entry: dict = {"file": path.name, "lines": text.count("\n") + 1}

        for label, heading in (
            ("decisions", DECISION_HEADING),
            ("open_questions", OPEN_HEADING),
            ("not_verified", NV_HEADING),
        ):
            m = heading.search(text)
            if not m:
                entry[label] = None
                entry[f"{label}_heading_line"] = -1
                entry[f"{label}_count"] = 0
                entry[f"{label}_format"] = "absent"
                continue
            line_no = text.count("\n", 0, m.start()) + 1
            entry[f"{label}_heading_line"] = line_no
            # look ahead 500 chars for a yaml fence; else treat as table
            window = text[m.end(): m.end() + 500]
            fm = re.search(r"```yaml\n(.*?)```", text[m.end():], re.S)
            # ensure the fence is close (before another ## heading)
            next_h = re.search(r"\n## ", text[m.end():])
            fence_ok = fm and (not next_h or fm.start() < next_h.start() + 2000)
            if fm and fence_ok and fm.start() < 3000:
                block = fm.group(1)
                entry[f"{label}_format"] = "yaml"
                # try strict, then tolerant
                try:
                    data = yaml.safe_load(block)
                    if isinstance(data, dict):
                        key = next(iter(data))
                        items = data.get(key) or []
                        items = [i if isinstance(i, dict) else {"value": i} for i in items]
                        parser_name = "safe_load"
                        yaml_key = key
                    elif isinstance(data, list):
                        items = [i if isinstance(i, dict) else {"value": i} for i in data]
                        parser_name = "safe_load_list"
                        yaml_key = None
                    else:
                        items = []
                        parser_name = "safe_load_empty"
                        yaml_key = None
                    entry[label] = {"yaml_key": yaml_key, "items": items, "parser": parser_name}
                except Exception as exc:  # noqa: BLE001
                    items = tolerant_items(block)
                    entry[label] = {"yaml_key": label, "items": items, "parser": "tolerant", "safe_load_error": str(exc)[:200]}
                    parse_errors.append(f"{stage}/{label}: safe_load failed ({str(exc)[:80]}), used tolerant parser ({len(items)} items)")
                entry[f"{label}_count"] = len(entry[label]["items"])
                for item in entry[label]["items"]:
                    iid = str(item.get("id", "")) if isinstance(item, dict) else ""
                    # ignore pure-numeric row numbers from markdown tables
                    if iid and not iid.isdigit():
                        all_ids.setdefault(iid, []).append(stage)
            else:
                # markdown table OR plain prose
                section = text[m.end():]
                # cut at next ## heading
                nh = re.search(r"\n## ", section)
                if nh:
                    section = section[: nh.start()]
                row_count, row_ids = count_markdown_rows(section)
                if row_count:
                    entry[label] = {
                        "yaml_key": None,
                        "items": ([{"id": r} for r in row_ids] if row_ids else [{"row": i} for i in range(1, row_count + 1)]),
                        "parser": "markdown_table",
                    }
                    entry[f"{label}_count"] = row_count
                    entry[f"{label}_format"] = "markdown_table"
                    for r in row_ids:
                        all_ids.setdefault(r, []).append(stage)
                else:
                    # numbered prose list, e.g. "1. **Q1 — …**" (stage-1 §8.2)
                    numbered = re.findall(r"^\s*\d+\.\s+\*\*(Q[\w-]+)", section, re.M)
                    if numbered:
                        entry[label] = {
                            "yaml_key": None,
                            "items": [{"id": q} for q in numbered],
                            "parser": "numbered_prose",
                        }
                        entry[f"{label}_count"] = len(numbered)
                        entry[f"{label}_format"] = "numbered_prose"
                        for q in numbered:
                            all_ids.setdefault(q, []).append(stage)
                    else:
                        # prose list — count bold claim groups or bullet items
                        bullets = re.findall(r"^\s*[-*]\s+", section, re.M)
                        bold_groups = re.findall(r"^\*\*[^*]+:\*\*", section, re.M)
                        entry[label] = None
                        entry[f"{label}_count"] = max(len(bullets), len(bold_groups), 0)
                        entry[f"{label}_format"] = "prose"
        inventory[stage] = entry

    collisions = {k: v for k, v in all_ids.items() if len(set(v)) > 1}

    status_by_id: dict[str, dict[str, str]] = {}
    for stage, entry in inventory.items():
        dec = entry.get("decisions")
        if not dec:
            continue
        for item in dec["items"]:
            if isinstance(item, dict) and item.get("id") and item.get("status"):
                status_by_id.setdefault(str(item["id"]), {})[stage] = str(item["status"])
    conflicts = {k: v for k, v in status_by_id.items() if len(set(v.values())) > 1}

    dec_yaml_files = sorted(str(p.name) for p in ROOT.glob("*_decisions.yaml"))

    report = {
        "inventory": inventory,
        "total_decisions": sum(max(e.get("decisions_count", 0), 0) for e in inventory.values()),
        "total_open_questions": sum(max(e.get("open_questions_count", 0), 0) for e in inventory.values()),
        "total_not_verified": sum(max(e.get("not_verified_count", 0), 0) for e in inventory.values()),
        "id_collisions": collisions,
        "status_conflicts": conflicts,
        "decision_yaml_files_on_disk": dec_yaml_files,
        "parse_notes": parse_errors,
    }
    out_path = OUT / "decision_inventory.json"
    out_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"wrote {out_path}")
    print(
        f"decisions={report['total_decisions']} "
        f"open_questions={report['total_open_questions']} "
        f"not_verified={report['total_not_verified']}"
    )
    print(f"collisions={len(collisions)} conflicts={len(conflicts)}")
    print(f"decision_yaml_files={dec_yaml_files}")
    for stage, e in inventory.items():
        print(
            f"  {stage}: D={e.get('decisions_count')}({e.get('decisions_format')}) "
            f"Q={e.get('open_questions_count')}({e.get('open_questions_format')}) "
            f"NV={e.get('not_verified_count')}({e.get('not_verified_format')})"
        )
    for pe in parse_errors:
        print("NOTE:", pe)
    return 0


if __name__ == "__main__":
    sys.exit(main())
