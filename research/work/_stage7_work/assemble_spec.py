"""Stage 7 — assemble SENTINEL_IMPLEMENTATION_SPEC.md.

Full verbatim splice of stage bodies; authored §1-§3, §9-§12 indexes, §13-§15.
Heading demotion is code-fence aware (YAML `#` comments inside fences are NOT demoted).
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WORK = Path(__file__).resolve().parent
OUT = ROOT / "SENTINEL_IMPLEMENTATION_SPEC.md"

STAGE_SOURCES = {
    4: ("stage-4-threat-model-and-windows-sandbox.md", "§4 — Threat model, sandbox, isolation"),
    2: ("stage-2-canonical-event-and-mappings.md", "§5 — Canonical event and source mappings"),
    3: ("stage-3-ingestion-and-artifact-triage.md", "§6 — Ingestion, parser interface, and artifact triage"),
    5: ("stage-5-dynamic-rule-engine.md", "§7 — Dynamic rule engine"),
    6: ("stage-6-platform-storage-jobs-api-testing-release.md", "§8 — Platform: storage, jobs, evidence, release"),
}


def demote_headings(text: str, levels: int = 1) -> str:
    """Demote ATX headings by `levels`, skipping lines inside code fences."""
    out: list[str] = []
    in_fence = False
    fence_marker = ""
    for line in text.splitlines(keepends=True):
        stripped = line.lstrip()
        if stripped.startswith("```") or stripped.startswith("~~~"):
            if not in_fence:
                in_fence = True
                fence_marker = stripped[:3]
            elif stripped.startswith(fence_marker):
                in_fence = False
            out.append(line)
            continue
        if not in_fence:
            m = re.match(r"^(#{1,6})(\s+)", line)
            if m:
                hashes = m.group(1)
                new_level = min(len(hashes) + levels, 6)
                line = "#" * new_level + m.group(2) + line[m.end():]
        out.append(line)
    return "".join(out)


def splice_stage(stage_no: int) -> str:
    filename, title = STAGE_SOURCES[stage_no]
    body = (ROOT / filename).read_text(encoding="utf-8")
    demoted = demote_headings(body, levels=1)
    header = (
        f"# {title}\n\n"
        f"> Verbatim splice of `{filename}`. Headings demoted one level; "
        f"code fences, decision blocks, and matrices preserved as authored. "
        f"Own section numbering inside the body is preserved.\n\n"
    )
    return header + demoted + "\n\n---\n\n"


def contract_index_section(number: int, title: str, filename: str, role: str, extra: str = "") -> str:
    p = ROOT / filename
    size = p.stat().st_size if p.exists() else 0
    lines = 0
    if p.exists():
        lines = sum(1 for _ in p.open(encoding="utf-8", errors="replace"))
    parts = [
        f"# {number} — {title}",
        "",
        f"**Delivered file:** `{filename}` ({lines} lines, {size} bytes). "
        f"Machine-normative contract; not inlined here (see §1.4 / §15.1).",
        "",
        role,
        "",
    ]
    if extra:
        parts.append(extra)
        parts.append("")
    parts.append(f"Full text: `{filename}` in the repository root.")
    parts.append("")
    parts.append("---")
    parts.append("")
    return "\n".join(parts)


def openapi_index_extra() -> str:
    p = ROOT / "openapi.yaml"
    if not p.exists():
        return ""
    try:
        import yaml

        spec = yaml.safe_load(p.read_text(encoding="utf-8"))
        paths = sorted(spec.get("paths", {}))
        schemas = sorted(spec.get("components", {}).get("schemas", {}))
        ops = []
        for path in paths:
            for method, op in spec["paths"][path].items():
                if method in ("get", "post", "put", "patch", "delete"):
                    oid = op.get("operationId", "")
                    ops.append(f"| `{method.upper()} {path}` | `{oid}` |")
        return (
            "### 9.1 Path index (from openapi.yaml)\n\n"
            "| Method + path | operationId |\n|---|---|\n" + "\n".join(ops) +
            "\n\n### 9.2 Component schemas\n\n"
            + ", ".join(f"`{s}`" for s in schemas)
            + f"\n\nTotal paths: {len(paths)}. OpenAPI version: {spec.get('openapi', '?')}."
        )
    except Exception as exc:  # noqa: BLE001
        return f"(path index unavailable: {exc})"


def ddl_index_extra() -> str:
    p = ROOT / "schema.sql"
    if not p.exists():
        return ""
    text = p.read_text(encoding="utf-8")
    tables = re.findall(r"CREATE TABLE (\w+) \(", text)
    rls = re.findall(r"ALTER\s+TABLE\s+([\w]+)\s+ENABLE\s+ROW\s+LEVEL\s+SECURITY", text, re.I)
    return (
        "### 10.1 Table index (from schema.sql)\n\n"
        + ", ".join(f"`{t}`" for t in tables)
        + f"\n\nTotal tables: {len(tables)}. RLS enabled on {len(rls)} tables."
    )


def main() -> None:
    authored_front = (WORK / "authored_s1_s3.md").read_text(encoding="utf-8")
    authored_back = (WORK / "authored_s13_s15.md").read_text(encoding="utf-8")

    chunks: list[str] = []
    # Title banner
    chunks.append(
        "# SENTINEL — Implementation Specification\n\n"
        "Merged from Stages 1–6 · assembled 2026-10-10 · Stage 7\n\n"
        "Conflicts: see `consistency_report.md` and §13. "
        "No silent conflict resolution. No summarised stage sections.\n\n"
        "---\n\n"
    )
    # Authored §1–§3
    chunks.append(authored_front.rstrip() + "\n\n---\n\n")

    # Stage splices §4–§8
    for stage_no in (4, 2, 3, 5, 6):
        chunks.append(splice_stage(stage_no))

    # §9–§12 contract file indexes
    chunks.append(
        contract_index_section(
            9,
            "HTTP API contract",
            "openapi.yaml",
            "OpenAPI 3.1.0 contract for the Sentinel HTTP surface. "
            "Implementers serve this file; the index below is convenience only. "
            "Known conflicts with stage bodies: upload path naming (C-4), "
            "Finding vs sentinel-finding/v1 (C-2), source.format xml omission (C-8), "
            "host free-form (C-9), Rule projection gaps (C-10), config_hash encoding (C-7).",
            openapi_index_extra(),
        )
    )
    chunks.append(
        contract_index_section(
            10,
            "Storage DDL contract",
            "schema.sql",
            "PostgreSQL DDL for the Sentinel platform. 21 tables, RLS on all "
            "tenant-scoped tables, CHECK constraints for enums. "
            "Known conflicts: missing findings.author (C-6), missing "
            "level_original on findings (C-3b), missing events.classification "
            "(C-13), rule_run metrics mismatch (C-5), ioc_pack DEFAULT 'active' (C-11), "
            "config_hash bytea (C-7).",
            ddl_index_extra(),
        )
    )
    chunks.append(
        contract_index_section(
            11,
            "Canonical event JSON Schema",
            "canonical_event_v1.schema.json",
            "Machine-normative schema for `canonical-event/v1`. "
            "Validates all 121 Stage-2 examples. Enforces bare-null policy "
            "via `$defs.time.allOf` + `$defs.state_object` (INV-10 PASS). "
            "host is structured (conflicts with OpenAPI free-form host, C-9); "
            "source.format includes `xml` (conflicts with OpenAPI, C-8).",
        )
    )
    chunks.append(
        contract_index_section(
            12,
            "Rule JSON Schema",
            "rule_schema.json",
            "Machine-normative schema for `sentinel-rule/v1`. "
            "Validates 25/25 Stage-5 worked examples and 5/5 Stage-3 AF rules. "
            "OpenAPI `RuleDocument` is free-form and does not $ref this file (C-10).",
        )
    )

    # Authored §13–§15
    chunks.append(authored_back.rstrip() + "\n")

    text = "".join(chunks)
    # Normalize trailing whitespace / ensure single trailing newline
    text = text.rstrip() + "\n"
    OUT.write_text(text, encoding="utf-8")
    lines = text.count("\n") + (0 if text.endswith("\n") else 1)
    print(f"wrote {OUT} ({lines} lines, {len(text)} chars)")

    # Acceptance: required final lines
    tail = text.rstrip().splitlines()
    last_two = [ln.strip().lower() for ln in tail[-6:] if ln.strip()]
    joined = " ".join(last_two)
    assert "open decisions requiring human input" in joined, "missing final open-decisions line"
    assert "what i could not verify" in joined, "missing final could-not-verify line"
    print("acceptance: final lines present")

    # Acceptance: heading order of top-level sections
    tops = re.findall(r"^# (§\d+|[0-9]+) —", text, re.M)
    # Normalize
    order = []
    for t in tops:
        if t.startswith("§"):
            order.append(int(t[1:]))
        else:
            order.append(int(t))
    print("top-level sections:", order)
    expected = list(range(1, 16))
    # §1..§15 may appear as "§1 —" from authored and "9 —" from contract sections
    # Collect in document order unique ascending
    seen = []
    for n in order:
        if n not in seen:
            seen.append(n)
    print("unique section numbers in order:", seen)
    assert seen == expected, f"section order mismatch: {seen} != {expected}"
    print("acceptance: section order 1..15")

    # Acceptance: stage bodies present
    for marker in (
        "Verbatim splice of `stage-4",
        "Verbatim splice of `stage-2",
        "Verbatim splice of `stage-3",
        "Verbatim splice of `stage-5",
        "Verbatim splice of `stage-6",
    ):
        assert marker in text, f"missing splice marker: {marker}"
    print("acceptance: all five stage splices present")

    # Acceptance: no silent conflict resolution — §13 table exists with C- rows
    assert text.count("| C-") >= 16, "conflict table incomplete"
    print("acceptance: conflict table rows present")


if __name__ == "__main__":
    main()
