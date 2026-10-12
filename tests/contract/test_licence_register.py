"""M0 exit criterion (5): every DEPENDENCY licence row has a Verification-Log entry.

Three artefacts must agree:

  * the licence tables inside ``research/SENTINEL_IMPLEMENTATION_SPEC.md`` —
    §10.3 (Class column ``DEPENDENCY``), §3.3 (the runtime framework stack) and
    §7.1 (the freezer verdicts);
  * ``research/verification/DEPENDENCY_LICENCES.yaml``, the committed register;
  * the spec's own Verification Log tables (V1…V18, V-6-001…V-6-040), which are
    the evidence the exit criterion asks for.

A licence row can therefore not be added to the spec without a register entry
and a real V-id, and a register entry cannot cite a V-id that is not in the log.
"""
from __future__ import annotations

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
SPEC = ROOT / "research" / "SENTINEL_IMPLEMENTATION_SPEC.md"
REGISTER = ROOT / "research" / "verification" / "DEPENDENCY_LICENCES.yaml"

FRAME_HEADING = "#### 3.3 Framework choices (licence VERIFIED 2026-10-10)"
DEPS_HEADING = "#### 10.3 Third-party content obligations (carried from Stage-1 §2.3)"
TOOL_HEADING = "#### 7.1 Freezer (D6-003)"

_VID = re.compile(r"^V\d+$|^V-\d+-\d+[a-z]?$")

#: components whose name does not appear verbatim in any Verification-Log row.
COMPONENT_TOKEN = {
    "psycopg / psycopg-binary": "psycopg",
    "prometheus-client": "prometheus",
    "opentelemetry-sdk": "opentelemetry",
    "PostgreSQL 18": "postgresql",
}


def _lines() -> list[str]:
    return SPEC.read_text(encoding="utf-8").splitlines()


def _table(heading: str, ncols: int) -> list[tuple[int, list[str]]]:
    """Data rows of the first table under ``heading``, as (1-based line, cells).

    The column-header row and the ``|---|`` separator are both dropped, so the
    returned list is exactly the licence rows.
    """
    lines = _lines()
    start = lines.index(heading)
    rows: list[tuple[int, list[str]]] = []
    for i in range(start + 1, len(lines)):
        line = lines[i]
        if line.startswith("#"):
            break
        if not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) != ncols or set(cells[0]) <= set("-: "):
            continue  # separator row
        rows.append((i + 1, cells))
    return rows[1:]  # drop the column-header row


def _component(cell: str) -> str:
    return cell.split(" (")[0].replace("`", "").replace("**", "").strip()


def frame_rows() -> list[tuple[str, str]]:
    """(component, licence cell) for the §3.3 framework table."""
    return [(_component(c[0]), c[2]) for _, c in _table(FRAME_HEADING, 3)]


def deps_rows() -> list[tuple[str, str, str]]:
    """(component, SPDX cell, class cell) for the §10.3 obligations table."""
    return [(_component(c[0]), c[1], c[2]) for _, c in _table(DEPS_HEADING, 4)]


def tool_rows() -> list[tuple[str, str, str]]:
    """(component, licence cell, verdict cell) for the §7.1 freezer table."""
    return [(_component(c[0]), c[1], c[2]) for _, c in _table(TOOL_HEADING, 3)]


def dependency_rows() -> list[tuple[str, str, str]]:
    """The literal exit-(5) set: §10.3 rows whose Class is DEPENDENCY."""
    return [r for r in deps_rows() if r[2].startswith("DEPENDENCY")]


def verification_log() -> dict[str, str]:
    """Every V-id in the spec mapped to the text of its Verification-Log row."""
    out: dict[str, str] = {}
    for line in _lines():
        if not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if cells and _VID.match(cells[0]):
            out.setdefault(cells[0], " | ".join(cells[1:]))
    return out


def register() -> dict:
    return yaml.safe_load(REGISTER.read_text(encoding="utf-8"))


def _by_table(table: str) -> dict[str, dict]:
    return {
        e["component"]: e for e in register()["entries"] if e["table"] == table
    }


def _token(component: str) -> str:
    return COMPONENT_TOKEN.get(component, component.lower())


# ---------------------------------------------------------------------------
# Parsing must keep working — a broken parser would make every check vacuous
# ---------------------------------------------------------------------------
def test_spec_tables_parse_to_the_expected_shape():
    assert len(frame_rows()) == 11, frame_rows()
    assert len(deps_rows()) == 9, deps_rows()
    assert len(tool_rows()) == 3, tool_rows()
    assert len(dependency_rows()) == 5, dependency_rows()
    names = [c for c, _, _ in dependency_rows()]
    assert names == [
        "google-re2",
        "pyahocorasick",
        "pySigma",
        "PostgreSQL 18",
        "fastjsonschema",
    ], names


def test_verification_log_parses():
    log = verification_log()
    assert "V10" in log and "V-6-007" in log and "V-6-040" in log
    assert len(log) >= 40, f"only {len(log)} V-ids found"


# ---------------------------------------------------------------------------
# The exit criterion itself
# ---------------------------------------------------------------------------
def test_every_dependency_row_has_a_register_entry():
    rows = {c for c, _, _ in dependency_rows()}
    registered = set(_by_table("deps"))
    assert rows == registered, (
        f"spec-only: {sorted(rows - registered)}; "
        f"register-only: {sorted(registered - rows)}"
    )


def test_every_dependency_row_cites_an_existing_verification_entry():
    """Exit (5) verbatim: no DEPENDENCY row may ship without evidence."""
    log = verification_log()
    for component, _spdx, _cls in dependency_rows():
        entry = _by_table("deps")[component]
        vids = entry.get("verification") or []
        assert vids, (
            f"spec §10.3 marks {component!r} as DEPENDENCY but the register "
            "gives it no Verification-Log entry"
        )
        missing = [v for v in vids if v not in log]
        assert not missing, f"{component}: V-ids not in the spec log: {missing}"


def test_framework_and_tool_rows_are_registered_too():
    for table, rows in (("frame", frame_rows()), ("tool", tool_rows())):
        spec_names = {c for c, *_ in rows}
        registered = set(_by_table(table))
        assert spec_names == registered, (
            f"[{table}] spec-only: {sorted(spec_names - registered)}; "
            f"register-only: {sorted(registered - spec_names)}"
        )


def test_every_cited_verification_entry_exists_and_names_the_component():
    log = verification_log()
    for entry in register()["entries"]:
        component = entry["component"]
        vids = entry.get("verification") or []
        missing = [v for v in vids if v not in log]
        assert not missing, f"{component}: V-ids not in the spec log: {missing}"
        if not vids:
            continue
        token = _token(component)
        hits = [v for v in vids if token in log[v].lower()]
        assert hits, (
            f"{component}: none of {vids} actually mentions {token!r} — "
            f"cited {[(v, log[v][:90]) for v in vids]}"
        )


def test_register_licence_labels_appear_in_the_spec_cells():
    spec_text = SPEC.read_text(encoding="utf-8")
    cells = {
        **{c: lic for c, lic in frame_rows()},
        **{c: lic for c, lic, _v in tool_rows()},
        **{c: spdx for c, spdx, _cls in deps_rows()},
    }
    for entry in register()["entries"]:
        component = entry["component"]
        for label in entry.get("licence") or []:
            pattern = rf"\b{re.escape(label)}\b"
            if entry["table"] == "prose":
                assert re.search(pattern, spec_text, re.I), (
                    f"{component}: licence label {label!r} not found in the spec"
                )
            else:
                cell = cells.get(component)
                assert cell is not None, f"{component} is not a parsed table row"
                assert re.search(pattern, cell, re.I), (
                    f"{component}: licence label {label!r} not in spec cell "
                    f"{cell!r}"
                )


def test_usage_class_labels_match_the_spec():
    """The Class/Verdict column must still say what the register claims."""
    for component, _spdx, cls in dependency_rows():
        assert "DEPENDENCY" in cls, (component, cls)
    for component, _lic, verdict in tool_rows():
        claimed = _by_table("tool")[component]["usage_class"]
        assert claimed in verdict, (
            f"{component}: register says {claimed!r}, spec verdict is "
            f"{verdict!r}"
        )


def test_unverified_exemptions_are_named_and_still_unresolved():
    """A row may lack a V-id only if the spec itself declares it NOT_VERIFIED."""
    exempt = {e["component"] for e in register()["not_verified"]}
    spec_text = SPEC.read_text(encoding="utf-8")
    for name in exempt:
        assert name in spec_text, f"not_verified names {name!r}, absent from spec"

    seen_empty = set()
    for table in ("deps", "frame", "tool"):
        for component, entry in _by_table(table).items():
            if not (entry.get("verification") or []):
                seen_empty.add(component)
    assert seen_empty <= exempt, (
        f"rows with no Verification-Log entry that are not declared "
        f"NOT_VERIFIED: {sorted(seen_empty - exempt)}"
    )
    assert seen_empty == exempt, (
        f"stale not_verified exemptions (row now has evidence): "
        f"{sorted(exempt - seen_empty)}"
    )


def test_register_has_no_orphan_component_tokens():
    registered = {e["component"] for e in register()["entries"]}
    assert set(COMPONENT_TOKEN) <= registered, (
        f"COMPONENT_TOKEN covers rows that no longer exist: "
        f"{sorted(set(COMPONENT_TOKEN) - registered)}"
    )
