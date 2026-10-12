"""M2 exit criteria → gate map: the mapping in spec §9b must stay true.

The spec's ``#### 9b. M2 exit criteria → machine gate`` table is the single
place that says *which* committed artefact enforces *which* §9 M2 exit
criterion, and `.github/workflows/ci.yml` is what actually runs them. This
module parses that table and fails when any of the four drifts apart:

  * a criterion disappears from (or is reordered in) the M2 milestone row,
  * a named gate is renamed, moved or deleted,
  * CI stops running the directory a gate lives in,
  * ①-④ stop naming the runnable exit gate, ⑤ stops naming the conformance
    oracle, or ⑥ stops naming the scored-run gate and drifts back toward the
    deferral it replaced (the register entry M2-A6 is checked for RESOLVED).

Gate cells are parsed with the same rules as ``test_m0_exit_gates.py``: a
backticked span counts as a path when it is all path characters and its last
segment contains a dot, which is why prose (``python -m tests.m2_drill``, the
bench tool) never registers as a gate.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = ROOT / "research" / "SENTINEL_IMPLEMENTATION_SPEC.md"
CI = ROOT / ".github" / "workflows" / "ci.yml"
REGISTER = ROOT / "research" / "DEVIATION_REGISTER.md"

GATE_HEADING = "#### 9b. M2 exit criteria → machine gate"
CIRCLED = "①②③④⑤⑥"
RUNNABLE_GATE = "tests/integration/test_m2_exit.py"
CONFORMANCE_GATE = "tests/integration/test_conformance_oracle.py"
SCORING_GATE = "tests/scoring/test_unsw_nb15_scoring.py"

#: Which gate each exit must name, in §9b order.
GATES_BY_EXIT = {
    "①": RUNNABLE_GATE,
    "②": RUNNABLE_GATE,
    "③": RUNNABLE_GATE,
    "④": RUNNABLE_GATE,
    "⑤": CONFORMANCE_GATE,
    "⑥": SCORING_GATE,
}

_PATHISH = re.compile(r"^[\w./-]+$")


def _lines() -> list[str]:
    return SPEC.read_text(encoding="utf-8").splitlines()


def m2_row() -> str:
    rows = [ln for ln in _lines() if ln.startswith("| **M2")]
    assert len(rows) == 1, f"expected one M2 milestone row, found {len(rows)}"
    return rows[0]


def gate_table() -> list[tuple[str, str, list[str]]]:
    """(exit cell, gate cell, gate paths) for each row of the §9b table."""
    lines = _lines()
    start = lines.index(GATE_HEADING)
    out: list[tuple[str, str, list[str]]] = []
    for ln in lines[start + 1 :]:
        if ln.startswith("#"):
            break
        if not ln.startswith("|"):
            continue
        cells = [c.strip() for c in ln.strip().strip("|").split("|")]
        if len(cells) != 2 or set(cells[0]) <= set("-: ") or cells[0] == "Exit":
            continue
        exit_cell, gate_cell = cells
        spans = re.findall(r"`([^`]+)`", gate_cell)
        paths = [s for s in spans if _PATHISH.match(s) and "." in s.rsplit("/", 1)[-1]]
        out.append((exit_cell, gate_cell, paths))
    return out


def test_m2_milestone_row_still_lists_six_exit_criteria():
    row = m2_row()
    positions = [row.index(c) for c in CIRCLED]
    assert positions == sorted(positions), f"exit markers out of {positions}"
    assert all(row.count(c) == 1 for c in CIRCLED), row[:200]


def test_gate_table_covers_every_exit_criterion():
    table = gate_table()
    assert len(table) == len(CIRCLED), f"expected 6 rows, got {len(table)}"
    for expected, (exit_cell, _gate_cell, paths) in zip(CIRCLED, table):
        assert exit_cell.startswith(expected), (expected, exit_cell[:60])
        assert paths, f"exit {expected}: gate cell names no files"


def test_every_named_gate_exists():
    missing: list[str] = []
    for exit_cell, _gate_cell, paths in gate_table():
        for rel in paths:
            if not (ROOT / rel).exists():
                missing.append(f"{exit_cell[:4]} -> {rel}")
    assert missing == [], f"gates referenced by spec §9b that do not exist: {missing}"


def test_gated_exits_name_the_m2_gate():
    """Every exit must name exactly its own gate module, ①-⑥."""
    table = gate_table()
    for expected, (_exit_cell, _gate_cell, paths) in zip(CIRCLED, table):
        assert paths == [GATES_BY_EXIT[expected]], (expected, paths)


def test_exit_six_gate_is_real_and_its_deferral_is_resolved():
    """⑥ used to defer to the register; the gate replaced the deferral."""
    table = gate_table()
    exit_cell, gate_cell, paths = table[5]
    assert exit_cell.startswith("⑥")
    assert paths == [SCORING_GATE], paths
    assert "deferred" not in gate_cell.lower(), gate_cell
    register = REGISTER.read_text(encoding="utf-8")
    assert "### M2-A6 - RESOLVED:" in register, (
        "exit⑥ is gated now: M2-A6 must record the resolution"
    )
    assert (ROOT / SCORING_GATE).exists()


def test_ci_workflow_runs_every_gate_directory():
    """Each gate's directory must be selected by some CI job."""
    text = CI.read_text(encoding="utf-8")
    selected: set[str] = set()
    for _exit_cell, _gate_cell, paths in gate_table():
        for rel in paths:
            if rel.startswith("tests/"):
                directory = "/".join(rel.split("/")[:2])
                assert re.search(rf"(?<![\w/]){re.escape(directory)}(?![\w-])", text), (
                    f"CI never selects {directory} but §9b routes a gate there"
                )
                selected.add(directory)
            elif rel.startswith("tools/"):
                assert rel in text, f"CI never invokes {rel} named by §9b"
            else:
                readers = [
                    str(p.relative_to(ROOT)).replace("\\", "/")
                    for p in (ROOT / "tests").rglob("*.py")
                    if rel in p.read_text(encoding="utf-8")
                ]
                assert readers, f"{rel} is named by §9b but no test reads it"
    assert "tests/integration" in selected
    assert "tests/scoring" in selected, "CI must run the scored-run gate"
