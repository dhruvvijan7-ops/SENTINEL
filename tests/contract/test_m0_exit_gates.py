"""M0 exit criteria → gate map: the mapping in spec §9a must stay true.

The spec's ``#### 9a. M0 exit criteria → machine gate`` table is the single
place that says *which* committed artefact enforces *which* §9 M0 exit
criterion, and `.github/workflows/ci.yml` is what actually runs them. This
module parses that table and fails when any of the three drifts apart:

  * a criterion disappears from the M0 milestone row,
  * a named gate is renamed, moved or deleted,
  * CI stops running the directory a gate lives in.
"""
from __future__ import annotations

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
SPEC = ROOT / "research" / "SENTINEL_IMPLEMENTATION_SPEC.md"
CI = ROOT / ".github" / "workflows" / "ci.yml"

GATE_HEADING = "#### 9a. M0 exit criteria \u2192 machine gate"
CIRCLED = "①②③④⑤"

_PATHISH = re.compile(r"^[\w./-]+$")


def _lines() -> list[str]:
    return SPEC.read_text(encoding="utf-8").splitlines()


def m0_row() -> str:
    rows = [ln for ln in _lines() if ln.startswith("| **M0")]
    assert len(rows) == 1, f"expected one M0 milestone row, found {len(rows)}"
    return rows[0]


def gate_table() -> list[tuple[str, list[str]]]:
    """(exit cell, gate paths) for each row of the §9a table."""
    lines = _lines()
    start = lines.index(GATE_HEADING)
    out: list[tuple[str, list[str]]] = []
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
        out.append((exit_cell, paths))
    return out


def test_m0_milestone_row_still_lists_five_exit_criteria():
    row = m0_row()
    positions = [row.index(c) for c in CIRCLED]
    assert positions == sorted(positions), f"exit markers out of order: {positions}"
    assert all(row.count(c) == 1 for c in CIRCLED), row[:200]


def test_gate_table_covers_every_exit_criterion():
    table = gate_table()
    assert len(table) == len(CIRCLED), f"expected 5 rows, got {len(table)}"
    for expected, (exit_cell, paths) in zip(CIRCLED, table):
        assert exit_cell.startswith(expected), (expected, exit_cell[:60])
        assert paths, f"exit {expected}: gate cell names no files"


def test_every_named_gate_exists():
    missing: list[str] = []
    for exit_cell, paths in gate_table():
        for rel in paths:
            if not (ROOT / rel).exists():
                missing.append(f"{exit_cell[:4]} -> {rel}")
    assert missing == [], f"gates referenced by spec §9a that do not exist: {missing}"


def test_ci_workflow_runs_every_gate_directory():
    """Each gate's directory must be selected by some CI job."""
    text = CI.read_text(encoding="utf-8")
    selected: set[str] = set()
    for _exit_cell, paths in gate_table():
        for rel in paths:
            if rel.startswith("tests/"):
                # tests/contract/… is selected by the space-separated argument
                # `pytest tests/contract tests/unit tests/tripwire` in ci.yml
                directory = "/".join(rel.split("/")[:2])
                assert re.search(rf"(?<![\w/]){re.escape(directory)}(?![\w-])", text), (
                    f"CI never selects {directory} but §9a routes a gate there"
                )
                selected.add(directory)
            else:
                # Data files (research/…) are consumed by a gate rather than
                # invoked by CI; tools/… are invoked directly by a job.
                if rel.startswith("tools/"):
                    assert rel in text, f"CI never invokes {rel} named by §9a"
                else:
                    readers = [
                        str(p.relative_to(ROOT)).replace("\\", "/")
                        for p in (ROOT / "tests").rglob("*.py")
                        if rel in p.read_text(encoding="utf-8")
                    ]
                    assert readers, (
                        f"{rel} is named by §9a but no test reads it"
                    )
    assert "tests/contract" in selected and "tests/integration" in selected


def test_ci_workflow_declares_the_jobs_described_in_the_spec():
    workflow = yaml.safe_load(CI.read_text(encoding="utf-8"))
    jobs = set(workflow["jobs"])
    assert jobs == {"contract", "schema", "integration", "scoring"}, sorted(jobs)
    runs = " ".join(
        str(step.get("run", ""))
        for job in workflow["jobs"].values()
        for step in job["steps"]
    )
    for fragment in ("tests/contract", "tools/schema_lint.py", "tests/integration"):
        assert fragment in runs, f"no CI step runs {fragment}"
