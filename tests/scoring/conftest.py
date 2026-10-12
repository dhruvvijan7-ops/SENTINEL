"""M2 exit ⑥ harness (spec §9b row ⑥, §6.3a detection scoring).

Two rules of the gate:

* **The corpus is out-of-tree** (D6-009): `.corpus/unsw-nb15/` is gitignored
  and sha-pinned. Tests that need it **fail — never skip —** when it is
  missing, and the failure message carries the fetch command.
* **The pack and the mapper are corpus-free**: `test_unsw_nb15_pack.py` and
  `test_unsw_nb15_mapping.py` run in every job, with no network and no data.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.evaluate_unsw_nb15 import ScoringError, load_pack, run  # noqa: E402


@pytest.fixture(scope="session")
def pack() -> list[tuple[str, dict[str, Any], list[dict[str, str]]]]:
    """The scored rule pack, or a hard failure naming the broken rule."""
    try:
        return load_pack()
    except ScoringError as exc:
        pytest.fail(f"scoring pack is not loadable: {exc}")


@pytest.fixture(scope="session")
def scoring_run() -> dict[str, Any]:
    """Both splits, schema-validated, scored once per session.

    Runs `tools/evaluate_unsw_nb15.py`'s `run()` so the gate and the CLI are
    the same code path, and writes the evidence report to the same
    `research/work/_stage6_work/bench/` path the audit cites.
    """
    try:
        return run(splits=("train", "test"), validate=True)
    except ScoringError as exc:
        pytest.fail(
            f"UNSW-NB15 scored run failed: {exc}\n"
            "If the corpus is missing: python tools/corpus_fetch.py"
        )
