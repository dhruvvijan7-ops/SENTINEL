"""Integration-suite configuration.

Every test here needs a reachable PostgreSQL 18, so the whole directory is
tagged ``integration``.  CI selects on that marker (``pytest -m "not slow"``
in the integration job); the unit/contract job never collects this directory.
"""
from __future__ import annotations

import pytest


def pytest_collection_modifyitems(config, items):
    for item in items:
        if "/integration/" in str(item.path).replace("\\", "/"):
            item.add_marker(pytest.mark.integration)
