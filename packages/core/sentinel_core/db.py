from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator

import re

import psycopg


def normalize_dsn(dsn: str) -> str:
    """Accept SQLAlchemy-style driver URLs (postgresql+psycopg://) in config
    and hand psycopg a plain libpq DSN."""
    return re.sub(r"\+(?:psycopg\d?|asyncpg|pg8000)", "", dsn)


@contextmanager
def tx(dsn: str) -> Iterator[psycopg.Connection]:
    """One transaction on a fresh connection; commits on success, rolls back
    and closes on error.  No pool (M1): PostgreSQL handles short-lived
    connections; keeps the dependency surface to the pinned psycopg only."""
    with psycopg.connect(normalize_dsn(dsn)) as conn:
        yield conn


def ping(dsn: str) -> bool:
    try:
        with psycopg.connect(normalize_dsn(dsn), connect_timeout=3) as conn:
            conn.execute("SELECT 1")
        return True
    except Exception:
        return False
