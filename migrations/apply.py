from __future__ import annotations

"""Apply migrations (schema.sql baseline) via the migrator role."""
from pathlib import Path

from alembic import command
from alembic.config import Config

_MIGRATIONS_DIR = Path(__file__).resolve().parent


def apply(url: str) -> None:
    cfg = Config(str(_MIGRATIONS_DIR / "alembic.ini"))
    cfg.set_main_option("script_location", str(_MIGRATIONS_DIR))
    if url:
        cfg.set_main_option("sqlalchemy.url", url)
    command.upgrade(cfg, "head")


if __name__ == "__main__":
    import sys

    from sentinel_core.config import load_settings

    if len(sys.argv) > 1:
        url = sys.argv[1]
    else:
        url = load_settings().database_migrator_url
    apply(url)
    print("migrations applied")

