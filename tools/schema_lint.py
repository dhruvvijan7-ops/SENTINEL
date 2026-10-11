#!/usr/bin/env python3
"""M0 exit criterion ① — ``schema.sql`` applies clean on PG 18 and does not
drift from the alembic migration chain.

Three checks, in order, any one of which fails the run:

1. **psql lint.** ``schema.sql`` is applied to a scratch database through
   ``psql -v ON_ERROR_STOP=1``.  Any line matching ``^(ERROR|WARNING|FATAL):``
   in psql's output fails the run.  This is the half of the "psql lint" exit
   criterion that did not exist before M0 — previously schema.sql was only ever
   executed through alembic, which swallows psql's own diagnostics.

2. **migration lint.** ``alembic upgrade head`` is run into a second scratch
   database, with the same output capture and the same failure rule.

3. **catalog diff.**  The two databases are compared catalogue-for-catalogue:
   relations, columns (type / nullability / default), PK/FK/CHECK/UNIQUE
   constraints, indexes (including partial), the RLS-enabled relation set, the
   full ``pg_policies`` set, and partition children with their bounds.  Any
   difference is drift between the rank-2 storage contract and the migration
   chain that is supposed to reproduce it — and nothing else in the tree
   catches it.

Scratch databases are dropped at the end (``--keep`` to retain them for
debugging).

Usage::

    python tools/schema_lint.py [--dsn postgresql://…] [--keep] [--json out.json]

The DSN must be an *admin* DSN (a role that can CREATE DATABASE).  It is taken
from ``--dsn``, else ``SENTINEL_LINT_DSN``, else the ``postgres``/``sentinel_dev_pw``
superuser in the dev docker-compose topology.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse, urlunparse

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_SQL = ROOT / "schema.sql"
MIGRATIONS_DIR = ROOT / "migrations"

DEFAULT_DSN = "postgresql://postgres:sentinel_dev_pw@127.0.0.1:54321/postgres"
DB_SCHEMA = "sentinel_lint_schema"
DB_MIGRATE = "sentinel_lint_migrate"

# psql writes its own diagnostics as "ERROR: …" / "WARNING: …" / "FATAL: …"
# at the start of a line; NOTICE is informational and is allowed.
_PSQL_DIAGNOSTIC = re.compile(r"^(ERROR|WARNING|FATAL):", re.M)

DOCKER_FALLBACK_CONTAINER = "sentinel-db"

# Relations alembic owns rather than the contract: `alembic_version` is
# bookkeeping created by the migration runner, present only in the migrated
# database, and is not part of the storage contract being compared.
IGNORED_RELATIONS = ("alembic_version",)


class LintError(RuntimeError):
    pass


def _run(cmd, **kwargs) -> subprocess.CompletedProcess:
    """subprocess.run pinned to UTF-8.

    schema.sql and the migration output contain non-ASCII (§, →).  On Windows
    the default locale encoding would re-encode the piped SQL as cp1252 and
    PostgreSQL would reject it with "invalid byte sequence for encoding UTF8".
    """
    kwargs.setdefault("capture_output", True)
    kwargs.setdefault("text", True)
    kwargs.setdefault("encoding", "utf-8")
    kwargs.setdefault("errors", "replace")
    return subprocess.run(cmd, **kwargs)


# ---------------------------------------------------------------------------
# DSN helpers
# ---------------------------------------------------------------------------
def _with_database(dsn: str, dbname: str) -> str:
    p = urlparse(dsn)
    return urlunparse(p._replace(path=f"/{dbname}"))


def _parts(dsn: str) -> tuple[str, int, str, str]:
    p = urlparse(dsn)
    host = p.hostname or "127.0.0.1"
    port = p.port or 5432
    user = p.username or "postgres"
    return host, port, user, p.path.lstrip("/") or "postgres"


# ---------------------------------------------------------------------------
# psql execution — PATH psql, else docker exec into the compose container
# ---------------------------------------------------------------------------
class PsqlRunner:
    """Runs psql against a database, preferring a local client."""

    def __init__(self, dsn: str, container: str | None = None):
        self.dsn = dsn
        self.host, self.port, self.user, _ = _parts(dsn)
        self.container = container
        self.mode = self._detect_mode()

    def _detect_mode(self) -> str:
        if shutil.which("psql"):
            return "psql"
        if self.container or self._find_container():
            return "docker"
        raise LintError(
            "no psql client on PATH and no docker container to exec into; "
            "install the PostgreSQL 18 client or start `docker compose up -d`"
        )

    def _find_container(self) -> str | None:
        if self.container:
            return self.container
        try:
            out = _run(
                ["docker", "ps", "--format", "{{.Names}}\t{{.Ports}}"],
                timeout=20,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        if out.returncode != 0:
            return None
        needle = f"{self.port}->5432"
        for line in out.stdout.splitlines():
            name, _, ports = line.partition("\t")
            if needle in ports:
                self.container = name.strip()
                return self.container
        return None

    def run_sql(self, dbname: str, sql: str) -> subprocess.CompletedProcess:
        if self.mode == "psql":
            cmd = [
                "psql",
                "-h", self.host,
                "-p", str(self.port),
                "-U", self.user,
                "-d", dbname,
                "-v", "ON_ERROR_STOP=1",
                "-q",
            ]
            return _run(cmd, input=sql)
        cmd = [
            "docker", "exec", "-i",
            self.container or DOCKER_FALLBACK_CONTAINER,
            "psql", "-U", self.user, "-d", dbname,
            "-v", "ON_ERROR_STOP=1",
            "-q",
        ]
        return _run(cmd, input=sql)

    def apply_file(self, dbname: str, path: Path) -> subprocess.CompletedProcess:
        return self.run_sql(dbname, path.read_text(encoding="utf-8"))

    def create_db(self, dbname: str) -> None:
        proc = self.run_sql("postgres", f"DROP DATABASE IF EXISTS {dbname}; "
                                        f"CREATE DATABASE {dbname};")
        if proc.returncode != 0:
            raise LintError(f"could not create scratch database {dbname}:\n{proc.stderr}")

    def drop_db(self, dbname: str) -> None:
        # DROP DATABASE fails if other connections are still open.
        self.run_sql("postgres", f"SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                                 f"WHERE datname = '{dbname}' AND pid <> pg_backend_pid();")
        self.run_sql("postgres", f"DROP DATABASE IF EXISTS {dbname};")


def _check_diagnostics(label: str, proc: subprocess.CompletedProcess) -> list[str]:
    """Fail on any psql ERROR/WARNING/FATAL line in stdout or stderr."""
    problems: list[str] = []
    for stream, text in (("stdout", proc.stdout), ("stderr", proc.stderr)):
        for m in _PSQL_DIAGNOSTIC.finditer(text or ""):
            line_start = (text or "").rfind("\n", 0, m.start()) + 1
            line_end = (text or "").find("\n", m.start())
            snippet = (text or "")[line_start: line_end if line_end != -1 else None]
            problems.append(f"{label}/{stream}: {snippet.strip()}")
    if proc.returncode != 0:
        problems.append(f"{label}: exit code {proc.returncode}")
        if proc.stderr:
            problems.append(f"{label}/stderr: {proc.stderr.strip()[:2000]}")
    return problems


# ---------------------------------------------------------------------------
# Catalog extraction
# ---------------------------------------------------------------------------
@dataclass
class Catalog:
    relations: list = field(default_factory=list)
    columns: list = field(default_factory=list)
    constraints: list = field(default_factory=list)
    indexes: list = field(default_factory=list)
    rls_enabled: list = field(default_factory=list)
    policies: list = field(default_factory=list)
    partitions: list = field(default_factory=list)

    def diff(self, other: "Catalog") -> dict[str, list]:
        out: dict[str, list] = {}
        for attr in (
            "relations", "columns", "constraints", "indexes",
            "rls_enabled", "policies", "partitions",
        ):
            mine = sorted(getattr(self, attr), key=_stable_key)
            theirs = sorted(getattr(other, attr), key=_stable_key)
            only_a = [x for x in mine if x not in theirs]
            only_b = [x for x in theirs if x not in mine]
            if only_a or only_b:
                out[attr] = [
                    *[f"- {x}" for x in only_a],
                    *[f"+ {x}" for x in only_b],
                ]
        return out


def _stable_key(value) -> str:
    return json.dumps(value, sort_keys=True, default=str)


_QUERIES = {
    "relations": """
        SELECT c.relname, c.relkind
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public' AND c.relkind IN ('r','p')
        ORDER BY 1
    """,
    "columns": """
        SELECT a.attrelid::regclass::text, a.attname,
               format_type(a.atttypid, a.atttypmod),
               a.attnotnull,
               COALESCE(pg_get_expr(d.adbin, d.adrelid), ''),
               a.attidentity <> '' OR a.attgenerated <> ''
        FROM pg_attribute a
        LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
        JOIN pg_class c ON c.oid = a.attrelid
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public' AND a.attnum > 0 AND NOT a.attisdropped
          AND c.relkind IN ('r','p')
        ORDER BY 1, 2
    """,
    "constraints": """
        SELECT conrelid::regclass::text, conname, contype, pg_get_constraintdef(oid)
        FROM pg_constraint
        WHERE connamespace = 'public'::regnamespace
        ORDER BY 1, 2
    """,
    "indexes": """
        SELECT tablename, indexname, indexdef
        FROM pg_indexes
        WHERE schemaname = 'public'
        ORDER BY 1, 2
    """,
    "rls_enabled": """
        SELECT relname FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public' AND c.relrowsecurity
        ORDER BY 1
    """,
    "policies": """
        SELECT tablename, policyname, cmd,
               COALESCE(qual, ''), COALESCE(with_check, ''),
               COALESCE(array_to_string(roles, ','), '')
        FROM pg_policies
        WHERE schemaname = 'public'
        ORDER BY 1, 2
    """,
    "partitions": """
        SELECT parent.relname, child.relname,
               pg_get_expr(child.relpartbound, child.oid)
        FROM pg_inherits i
        JOIN pg_class child ON child.oid = i.inhrelid
        JOIN pg_class parent ON parent.oid = i.inhparent
        JOIN pg_namespace n ON n.oid = parent.relnamespace
        WHERE n.nspname = 'public'
          AND parent.relkind = 'p' AND child.relkind = 'r'
        ORDER BY 1, 2
    """,
}


def _is_ignored_relation(name: str) -> bool:
    return name in IGNORED_RELATIONS or name.startswith("alembic_version")


def extract_catalog(dsn: str) -> Catalog:
    import psycopg

    cat = Catalog()
    with psycopg.connect(dsn, autocommit=True) as conn:
        with conn.cursor() as cur:
            for attr, query in _QUERIES.items():
                cur.execute(query)
                rows = cur.fetchall()
                rows = [r for r in rows if not _is_ignored_relation(str(r[0]))]
                setattr(cat, attr, [tuple(_jsonable(v) for v in row) for row in rows])
    return cat


def _jsonable(value):
    if isinstance(value, bool):
        return value
    if value is None:
        return None
    if isinstance(value, (int, float, str)):
        return value
    return str(value)


# ---------------------------------------------------------------------------
# Migration run
# ---------------------------------------------------------------------------
def run_migrations(dsn: str) -> subprocess.CompletedProcess:
    """Run `alembic upgrade head` in a subprocess so its stdout/stderr are
    capturable exactly like psql's."""
    env = dict(os.environ)
    env["SENTINEL_DATABASE__MIGRATOR_URL"] = dsn  # spec §4 spelling
    env["SENTINEL_MIGRATOR_URL"] = dsn  # pre-M0 alias, still read by env.py
    env.setdefault("PYTHONIOENCODING", "utf-8")
    return subprocess.run(
        [sys.executable, str(MIGRATIONS_DIR / "apply.py"), dsn],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        cwd=ROOT,
        env=env,
    )


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------
def ensure_postgres(dsn: str, *, auto_start_compose: bool = True) -> None:
    import psycopg

    try:
        with psycopg.connect(dsn, connect_timeout=5) as conn:
            with conn.cursor() as cur:
                cur.execute("SHOW server_version")
                version = cur.fetchone()[0]
    except Exception as exc:  # noqa: BLE001
        if auto_start_compose and shutil.which("docker"):
            print(f"Postgres unreachable ({exc}); starting docker compose…")
            subprocess.run(
                ["docker", "compose", "up", "-d"],
                cwd=ROOT, capture_output=True, text=True, timeout=600,
            )
            for _ in range(60):
                time.sleep(2)
                try:
                    with psycopg.connect(dsn, connect_timeout=5) as conn:
                        return
                except Exception:  # noqa: BLE001
                    continue
        raise LintError(f"PostgreSQL not reachable at {dsn}: {exc}") from exc
    if not version.startswith("18"):
        print(f"WARNING: server_version is {version!r}; the M0 contract targets PG 18",
              file=sys.stderr)


def lint(dsn: str, *, keep: bool = False, container: str | None = None) -> dict:
    ensure_postgres(dsn)
    runner = PsqlRunner(dsn, container=container)
    report: dict = {"psql_mode": runner.mode, "problems": [], "diff": {}}

    runner.create_db(DB_SCHEMA)
    schema_dsn = _with_database(dsn, DB_SCHEMA)
    proc = runner.apply_file(DB_SCHEMA, SCHEMA_SQL)
    problems = _check_diagnostics("schema.sql", proc)
    report["problems"].extend(problems)

    runner.create_db(DB_MIGRATE)
    migrate_dsn = _with_database(dsn, DB_MIGRATE)
    proc = run_migrations(migrate_dsn)
    problems = _check_diagnostics("alembic upgrade head", proc)
    report["problems"].extend(problems)

    if not report["problems"]:
        cat_schema = extract_catalog(schema_dsn)
        cat_migrate = extract_catalog(migrate_dsn)
        diff = cat_schema.diff(cat_migrate)
        report["diff"] = diff
        report["counts"] = {
            "relations": len(cat_schema.relations),
            "columns": len(cat_schema.columns),
            "constraints": len(cat_schema.constraints),
            "indexes": len(cat_schema.indexes),
            "rls_enabled": len(cat_schema.rls_enabled),
            "policies": len(cat_schema.policies),
            "partitions": len(cat_schema.partitions),
        }
    else:
        report["counts"] = None

    if not keep:
        runner.drop_db(DB_SCHEMA)
        runner.drop_db(DB_MIGRATE)
    else:
        report["kept"] = [DB_SCHEMA, DB_MIGRATE]

    report["ok"] = not report["problems"] and not report["diff"]
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dsn", default=os.environ.get("SENTINEL_LINT_DSN", DEFAULT_DSN))
    parser.add_argument("--keep", action="store_true", help="keep the scratch databases")
    parser.add_argument("--json", dest="json_out", help="write the report to this path")
    parser.add_argument("--container", default=None,
                        help="docker container to exec psql into when no local client exists")
    args = parser.parse_args(argv)

    try:
        report = lint(args.dsn, keep=args.keep, container=args.container)
    except LintError as exc:
        print(f"schema_lint: {exc}", file=sys.stderr)
        return 2

    if args.json_out:
        Path(args.json_out).write_text(
            json.dumps(report, indent=2, ensure_ascii=False, default=str) + "\n",
            encoding="utf-8",
        )

    if report["ok"]:
        c = report["counts"]
        print(
            "schema_lint OK — psql applied schema.sql and alembic upgrade head "
            f"with no ERROR/WARNING/FATAL; catalogs identical "
            f"({c['relations']} relations, {c['columns']} columns, "
            f"{c['constraints']} constraints, {c['indexes']} indexes, "
            f"{c['rls_enabled']} RLS-enabled, {c['policies']} policies, "
            f"{c['partitions']} partitions)"
        )
        return 0

    for problem in report["problems"]:
        print(f"schema_lint: {problem}", file=sys.stderr)
    for attr, entries in report["diff"].items():
        print(f"schema_lint: catalog drift in {attr}:", file=sys.stderr)
        for entry in entries:
            print(f"  {entry}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
