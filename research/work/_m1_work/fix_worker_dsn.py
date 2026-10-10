import pathlib

p = pathlib.Path("packages/ingest/sentinel_ingest/worker_handlers.py")
s = p.read_text(encoding="utf-8")
helper = (
    "def _dsn(settings: Settings) -> str:\n"
    "    # Workers run under the BYPASSRLS sentinel_worker role (platform\n"
    "    # processor); handlers still set RLS vars explicitly for job scoping.\n"
    "    return settings.worker_url or settings.database_url\n"
    "\n"
    "\n"
    "def handle_ingest_file"
)
assert "def handle_ingest_file" in s
s = s.replace("def handle_ingest_file", helper, 1)
s = s.replace("tx(settings.database_url)", "tx(_dsn(settings))")
p.write_text(s, encoding="utf-8")
print("replacements:", s.count("tx(_dsn(settings))"))
