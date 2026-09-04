# SentinelAI backend

This first vertical slice accepts and persists host system-call trace summaries. It does **not** claim to run LIGHT-HIDS yet.

## Run on Windows

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Set `DATABASE_URL` to a PostgreSQL SQLAlchemy URL for PostgreSQL. The default SQLite database is a development-only fallback so the first slice runs locally.

## Supported trace format

```json
{
  "sequences": [
    { "system_calls": ["open", "read", "close"] }
  ]
}
```
