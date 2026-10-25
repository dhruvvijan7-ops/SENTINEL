# Sentinel — LIGHT-HIDS Security Operations Platform

A full-stack cybersecurity monitoring platform with real authentication, PostgreSQL, a rule-based detection engine, CSV/JSON trace ingestion, RBAC, and a comprehensive security audit system.

**Last updated:** 2026-08-25 (Security Audit Log System v2)

---

## Quick Start

### Prerequisites

- Python 3.11+
- Node.js 18+ (pnpm recommended)
- Docker (for PostgreSQL)
- Git

### 1. Start PostgreSQL

```powershell
docker run -d --name sentinelai-db `
  -e POSTGRES_USER=sentinelai `
  -e POSTGRES_PASSWORD=sentinelai `
  -e POSTGRES_DB=sentinelai `
  -p 5432:5432 `
  postgres:16-alpine
```

### 2. Start Backend

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m alembic upgrade head
uvicorn app.main:app --reload --port 8000
```

### 3. Start Frontend

```powershell
cd frontend
pnpm install
pnpm dev
```

The frontend runs at `http://localhost:5173` and the API at `http://localhost:8000`.

### 4. Create Admin User

```powershell
cd backend
python -c "
from app.core.database import SessionLocal
from app.models.user import User
from app.services.auth import hash_password
db = SessionLocal()
admin = db.query(User).filter(User.role == 'admin').first()
if not admin:
    admin = User(email='admin@sentinelai.local', hashed_password=hash_password('SentinelAdmin123!'), name='System Admin', role='admin')
    db.add(admin); db.commit()
    print('Admin created: admin@sentinelai.local / SentinelAdmin123!')
else:
    print(f'Admin exists: {admin.email}')
db.close()
"
```

### Test Credentials

| Role | Email | Password |
|------|-------|----------|
| Admin | `admin@sentinelai.local` | `SentinelAdmin123!` |


---

## Architecture

```
SentinalAI/
├── backend/                 # FastAPI + SQLAlchemy + Alembic
│   ├── app/
│   │   ├── api/routes/      # API endpoints
│   │   ├── core/            # Config, database
│   │   ├── models/          # SQLAlchemy models
│   │   ├── schemas/         # Pydantic schemas
│   │   └── services/        # Business logic
│   ├── tests/               # pytest test suite
│   └── alembic/             # Database migrations
├── frontend/                # React + TypeScript + Vite
│   └── src/
│       ├── app/router/      # Route definitions + guards
│       ├── components/ui/   # Reusable UI components
│       ├── features/        # Feature pages
│       ├── layouts/         # Dashboard layout + sidebar
│       ├── routes/          # Route path constants
│       ├── services/        # API client services
│       ├── store/           # Zustand state stores
│       └── types/           # TypeScript types
└── README.md
```

---

## Backend

### Technology Stack

| Component | Technology |
|-----------|-----------|
| Framework | FastAPI |
| ORM | SQLAlchemy 2.0 (typed Mapped columns) |
| Auth | JWT (python-jose) + bcrypt (passlib) |
| Validation | Pydantic v2 |
| Migrations | Alembic |
| Database | PostgreSQL 16 (SQLite for tests) |
| Tests | pytest + httpx |

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `sqlite:///./sentinelai.db` | PostgreSQL connection string |
| `JWT_SECRET_KEY` | `dev-secret-change-in-production` | JWT signing secret |
| `JWT_ALGORITHM` | `HS256` | JWT algorithm |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `60` | Token expiry |
| `FRONTEND_ORIGIN` | `http://localhost:5173` | CORS origin |

### Database Models

| Model | Table | Description |
|-------|-------|-------------|
| `User` | `users` | User accounts (id, email, hashed_password, name, role, is_active) |
| `AnalysisRun` | `analysis_runs` | Uploaded trace analyses (source_type, file_name, status, event_count) |
| `Detection` | `detections` | Security detections (type, severity, status, confidence, evidence) |
| `Alert` | `alerts` | Alerts linked to detections (severity, status, source) |
| `AuditLog` | `audit_logs` | Security audit trail (category, action, result, metadata) |
| `SystemSettings` | `system_settings` | Singleton config row (max_upload_mb, analysis_history_limit) |

### API Endpoints

#### Authentication (`/api/auth`)

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/register` | Public | Create account |
| POST | `/login` | Public | Get JWT token |
| GET | `/me` | Bearer | Current user info |
| POST | `/forgot-password` | Public | Request password reset |
| POST | `/reset-password` | Public | Reset password with token |

#### Analysis (`/api/analysis-runs`)

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/` | Bearer | List analysis runs |
| GET | `/{run_id}` | Bearer | Run detail |
| GET | `/{run_id}/detections` | Bearer | Detections from a run |
| POST | `/host-traces` | Bearer | Upload JSON/CSV trace file |

#### Detections (`/api/detections`)

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/` | Bearer | List (paginated, filterable, searchable) |
| GET | `/{id}` | Bearer | Detail with alerts + analysis run |
| PATCH | `/{id}` | Bearer | Update status (new → investigating → resolved) |
| GET | `/{id}/alerts` | Bearer | Alerts for a detection |

#### Alerts (`/api/alerts`)

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/` | Bearer | List (optional status filter) |
| PATCH | `/{id}` | Bearer | Update alert status |

#### User Management (`/api/users`) — Admin Only

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/` | Admin | List users (paginated, searchable, role/active filters) |
| GET | `/{id}` | Admin | User detail |
| PATCH | `/{id}` | Admin | Change role or activate/deactivate |

#### Network Analysis (`/api/network`) — Authenticated

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/events` | Bearer | List network events (paginated, filterable) |
| GET | `/events/{id}` | Bearer | Event detail with related detections/alerts |
| GET | `/summary` | Bearer | Summary stats (totals, unique IPs, ports, protocols) |
| GET | `/ips/{ip}` | Bearer | IP investigation (activity, destinations, protocols) |
| GET | `/ports` | Bearer | Port analysis (counts, unique sources/destinations) |
| GET | `/protocols` | Bearer | Protocol statistics with percentages |
| GET | `/top-talkers` | Bearer | Most active source/destination IPs |
| GET | `/timeline` | Bearer | Activity timeline with adaptive intervals |

#### System (`/api/system`)

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/status` | Public | API + DB status |
| GET | `/dashboard/summary` | Bearer | Dashboard stats |
| GET | `/settings` | Bearer | System settings |
| PATCH | `/settings` | Admin | Update settings |

#### Audit Logs (`/api/audit-logs`) — Admin Only

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/` | Admin | Query audit logs (filtered, paginated, searchable) |

**Query parameters:** `page`, `page_size`, `category`, `action`, `actor_user_id`, `actor_email`, `resource_type`, `resource_id`, `result`, `from_timestamp`, `to_timestamp`, `search`, `sort_by`, `sort_order`

### Role-Based Access Control (RBAC)

| Role | Capabilities |
|------|-------------|
| `admin` | Full access: user management, settings, audit logs, all data |
| `analyst` | View/manage detections, alerts, analysis runs, settings (read-only) |

Enforced server-side via `require_role()` FastAPI dependency in `deps.py`. JWT contains only `user_id` — role is always fetched from the database.

### Detection Engine

Rule-based engine in `services/detection_engine.py` that analyzes uploaded host system-call traces:

| Rule | Trigger | Severity |
|------|---------|----------|
| High event volume | >500 events | Medium |
| Excessive sequences | >50 sequences | Medium |
| Suspicious network pattern | ≥3 network calls | High |
| Privilege escalation | Any privilege calls | Critical |
| Suspicious file operations | ≥2 sensitive file calls | High |
| High syscall diversity | >30 unique calls | Low |

**Network detection rules** (applied when network events are present):

| Rule | Trigger | Severity |
|------|---------|----------|
| Excessive connection attempts | ≥10 unique destinations from one source | High |
| Port scan detected | ≥5 unique sources to one port | High |
| High connection frequency | ≥50 events on a single port | Medium |
| Repeated connection attempts | ≥20 unique destinations from one source | Critical |

Each fired rule creates a Detection + linked Alert pair.

### Host Trace Formats

**JSON:**
```json
{
  "sequences": [
    { "system_calls": ["open", "read", "close", "write"] }
  ]
}
```

**CSV:** Columns `trace_id, syscall_name` (or `syscall_id` for x86_64 mapping).

### Security Audit System

Records structured events across 6 categories with 22 action types:

| Category | Actions |
|----------|---------|
| AUTHENTICATION | LOGIN_SUCCESS, LOGIN_FAILED, LOGOUT, REGISTRATION, PASSWORD_RESET_REQUEST, PASSWORD_RESET |
| ANALYSIS | FILE_UPLOADED, FILE_REJECTED, ANALYSIS_STARTED, ANALYSIS_COMPLETED, ANALYSIS_FAILED |
| DETECTION | DETECTION_GENERATED, DETECTION_INVESTIGATED |
| ALERT | ALERT_CREATED, ALERT_UPDATED, ALERT_STATUS_CHANGED |
| ADMINISTRATION | USER_CREATED, USER_ROLE_CHANGED, USER_ACTIVATED, USER_DEACTIVATED |
| SYSTEM | SETTINGS_CHANGED, SYSTEM_CONFIGURATION_CHANGED |

Each event stores: actor, category, action, result, resource type/id, IP address, structured metadata, timestamp.

### Running Tests

```powershell
cd backend
python -m pytest tests/ -v
```

76 tests covering detections (22), RBAC (20), audit events + filtering + security (34).

---

## Frontend

### Technology Stack

| Component | Technology |
|-----------|-----------|
| Framework | React 19 + TypeScript |
| Build | Vite |
| Routing | React Router v7 |
| State | Zustand |
| Styling | Tailwind CSS (SOC dark theme) |
| Icons | Lucide React |
| Notifications | Sonner (toast) |
| Animations | Framer Motion |
| Charts | Recharts |

### Pages

| Route | Page | Access | Description |
|-------|------|--------|-------------|
| `/` | Landing Page | Public | Marketing page with hero, features, pipeline demo |
| `/login` | Login | Public | Email/password authentication |
| `/register` | Register | Public | Account creation |
| `/forgot-password` | Forgot Password | Public | Password reset request |
| `/dashboard` | Dashboard | Authenticated | Overview stats + recent activity |
| `/monitoring` | Monitoring | Authenticated | Detection list with severity/search/pagination |
| `/monitoring/:id` | Investigation | Authenticated | Detection detail, alerts, analysis run, status actions |
| `/analysis` | Analysis | Authenticated | Upload JSON/CSV traces, view run history |
| `/alerts` | Alerts | Authenticated | Alert list with status filter |
| `/network` | Network Analysis | Authenticated | 7-tab network investigation tool |
| `/settings` | Settings | Authenticated | System config (admin-editable, analyst read-only) |
| `/admin/users` | User Management | Admin | User list, role changes, activate/deactivate |
| `/admin/audit-logs` | Audit Logs | Admin | Full audit trail with multi-dimensional filtering |

### Services

| Service | File | Description |
|---------|------|-------------|
| `apiClient` | `services/apiClient.ts` | HTTP client with JWT Bearer + 401 interceptor |
| `authService` | `services/authService.ts` | Login, register, forgot/reset password |
| `alertService` | `services/alertService.ts` | Alert list + update |
| `userService` | `services/userService.ts` | User CRUD (admin) |
| `auditService` | `services/auditService.ts` | Audit log queries + time presets |
| `systemService` | `services/systemService.ts` | System status + settings |

### Auth Flow

1. Login returns `{ user, token }` — stored in Zustand + localStorage
2. `apiClient` attaches `Authorization: Bearer <token>` to all requests
3. 401 response clears storage and redirects to `/login`
4. `ProtectedRoute` wrapper guards all authenticated pages
5. `AdminRoute` wrapper additionally checks `user.role === "admin"`

### UI Theme

SOC dark theme with `#070A0F` background, `#F8FAFC` foreground, orange primary accent. Applied via Tailwind CSS with `forcedTheme="dark"`.

---

## Changelog

### 2026-08-25 — Network & Traffic Analysis

**Added:**
- `NetworkEvent` model with fields: timestamp, source_ip, destination_ip, source_port, destination_port, protocol, connection_id, syscall_name, detection_id, alert_id, analysis_run_id
- Extended host trace parser to extract network events from JSON (`network_events` array in sequences) and CSV (source_ip, destination_ip, source_port, destination_port, protocol, connection_id columns)
- `GET /api/network/events` — paginated, filterable (source_ip, destination_ip, ports, protocol, time range, search, analysis_run_id)
- `GET /api/network/summary` — total events, unique IPs, unique ports, protocols observed
- `GET /api/network/ips/{ip}` — IP investigation (first/last seen, unique destinations/sources, ports, protocols, related detections/alerts)
- `GET /api/network/ports` — port analysis with connection counts, unique sources/destinations
- `GET /api/network/protocols` — protocol statistics with event counts and percentages
- `GET /api/network/top-talkers` — most active source/destination IPs
- `GET /api/network/timeline` — activity timeline with auto-adaptive aggregation intervals
- `GET /api/network/events/{id}` — event detail with related detections and alerts
- 4 network-specific detection rules: excessive_connection_attempts, port_scan_detected, high_connection_frequency, repeated_connection_attempts
- Audit logging: NETWORK_DATA_VIEWED, IP_INVESTIGATION_VIEWED, PORT_INVESTIGATION_VIEWED, NETWORK_EVENT_VIEWED
- Frontend `NetworkPage` with 7 tabs: Overview, Events, IP Investigation, Ports, Protocols, Top Talkers, Timeline
- "Network" nav item in sidebar
- 12 composite database indexes for query performance
- 42 backend tests covering auth, filtering, pagination, IP/port/protocol analysis, timeline, upload integration, SQL injection safety, detection engine
- Alembic migration `c3d4e5f6a7b8` for network_events table

### 2026-08-25 — Security Audit & Activity System v2

**Added:**
- `AuditLog` model with comprehensive fields: timestamp, created_at, actor_user_id, actor_email, actor_type, category, action, result, resource_type, resource_id, ip_address, user_agent, request_id, metadata_json, description
- `AuditService` with `record()` method accepting user_agent, request_id, actor_type
- 10 audit categories: AUTHENTICATION, USER_MANAGEMENT, INGESTION, ANALYSIS, DETECTION, ALERT, SETTINGS, ADMINISTRATION, SYSTEM, NETWORK
- 40+ audit action types covering all security, user, ingestion, analysis, detection, alert, admin, and system events
- `GET /api/audit-logs` admin-only query API with server-side filtering (category, action, actor, resource, result, user_agent, date range, search) with default page size 50
- `GET /api/audit-logs/{id}` admin-only single log detail endpoint
- Composite database indexes for query performance (category+action, actor+timestamp, resource, request_id)
- Audit events integrated into all routes: auth (login/register/logout/password reset), analysis (validation started/completed/failed, JSON/CSV upload, upload rejected), detections (created, viewed, status changed), alerts (created, viewed, resolved, reopened, status changed), admin (role/activation changes), system (settings changed), network (data viewed, IP investigation, event viewed)
- Frontend `AuditLogsPage` with time presets (Today, Yesterday, Last 24h, Last 7d, Last 30d, This/Previous month), custom datetime range, category/action/result/resource/user_id filters, searchable table, detail modal showing all fields including user_agent, request_id, actor_type
- All 10 audit categories in frontend filter dropdown (including Network, User Management, Ingestion, Settings)
- 46 backend tests covering all event types, filtering, pagination, authorization, security, new endpoints, and new fields
- Alembic migration for audit_logs table with user_agent, request_id, actor_type, created_at columns

### 2026-08-22 — RBAC & Admin User Management

**Added:**
- `require_role()` FastAPI dependency for server-side RBAC
- `GET /api/users`, `GET /api/users/{id}`, `PATCH /api/users/{id}` admin-only endpoints
- Frontend `UsersPage` with search, role/status filters, inline role dropdown, activate/deactivate
- `AdminRoute` wrapper component
- "Users" admin nav item in sidebar
- Settings page read-only mode for analysts
- `AuditLog` model (basic version, later replaced)
- 20 RBAC tests covering admin access, analyst 403s, unauth 401s, password hash exclusion, last-admin protection

### 2026-08-22 — Detection Investigation Feature

**Added:**
- `GET /api/detections/{id}` with analysis_run, alerts, sibling count
- `PATCH /api/detections/{id}` for status updates
- `GET /api/detections/{id}/alerts`
- `GET /api/analysis-runs/{id}` and `/{id}/detections`
- Frontend `InvestigationPage` at `/monitoring/:detectionId`
- "Investigate" button on monitoring page

### 2026-08-22 — Detection Engine & Monitoring

**Added:**
- Rule-based detection engine (6 rules, Detection + Alert pair creation)
- `Detection` model with severity, status, confidence, evidence
- Alembic migrations for detections table
- Frontend `MonitoringPage` with real API, filters, pagination
- Frontend `AnalysisPage` with JSON/CSV upload

### 2026-08-22 — Auth System & Full Rebrand

**Added:**
- User model, JWT auth, login/register/forgot-password/reset-password
- PostgreSQL via Docker, Alembic migrations
- Frontend auth flow (authStore, apiClient, AuthInitializer, ProtectedRoute)
- Login page with show/hide password toggle
- Full rebrand from SentinelAI → Sentinel
- SOC dark theme
- Landing page

---

## Design Decisions

- **No foreign keys** — All model relationships use plain string ID columns for flexibility
- **No ML** — Detection engine is rule-based; ML integration is a future goal
- **No mock data** — All data flows through real PostgreSQL + API
- **JWT in localStorage** — Simple implementation; httpOnly cookies are a future improvement
- **Audit events are append-only** — No UPDATE or DELETE endpoints for audit logs; only admin GET access
- **Audit logs include user_agent and request_id** — For forensic traceability without storing sensitive payloads
- **System events use `__system__` actor** — Automated detection events are not attributed to human users
