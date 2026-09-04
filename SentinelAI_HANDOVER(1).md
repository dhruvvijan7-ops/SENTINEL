# SentinelAI — Complete Project Handover

## 1. Project

**Name:** SentinelAI  
**Folder:** `SentinalAI`  
**Purpose:** Lightweight cybersecurity monitoring, detection, and investigation platform  
**Research basis:** LIGHT-HIDS  
**Paper:** https://arxiv.org/pdf/2509.13464

SentinelAI must become a **real, functional cybersecurity application**, not a dashboard mockup.

Required final layers:
- Professional React frontend
- Real backend
- PostgreSQL database
- REST API
- WebSocket where appropriate
- Real cybersecurity/network functionality
- LIGHT-HIDS integration
- Detection, alerting, and investigation

---

## 2. CRITICAL REQUIREMENT — LIGHT-HIDS VS ML

This distinction is mandatory.

### LIGHT-HIDS integration is REQUIRED.

LIGHT-HIDS is part of the core project and must not be removed or treated as optional.

### ML is OPTIONAL.

The project must not depend on successfully implementing a machine-learning model.

Therefore:

```text
LIGHT-HIDS integration      REQUIRED
Cybersecurity functionality REQUIRED
Functional frontend         REQUIRED
Functional backend          REQUIRED
REST API                    REQUIRED
Database                    REQUIRED
Real detection workflow     REQUIRED
ML/anomaly model            OPTIONAL
```

If ML cannot be implemented reliably, the project must still be complete using appropriate non-ML/rule-based or otherwise technically justified detection/analysis while preserving the required LIGHT-HIDS integration.

**Never fabricate ML results. Never remove LIGHT-HIDS because ML is difficult. Never make ML a completion blocker.**

---

## 3. Product Goal

SentinelAI should help a security analyst:

- Monitor network/security events
- Analyze network traffic
- Inspect packet/event metadata
- Detect suspicious behavior
- Generate and manage alerts
- Investigate incidents
- Search/filter security events
- View traffic statistics
- Monitor detection-engine/system status
- Receive relevant real-time events

The project can take useful ideas from Wireshark, but **must not become a Wireshark clone**.

The goal is a focused security monitoring and investigation platform.

---

## 4. Target Architecture

```text
                    SENTINELAI
                        |
                        v
              Network / Security Data
                        |
                        v
                  LIGHT-HIDS
              Detection / Analysis
                        |
              +---------+---------+
              |                   |
              v                   v
        Rule/logic based      ML-based
          detection          detection
              |                   |
              +---------+---------+
                        |
                        v
                 Detection Results
                        |
                        v
                     FastAPI
                        |
             +----------+----------+
             |                     |
             v                     v
        PostgreSQL              WebSocket
             |                     |
             +----------+----------+
                        |
                        v
                SentinelAI Frontend
```

The ML branch is optional. LIGHT-HIDS integration and the cybersecurity workflow are not.

---

## 5. Current Frontend Stack

Already established:

- React 19
- TypeScript
- Vite
- Tailwind CSS v4
- shadcn/ui
- Radix UI
- React Router
- TanStack Query
- Zustand
- React Hook Form
- Zod
- Lucide React
- Recharts
- Framer Motion

Do not replace the stack without a strong technical reason.

---

## 6. Existing Frontend Architecture

The existing project conceptually contains:

```text
src/
├── app/
│   ├── providers/
│   │   ├── AppProviders.tsx
│   │   ├── QueryProvider.tsx
│   │   └── ThemeProvider.tsx
│   └── router/
│       └── AppRouter.tsx
├── components/
│   └── ui/
├── features/
│   ├── auth/
│   │   └── pages/
│   └── dashboard/
│       └── pages/
├── layouts/
│   ├── DashboardLayout.tsx
│   └── AuthLayout.tsx
├── routes/
│   └── paths.ts
├── services/
├── store/
│   └── authStore.ts
├── types/
│   └── auth.ts
└── hooks/
```

This is a record of the architecture, not a guarantee that every path is unchanged. **The actual repository is the source of truth.**

---

## 7. Frontend Work Already Completed

The frontend foundation has been established:

- Vite
- React
- TypeScript
- Tailwind CSS v4
- shadcn/ui
- Radix UI
- Lucide
- React Router
- TanStack Query
- Zustand
- React Hook Form/Zod infrastructure
- Theme provider
- Dark/light mode
- ESLint
- TypeScript aliases
- Reusable UI components
- Authentication layout
- Dashboard layout
- Route structure
- Authentication store

The frontend previously reached a state where TypeScript, ESLint, and production build passed. Always rerun checks after future changes.

Do not unnecessarily rebuild the working frontend.

---

## 8. Existing Dashboard

DashboardLayout already includes:

- SentinelAI branding
- LIGHT-HIDS branding
- Security Operations navigation
- Overview navigation
- Monitoring navigation
- Alerts indicator
- Settings entry
- Detection Engine status
- Engine Online indicator
- User information
- Logout
- Mobile navigation
- Responsive sidebar
- Breadcrumb-style header
- Notification button
- User indicator
- Outlet-based rendering
- Sentinel grid styling

The intended UI is a professional security-operations interface.

Preserve working functionality.

---

## 9. Authentication

Current Zustand authentication state contains:

```text
user
token
isAuthenticated

login()
logout()
setUser()
```

Current authentication is frontend infrastructure and must be connected to the backend.

Target:

```text
Register
  -> POST /api/auth/register
  -> FastAPI
  -> PostgreSQL
```

```text
Login
  -> POST /api/auth/login
  -> JWT/secure token
  -> frontend auth state
```

Requirements:
- Secure password hashing
- No plaintext passwords
- Protected backend endpoints
- Proper validation
- Secure token handling

---

## 10. Registration

Registration has been implemented beyond the original placeholder.

It includes:
- Full name
- Email
- Password
- Confirm password
- Validation
- Loading state
- Error state
- Create Account
- Login link
- SentinelAI branding

It still needs real backend integration.

---

# 11. REQUIRED CYBERSECURITY FUNCTIONALITY

These are core requirements.

## Network Monitoring

Support meaningful network-event information such as:
- Source IP
- Destination IP
- Source port
- Destination port
- Protocol
- Timestamp
- Packet/event size
- Connection/session information
- Event status

## Packet / Network Analysis

Where technically practical:
- Packet metadata
- Protocol classification
- Source/destination
- Packet size
- Timestamp
- TCP/UDP/ICMP information
- Connection information
- Traffic statistics
- Filtering
- Searching
- Detailed event views

PCAP ingestion should be considered a major feature if it can be implemented reliably:

```text
PCAP
 -> packet parsing
 -> metadata extraction
 -> LIGHT-HIDS analysis/detection
 -> detection results
 -> database
 -> investigation UI
```

Do not attempt to reproduce Wireshark's complete protocol-dissection ecosystem.

## Traffic Analytics

Useful metrics may include:
- Traffic volume
- Packets/sec
- Bytes/sec
- Connection count
- Top source IPs
- Top destination IPs
- Top ports
- Protocol distribution
- Traffic spikes
- Suspicious traffic patterns

These should eventually come from backend data, not decorative fake values.

## Detection Engine

A real detection mechanism is required.

Potential detections, subject to available data and technical justification:
- Port scanning
- Brute-force patterns
- Abnormal traffic
- Suspicious connections
- Unusual port/protocol combinations
- Other justified security detections

Do not invent scientific claims or claim a detection is from LIGHT-HIDS unless supported by the paper.

## Alerts

Alerts must be real backend objects, not a hardcoded badge.

Potential fields:
- ID
- Severity
- Detection type
- Source
- Destination
- Timestamp
- Description
- Status
- Related event/detection
- Created/updated time

Useful lifecycle:
- New
- Investigating
- Resolved

Useful operations:
- Acknowledge
- Investigate
- Resolve
- Search
- Filter
- View details
- View related events

## Investigation

The analyst should be able to go:

```text
Alert
 -> Detection
 -> Related events
 -> Source/destination
 -> Ports/protocol
 -> Timeline
 -> Related connections
 -> Investigation result
```

The system should help answer:
- What happened?
- When?
- Where did it originate?
- What did it communicate with?
- What related events occurred?
- Why was it suspicious?

## Security Logs

Provide:
- Timestamp
- Source
- Event type
- Severity
- Description
- Related detection

Support:
- Search
- Severity filtering
- Event-type filtering
- Source filtering
- Time-range filtering

## Real-Time Monitoring

After REST is stable, use WebSocket for relevant live events:

```text
Detection engine
 -> FastAPI
 -> WebSocket
 -> Monitoring UI
```

Use REST for normal API operations. Do not use WebSocket for everything.

---

# 12. REST API

REST is the primary API style.

Initial conceptual endpoints:

```text
POST  /api/auth/register
POST  /api/auth/login
GET   /api/auth/me

GET   /api/dashboard/summary

GET   /api/detections
GET   /api/detections/{id}

GET   /api/alerts
GET   /api/alerts/{id}
PATCH /api/alerts/{id}

GET   /api/network/events
GET   /api/network/statistics
GET   /api/network/connections

GET   /api/system/status
```

These are initial suggestions. Finalize them after auditing the repository and studying the LIGHT-HIDS requirements.

---

# 13. Frontend API Architecture

Do not put direct API calls throughout page components.

Preferred:

```text
Page
 -> TanStack Query hook
 -> Service
 -> API client
 -> FastAPI
```

Example:

```text
MonitoringPage
 -> useDetections()
 -> detectionService
 -> apiClient
 -> FastAPI
```

Mock data may be used during development, but must stay behind a service abstraction.

The UI should not need to be rewritten when mock data is replaced with real backend data.

---

# 14. Backend

Recommended:
- Python
- FastAPI
- PostgreSQL
- Pydantic
- SQLAlchemy or appropriate DB layer
- Alembic
- JWT
- Secure password hashing

Target architecture:

```text
backend/
├── app/
│   ├── main.py
│   ├── api/
│   │   ├── router.py
│   │   └── routes/
│   │       ├── auth.py
│   │       ├── dashboard.py
│   │       ├── detections.py
│   │       ├── alerts.py
│   │       ├── network.py
│   │       └── system.py
│   ├── core/
│   │   ├── config.py
│   │   ├── security.py
│   │   └── database.py
│   ├── models/
│   ├── schemas/
│   ├── services/
│   ├── repositories/
│   └── integrations/
├── alembic/
├── tests/
├── requirements.txt
└── .env.example
```

This is a target, not an instruction to create every directory blindly.

A modular monolith is preferred initially.

---

# 15. LIGHT-HIDS Integration — MANDATORY

Before implementing it:

1. Study the supplied LIGHT-HIDS paper.
2. Identify relevant architecture.
3. Identify relevant inputs.
4. Identify relevant features/data.
5. Identify the detection workflow.
6. Determine what can realistically be implemented.
7. Map it to SentinelAI.
8. Distinguish actual implementation from research concepts.

Do not fabricate implementation details.

Do not claim unverified experimental results.

Do not claim a rule is a LIGHT-HIDS algorithm unless the paper supports that statement.

The integration must be technically honest and actually functional.

---

# 16. ML — OPTIONAL

ML is not a completion criterion.

ML may be added later if:
- data supports it
- implementation is reliable
- it is technically justified
- evaluation can be done honestly

If ML is absent, the project must still be complete through:
- required LIGHT-HIDS integration
- real network/security processing
- detection logic
- alerts
- investigation
- monitoring

Never create fake ML output.

---

# 17. Database

Recommended: PostgreSQL.

Conceptual entities:

## Users
```text
id
name
email
password_hash
role
created_at
```

## Detections
```text
id
timestamp
source information
destination information
protocol
source port
destination port
severity
confidence where justified
detection type
status
description
created_at
```

## Alerts
```text
id
detection_id
severity
status
created_at
updated_at
```

## Network Events
Potential fields:
```text
id
timestamp
source_ip
destination_ip
source_port
destination_port
protocol
packet_size
event_type
metadata
```

Final schema must be based on actual requirements and LIGHT-HIDS data flow.

Use migrations and justified indexes.

---

# 18. Security Requirements

Implement reasonable application security:
- Password hashing
- Authentication
- Authorization where necessary
- Environment variables for secrets
- Correct CORS
- Input validation
- Backend validation
- Parameterized DB operations/ORM
- No hardcoded credentials
- No plaintext passwords
- Safe error handling
- Rate limiting where appropriate
- Secure token handling
- HTTPS in production
- WebSocket security
- Dependency hygiene

Do not claim the system is secure merely because login exists.

---

# 19. UI/UX

The application should feel like a serious security operations product.

Desired:
- Professional
- Clean
- Technical
- Readable
- Responsive
- Accessible
- Lightweight
- Consistent

Avoid:
- Excessive neon
- Generic hacker aesthetics
- Fake terminal effects
- Excessive animation
- Decorative fake widgets
- Meaningless metrics
- Visual clutter

Major displayed values should correspond to real backend data or be clearly identified as development/mock data.

---

# 20. What NOT to Build

Do not turn SentinelAI into:
- A Wireshark clone
- An unrelated generic SIEM
- A vulnerability scanner
- An offensive-security toolkit
- A password manager
- A generic AI chatbot
- A collection of fake cybersecurity widgets

Do not add Kubernetes, Kafka, microservices, GraphQL, gRPC, Redis, or separate ML infrastructure unless there is a demonstrated technical requirement.

Avoid overengineering.

---

# 21. Development Phases

## Phase 1 — Frontend stabilization
Verify:
- Routes
- Dashboard
- Monitoring
- Registration
- Login/logout
- Responsive layout
- TypeScript
- ESLint
- Production build

## Phase 2 — API/service abstraction
Complete clean frontend API/service boundaries.

## Phase 3 — FastAPI foundation
Implement:
- FastAPI
- Configuration
- Database connection
- Health/status
- API routing
- Schemas
- Error handling
- Tests

## Phase 4 — PostgreSQL
Implement:
- Models
- Migrations
- Indexes
- Repositories/services
- Development/production DB configuration

## Phase 5 — Real authentication
Implement:
- Register
- Login
- Password hashing
- JWT
- Protected routes
- Current-user endpoint
- Token strategy

## Phase 6 — Network/security data
Implement:
- Network events
- Connections
- Detections
- Alerts
- Relationships
- Query/filtering

## Phase 7 — REQUIRED LIGHT-HIDS integration
Implement it from the research paper and actual available data.

## Phase 8 — Cybersecurity detection
Implement meaningful, technically justified detections.

## Phase 9 — Packet/PCAP functionality
If practical, implement:
```text
PCAP upload
 -> parsing
 -> metadata extraction
 -> LIGHT-HIDS analysis
 -> detection
 -> storage
 -> investigation
```

## Phase 10 — Alerts/investigation
Implement alert lifecycle, details, related events, timelines, search and filtering.

## Phase 11 — Real-time
Implement WebSocket updates.

## Phase 12 — Frontend/backend integration
Replace development mocks with real API calls.

## Phase 13 — Optional ML
Only after the core system works.

## Phase 14 — Testing/hardening
Test frontend, backend, auth, DB, APIs, detection, alerts, network analysis, WebSocket, integration and security controls.

## Phase 15 — Deployment
Prepare production environment, database, backend, frontend, CORS, HTTPS, WebSocket, migrations and documentation.

---

# 22. Testing

Frontend:
```text
TypeScript
ESLint
Production build
Component tests where useful
Service tests
Route tests
```

Backend:
```text
API tests
Authentication tests
Database tests
Detection tests
Alert tests
Validation tests
Network-analysis tests
```

Integration:
```text
Register
 -> Login
 -> Authenticated request
 -> Dashboard
 -> Detection
 -> Alert
 -> Investigation
 -> Logout
```

Real-time:
```text
Detection generated
 -> Backend
 -> WebSocket
 -> Frontend update
```

---

# 23. Deployment

A practical deployment can use:

```text
GitHub
  |
  +--> Frontend host such as Vercel
  |
  +--> Backend host such as Render/Railway
  |
  +--> Managed PostgreSQL
```

Select providers based on the final architecture and current free-tier/resource constraints.

Do not assume a provider until the final architecture is known.

---

# 24. Documentation

Final repository should contain:

```text
README.md
DEPLOYMENT.md
.env.example
```

README:
- Purpose
- Architecture
- Technologies
- Setup
- Features
- LIGHT-HIDS relationship
- ML status
- Screenshots where useful

DEPLOYMENT:
- Frontend
- Backend
- Database
- Environment variables
- Migrations
- CORS
- WebSocket
- Production startup
- Troubleshooting

---

# 25. Git

Use Git throughout.

Before major changes:
```text
git status
git add .
git commit
```

Do not commit:
- `.env`
- secrets
- private keys
- passwords
- database credentials
- unnecessary generated files

Use `.env.example`.

---

# 26. CRITICAL CODEX INSTRUCTION — INITIAL AUDIT

## DO NOT START CODING IMMEDIATELY.

First audit the existing repository.

The repository is the source of truth for the current implementation.

This handover describes intended direction.

The LIGHT-HIDS paper is the source of truth for research-specific claims.

During the initial audit inspect:

1. Project structure
2. package files
3. Routes
4. Pages
5. Layouts
6. Components
7. Hooks
8. Services
9. Stores
10. Types
11. Mock data
12. Authentication
13. Dashboard
14. Monitoring
15. Configuration
16. Scripts
17. Backend, if any
18. Database, if any
19. API functionality, if any
20. Tests

Then report:

- What exists
- What works
- What is incomplete
- What is incorrect
- What must be preserved
- What should change
- What should be added
- Recommended implementation order
- Any conflicts between the repository and this handover

### During the audit:

**Do not modify files.**  
**Do not delete files.**  
**Do not refactor.**  
**Do not install packages.**  
**Do not rewrite the frontend.**  
**Do not create fake functionality.**  
**Do not fabricate ML.**  
**Do not remove LIGHT-HIDS.**  
**Do not treat LIGHT-HIDS as optional.**  
**Do not make ML a completion blocker.**

Wait for approval before major modifications.

---

# 27. Final Definition of Done

SentinelAI is complete only when it has:

```text
✓ Professional React frontend
✓ Real FastAPI backend
✓ PostgreSQL
✓ Real authentication
✓ REST API
✓ Real network/security data handling
✓ REQUIRED LIGHT-HIDS integration
✓ Real detection workflow
✓ Alerts
✓ Investigation
✓ Logs/search/filtering
✓ Network/traffic analysis
✓ Real-time monitoring where appropriate
✓ Functional frontend/backend integration
✓ Security-conscious implementation
✓ Automated tests
✓ Deployment documentation
```

And:

```text
ML = OPTIONAL
LIGHT-HIDS = REQUIRED
CYBERSECURITY FUNCTIONALITY = REQUIRED
FRONTEND + BACKEND = REQUIRED
```

The absence of ML does not make the project incomplete.

The absence of LIGHT-HIDS integration or core cybersecurity functionality does.

---

# 28. Guiding Principle

Build a **real, lightweight cybersecurity product**, not a visually impressive mockup.

For every major feature, answer:

> What real security problem does this solve, what data does it use, where does the logic execute, and how does the analyst use the result?

If the answer is unclear, reconsider the feature before implementing it.


---

# 29. Data Ingestion Strategy

SentinelAI must eventually consume a real source of network/security data.

Potential sources to evaluate:

1. Live network capture
2. PCAP file upload
3. Existing system/network logs
4. LIGHT-HIDS-compatible input

The implementation should begin with the most reliable and reproducible source.

PCAP ingestion is a strong initial option because the same traffic can be analyzed repeatedly during development and testing.

**Do not claim live network monitoring if the backend is only processing static or mock data.**

---

# 30. Detection Pipeline

The intended security-data pipeline is:

```text
Data Source
    ↓
Capture / Ingestion
    ↓
Parsing / Normalization
    ↓
Feature / Metadata Extraction
    ↓
LIGHT-HIDS Integration
    ↓
Detection
    ↓
Severity / Classification
    ↓
Alert Generation
    ↓
Database
    ↓
REST / WebSocket
    ↓
Frontend
```

The exact implementation must be determined after auditing the repository and studying the LIGHT-HIDS paper.

Keep the pipeline modular so the data source and detection implementation can evolve without rewriting the UI.

---

# 31. PCAP Investigation

Where technically practical, users should be able to:

- Upload a PCAP file
- Start analysis
- See analysis progress/status
- View packet/event counts
- Filter by protocol
- Filter by source/destination IP
- Filter by ports
- Inspect timestamps
- Inspect packet sizes
- View suspicious events
- Navigate from a detection to related events
- View an analysis summary

SentinelAI does **not** need to reproduce Wireshark's complete packet-dissector ecosystem.

The goal is focused security analysis rather than replacing Wireshark.

---

# 32. Detection Explainability

Detections should provide understandable evidence/reasoning whenever possible.

Example:

```text
Detection: Possible Port Scan

Source: 192.168.1.20
Target: 192.168.1.10
Ports contacted: 22, 23, 80, 443, 8080
Time window: 10 seconds

Reason:
Multiple destination ports were contacted from the same
source within a short time window.
```

Avoid displaying unexplained security scores.

If a score/confidence value is displayed, document how it was calculated and do not imply statistical meaning that has not been established.

---

# 33. Audit Logging

Important analyst actions should be auditable where appropriate.

Potential actions:

- Login
- Logout
- Alert acknowledgement
- Alert status changes
- Investigation actions
- Configuration changes

Audit records should contain, where appropriate:

```text
Actor
Action
Timestamp
Resource
Relevant metadata
```

Do not log passwords, tokens, or other secrets.

---

# 34. Role-Based Access

The existing authentication model contains a user role.

The architecture should support at least the conceptual roles:

```text
admin
analyst
viewer
```

Do not build an unnecessarily complex RBAC system initially.

Implement only permissions that are actually required by the application's functionality.

---

# 35. Performance Requirements

SentinelAI should remain lightweight.

Requirements:

- Avoid unnecessarily expensive frontend rendering.
- Paginate large event datasets.
- Prefer server-side filtering for large datasets.
- Do not load thousands of events into the browser unnecessarily.
- Add database indexes for frequent queries where justified.
- Keep WebSocket updates bounded and efficient.
- Avoid unnecessary polling when real-time delivery is appropriate.
- Avoid unnecessary dependencies and background services.

---

# 36. Required UI States

Important pages and operations must handle more than the successful state.

Support appropriate:

```text
Loading
Empty
Error
Unauthorized
Backend unavailable
No detections
No alerts
No network data
Analysis in progress
Analysis completed
Analysis failed
```

Do not leave users with blank screens when an API fails.

---

# 37. Development / Demo Mode

A development mode may provide deterministic sample security data for frontend development and demonstrations.

However:

- Demo data must be clearly identifiable in development.
- Demo data must never be presented as live network telemetry.
- Production mode must use the real backend/data pipeline.
- Demo data must remain behind the same service/API abstraction.
- Detection/alert examples should be deterministic and reproducible.

The purpose of demo mode is development convenience, not to fake production functionality.

---

# 38. Feature Prioritization Rule

Prioritize features in this order:

```text
1. Working end-to-end architecture
2. Real data ingestion
3. Required LIGHT-HIDS integration
4. Detection functionality
5. Alerts
6. Investigation
7. Network/PCAP analysis
8. Real-time monitoring
9. Security hardening
10. UI refinement
11. Optional ML
```

A smaller set of working cybersecurity capabilities is preferable to a large set of simulated features.

---

# 39. CODEX EXECUTION PROTOCOL

After the initial repository audit is complete:

### Step 1 — Present the audit

Codex must report:

```text
Current architecture
Working features
Broken/incomplete features
Frontend/backend status
Existing mock services
Existing API boundaries
Existing dependencies
Database status
LIGHT-HIDS status
Recommended changes
Risks/blockers
Implementation plan
```

### Step 2 — Identify the first milestone

Codex should recommend the smallest milestone that creates a real end-to-end vertical slice.

Preferred example:

```text
Network/PCAP input
    ↓
Backend ingestion
    ↓
LIGHT-HIDS/detection layer
    ↓
Stored detection
    ↓
REST API
    ↓
Monitoring UI
```

Do not build every page before creating a functional backend path.

### Step 3 — Implement incrementally

For each milestone:

1. Explain what will change.
2. Make the change.
3. Run tests/type checks/lint/build.
4. Report the results.
5. Fix regressions before moving on.

### Step 4 — Preserve working functionality

Before modifying existing code:

- inspect it
- understand its dependencies
- preserve compatible behavior
- avoid unnecessary rewrites

### Step 5 — Verify claims

If Codex says a feature is "functional", it must demonstrate the relevant request/data flow rather than merely showing a UI.

---

# 40. FINAL CODEX RULE

**The repository is the source of truth for existing implementation.  
This handover is the source of truth for project direction.  
The LIGHT-HIDS paper is the source of truth for research-specific claims.**

When these appear to conflict:

1. Do not silently overwrite existing code.
2. Report the conflict.
3. Explain the technical reason.
4. Propose the smallest safe resolution.
5. Wait for approval if the change is architectural or destructive.

Do not fabricate functionality.

Do not fabricate research claims.

Do not fabricate ML.

Do not remove LIGHT-HIDS.

Do not make ML mandatory.

Build a real cybersecurity workflow from data ingestion through detection, storage, API delivery, and analyst investigation.
