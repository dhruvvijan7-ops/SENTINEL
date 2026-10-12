-- ============================================================================
-- Sentinel Light HIDS — Stage 6 storage schema (companion to
-- stage-6-platform-storage-jobs-api-testing-release.md §1)
--
-- Target engine : PostgreSQL 18 (current stable as of 2026-10-10; 19 is Beta 4)
-- Conventions   : every tenant-scoped table carries tenant_id + workspace_id;
--                 RLS is ENABLEd on all of them (single-tenant-first: the
--                 default tenant/workspace literals are 'default'); UUID PKs
--                 are uuidv7() where time-ordered identity matters (events,
--                 findings, jobs, uploads — VERIFIED: uuidv7() is native in
--                 PG 18, docs/18/functions-uuid.html).
-- Tenancy model : application sets, per transaction,
--                     SELECT set_config('sentinel.tenant_id',  $tenant, true);
--                     SELECT set_config('sentinel.workspace_id', $ws,    true);
--                 every RLS policy compares the row's columns to
--                 current_setting('sentinel.tenant_id', true).  The app role
--                 is NOT owner of the tables (no BYPASSRLS); the schema owner
--                 is a separate migration role.
-- Evidence model: findings.evidence_snapshot is an immutable JSONB freeze of
--                 the full finding document + rule version + config hash at
--                 detection time.  It does NOT reference raw bytes.  Purging
--                 raw objects (retention) therefore never destroys evidence —
--                 reject-condition #1.
-- Partitioning  : events, findings, audit_log are RANGE-partitioned by month
--                 on their UTC instant column (declarative partitioning,
--                 VERIFIED docs/18/ddl-partitioning.html §5.12.2).  A
--                 maintenance job creates future partitions; a pg_partman-
--                 free design keeps the logic in our job system.
-- Retention     : raw_objects rows carry retention_until + legal_hold; the
--                 purge job archives-then-deletes; uploads metadata outlives
--                 the bytes by a configurable grace period (default 90 PROPOSED).
-- Frozen shape  : 21 base tables, 12 partition children, 33 RLS policies.
--                 These three numbers are frozen at M0 and asserted by
--                 tests/contract/test_rls_lint.py; changing any of them is a
--                 spec §10 contract change and needs a spec amendment first.
-- ============================================================================

BEGIN;

-- ---------------------------------------------------------------------------
-- 0. Extensions
-- ---------------------------------------------------------------------------
CREATE EXTENSION IF NOT EXISTS pgcrypto;   -- gen_random_uuid fallback, digest()
                                            -- (PostgreSQL Licence — VERIFIED)

-- ---------------------------------------------------------------------------
-- 1. Tenancy & identity
-- ---------------------------------------------------------------------------
CREATE TABLE tenants (
    id          text PRIMARY KEY,                  -- 'default' from day 1 (D-001)
    name        text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    disabled_at timestamptz
);

CREATE TABLE workspaces (
    id          text NOT NULL,
    tenant_id   text NOT NULL REFERENCES tenants(id),
    name        text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    disabled_at timestamptz,
    PRIMARY KEY (tenant_id, id)
);

INSERT INTO tenants (id, name) VALUES ('default', 'Default tenant') ON CONFLICT DO NOTHING;
INSERT INTO workspaces (id, tenant_id, name) VALUES ('default', 'default', 'Default workspace') ON CONFLICT DO NOTHING;

CREATE TABLE principals (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   text NOT NULL,
    workspace_id text NOT NULL,
    kind        text NOT NULL CHECK (kind IN ('api_key','oidc','service')),
    display_name text NOT NULL,
    key_hash    bytea,                            -- Argon2id of the API key; null for OIDC
    scopes      text[] NOT NULL DEFAULT '{}',     -- e.g. {'upload','read:events','write:rules'}
    created_at  timestamptz NOT NULL DEFAULT now(),
    revoked_at  timestamptz,
    UNIQUE (tenant_id, key_hash)
);

-- ---------------------------------------------------------------------------
-- 2. Content-addressed raw store + accepted-upload record (Stage 3 §1.6–§1.7)
-- ---------------------------------------------------------------------------
CREATE TABLE raw_objects (
    sha256          bytea PRIMARY KEY,            -- storage_key == sha256
    size            bigint NOT NULL CHECK (size > 0),
    refcount        integer NOT NULL DEFAULT 1,   -- dedup: one object, many uploads
    storage_uri     text NOT NULL,                -- file:// or s3:// hot location
    archive_uri     text,                         -- cold location after archive step
    state           text NOT NULL DEFAULT 'hot'
                        CHECK (state IN ('hot','archived','purged')),
    retention_until timestamptz NOT NULL,         -- computed at ingest from policy
    legal_hold      boolean NOT NULL DEFAULT false,
    created_at      timestamptz NOT NULL DEFAULT now(),
    purged_at       timestamptz,
    CHECK (state <> 'purged' OR purged_at IS NOT NULL)
);

CREATE TABLE uploads (
    artifact_id   uuid PRIMARY KEY DEFAULT uuidv7(),
    tenant_id     text NOT NULL,
    workspace_id  text NOT NULL,
    run_id        text NOT NULL,
    sha256        bytea NOT NULL REFERENCES raw_objects(sha256),
    sha1          bytea,                          -- computed at gate; nullable
    md5           bytea,
    size          bigint NOT NULL CHECK (size > 0),
    original_filename text NOT NULL,              -- verbatim, opaque
    display_name  text NOT NULL,                  -- sanitised (Stage 3 §1.4)
    motw_zone_id  integer,
    motw_referrer_url text,
    motw_source   text CHECK (motw_source IN ('agent','upload_field','absent')),
    agent_id      text,
    collection_kind text,
    source_path   text,                           -- endpoint path; never opened server-side
    received_at   timestamptz NOT NULL DEFAULT now(),
    gate_warnings text[] NOT NULL DEFAULT '{}',
    triage_state  text NOT NULL DEFAULT 'queued'
                    CHECK (triage_state IN ('queued','running','done','failed','rejected_by_policy'))
);

CREATE INDEX uploads_tenant_ws_idx ON uploads (tenant_id, workspace_id, received_at DESC);
CREATE INDEX uploads_run_idx       ON uploads (tenant_id, workspace_id, run_id);

-- ---------------------------------------------------------------------------
-- 3. Ingested canonical events (canonical-event/v1) — partitioned monthly by
--    ingest_time (always present; retention runs from ingest — D6-016).
--    event_time_utc stays NULLable: Stage 2 D2-003 allows a bare null when
--    time.state is unknown/invalid; such events still land in the normal
--    monthly partition of their ingest month (no special routing needed).
--    Indexed columns are the envelope's typed fields; `document` holds the
--    complete validated envelope JSONB (lossless — Stage 1 §6.1).
--    PK includes the partition key because PostgreSQL requires unique
--    constraints on partitioned tables to include all partition columns.
-- ---------------------------------------------------------------------------
CREATE TABLE events (
    event_uid        uuid NOT NULL DEFAULT uuidv7(),
    tenant_id        text NOT NULL,
    workspace_id     text NOT NULL,
    run_id           text NOT NULL,
    artifact_id      uuid NOT NULL REFERENCES uploads(artifact_id),
    event_time_utc   timestamptz,                 -- NULL allowed (time.state != ok)
    event_time_state text NOT NULL
                        CHECK (event_time_state IN ('ok','inferred','unknown','invalid')),
    ingest_time      timestamptz NOT NULL DEFAULT now(),
    event_category   text NOT NULL,               -- 26 values (Stage 2 §1.2)
    event_type       text NOT NULL,
    event_action     text NOT NULL,
    event_outcome    text NOT NULL CHECK (event_outcome IN ('success','failure','unknown')),
    event_severity   text NOT NULL
                        CHECK (event_severity IN ('informational','low','medium','high','critical')),
    event_derived_by text NOT NULL CHECK (event_derived_by IN ('source','sentinel')),
    classification   text NOT NULL
                        CHECK (classification IN ('public','internal','restricted')),
                                           -- data-sensitivity axis (Stage-1 §6.4); third of
                                           -- three non-collapsible axes; drives export/redaction
    host_hostname    text,
    user_name        text,
    user_sid         text,
    source_format    text NOT NULL,
    source_parser    text NOT NULL,
    source_channel   text,
    source_provider  text,
    source_event_id  text,
    source_record_type text NOT NULL,
    document         jsonb NOT NULL,              -- full canonical-event/v1 envelope
    PRIMARY KEY (event_uid, ingest_time)
) PARTITION BY RANGE (ingest_time);

-- Monthly partitions for the MVP window; the partition-maintenance job
-- (Stage 6 §2, job type 'partition_maintain') creates the next N months.
CREATE TABLE events_2026_10 PARTITION OF events
    FOR VALUES FROM ('2026-10-01') TO ('2026-11-01');
CREATE TABLE events_2026_11 PARTITION OF events
    FOR VALUES FROM ('2026-11-01') TO ('2026-12-01');
CREATE TABLE events_2026_12 PARTITION OF events
    FOR VALUES FROM ('2026-12-01') TO ('2027-01-01');

CREATE INDEX events_tenant_ws_time_idx ON events (tenant_id, workspace_id, event_time_utc DESC);
CREATE INDEX events_tenant_ws_ingest_idx ON events (tenant_id, workspace_id, ingest_time DESC);
CREATE INDEX events_run_idx            ON events (tenant_id, workspace_id, run_id);
CREATE INDEX events_artifact_idx       ON events (artifact_id);
CREATE INDEX events_category_idx       ON events (tenant_id, workspace_id, event_category);
CREATE INDEX events_doc_gin            ON events USING gin (document jsonb_path_ops);

-- ---------------------------------------------------------------------------
-- 4. Detection rule storage (Stage 5 D5-001 storage split)
-- ---------------------------------------------------------------------------
CREATE TABLE rules (
    rule_id         uuid NOT NULL,                -- our stable id (Stage 1 §6.2)
    tenant_id       text NOT NULL,
    workspace_id    text NOT NULL,
    name            text NOT NULL,
    kind            text NOT NULL
                        CHECK (kind IN ('sigma','correlation','ioc','fim','sca','statistical','artifact')),
    schema_tag      text NOT NULL DEFAULT 'sentinel-rule/v1',
    source          text NOT NULL,                -- sigma|falco|yara|suricata|wazuh|native
    source_id       text,                         -- upstream id, verbatim
    source_ref      text,
    source_spec     text,
    license         text NOT NULL,
    author          text NOT NULL,
    title           text NOT NULL,
    description     text,
    status          text NOT NULL,                -- verbatim upstream
    level_original  text,                         -- verbatim upstream, never rewritten
    severity        text NOT NULL CHECK (severity IN ('LOW','MEDIUM','HIGH')),
    enabled         boolean NOT NULL DEFAULT true,
    document        jsonb NOT NULL,               -- schema-validated normalized doc
    compile         jsonb,                        -- engine-owned (detection_path, prefilters…)
    provenance      jsonb,
    imported_at     timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    deleted_at      timestamptz,
    PRIMARY KEY (tenant_id, workspace_id, rule_id),
    UNIQUE (tenant_id, workspace_id, source_id)
);

CREATE TABLE rule_source (
    tenant_id    text NOT NULL,
    workspace_id text NOT NULL,
    rule_id      uuid NOT NULL,
    text         text NOT NULL,                   -- verbatim upstream bytes as text
    sha256       bytea NOT NULL,
    imported_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, workspace_id, rule_id, sha256)
);

CREATE TABLE rule_baseline (
    tenant_id     text NOT NULL,
    workspace_id  text NOT NULL,
    rule_id       uuid NOT NULL,
    baseline_key  text NOT NULL,                  -- group_by tuple, serialized
    bucket_start  timestamptz NOT NULL,
    bucket_span   interval NOT NULL,
    measure       double precision,               -- rate/proportion value or NULL for rare_value
    observations  bigint NOT NULL DEFAULT 0,
    extras        jsonb NOT NULL DEFAULT '{}',    -- rare_value: value-frequency sketch
    PRIMARY KEY (tenant_id, workspace_id, rule_id, baseline_key, bucket_start)
) PARTITION BY RANGE (bucket_start);

CREATE TABLE rule_baseline_2026 PARTITION OF rule_baseline
    FOR VALUES FROM ('2026-01-01') TO ('2027-01-01');
CREATE TABLE rule_baseline_2027 PARTITION OF rule_baseline
    FOR VALUES FROM ('2027-01-01') TO ('2028-01-01');

CREATE TABLE fim_baseline (
    tenant_id     text NOT NULL,
    workspace_id  text NOT NULL,
    host_key      text NOT NULL,                  -- agent_id or hostname
    path          text NOT NULL,
    size          bigint,
    mtime         timestamptz,
    sha256        bytea,
    uploaded_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, workspace_id, host_key, path, uploaded_at)
);

CREATE TABLE ioc_pack (
    pack_id       uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     text NOT NULL,
    workspace_id  text NOT NULL,
    name          text NOT NULL,
    version       text NOT NULL,
    sha256        bytea NOT NULL,                 -- digest of the pack document
    signature     bytea,                          -- Ed25519 (D4-003); NULL only in dev
    signing_key_id text,
    status        text NOT NULL DEFAULT 'pending_verify'  -- C-11 (was 'active'): verify-then-activate
                      CHECK (status IN ('pending_verify','active','rejected','retired')),
    imported_at   timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, workspace_id, name, version)
);

CREATE TABLE ioc_entry (
    tenant_id     text NOT NULL,
    workspace_id  text NOT NULL,
    pack_id       uuid NOT NULL REFERENCES ioc_pack(pack_id) ON DELETE CASCADE,
    kind          text NOT NULL CHECK (kind IN ('sha256','sha1','md5','ipv4','ipv6','domain','url')),
    value_hash    bytea NOT NULL,                 -- sha256 of normalized value
    value_norm    text NOT NULL,                  -- normalized exact-confirm value
    bloom_slot    bigint,                         -- prefilter slot (D5-007 Bloom layer)
    PRIMARY KEY (tenant_id, workspace_id, pack_id, kind, value_hash)
);

-- ---------------------------------------------------------------------------
-- 5. Job queue (Stage 6 §2) — FOR UPDATE SKIP LOCKED (VERIFIED syntax,
--    docs/18/sql-select.html: FOR {UPDATE|...} [NOWAIT|SKIP LOCKED])
-- ---------------------------------------------------------------------------
CREATE TABLE jobs (
    job_id          uuid PRIMARY KEY DEFAULT uuidv7(),
    tenant_id       text NOT NULL,
    workspace_id    text NOT NULL,
    job_type        text NOT NULL,                -- ingest_file|detect_run|ioc_import|purge_raw|partition_maintain|…
    payload         jsonb NOT NULL DEFAULT '{}',
    status          text NOT NULL DEFAULT 'queued'
                        CHECK (status IN ('queued','running','succeeded','failed','dead','cancelled')),
    priority        integer NOT NULL DEFAULT 100, -- lower = sooner
    run_after       timestamptz NOT NULL DEFAULT now(),
    attempts        integer NOT NULL DEFAULT 0,
    max_attempts    integer NOT NULL DEFAULT 5,
    locked_by       text,                         -- worker identity
    locked_at       timestamptz,
    heartbeat_at    timestamptz,
    idempotency_key text,
    last_error      text,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    finished_at     timestamptz
);

-- The claim index: workers SELECT ... WHERE status='queued' AND run_after<=now()
--                   ORDER BY priority, run_after FOR UPDATE SKIP LOCKED LIMIT 1;
CREATE INDEX jobs_claim_idx ON jobs (status, priority, run_after)
    WHERE status = 'queued';
CREATE INDEX jobs_lock_idx  ON jobs (locked_at)
    WHERE status = 'running';
CREATE UNIQUE INDEX jobs_idem_idx ON jobs (tenant_id, workspace_id, idempotency_key)
    WHERE idempotency_key IS NOT NULL;

CREATE TABLE job_attempts (
    job_id      uuid NOT NULL REFERENCES jobs(job_id) ON DELETE CASCADE,
    attempt     integer NOT NULL,
    worker      text NOT NULL,
    started_at  timestamptz NOT NULL DEFAULT now(),
    finished_at timestamptz,
    outcome     text CHECK (outcome IN ('succeeded','failed','lost_lock')),
    error       text,
    PRIMARY KEY (job_id, attempt)
);

-- ---------------------------------------------------------------------------
-- 6. Detection runs, per-rule accounting, findings
-- ---------------------------------------------------------------------------
CREATE TABLE detection_runs (
    run_id        uuid PRIMARY KEY DEFAULT uuidv7(),
    tenant_id     text NOT NULL,
    workspace_id  text NOT NULL,
    requested_by  text NOT NULL,                  -- principal id
    scope         jsonb NOT NULL DEFAULT '{}',    -- filters: time range, hosts, categories, rule selection
    status        text NOT NULL DEFAULT 'queued'
                    CHECK (status IN ('queued','running','completed','completed_with_warnings','failed','cancelled')),
    config_hash   bytea NOT NULL,                 -- engine config at run start
    started_at    timestamptz,
    finished_at   timestamptz,
    summary       jsonb,                          -- counts, duration, per-kind breakdown
    created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE rule_run (
    run_id           uuid NOT NULL REFERENCES detection_runs(run_id) ON DELETE CASCADE,
    rule_id          uuid NOT NULL,
    outcome          text NOT NULL
                        CHECK (outcome IN ('ok','ok_partial','rejected','skipped','error')),
    findings         integer NOT NULL DEFAULT 0,
    processed_events bigint NOT NULL DEFAULT 0,
    rejected_events  bigint NOT NULL DEFAULT 0,
    max_group_size   integer,
    max_window_ms    bigint,                          -- C-5: longest window closed this run (ms)
    sql_ms           bigint,                          -- C-5: SQL-path execution time (ms)
    native_ms        bigint,                          -- C-5: native-path execution time (ms)
    detection_path   text CHECK (detection_path IN ('sql','native')),
    reason_codes     text[] NOT NULL DEFAULT '{}',
    started_at       timestamptz NOT NULL DEFAULT now(),
    finished_at      timestamptz,
    PRIMARY KEY (run_id, rule_id)
);

CREATE TABLE findings (
    finding_uid      uuid NOT NULL DEFAULT uuidv7(),
    tenant_id        text NOT NULL,
    workspace_id     text NOT NULL,
    run_id           uuid NOT NULL,
    rule_id          uuid NOT NULL,
    rule_name        text NOT NULL,
    author           text NOT NULL,              -- DRL 1.1: rule author flows to every alert
                                              -- (D6-001 lineage; native rules use 'sentinel')
    kind             text NOT NULL,
    severity         text NOT NULL CHECK (severity IN ('LOW','MEDIUM','HIGH')),
    level_original   text,                            -- C-3b: verbatim upstream rule level
                                              -- (informational..critical / tool-native);
                                              -- NULL when the source carries no level
    time_utc         timestamptz NOT NULL,
    host_hostname    text,
    user_name        text,
    detection_path   text NOT NULL CHECK (detection_path IN ('sql','native')),
    reason_codes     text[] NOT NULL DEFAULT '{}',
    fingerprint      bytea NOT NULL,              -- sha256 of stable identity tuple
    event_uids       uuid[] NOT NULL DEFAULT '{}',
    evidence_snapshot jsonb NOT NULL,             -- immutable freeze; never references raw bytes
    first_seen       timestamptz NOT NULL DEFAULT now(),
    last_seen        timestamptz NOT NULL DEFAULT now(),
    occurrence_count integer NOT NULL DEFAULT 1,
    triage_state     text NOT NULL DEFAULT 'new'
                        CHECK (triage_state IN ('new','acknowledged','escalated','resolved','false_positive')),
    -- Partition key is in the PK (PG requirement). Fingerprint uniqueness is
    -- enforced within a time bucket; cross-month duplicates are impossible in
    -- practice because finalize() dedups against the run window (D6-013).
    PRIMARY KEY (finding_uid, time_utc),
    UNIQUE (tenant_id, workspace_id, rule_id, fingerprint, time_utc)
) PARTITION BY RANGE (time_utc);

CREATE TABLE findings_2026_10 PARTITION OF findings
    FOR VALUES FROM ('2026-10-01') TO ('2026-11-01');
CREATE TABLE findings_2026_11 PARTITION OF findings
    FOR VALUES FROM ('2026-11-01') TO ('2026-12-01');
CREATE TABLE findings_2026_12 PARTITION OF findings
    FOR VALUES FROM ('2026-12-01') TO ('2027-01-01');
-- M2-A12: findings.time_utc is the *event* instant (the §6.6 timeline unions
-- findings with events by their own time), so a capture imported today can
-- carry an event from any date in the past.  The three maintained monthly
-- partitions above only cover the MVP window; without this catch-all the
-- INSERT fails with "no partition of relation findings found for row" and the
-- whole vertical slice dies on the first historical EVTX.  partition_maintain
-- may later ATTACH a tighter range by sweeping this child first.
CREATE TABLE findings_default PARTITION OF findings DEFAULT;

CREATE INDEX findings_tenant_ws_time_idx ON findings (tenant_id, workspace_id, time_utc DESC);
CREATE INDEX findings_rule_idx           ON findings (tenant_id, workspace_id, rule_id, time_utc DESC);
CREATE INDEX findings_sev_idx            ON findings (tenant_id, workspace_id, severity, time_utc DESC);

-- ---------------------------------------------------------------------------
-- 7. Artifact facts (Stage 3 §12) — the only detector-visible fact store
--    for `kind: artifact` rules; artifact_finding output is a canonical
--    events row (category = artifact_finding), not a second table.
-- ---------------------------------------------------------------------------
CREATE TABLE artifact_facts (
    fact_uid      uuid PRIMARY KEY DEFAULT uuidv7(),
    tenant_id     text NOT NULL,
    workspace_id  text NOT NULL,
    run_id        text NOT NULL,
    artifact_id   uuid NOT NULL REFERENCES uploads(artifact_id),
    namespace     text NOT NULL,                  -- pe|ooxml|pdf|archive|…
    fact_name     text NOT NULL,
    fact_value    jsonb NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX artifact_facts_artifact_idx ON artifact_facts (artifact_id);
CREATE INDEX artifact_facts_ns_idx       ON artifact_facts (tenant_id, workspace_id, namespace, fact_name);

-- ---------------------------------------------------------------------------
-- 8. API plumbing: idempotency, audit, retention policy
-- ---------------------------------------------------------------------------
CREATE TABLE idempotency_keys (
    key           text NOT NULL,
    principal_id  uuid NOT NULL REFERENCES principals(id),
    request_hash  bytea NOT NULL,
    response_code integer NOT NULL,
    response_body jsonb,
    created_at    timestamptz NOT NULL DEFAULT now(),
    expires_at    timestamptz NOT NULL,
    PRIMARY KEY (principal_id, key)
);

CREATE TABLE audit_log (
    audit_uid   uuid NOT NULL DEFAULT uuidv7(),
    tenant_id   text NOT NULL,
    workspace_id text NOT NULL,
    at          timestamptz NOT NULL DEFAULT now(),
    principal   text,
    action      text NOT NULL,                    -- e.g. rule.import, upload.reject, retention.override
    object_kind text,
    object_id   text,
    outcome     text NOT NULL CHECK (outcome IN ('ok','denied','error')),
    detail      jsonb NOT NULL DEFAULT '{}',
    PRIMARY KEY (audit_uid, at)
) PARTITION BY RANGE (at);

CREATE TABLE audit_log_2026_10 PARTITION OF audit_log
    FOR VALUES FROM ('2026-10-01') TO ('2026-11-01');
CREATE TABLE audit_log_2026_11 PARTITION OF audit_log
    FOR VALUES FROM ('2026-11-01') TO ('2026-12-01');
CREATE TABLE audit_log_2026_12 PARTITION OF audit_log
    FOR VALUES FROM ('2026-12-01') TO ('2027-01-01');

CREATE TABLE retention_policies (
    tenant_id     text NOT NULL,
    workspace_id  text NOT NULL,
    scope_kind    text NOT NULL CHECK (scope_kind IN ('raw_object','event','finding','audit','rejected_upload')),
    scope_match   text NOT NULL DEFAULT '*',      -- category or '*' 
    retention_days integer NOT NULL CHECK (retention_days > 0),
    updated_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, workspace_id, scope_kind, scope_match)
);

INSERT INTO retention_policies (tenant_id, workspace_id, scope_kind, retention_days) VALUES
    ('default','default','raw_object',       90),
    ('default','default','event',           365),
    ('default','default','finding',         730),
    ('default','default','audit',           365),
    ('default','default','rejected_upload',  90);

-- ---------------------------------------------------------------------------
-- 9. Row-Level Security (VERIFIED mechanism: docs/18/ddl-rowsecurity.html)
--    Policies are created only on tables that exist at this point; the app
--    role has no BYPASSRLS.  current_setting(..., true) returns NULL for
--    unset vars, so an unscoped session sees zero rows.
--
--    Frozen counts (M0-A1 amendment, see research/DEVIATION_REGISTER.md):
--      21 base tables + 11 partition children  = 32 relations
--      32 CREATE POLICY statements             = 20 base-table policies
--                                                + 11 partition policies
--                                                + 1 raw_objects_cas exemption
--    (The M0 plan text said 31; the true count is 32 because there are 11
--     partition children, not 10. Recorded as an M0-A1 correction in
--     research/DEVIATION_REGISTER.md.)
--    Every tenant-column table AND every partition child carries both
--    ENABLE ROW LEVEL SECURITY and at least one policy — enforced by
--    tests/contract/test_rls_lint.py (policy-less ENABLEd tables were the
--    M1-D3 defect this layout closes).
-- ---------------------------------------------------------------------------
ALTER TABLE tenants            ENABLE ROW LEVEL SECURITY;
ALTER TABLE workspaces         ENABLE ROW LEVEL SECURITY;
ALTER TABLE principals         ENABLE ROW LEVEL SECURITY;
ALTER TABLE raw_objects        ENABLE ROW LEVEL SECURITY;  -- shared CAS, no tenant column; pass-through policy raw_objects_cas below (see M1-D3 / M0 resolution in research/DEVIATION_REGISTER.md)
ALTER TABLE uploads            ENABLE ROW LEVEL SECURITY;
ALTER TABLE events             ENABLE ROW LEVEL SECURITY;
ALTER TABLE rules              ENABLE ROW LEVEL SECURITY;
ALTER TABLE rule_source        ENABLE ROW LEVEL SECURITY;
ALTER TABLE rule_baseline      ENABLE ROW LEVEL SECURITY;
ALTER TABLE fim_baseline       ENABLE ROW LEVEL SECURITY;
ALTER TABLE ioc_pack           ENABLE ROW LEVEL SECURITY;
ALTER TABLE ioc_entry          ENABLE ROW LEVEL SECURITY;
ALTER TABLE jobs               ENABLE ROW LEVEL SECURITY;
ALTER TABLE job_attempts       ENABLE ROW LEVEL SECURITY;
ALTER TABLE detection_runs     ENABLE ROW LEVEL SECURITY;
ALTER TABLE rule_run           ENABLE ROW LEVEL SECURITY;
ALTER TABLE findings           ENABLE ROW LEVEL SECURITY;
ALTER TABLE artifact_facts     ENABLE ROW LEVEL SECURITY;
ALTER TABLE idempotency_keys   ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_log          ENABLE ROW LEVEL SECURITY;
ALTER TABLE retention_policies ENABLE ROW LEVEL SECURITY;

-- Partition children inherit their parent's RLS *policies* only when the
-- parent is the target of ALTER ... ENABLE; declarative children do NOT
-- inherit ENABLE ROW LEVEL SECURITY, so each child is enabled and policed
-- explicitly (M0-A1; required for the cross-tenant probe to hold on a direct
-- SELECT against a partition).
ALTER TABLE events_2026_10      ENABLE ROW LEVEL SECURITY;
ALTER TABLE events_2026_11      ENABLE ROW LEVEL SECURITY;
ALTER TABLE events_2026_12      ENABLE ROW LEVEL SECURITY;
ALTER TABLE findings_2026_10    ENABLE ROW LEVEL SECURITY;
ALTER TABLE findings_2026_11    ENABLE ROW LEVEL SECURITY;
ALTER TABLE findings_2026_12    ENABLE ROW LEVEL SECURITY;
ALTER TABLE findings_default    ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_log_2026_10   ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_log_2026_11   ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_log_2026_12   ENABLE ROW LEVEL SECURITY;
ALTER TABLE rule_baseline_2026  ENABLE ROW LEVEL SECURITY;
ALTER TABLE rule_baseline_2027  ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenants_ws ON tenants
    USING (id = current_setting('sentinel.tenant_id', true));

CREATE POLICY workspaces_ws ON workspaces
    USING (tenant_id = current_setting('sentinel.tenant_id', true)
           AND id = current_setting('sentinel.workspace_id', true));

CREATE POLICY principals_ws ON principals
    USING (tenant_id = current_setting('sentinel.tenant_id', true)
           AND workspace_id = current_setting('sentinel.workspace_id', true));

CREATE POLICY uploads_ws ON uploads
    USING (tenant_id = current_setting('sentinel.tenant_id', true)
           AND workspace_id = current_setting('sentinel.workspace_id', true));

CREATE POLICY events_ws ON events
    USING (tenant_id = current_setting('sentinel.tenant_id', true)
           AND workspace_id = current_setting('sentinel.workspace_id', true));

CREATE POLICY events_2026_10_ws ON events_2026_10
    USING (tenant_id = current_setting('sentinel.tenant_id', true)
           AND workspace_id = current_setting('sentinel.workspace_id', true));

CREATE POLICY events_2026_11_ws ON events_2026_11
    USING (tenant_id = current_setting('sentinel.tenant_id', true)
           AND workspace_id = current_setting('sentinel.workspace_id', true));

CREATE POLICY events_2026_12_ws ON events_2026_12
    USING (tenant_id = current_setting('sentinel.tenant_id', true)
           AND workspace_id = current_setting('sentinel.workspace_id', true));

CREATE POLICY rules_ws ON rules
    USING (tenant_id = current_setting('sentinel.tenant_id', true)
           AND workspace_id = current_setting('sentinel.workspace_id', true));

CREATE POLICY rule_source_ws ON rule_source
    USING (tenant_id = current_setting('sentinel.tenant_id', true)
           AND workspace_id = current_setting('sentinel.workspace_id', true));

CREATE POLICY rule_baseline_ws ON rule_baseline
    USING (tenant_id = current_setting('sentinel.tenant_id', true)
           AND workspace_id = current_setting('sentinel.workspace_id', true));

CREATE POLICY rule_baseline_2026_ws ON rule_baseline_2026
    USING (tenant_id = current_setting('sentinel.tenant_id', true)
           AND workspace_id = current_setting('sentinel.workspace_id', true));

CREATE POLICY rule_baseline_2027_ws ON rule_baseline_2027
    USING (tenant_id = current_setting('sentinel.tenant_id', true)
           AND workspace_id = current_setting('sentinel.workspace_id', true));

CREATE POLICY fim_baseline_ws ON fim_baseline
    USING (tenant_id = current_setting('sentinel.tenant_id', true)
           AND workspace_id = current_setting('sentinel.workspace_id', true));

CREATE POLICY ioc_pack_ws ON ioc_pack
    USING (tenant_id = current_setting('sentinel.tenant_id', true)
           AND workspace_id = current_setting('sentinel.workspace_id', true));

CREATE POLICY ioc_entry_ws ON ioc_entry
    USING (tenant_id = current_setting('sentinel.tenant_id', true)
           AND workspace_id = current_setting('sentinel.workspace_id', true));

CREATE POLICY jobs_ws ON jobs
    USING (tenant_id = current_setting('sentinel.tenant_id', true)
           AND workspace_id = current_setting('sentinel.workspace_id', true));

CREATE POLICY job_attempts_ws ON job_attempts
    USING (EXISTS (SELECT 1 FROM jobs j
                   WHERE j.job_id = job_attempts.job_id
                     AND j.tenant_id = current_setting('sentinel.tenant_id', true)
                     AND j.workspace_id = current_setting('sentinel.workspace_id', true)));

CREATE POLICY detection_runs_ws ON detection_runs
    USING (tenant_id = current_setting('sentinel.tenant_id', true)
           AND workspace_id = current_setting('sentinel.workspace_id', true));

CREATE POLICY rule_run_ws ON rule_run
    USING (EXISTS (SELECT 1 FROM detection_runs d
                   WHERE d.run_id = rule_run.run_id
                     AND d.tenant_id = current_setting('sentinel.tenant_id', true)
                     AND d.workspace_id = current_setting('sentinel.workspace_id', true)));

CREATE POLICY findings_ws ON findings
    USING (tenant_id = current_setting('sentinel.tenant_id', true)
           AND workspace_id = current_setting('sentinel.workspace_id', true));

CREATE POLICY findings_2026_10_ws ON findings_2026_10
    USING (tenant_id = current_setting('sentinel.tenant_id', true)
           AND workspace_id = current_setting('sentinel.workspace_id', true));

CREATE POLICY findings_2026_11_ws ON findings_2026_11
    USING (tenant_id = current_setting('sentinel.tenant_id', true)
           AND workspace_id = current_setting('sentinel.workspace_id', true));

CREATE POLICY findings_2026_12_ws ON findings_2026_12
    USING (tenant_id = current_setting('sentinel.tenant_id', true)
           AND workspace_id = current_setting('sentinel.workspace_id', true));

CREATE POLICY findings_default_ws ON findings_default
    USING (tenant_id = current_setting('sentinel.tenant_id', true)
           AND workspace_id = current_setting('sentinel.workspace_id', true));

CREATE POLICY artifact_facts_ws ON artifact_facts
    USING (tenant_id = current_setting('sentinel.tenant_id', true)
           AND workspace_id = current_setting('sentinel.workspace_id', true));

CREATE POLICY idempotency_keys_ws ON idempotency_keys
    USING (principal_id IN (SELECT id FROM principals
                            WHERE tenant_id = current_setting('sentinel.tenant_id', true)
                              AND workspace_id = current_setting('sentinel.workspace_id', true)));

CREATE POLICY audit_log_ws ON audit_log
    USING (tenant_id = current_setting('sentinel.tenant_id', true)
           AND workspace_id = current_setting('sentinel.workspace_id', true));

CREATE POLICY audit_log_2026_10_ws ON audit_log_2026_10
    USING (tenant_id = current_setting('sentinel.tenant_id', true)
           AND workspace_id = current_setting('sentinel.workspace_id', true));

CREATE POLICY audit_log_2026_11_ws ON audit_log_2026_11
    USING (tenant_id = current_setting('sentinel.tenant_id', true)
           AND workspace_id = current_setting('sentinel.workspace_id', true));

CREATE POLICY audit_log_2026_12_ws ON audit_log_2026_12
    USING (tenant_id = current_setting('sentinel.tenant_id', true)
           AND workspace_id = current_setting('sentinel.workspace_id', true));

CREATE POLICY retention_policies_ws ON retention_policies
    USING (tenant_id = current_setting('sentinel.tenant_id', true)
           AND workspace_id = current_setting('sentinel.workspace_id', true));

-- raw_objects has no tenant column (shared CAS across workspaces by design);
-- access is mediated entirely through uploads (app-level join) — see Stage 6
-- §1.4 for the rationale and the INFERRED-marked alternative.
--
-- RLS is ENABLEd (above) but has no tenant predicate to apply, so without a
-- policy the table would be *empty* for the non-owner app role: an ENABLEd
-- table with no policy denies everything.  M0 fixes that by giving it an
-- explicit pass-through policy.  This is the ONE documented exemption from
-- the "every policy references sentinel.tenant_id/workspace_id" rule, and it
-- is pinned by tests/contract/test_rls_lint.py (POLICY_EXEMPTIONS).
CREATE POLICY raw_objects_cas ON raw_objects
    USING (true)
    WITH CHECK (true);

COMMIT;
