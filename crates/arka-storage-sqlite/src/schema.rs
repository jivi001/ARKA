//! SQLite DDL and Schema Initializer.

pub const INIT_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS missions (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    state TEXT NOT NULL,
    scope_ref TEXT NOT NULL,
    created_at_unix INTEGER NOT NULL,
    updated_at_unix INTEGER NOT NULL,
    created_by TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS emergency_stop (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    active INTEGER NOT NULL,
    triggered_at_unix INTEGER NOT NULL,
    triggered_by TEXT NOT NULL,
    reason TEXT NOT NULL,
    cleared_at_unix INTEGER,
    cleared_by TEXT,
    clear_reason TEXT
);

CREATE TABLE IF NOT EXISTS replay_log (
    replay_key TEXT PRIMARY KEY,
    mission_id TEXT NOT NULL,
    proposal_id TEXT NOT NULL,
    action_id TEXT NOT NULL,
    consumed_at_unix INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS approvals (
    approval_id TEXT PRIMARY KEY,
    mission_id TEXT NOT NULL,
    action_hash TEXT NOT NULL,
    approver_id TEXT NOT NULL,
    status TEXT NOT NULL,
    issued_at_unix INTEGER NOT NULL,
    expires_at_unix INTEGER NOT NULL,
    consumed_at_unix INTEGER
);

CREATE TABLE IF NOT EXISTS actions (
    action_id TEXT PRIMARY KEY,
    proposal_id TEXT NOT NULL,
    mission_id TEXT NOT NULL,
    capability_id TEXT NOT NULL,
    target TEXT NOT NULL,
    parameter_hash TEXT NOT NULL,
    action_hash TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at_unix INTEGER NOT NULL,
    updated_at_unix INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS system_audit_log (
    event_id TEXT PRIMARY KEY,
    sequence_number INTEGER NOT NULL UNIQUE,
    timestamp_unix INTEGER NOT NULL,
    mission_id TEXT,
    event_type TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    details_json TEXT NOT NULL,
    previous_hash TEXT NOT NULL,
    current_hash TEXT NOT NULL,
    signature TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS mission_audit_log (
    event_id TEXT PRIMARY KEY,
    mission_id TEXT NOT NULL,
    sequence_number INTEGER NOT NULL,
    timestamp_unix INTEGER NOT NULL,
    event_type TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    details_json TEXT NOT NULL,
    previous_hash TEXT NOT NULL,
    current_hash TEXT NOT NULL,
    signature TEXT NOT NULL,
    UNIQUE(mission_id, sequence_number)
);
"#;
