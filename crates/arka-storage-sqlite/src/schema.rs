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
"#;
