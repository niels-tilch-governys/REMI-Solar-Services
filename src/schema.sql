-- ============================================================
--  REMI Solar Services — AI Email Triage
--  Created by GOVERNYS (Niels Tilch — CTO)
-- ============================================================
-- =====================================================================
--  REMI Solar Services — AI Email Triage MVP
--  SQLite schema (translated from remi_solar_schema.dbml v0.2)
--  Enums are enforced via CHECK constraints (SQLite has no native enum).
-- =====================================================================
PRAGMA foreign_keys = ON;

-- ---------- Identity & access ----------
CREATE TABLE roles (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  name        TEXT NOT NULL UNIQUE,
  description TEXT
);

CREATE TABLE departments (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  uuid          TEXT UNIQUE,             -- UUIDv7
  name          TEXT NOT NULL UNIQUE,
  email_address TEXT UNIQUE,              -- e.g. it@remi-solar.eu
  description   TEXT
);

CREATE TABLE users (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  uuid          TEXT UNIQUE,             -- UUIDv7
  full_name     TEXT NOT NULL,
  email         TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,            -- bcrypt hash
  role_id       INTEGER NOT NULL REFERENCES roles(id),
  department_id INTEGER REFERENCES departments(id),
  is_active     INTEGER NOT NULL DEFAULT 1,
  mfa_enabled   INTEGER NOT NULL DEFAULT 0,
  mfa_secret    TEXT,                     -- base32 TOTP secret (set when MFA enabled)
  last_login_at TEXT,
  created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ---------- Lookups ----------
CREATE TABLE email_categories (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  description TEXT
);

CREATE TABLE request_types (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE
);

CREATE TABLE priorities (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  level TEXT NOT NULL UNIQUE,
  score_min REAL,
  score_max REAL,
  description TEXT
);

CREATE TABLE mailboxes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  address TEXT,
  department_id INTEGER REFERENCES departments(id),
  is_default INTEGER NOT NULL DEFAULT 0
);

-- ---------- Key-value app settings (confidence threshold, flagged topics) ----------
CREATE TABLE app_settings (
  key   TEXT PRIMARY KEY,
  value TEXT
);

-- ---------- Email ingestion ----------
CREATE TABLE emails (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  uuid            TEXT UNIQUE,           -- UUIDv7, used by the front-end
  message_id      TEXT NOT NULL UNIQUE,
  sender_email    TEXT NOT NULL,
  sender_name     TEXT,
  subject         TEXT,
  body            TEXT,
  received_at     TEXT NOT NULL,
  ingested_at     TEXT NOT NULL DEFAULT (datetime('now')),
  status          TEXT NOT NULL DEFAULT 'received'
                    CHECK (status IN ('received','processing','classified','manual_review','routed','completed','failed')),
  has_attachments INTEGER NOT NULL DEFAULT 0,
  storage_ref     TEXT
);

CREATE TABLE attachments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email_id INTEGER NOT NULL REFERENCES emails(id),
  filename TEXT,
  file_type TEXT DEFAULT 'other' CHECK (file_type IN ('pdf','image','docx','other')),
  file_size INTEGER,
  storage_ref TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ---------- AI processing ----------
CREATE TABLE ocr_results (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  attachment_id INTEGER NOT NULL REFERENCES attachments(id),
  model_version TEXT,
  extracted_text TEXT,
  confidence REAL,
  status TEXT DEFAULT 'pending' CHECK (status IN ('pending','success','failed')),
  processed_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE email_analysis (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email_id INTEGER NOT NULL REFERENCES emails(id),
  category_id INTEGER REFERENCES email_categories(id),
  request_type_id INTEGER REFERENCES request_types(id),
  priority_id INTEGER REFERENCES priorities(id),
  priority_score REAL,
  confidence REAL,
  summary TEXT,
  model_version TEXT,
  is_manual INTEGER NOT NULL DEFAULT 0,
  created_by INTEGER REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE extracted_fields (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email_id INTEGER NOT NULL REFERENCES emails(id),
  analysis_id INTEGER REFERENCES email_analysis(id),
  field_name TEXT NOT NULL,
  field_value TEXT,
  confidence REAL,
  model_version TEXT,
  extracted_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ---------- Routing & human-in-the-loop ----------
CREATE TABLE routing_assignments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email_id INTEGER NOT NULL REFERENCES emails(id),
  analysis_id INTEGER REFERENCES email_analysis(id),
  department_id INTEGER REFERENCES departments(id),
  mailbox_id INTEGER REFERENCES mailboxes(id),
  priority_id INTEGER REFERENCES priorities(id),
  assigned_to INTEGER REFERENCES users(id),
  assigned_by INTEGER REFERENCES users(id),
  is_manual_override INTEGER NOT NULL DEFAULT 0,
  status TEXT DEFAULT 'routed',
  routed_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE review_tasks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email_id INTEGER NOT NULL REFERENCES emails(id),
  analysis_id INTEGER REFERENCES email_analysis(id),
  reason TEXT NOT NULL CHECK (reason IN ('low_confidence','flagged_topic','manual_request')),
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','confirmed','corrected','rejected')),
  assigned_to INTEGER REFERENCES users(id),
  reviewed_by INTEGER REFERENCES users(id),
  notes TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  reviewed_at TEXT
);

-- ---------- Audit & compliance ----------
CREATE TABLE audit_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  uuid TEXT UNIQUE,                       -- UUIDv7, external identifier for the log entry
  email_id INTEGER REFERENCES emails(id),
  user_id INTEGER REFERENCES users(id),
  model_version TEXT,
  action_type TEXT NOT NULL
    CHECK (action_type IN ('ingestion','ocr_extraction','classification','field_extraction','routing','manual_override','access','login','deletion')),
  entity_type TEXT,
  entity_id INTEGER,
  details TEXT,
  ip_address TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE retention_policies (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  category_id INTEGER REFERENCES email_categories(id),
  data_type TEXT NOT NULL,
  retention_days INTEGER NOT NULL,
  action TEXT DEFAULT 'automated' CHECK (action IN ('manual','automated','scheduled')),
  description TEXT
);

CREATE TABLE deletion_records (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email_id INTEGER REFERENCES emails(id),
  policy_id INTEGER REFERENCES retention_policies(id),
  entity_type TEXT,
  entity_id INTEGER,
  type TEXT NOT NULL CHECK (type IN ('manual','automated','scheduled')),
  scope TEXT DEFAULT 'production' CHECK (scope IN ('production','backup','archive','logs')),
  reason TEXT,
  performed_by INTEGER REFERENCES users(id),
  status TEXT DEFAULT 'completed',
  scheduled_at TEXT,
  executed_at TEXT
);

-- ---------- AI usage metering (tokens, pages, scores) ----------
CREATE TABLE ai_usage_events (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  email_id      INTEGER REFERENCES emails(id),
  kind          TEXT NOT NULL CHECK (kind IN ('ocr','classification')),
  provider      TEXT NOT NULL,          -- 'mistral' | 'local'
  model_version TEXT,
  pages         INTEGER DEFAULT 0,
  input_tokens  INTEGER DEFAULT 0,
  output_tokens INTEGER DEFAULT 0,
  confidence    REAL,
  created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

-- indexes
CREATE INDEX idx_emails_status ON emails(status);
CREATE INDEX idx_analysis_email ON email_analysis(email_id);
CREATE INDEX idx_routing_dept ON routing_assignments(department_id);
CREATE INDEX idx_review_status ON review_tasks(status);
CREATE INDEX idx_audit_created ON audit_logs(created_at);
CREATE INDEX idx_usage_kind ON ai_usage_events(kind);
