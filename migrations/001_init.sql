-- PNC3 Secure Agent Tool Gateway — Level 2 database schema.
-- Applied automatically by the gateway on start when DATABASE_URL is set.
-- Only the audit log needs a database; policy, pins and sessions live in files/Redis.

CREATE TABLE IF NOT EXISTS audit_log (
  seq          BIGINT PRIMARY KEY,            -- position in the hash chain
  id           TEXT UNIQUE NOT NULL,          -- decision/event id (dec-..., evt-...)
  ts           TIMESTAMPTZ NOT NULL,
  type         TEXT NOT NULL,                 -- decision | approval | revocation | manifest | policy
  agent_id     TEXT,
  tool         TEXT,
  verdict      TEXT,                          -- allow | deny | approval | error
  record_json  TEXT NOT NULL,                 -- exact bytes that were signed
  record       JSONB NOT NULL,                -- same content, queryable
  prev_hash    TEXT NOT NULL,                 -- hash of the previous record
  hash         TEXT NOT NULL,                 -- SHA-256 of this record
  sig          TEXT NOT NULL                  -- Ed25519 signature over hash
);
CREATE INDEX IF NOT EXISTS audit_log_agent_idx   ON audit_log (agent_id, seq DESC);
CREATE INDEX IF NOT EXISTS audit_log_verdict_idx ON audit_log (verdict, seq DESC);
CREATE INDEX IF NOT EXISTS audit_log_ts_idx      ON audit_log (ts DESC);

-- Reference tables for the data model in the SRS. The MVP keeps live state in
-- the gateway process; these exist so a deployment can persist and query it.
CREATE TABLE IF NOT EXISTS agents (
  agent_id      TEXT PRIMARY KEY,
  owner         TEXT NOT NULL,
  allowed_tools TEXT[] NOT NULL DEFAULT '{}',
  status        TEXT NOT NULL DEFAULT 'active'
);
CREATE TABLE IF NOT EXISTS tools (
  tool_id          TEXT PRIMARY KEY,
  server           TEXT NOT NULL,
  description_hash TEXT NOT NULL,
  risk_level       TEXT NOT NULL DEFAULT 'normal',
  destructive      BOOLEAN NOT NULL DEFAULT FALSE
);
CREATE TABLE IF NOT EXISTS policies (
  policy_id    TEXT NOT NULL,
  version      INT  NOT NULL,
  cedar_source TEXT NOT NULL,
  active       BOOLEAN NOT NULL DEFAULT TRUE,
  PRIMARY KEY (policy_id, version)
);
CREATE TABLE IF NOT EXISTS approvals (
  approval_id TEXT PRIMARY KEY,
  decision_id TEXT NOT NULL,
  approver    TEXT,
  outcome     TEXT NOT NULL,
  decided_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
