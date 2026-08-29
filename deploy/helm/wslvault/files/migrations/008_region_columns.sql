-- 008_region_columns.sql
-- Add region-awareness columns to existing secret tables.
-- All new columns are NULLable to preserve backward compatibility with
-- pre-region data. New writes populate these columns; old rows remain NULL.

-- Track which region originally created each secret path.
ALTER TABLE shared.secrets
    ADD COLUMN IF NOT EXISTS origin_region TEXT,
    ADD COLUMN IF NOT EXISTS vector_clock  JSONB NOT NULL DEFAULT '{}';

-- Track which region wrote each version and its position in the replication stream.
ALTER TABLE shared.secret_versions
    ADD COLUMN IF NOT EXISTS origin_region    TEXT,
    ADD COLUMN IF NOT EXISTS replication_seq  BIGINT;

-- Add region field to audit events for cross-region traceability.
ALTER TABLE shared.audit_events
    ADD COLUMN IF NOT EXISTS origin_region TEXT;
