-- 009_sync_jobs.sql
-- Sync job tracking for external secret manager integrations.
-- Integration credentials are stored as WSLVault secrets at the path:
--   system/integrations/{integration_id}/credentials

CREATE TABLE IF NOT EXISTS system.sync_jobs (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    integration_id          TEXT NOT NULL,
    connector_type          TEXT NOT NULL
                            CHECK (connector_type IN ('aws', 'azure', 'gcp', 'hashicorp', 'k8s', 'postgres_rotation')),
    direction               TEXT NOT NULL
                            CHECK (direction IN ('pull', 'push', 'bidirectional')),
    prefix                  TEXT NOT NULL DEFAULT '',
    schedule                TEXT,                 -- cron expression; NULL = event-driven only
    last_run_at             TIMESTAMPTZ,
    last_run_status         TEXT
                            CHECK (last_run_status IS NULL OR last_run_status IN ('success', 'partial', 'failed', 'running')),
    last_run_result         JSONB,                -- SyncResult serialised
    consecutive_failures    INTEGER NOT NULL DEFAULT 0,
    max_failures            INTEGER NOT NULL DEFAULT 3,
    enabled                 BOOLEAN NOT NULL DEFAULT true,
    tenant_id               UUID NOT NULL REFERENCES system.tenants(id),
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_sync_jobs_tenant
    ON system.sync_jobs(tenant_id);

CREATE INDEX IF NOT EXISTS idx_sync_jobs_enabled_schedule
    ON system.sync_jobs(enabled, schedule)
    WHERE enabled = true AND schedule IS NOT NULL;

-- Trigger for updated_at maintenance.
CREATE TRIGGER update_sync_jobs_updated_at
    BEFORE UPDATE ON system.sync_jobs
    FOR EACH ROW
    EXECUTE FUNCTION system.update_updated_at();
