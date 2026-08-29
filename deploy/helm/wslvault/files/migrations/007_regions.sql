-- 007_regions.sql
-- Multi-region support: region registry, replication event outbox, and
-- per-region sequence tracking for cross-region secret synchronisation.

-- Region registry: one row per deployed region.
-- Updated by the region-health service and read by gateways for routing.
CREATE TABLE IF NOT EXISTS system.regions (
    id                  TEXT PRIMARY KEY,           -- e.g. "eu-west-2"
    display_name        TEXT NOT NULL,
    endpoint            TEXT NOT NULL,              -- regional gateway URL
    status              TEXT NOT NULL DEFAULT 'active'
                        CHECK (status IN ('active', 'degraded', 'offline')),
    is_local            BOOLEAN NOT NULL DEFAULT false,
    replication_lag_ms  BIGINT,                     -- updated by replication-agent
    last_seen           TIMESTAMPTZ NOT NULL DEFAULT now(),
    metadata            JSONB NOT NULL DEFAULT '{}'
);

-- Replication event outbox: written by the originating region's secret-engine
-- within the same transaction as the secret upsert. Consumed by the
-- replication-agent in peer regions.
CREATE TABLE IF NOT EXISTS system.replication_events (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type      TEXT NOT NULL
                    CHECK (event_type IN (
                        'secret_upsert', 'secret_delete', 'secret_destroy',
                        'key_rotate', 'policy_update', 'tenant_update',
                        'region_failover', 'region_promote'
                    )),
    source_region   TEXT NOT NULL,
    payload         JSONB NOT NULL,                 -- opaque per event_type
    vector_clock    JSONB NOT NULL DEFAULT '{}',    -- {region_id: sequence_number}
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    replicated_at   TIMESTAMPTZ,                    -- set when fully propagated
    replicated_to   TEXT[] NOT NULL DEFAULT '{}'     -- region IDs that have ACKed
);

-- Fast lookup of un-replicated events for the replication-agent consumer.
CREATE INDEX IF NOT EXISTS idx_replication_events_pending
    ON system.replication_events(created_at)
    WHERE replicated_at IS NULL;

-- Filter by source region for targeted polling.
CREATE INDEX IF NOT EXISTS idx_replication_events_source
    ON system.replication_events(source_region, created_at);

-- Per-region monotonic sequence tracking.
-- Each region increments its own sequence on every write; peer regions
-- track the last consumed sequence to detect gaps.
CREATE TABLE IF NOT EXISTS system.region_sequences (
    region_id       TEXT NOT NULL,
    sequence        BIGINT NOT NULL DEFAULT 0,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (region_id)
);
