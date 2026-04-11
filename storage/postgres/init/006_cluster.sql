-- 006_cluster.sql
-- Cluster node registration and heartbeat tracking for HA leader election.
-- Each service instance registers here on startup and refreshes its heartbeat
-- periodically. The leader flag is set by the node that holds the PostgreSQL
-- advisory lock for its service type.

CREATE TABLE IF NOT EXISTS system.cluster_nodes (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    service_name    TEXT NOT NULL,
    node_id         TEXT NOT NULL UNIQUE,
    region          TEXT NOT NULL DEFAULT 'default',
    is_leader       BOOLEAN NOT NULL DEFAULT false,
    last_heartbeat  TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    metadata        JSONB NOT NULL DEFAULT '{}'
);

-- Fast lookup by service name for cluster status queries.
CREATE INDEX IF NOT EXISTS idx_cluster_nodes_service
    ON system.cluster_nodes(service_name);

-- Fast identification of stale nodes for pruning.
CREATE INDEX IF NOT EXISTS idx_cluster_nodes_heartbeat
    ON system.cluster_nodes(last_heartbeat);

-- Fast lookup of current leader per service.
CREATE INDEX IF NOT EXISTS idx_cluster_nodes_leader
    ON system.cluster_nodes(service_name, is_leader)
    WHERE is_leader = true;
