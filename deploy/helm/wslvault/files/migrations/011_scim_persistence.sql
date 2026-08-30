-- WSLVault SCIM 2.0 Persistence Layer
-- Stores SCIM User and Group resources in PostgreSQL for durable,
-- multi-instance provisioning.  Replaces the in-memory HashMap stores.
--
-- Apply after 010_secret_lifecycle.sql.

-- =============================================================================
-- 1. SCIM Users table
-- =============================================================================

CREATE TABLE IF NOT EXISTS shared.scim_users (
    id              TEXT PRIMARY KEY,                -- server-assigned UUID (v7)
    external_id     TEXT,                            -- client-supplied externalId
    tenant_id       TEXT NOT NULL DEFAULT 'scim',    -- tenant namespace
    user_name       TEXT NOT NULL,                   -- unique login / email
    display_name    TEXT,
    active          BOOLEAN NOT NULL DEFAULT true,
    name_formatted  TEXT,
    name_given      TEXT,
    name_family     TEXT,
    emails          JSONB NOT NULL DEFAULT '[]'::jsonb,  -- array of {value, type, primary}
    groups_ref      JSONB NOT NULL DEFAULT '[]'::jsonb,  -- array of {value, display, $ref}
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- userName must be unique within a tenant (case-insensitive).
CREATE UNIQUE INDEX IF NOT EXISTS idx_scim_users_tenant_username
    ON shared.scim_users (tenant_id, lower(user_name));

CREATE INDEX IF NOT EXISTS idx_scim_users_external_id
    ON shared.scim_users (tenant_id, external_id)
    WHERE external_id IS NOT NULL;

COMMENT ON TABLE shared.scim_users IS
    'SCIM 2.0 User resources (RFC 7643 s4.1). One row per provisioned identity.';

-- =============================================================================
-- 2. SCIM Groups table
-- =============================================================================

CREATE TABLE IF NOT EXISTS shared.scim_groups (
    id              TEXT PRIMARY KEY,                -- server-assigned UUID (v7)
    tenant_id       TEXT NOT NULL DEFAULT 'scim',    -- tenant namespace
    display_name    TEXT NOT NULL,                   -- maps to wslvault policy name
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- displayName must be unique within a tenant (case-insensitive).
CREATE UNIQUE INDEX IF NOT EXISTS idx_scim_groups_tenant_display_name
    ON shared.scim_groups (tenant_id, lower(display_name));

COMMENT ON TABLE shared.scim_groups IS
    'SCIM 2.0 Group resources (RFC 7643 s4.2). displayName maps to a wslvault policy name.';

-- =============================================================================
-- 3. SCIM Group Memberships (join table)
-- =============================================================================

CREATE TABLE IF NOT EXISTS shared.scim_group_members (
    group_id        TEXT NOT NULL REFERENCES shared.scim_groups(id) ON DELETE CASCADE,
    user_id         TEXT NOT NULL REFERENCES shared.scim_users(id) ON DELETE CASCADE,
    display         TEXT,                            -- cached user displayName
    member_type     TEXT NOT NULL DEFAULT 'User',    -- always "User" per SCIM spec
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (group_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_scim_group_members_user
    ON shared.scim_group_members (user_id);

COMMENT ON TABLE shared.scim_group_members IS
    'Many-to-many relationship between SCIM groups and users.';

-- =============================================================================
-- 4. Row Level Security (tenant isolation)
-- =============================================================================

ALTER TABLE shared.scim_users ENABLE ROW LEVEL SECURITY;
ALTER TABLE shared.scim_groups ENABLE ROW LEVEL SECURITY;

-- Policies for scim_users
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE tablename = 'scim_users' AND policyname = 'scim_users_tenant_isolation'
    ) THEN
        EXECUTE 'CREATE POLICY scim_users_tenant_isolation ON shared.scim_users
            USING (tenant_id = current_setting(''app.tenant_id'', true))';
    END IF;
END $$;

-- Policies for scim_groups
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE tablename = 'scim_groups' AND policyname = 'scim_groups_tenant_isolation'
    ) THEN
        EXECUTE 'CREATE POLICY scim_groups_tenant_isolation ON shared.scim_groups
            USING (tenant_id = current_setting(''app.tenant_id'', true))';
    END IF;
END $$;

-- =============================================================================
-- 5. Helper function: update timestamps on modification
-- =============================================================================

CREATE OR REPLACE FUNCTION shared.scim_set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Attach triggers (idempotent via DROP IF EXISTS).
DROP TRIGGER IF EXISTS trg_scim_users_updated_at ON shared.scim_users;
CREATE TRIGGER trg_scim_users_updated_at
    BEFORE UPDATE ON shared.scim_users
    FOR EACH ROW EXECUTE FUNCTION shared.scim_set_updated_at();

DROP TRIGGER IF EXISTS trg_scim_groups_updated_at ON shared.scim_groups;
CREATE TRIGGER trg_scim_groups_updated_at
    BEFORE UPDATE ON shared.scim_groups
    FOR EACH ROW EXECUTE FUNCTION shared.scim_set_updated_at();
