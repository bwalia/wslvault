-- Secret tags + SDLC environments (INT / TEST / ACC / PROD)
-- and tenant allowed_environments for project vs production tenancy.
--
-- Product rule: a project tenant (e.g. project-dta) may hold INT/TEST/ACC;
-- PROD lives in a separate production tenant (e.g. project-dta-prod).

-- =============================================================================
-- 1. Tenants: allowed environments, default, optional tags, kind
-- =============================================================================

ALTER TABLE system.tenants
    ADD COLUMN IF NOT EXISTS allowed_environments TEXT[] NOT NULL DEFAULT ARRAY['INT','TEST','ACC']::TEXT[],
    ADD COLUMN IF NOT EXISTS default_environment TEXT NOT NULL DEFAULT 'INT',
    ADD COLUMN IF NOT EXISTS tags TEXT[] NOT NULL DEFAULT '{}',
    ADD COLUMN IF NOT EXISTS tenant_kind TEXT NOT NULL DEFAULT 'project';

-- Tighten defaults for existing rows: keep project defaults unless slug ends with -prod.
UPDATE system.tenants
SET tenant_kind = 'production',
    allowed_environments = ARRAY['PROD']::TEXT[],
    default_environment = 'PROD'
WHERE slug LIKE '%-prod' OR slug LIKE '%-production';

ALTER TABLE system.tenants
    DROP CONSTRAINT IF EXISTS tenants_tenant_kind_check;
ALTER TABLE system.tenants
    ADD CONSTRAINT tenants_tenant_kind_check
    CHECK (tenant_kind IN ('project', 'production'));

ALTER TABLE system.tenants
    DROP CONSTRAINT IF EXISTS tenants_allowed_environments_check;
ALTER TABLE system.tenants
    ADD CONSTRAINT tenants_allowed_environments_check
    CHECK (
        allowed_environments <@ ARRAY['INT','TEST','ACC','PROD']::TEXT[]
        AND cardinality(allowed_environments) >= 1
    );

ALTER TABLE system.tenants
    DROP CONSTRAINT IF EXISTS tenants_default_environment_check;
ALTER TABLE system.tenants
    ADD CONSTRAINT tenants_default_environment_check
    CHECK (default_environment = ANY (allowed_environments));

COMMENT ON COLUMN system.tenants.allowed_environments IS
    'SDLC environments this tenant may store secrets for. Project tenants: INT/TEST/ACC; production tenants: PROD only.';
COMMENT ON COLUMN system.tenants.tenant_kind IS
    'project = lower envs in one tenancy; production = PROD-only tenant (recommended separate from project).';

-- =============================================================================
-- 2. Secrets: environment + tags on shared schema
-- =============================================================================

ALTER TABLE shared.secrets
    ADD COLUMN IF NOT EXISTS environment TEXT NOT NULL DEFAULT 'INT',
    ADD COLUMN IF NOT EXISTS tags TEXT[] NOT NULL DEFAULT '{}';

ALTER TABLE shared.secrets
    DROP CONSTRAINT IF EXISTS secrets_environment_check;
ALTER TABLE shared.secrets
    ADD CONSTRAINT secrets_environment_check
    CHECK (environment IN ('INT', 'TEST', 'ACC', 'PROD'));

CREATE INDEX IF NOT EXISTS idx_secrets_tenant_environment
    ON shared.secrets (tenant_id, environment);

CREATE INDEX IF NOT EXISTS idx_secrets_tags_gin
    ON shared.secrets USING GIN (tags);

COMMENT ON COLUMN shared.secrets.environment IS
    'SDLC environment label: INT | TEST | ACC | PROD. Independent of geo region.';
COMMENT ON COLUMN shared.secrets.tags IS
    'Free-form category labels (lowercase kebab recommended), e.g. database, api-key, app:billing.';

-- =============================================================================
-- 3. Apply the same columns to every active dedicated/sovereign tenant schema
-- =============================================================================

DO $migrate$
DECLARE
    r RECORD;
BEGIN
    FOR r IN
        SELECT schema_name
        FROM system.tenant_schemas
        WHERE deprovisioned_at IS NULL
    LOOP
        EXECUTE format(
            'ALTER TABLE %I.secrets
                ADD COLUMN IF NOT EXISTS environment TEXT NOT NULL DEFAULT ''INT'',
                ADD COLUMN IF NOT EXISTS tags TEXT[] NOT NULL DEFAULT ''{}''',
            r.schema_name
        );
        EXECUTE format(
            'ALTER TABLE %I.secrets DROP CONSTRAINT IF EXISTS secrets_environment_check',
            r.schema_name
        );
        EXECUTE format(
            'ALTER TABLE %I.secrets
                ADD CONSTRAINT secrets_environment_check
                CHECK (environment IN (''INT'', ''TEST'', ''ACC'', ''PROD''))',
            r.schema_name
        );
        EXECUTE format(
            'CREATE INDEX IF NOT EXISTS %I ON %I.secrets (tenant_id, environment)',
            'idx_' || r.schema_name || '_secrets_env',
            r.schema_name
        );
        EXECUTE format(
            'CREATE INDEX IF NOT EXISTS %I ON %I.secrets USING GIN (tags)',
            'idx_' || r.schema_name || '_secrets_tags',
            r.schema_name
        );
    END LOOP;
END
$migrate$;

-- =============================================================================
-- 4. Refresh provision_tenant_schema so new dedicated tenants get the columns
-- =============================================================================

CREATE OR REPLACE FUNCTION system.provision_tenant_schema(
    p_tenant_id UUID,
    p_tier      TEXT DEFAULT 'dedicated'
)
RETURNS TEXT
LANGUAGE plpgsql
SECURITY DEFINER
AS $fn$
DECLARE
    v_schema TEXT;
BEGIN
    v_schema := 'tenant_' || replace(p_tenant_id::text, '-', '');

    IF EXISTS (
        SELECT 1 FROM system.tenant_schemas
        WHERE tenant_id = p_tenant_id AND deprovisioned_at IS NULL
    ) THEN
        RAISE NOTICE 'schema already provisioned for tenant %', p_tenant_id;
        RETURN v_schema;
    END IF;

    EXECUTE format('CREATE SCHEMA IF NOT EXISTS %I', v_schema);

    EXECUTE format($t$
        CREATE TABLE %I.secrets (
            id              UUID PRIMARY KEY,
            tenant_id       UUID NOT NULL DEFAULT %L::uuid
                            CHECK (tenant_id = %L::uuid),
            path            TEXT NOT NULL,
            engine          TEXT NOT NULL
                            CHECK (engine IN ('kv_v2','transit','dynamic_database','ssh','pki','cloud_aws','cloud_gcp','cloud_azure')),
            current_version INTEGER NOT NULL DEFAULT 0,
            max_versions    INTEGER NOT NULL DEFAULT 10,
            cas_required    BOOLEAN NOT NULL DEFAULT false,
            custom_metadata JSONB NOT NULL DEFAULT '{}',
            environment     TEXT NOT NULL DEFAULT 'INT'
                            CHECK (environment IN ('INT','TEST','ACC','PROD')),
            tags            TEXT[] NOT NULL DEFAULT '{}',
            created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
            UNIQUE (tenant_id, path)
        )
    $t$, v_schema, p_tenant_id, p_tenant_id);

    EXECUTE format(
        'CREATE INDEX %I ON %I.secrets (tenant_id, environment)',
        'idx_' || v_schema || '_secrets_env', v_schema
    );
    EXECUTE format(
        'CREATE INDEX %I ON %I.secrets USING GIN (tags)',
        'idx_' || v_schema || '_secrets_tags', v_schema
    );

    EXECUTE format($t$
        CREATE TABLE %I.secret_versions (
            id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            secret_id       UUID NOT NULL REFERENCES %I.secrets(id) ON DELETE CASCADE,
            version         INTEGER NOT NULL,
            ciphertext      TEXT NOT NULL,
            dek_id          TEXT NOT NULL,
            custom_metadata JSONB NOT NULL DEFAULT '{}',
            created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
            deleted_at      TIMESTAMPTZ,
            destroyed       BOOLEAN NOT NULL DEFAULT false,
            UNIQUE (secret_id, version)
        )
    $t$, v_schema, v_schema);

    EXECUTE format($t$
        CREATE TABLE %I.leases (
            id              UUID PRIMARY KEY,
            tenant_id       UUID NOT NULL DEFAULT %L::uuid
                            CHECK (tenant_id = %L::uuid),
            target_type     TEXT NOT NULL
                            CHECK (target_type IN ('token','dynamic_secret','service_credential')),
            target_data     JSONB NOT NULL,
            state           TEXT NOT NULL
                            CHECK (state IN ('active','renewing','expired','revoked')) DEFAULT 'active',
            ttl_seconds     BIGINT NOT NULL,
            max_ttl_seconds BIGINT NOT NULL,
            renewable       BOOLEAN NOT NULL DEFAULT true,
            issue_time      TIMESTAMPTZ NOT NULL DEFAULT now(),
            expire_time     TIMESTAMPTZ NOT NULL,
            last_renewal    TIMESTAMPTZ,
            revoked_at      TIMESTAMPTZ,
            created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
        )
    $t$, v_schema, p_tenant_id, p_tenant_id);

    INSERT INTO system.tenant_schemas (tenant_id, schema_name, tier)
    VALUES (p_tenant_id, v_schema, p_tier)
    ON CONFLICT (tenant_id) DO UPDATE
        SET schema_name = EXCLUDED.schema_name,
            tier = EXCLUDED.tier,
            deprovisioned_at = NULL,
            provisioned_at = now();

    RETURN v_schema;
END
$fn$;
