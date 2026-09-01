-- WSLVault: create the least-privilege role that row-level security needs.
-- Run ONCE per region, as a superuser. Not part of the migration sequence.
--
-- ## Why this is not a migration
--
-- The migration Job connects as `wslvault` (see templates/migrations.yaml,
-- PGUSER = postgresql.auth.username), and that role has neither SUPERUSER nor
-- CREATEROLE:
--
--   rolname  | rolsuper | rolbypassrls | rolcreaterole
--   wslvault | f        | f            | f
--
-- so `CREATE ROLE` fails there. Giving the migration Job admin credentials to
-- work around that would hand every schema change the ability to create roles
-- and reset passwords — a much larger grant than the one thing it needs. This
-- stays a deliberate, operator-run step instead.
--
-- ## Why a second role at all
--
-- `wslvault` OWNS these tables. PostgreSQL exempts a table's owner from its own
-- row-level security unless FORCE ROW LEVEL SECURITY is set, and FORCE is a
-- blunt switch that also applies to the migration Job and to any operator
-- debugging with psql. A separate non-owning role is the clean split: the owner
-- keeps unrestricted access for schema work, and the services run as a role
-- that RLS genuinely applies to.
--
-- ## Usage
--
--   psql -U postgres -d wslvault \
--        -v app_password="$(openssl rand -base64 32)" \
--        -f rls_app_role.sql
--
-- Then store that password in the chart's database credentials Secret under the
-- key the services read, and set postgresql.auth.appUsername=wslvault_app.
--
-- Re-running is safe: the role is created only if absent, and the password is
-- always reset to the supplied value.

\set ON_ERROR_STOP on

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'wslvault_app') THEN
        -- LOGIN so services can connect. Explicitly NOSUPERUSER and
        -- NOBYPASSRLS: those two attributes are exactly what would make the
        -- whole exercise pointless, so they are stated rather than defaulted.
        CREATE ROLE wslvault_app
            LOGIN
            NOSUPERUSER
            NOBYPASSRLS
            NOCREATEDB
            NOCREATEROLE
            NOREPLICATION;
        RAISE NOTICE 'created role wslvault_app';
    ELSE
        RAISE NOTICE 'role wslvault_app already exists; resetting password only';
    END IF;
END $$;

-- Password comes from the caller so it never appears in this file or in the
-- chart. `\set` substitution is quoted to survive punctuation in the value.
ALTER ROLE wslvault_app PASSWORD :'app_password';

-- Belt and braces: if someone ever grants these by hand, take them back.
ALTER ROLE wslvault_app NOSUPERUSER NOBYPASSRLS NOCREATEROLE;

-- Connect privilege. Object-level grants are applied by migration 029, which
-- also installs ALTER DEFAULT PRIVILEGES so later migrations' tables are
-- covered automatically.
GRANT CONNECT ON DATABASE wslvault TO wslvault_app;

-- The role must NOT be able to create objects in these schemas — it reads and
-- writes rows, it does not shape the schema.
REVOKE CREATE ON SCHEMA shared, system FROM wslvault_app;
REVOKE CREATE ON SCHEMA public FROM wslvault_app;

\echo 'wslvault_app ready. Object grants are applied by migration 029.'
\echo 'Verify with:  SELECT * FROM shared.rls_status();'
