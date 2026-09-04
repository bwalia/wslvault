-- WSLVault: let a tenant use its own transit keys.
-- Migration: 034_default_policy_transit.sql
--
-- ## Why
--
-- The `default` policy from 032 grants `secret/**` and nothing else, but the
-- console shows Transit to every member — it is not an administrator-only
-- destination. So the page loaded, listed nothing, and answered
-- "no policy grants 'read' on resource 'transit/keys'" to every request: a
-- feature advertised in the sidebar that no tenant could reach.
--
-- ## Scope
--
-- `transit/**` is not a widening of the tenant boundary. transit-engine takes
-- the tenant from the caller's verified token and scopes every store call to
-- it (`list_keys(&tenant_id)`, `get_key(&tenant_id, ..)`), so these paths can
-- only ever name the tenant's own keys. This grants a tenant control of its own
-- encryption keys, exactly as 032 granted control of its own secrets — still no
-- policy management and still nothing cross-tenant.
--
-- Rewritten rather than appended so re-running is a no-op, and so a tenant that
-- has edited its own `default` document is not silently handed a second rule
-- set it did not write.

UPDATE shared.policies
SET document = jsonb_build_object(
        'name', 'default',
        'rules', jsonb_build_array(
            jsonb_build_object(
                'paths', jsonb_build_array('secret/**'),
                'capabilities', jsonb_build_array('read', 'write', 'list', 'delete')
            ),
            jsonb_build_object(
                -- Covers every resource shape the handlers build:
                -- `transit/keys`, `transit/keys/<name>`, `transit/encrypt/<name>`,
                -- and the decrypt, sign, verify and rewrap forms.
                'paths', jsonb_build_array('transit/**'),
                'capabilities', jsonb_build_array('read', 'write', 'list')
            )
        )
    )
WHERE name = 'default'
  AND NOT (document -> 'rules' @> '[{"paths": ["transit/**"]}]'::jsonb);
