-- WSLVault Token Presence Check
--
-- Rejects requests that carry no credential at all, so obviously-anonymous
-- traffic does not reach a backend. It does NOT validate the token: the
-- gateway holds no signing key, and the backends verify signatures and enforce
-- policy themselves. Naming it "authentication" oversold what it does.

local cjson = require "cjson.safe"

-- Extract the caller's token.
--
-- Two spellings are accepted:
--   * X-Vault-Token      — what HashiCorp Vault clients send (the vault CLI,
--                          the Terraform provider, and the External Secrets
--                          Operator's `vault` provider). Required for the KV v2
--                          compatibility mount at /v1/kv/... to be reachable;
--                          without it those clients are rejected here with 401
--                          before ever reaching the secret-engine.
--   * Authorization: Bearer <token> — the native wslvault spelling.
local function get_token()
    local headers = ngx.req.get_headers()

    local vault_token = headers["X-Vault-Token"]
    if vault_token and vault_token ~= "" then
        return vault_token, nil
    end

    local auth_header = headers["Authorization"]
    if not auth_header then
        return nil, "missing credentials: send X-Vault-Token or Authorization: Bearer <token>"
    end

    local token = auth_header:match("^Bearer%s+(.+)$")
    if not token then
        return nil, "invalid Authorization header format, expected: Bearer <token>"
    end

    return token, nil
end

-- Main authentication logic
local token, err = get_token()
if not token then
    ngx.status = 401
    ngx.header["Content-Type"] = "application/json"
    ngx.say(cjson.encode({
        error = "unauthenticated",
        message = err
    }))
    return ngx.exit(401)
end

-- Client-supplied identity headers are stripped at server level in
-- conf.d/main.conf, so they are already gone by the time this runs. That is
-- deliberately not done here: /v1/auth/ and the health endpoints do not run
-- this file, and a location added later would not either.

-- Forward the raw token; the upstream service verifies its signature and
-- enforces authorization. The gateway deliberately does not validate tokens
-- itself: it holds no signing key, and a second verifier is a second thing to
-- get wrong.
--
-- The former shared-memory token cache is gone. `cache_token` was defined and
-- never called, so the cache was always empty and the cache-hit branch that
-- set the identity headers above was unreachable. It only ever looked like a
-- fast path.
ngx.req.set_header("X-Vault-Token", token)
