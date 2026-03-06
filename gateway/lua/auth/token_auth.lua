-- WSLVault Token Authentication Middleware
-- Validates Bearer tokens at the gateway layer before forwarding to upstream services.
-- This is a fast-path check; full authorization is delegated to the policy-engine.

local cjson = require "cjson.safe"

-- Extract Bearer token from Authorization header
local function get_bearer_token()
    local auth_header = ngx.req.get_headers()["Authorization"]
    if not auth_header then
        return nil, "missing Authorization header"
    end

    local token = auth_header:match("^Bearer%s+(.+)$")
    if not token then
        return nil, "invalid Authorization header format, expected: Bearer <token>"
    end

    return token, nil
end

-- Check token in shared memory cache
local function check_cache(token_hash)
    local cache = ngx.shared.token_cache
    local cached = cache:get(token_hash)
    if cached then
        local data = cjson.decode(cached)
        if data and data.exp and data.exp > ngx.time() then
            return data
        end
        -- Expired entry; remove from cache
        cache:delete(token_hash)
    end
    return nil
end

-- Cache a validated token
local function cache_token(token_hash, claims, ttl)
    local cache = ngx.shared.token_cache
    local data = cjson.encode(claims)
    -- Cache for the shorter of: token remaining lifetime or 60 seconds
    local cache_ttl = math.min(ttl, 60)
    cache:set(token_hash, data, cache_ttl)
end

-- Main authentication logic
local token, err = get_bearer_token()
if not token then
    ngx.status = 401
    ngx.header["Content-Type"] = "application/json"
    ngx.say(cjson.encode({
        error = "unauthenticated",
        message = err
    }))
    return ngx.exit(401)
end

-- Hash the token for cache lookup (avoid storing raw tokens in shared memory)
local token_hash = ngx.md5(token)

-- Check cache first
local cached_claims = check_cache(token_hash)
if cached_claims then
    -- Set headers for upstream services
    ngx.req.set_header("X-Vault-Principal-ID", cached_claims.sub)
    ngx.req.set_header("X-Vault-Tenant-ID", cached_claims.tenant_id)
    ngx.req.set_header("X-Vault-Policies", table.concat(cached_claims.policies or {}, ","))
    return -- Allow request to proceed
end

-- Token not in cache — forward raw token to upstream for validation
-- The upstream service will validate the JWT and enforce authorization
ngx.req.set_header("X-Vault-Token", token)
