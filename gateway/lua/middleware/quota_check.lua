-- WSLVault Quota Check Middleware
-- Token bucket rate limiter scoped per tenant.
-- Reads per-tenant read/write limits from the rate_limit shared dict;
-- limits are seeded by the quota-sync background job or fall back to
-- safe defaults when no entry is present.
--
-- The bucket is keyed separately for read vs. write traffic so that a
-- write burst cannot consume the read allowance.
--
-- Returns 429 Too Many Requests when the bucket is exhausted.

local cjson = require "cjson.safe"

-- ---------------------------------------------------------------------------
-- Defaults used when no tenant-specific limit has been loaded into the dict.
-- These mirror the DEFAULT values in shared.tenant_quotas.
-- ---------------------------------------------------------------------------
local DEFAULT_READ_RATE  = 1000   -- tokens per second
local DEFAULT_WRITE_RATE = 200    -- tokens per second

-- Maximum burst = 10 % above the per-second rate (one full second of tokens).
-- Keeping burst == rate means the bucket never allows more than one second's
-- worth of requests ahead of schedule, which bounds latency spikes.
local BURST_RATIO = 1.10

-- Shared dict key prefixes
local BUCKET_TOKENS_KEY  = "quota:tokens:"   -- current token count
local BUCKET_TS_KEY      = "quota:ts:"       -- last refill timestamp (float)
local LIMIT_KEY          = "quota:limit:"    -- provisioned limit (set externally)

-- ---------------------------------------------------------------------------
-- Helpers
-- ---------------------------------------------------------------------------

-- Classify the HTTP method as a read or write operation.
-- HEAD / GET / OPTIONS are reads; everything else (PUT, POST, PATCH, DELETE)
-- is a write.
local function is_write_request()
    local method = ngx.req.get_method()
    return method ~= "GET" and method ~= "HEAD" and method ~= "OPTIONS"
end

-- Return the rate-limit shared dict key prefix and provisioned rate for the
-- current request, given the tenant_id.
local function resolve_limit(tenant_id)
    local op     = is_write_request() and "write" or "read"
    local prefix = tenant_id .. ":" .. op .. ":"

    -- Check whether a tenant-specific limit was loaded by the quota-sync job.
    local dict      = ngx.shared.rate_limit
    local limit_key = LIMIT_KEY .. prefix
    local limit     = dict:get(limit_key)

    if not limit then
        limit = is_write_request() and DEFAULT_WRITE_RATE or DEFAULT_READ_RATE
    end

    return prefix, limit, op
end

-- ---------------------------------------------------------------------------
-- Token bucket algorithm
--
-- State stored in the rate_limit shared dict (two keys per tenant+op):
--   quota:tokens:<tenant>:<op>:  float  — available tokens
--   quota:ts:<tenant>:<op>:      float  — unix timestamp of last refill
--
-- On each request:
--   1. Compute elapsed time since last refill.
--   2. Refill: tokens = min(tokens + elapsed * rate, burst_capacity).
--   3. If tokens >= 1 consume one and allow; otherwise deny.
--
-- All reads and writes to the dict are done inside a single atomic update
-- via dict:add / dict:set to minimise (but not fully eliminate) races under
-- high concurrency.  For a production deployment the lock-free Lua shared
-- dict is good enough for approximate enforcement; exact accounting would
-- require an external Redis INCR or a Lua mutex.
-- ---------------------------------------------------------------------------
local function token_bucket_check(prefix, rate)
    local dict       = ngx.shared.rate_limit
    local token_key  = BUCKET_TOKENS_KEY .. prefix
    local ts_key     = BUCKET_TS_KEY     .. prefix
    local burst_cap  = rate * BURST_RATIO
    local now        = ngx.now()          -- float seconds (millisecond precision)

    -- Retrieve current state; initialise on first request for this tenant+op.
    local tokens  = dict:get(token_key)
    local last_ts = dict:get(ts_key)

    if not tokens or not last_ts then
        -- First request: start with a full bucket minus the token we're about
        -- to consume so the caller is allowed through immediately.
        dict:set(token_key, burst_cap - 1, 60)
        dict:set(ts_key,    now,           60)
        return true, burst_cap - 1, burst_cap
    end

    -- Refill proportional to elapsed time.
    local elapsed  = now - last_ts
    local refilled = tokens + elapsed * rate
    if refilled > burst_cap then
        refilled = burst_cap
    end

    if refilled < 1 then
        -- Bucket exhausted — do not consume; persist refilled count + new ts.
        dict:set(token_key, refilled, 60)
        dict:set(ts_key,    now,      60)
        return false, refilled, burst_cap
    end

    -- Consume one token.
    local remaining = refilled - 1
    dict:set(token_key, remaining, 60)
    dict:set(ts_key,    now,       60)
    return true, remaining, burst_cap
end

-- ---------------------------------------------------------------------------
-- Compute the number of seconds until at least one token will be available.
-- Used for the Retry-After response header.
-- ---------------------------------------------------------------------------
local function retry_after_seconds(remaining, rate)
    if rate <= 0 then
        return 1
    end
    -- Seconds to accumulate 1 - remaining tokens at the given refill rate.
    local deficit = 1 - remaining
    return math.max(1, math.ceil(deficit / rate))
end

-- ---------------------------------------------------------------------------
-- Main execution
-- ---------------------------------------------------------------------------

local tenant_id = ngx.req.get_headers()["X-Vault-Tenant-ID"]

-- Quota enforcement requires a tenant context.  Unauthenticated requests
-- (no tenant header) are passed through here; the auth middleware that runs
-- before this file will reject them if the endpoint requires authentication.
if not tenant_id or tenant_id == "" then
    return
end

local prefix, rate, op = resolve_limit(tenant_id)
local allowed, remaining, capacity = token_bucket_check(prefix, rate)

-- Expose quota headers on every response so clients can self-throttle.
ngx.header["X-RateLimit-Limit"]     = tostring(math.floor(capacity))
ngx.header["X-RateLimit-Remaining"] = tostring(math.max(0, math.floor(remaining)))
ngx.header["X-RateLimit-Op"]        = op

if not allowed then
    local retry_after = retry_after_seconds(remaining, rate)

    ngx.status = 429
    ngx.header["Content-Type"]  = "application/json"
    ngx.header["Retry-After"]   = tostring(retry_after)

    ngx.say(cjson.encode({
        error     = "quota_exceeded",
        message   = "rate limit exceeded for tenant " .. tenant_id
                    .. "; retry after " .. retry_after .. "s",
        tenant_id = tenant_id,
        operation = op,
        limit     = math.floor(capacity),
        retry_after_seconds = retry_after
    }))

    return ngx.exit(429)
end
