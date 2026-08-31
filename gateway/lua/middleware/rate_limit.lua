-- WSLVault Rate Limiting Middleware
-- Sliding window rate limiter using shared memory.
-- Limits are per-tenant (extracted from token) or per-IP for unauthenticated endpoints.

local cjson = require "cjson.safe"

-- Configuration
local DEFAULT_RATE = 100      -- requests per window
local DEFAULT_WINDOW = 60     -- window size in seconds
local BURST_MULTIPLIER = 1.5  -- allow burst up to 150% of rate

-- Get the rate limit key.
--
-- This used to bucket on the X-Vault-Tenant-ID *request* header, which the
-- client supplies. Sending a fresh random value on every request produced a
-- fresh bucket every time, so the limit was bypassed by one header — and the
-- limiter was, if anything, worse than nothing, because it looked enforced.
--
-- The gateway does not verify tokens (backends do), so it has no authenticated
-- tenant to bucket on. The remote address is the only identity it can actually
-- attest to, so that is what is used.
--
-- ponytail: per-IP only. Once the gateway validates tokens itself, bucket on
-- the verified tenant claim and keep per-IP as the unauthenticated fallback.
local function get_rate_key()
    return "ip:" .. ngx.var.remote_addr
end

-- Sliding window counter
local function check_rate_limit(key, rate, window)
    local limit = ngx.shared.rate_limit
    local now = ngx.time()
    local window_key = key .. ":" .. math.floor(now / window)
    local prev_key = key .. ":" .. (math.floor(now / window) - 1)

    -- Increment FIRST, then decide. Reading and then incrementing is not
    -- atomic across workers, so concurrent requests all saw the same
    -- pre-increment count and sailed past the limit together. incr() with an
    -- init value is atomic in the shared dict, so the count is always the true
    -- one for this request.
    local current = limit:incr(window_key, 1, 0, window * 2) or 1
    local previous = limit:get(prev_key) or 0

    -- Weighted sliding window across the current and previous buckets.
    local elapsed = now % window
    local weight = 1 - (elapsed / window)
    local estimated = previous * weight + current

    if estimated > rate * BURST_MULTIPLIER then
        return false, estimated, rate
    end

    return true, estimated, rate
end

-- Execute rate limit check
local key = get_rate_key()
local allowed, count, limit = check_rate_limit(key, DEFAULT_RATE, DEFAULT_WINDOW)

-- Set rate limit headers
ngx.header["X-RateLimit-Limit"] = tostring(limit)
ngx.header["X-RateLimit-Remaining"] = tostring(math.max(0, math.floor(limit - count)))
ngx.header["X-RateLimit-Reset"] = tostring(math.ceil(ngx.time() / DEFAULT_WINDOW) * DEFAULT_WINDOW)

if not allowed then
    ngx.status = 429
    ngx.header["Content-Type"] = "application/json"
    ngx.header["Retry-After"] = tostring(DEFAULT_WINDOW)
    ngx.say(cjson.encode({
        error = "rate_limited",
        message = "too many requests, please retry later"
    }))
    return ngx.exit(429)
end
