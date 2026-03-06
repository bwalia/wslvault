-- WSLVault Rate Limiting Middleware
-- Sliding window rate limiter using shared memory.
-- Limits are per-tenant (extracted from token) or per-IP for unauthenticated endpoints.

local cjson = require "cjson.safe"

-- Configuration
local DEFAULT_RATE = 100      -- requests per window
local DEFAULT_WINDOW = 60     -- window size in seconds
local BURST_MULTIPLIER = 1.5  -- allow burst up to 150% of rate

-- Get rate limit key: tenant_id if authenticated, client IP otherwise
local function get_rate_key()
    local tenant_id = ngx.req.get_headers()["X-Vault-Tenant-ID"]
    if tenant_id and tenant_id ~= "" then
        return "tenant:" .. tenant_id
    end
    return "ip:" .. ngx.var.remote_addr
end

-- Sliding window counter
local function check_rate_limit(key, rate, window)
    local limit = ngx.shared.rate_limit
    local now = ngx.time()
    local window_key = key .. ":" .. math.floor(now / window)
    local prev_key = key .. ":" .. (math.floor(now / window) - 1)

    -- Get counts for current and previous windows
    local current = limit:get(window_key) or 0
    local previous = limit:get(prev_key) or 0

    -- Calculate weighted count using sliding window
    local elapsed = now % window
    local weight = 1 - (elapsed / window)
    local estimated = previous * weight + current

    if estimated >= rate * BURST_MULTIPLIER then
        return false, estimated, rate
    end

    -- Increment current window
    local new_count = limit:incr(window_key, 1, 0, window * 2)

    return true, estimated + 1, rate
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
