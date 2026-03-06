-- WSLVault Gateway Readiness Check
-- Verifies that at least the core upstream services are reachable.

local cjson = require "cjson.safe"

local function check_upstream(name, host, port)
    local sock = ngx.socket.tcp()
    sock:settimeout(1000) -- 1 second timeout
    local ok, err = sock:connect(host, port)
    if ok then
        sock:close()
        return true
    end
    return false, err
end

local services = {
    { name = "secret-engine", host = "secret-engine", port = 8081 },
    { name = "crypto-service", host = "crypto-service", port = 8080 },
    { name = "identity-service", host = "identity-service", port = 8082 },
}

local all_ready = true
local results = {}

for _, svc in ipairs(services) do
    local ok, err = check_upstream(svc.name, svc.host, svc.port)
    results[svc.name] = ok and "ready" or ("unreachable: " .. (err or "unknown"))
    if not ok then
        all_ready = false
    end
end

local status = all_ready and 200 or 503

ngx.status = status
ngx.header["Content-Type"] = "application/json"
ngx.say(cjson.encode({
    status = all_ready and "ready" or "degraded",
    services = results
}))
return ngx.exit(status)
