-- Per-request routing: flagged mg_session / IP -> Ghost Shell, else -> upstream.
-- Fail-open: if Redis is unreachable, never break the protected app.
require("canary").maybe_serve()   -- always-on traps first; ngx.exit()s on a match

local redis = require "resty.redis"
local cfg = _G.miraige

local session = ngx.var.cookie_mg_session
local ip = ngx.var.remote_addr
local xff = ngx.req.get_headers()["x-forwarded-for"]
if xff then
    if type(xff) == "table" then xff = xff[#xff] end
    local last = tostring(xff):match("([^,%s]+)%s*$")
    if last then ip = last end
end

local function is_flagged()
    local red = redis:new()
    red:set_timeout(200)
    local ok = red:connect(cfg.redis_host, cfg.redis_port)
    if not ok then
        return false   -- fail-open
    end

    local hit = false
    if session and session ~= "" then
        local v = red:get(cfg.prefix .. ":flag:sess:" .. session)
        if v and v ~= ngx.null then hit = true end
    end
    if not hit and ip and ip ~= "" then
        local v = red:get(cfg.prefix .. ":flag:ip:" .. ip)
        if v and v ~= ngx.null then hit = true end
    end

    red:set_keepalive(10000, 100)
    return hit
end

if is_flagged() then
    ngx.var.target = cfg.ghost
    ngx.header["X-Mir-Route"] = "ghost"
else
    ngx.var.target = cfg.upstream
    ngx.header["X-Mir-Route"] = "upstream"
end
