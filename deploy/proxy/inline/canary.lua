-- Always-on trap layer: serve bait paths and the reverse-PI canary IN FRONT of
-- the protected app (the app never hosts these). A hit on the acknowledge path
-- is the gold AI signal -> POST Sentinel /canary-hit (confidence 0.97).
-- Driven by canary_manifest.json (loaded into _G.miraige.canary at init).
local M = {}

local function client_ip()
    local ip = ngx.var.remote_addr
    local xff = ngx.var.http_x_forwarded_for
    if xff and xff ~= "" then
        local last = xff:match("([^,%s]+)%s*$")
        if last then ip = last end
    end
    return ip
end

local function report_ack(can)
    local cfg = _G.miraige
    if not cfg.sentinel or cfg.sentinel == "" then return end
    local cjson = require "cjson"
    local session = ngx.var.cookie_mg_session
    local body = cjson.encode({
        src_ip = client_ip(),
        session_id = (session and session ~= "" and session) or "",
        canary_id = can.canary_id or "pi_notice_to_admins",
    })
    local url = cfg.sentinel .. "/canary-hit"
    ngx.timer.at(0, function(premature)
        if premature then return end
        local http = require "resty.http"
        local httpc = http.new()
        httpc:set_timeout(500)
        httpc:request_uri(url, {
            method = "POST",
            body = body,
            headers = { ["Content-Type"] = "application/json" },
        })
    end)
end

local function serve(ct, body)
    ngx.header["X-Mir-Route"] = "canary"
    ngx.header.content_type = ct or "text/plain"
    ngx.say(body or "")
    return ngx.exit(ngx.HTTP_OK)
end

-- Returns nothing; ngx.exit()s the request when a trap matches, else falls through.
function M.maybe_serve()
    local can = _G.miraige.canary
    if not can or not next(can) then return end
    local path = ngx.var.uri

    if can.robots and path == "/robots.txt" then
        return serve("text/plain", can.robots)
    end
    if can.notice_path and path == can.notice_path then
        return serve("text/plain", can.notice_body)
    end
    if can.ack_path and path == can.ack_path then
        report_ack(can)
        return serve("application/json", '{"status":"acknowledged"}')
    end
    local b = can.bait and can.bait[path]
    if b then
        return serve(b.ct, b.body)
    end
end

return M
