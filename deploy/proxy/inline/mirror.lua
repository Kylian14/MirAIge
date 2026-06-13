-- log_by_lua: fire-and-forget mirror of each request to Sentinel /logs, so the
-- detection cascade works in front of ANY upstream (not just the demo portal).
-- Disabled when SENTINEL_URL is empty (e.g. the upstream already streams logs).
local cfg = _G.miraige
if not cfg.sentinel or cfg.sentinel == "" then
    return
end

local cjson = require "cjson"

local method = ngx.var.request_method or "GET"
local uri = ngx.var.request_uri or "/"
local status = tonumber(ngx.var.status) or 0
local ua = ngx.var.http_user_agent or "-"
local bytes = ngx.var.body_bytes_sent or "0"
local rt = tonumber(ngx.var.request_time) or 0
local session = ngx.var.cookie_mg_session

local ip = ngx.var.remote_addr
local xff = ngx.var.http_x_forwarded_for
if xff and xff ~= "" then
    local last = xff:match("([^,%s]+)%s*$")
    if last then ip = last end
end

-- Combined-log-format line (Sentinel's T0/T1 parse the UA + path from `raw`).
local raw = string.format('%s - - [%s] "%s %s HTTP/1.1" %d %s "%s" %dms',
    ip, os.date("!%d/%b/%Y:%H:%M:%S +0000"), method, uri, status, tostring(bytes), ua,
    math.floor(rt * 1000))

local event = {
    timestamp = os.date("!%Y-%m-%dT%H:%M:%SZ"),
    source = "lb",
    src_ip = ip,
    session_id = (session and session ~= "" and session) or nil,
    method = method,
    path = uri,
    status_code = status,
    raw = raw,
}
local body = cjson.encode({ event })
local url = cfg.sentinel .. "/logs"

local function post(premature, url, body)
    if premature then return end
    local http = require "resty.http"
    local httpc = http.new()
    httpc:set_timeout(500)
    httpc:request_uri(url, {
        method = "POST",
        body = body,
        headers = { ["Content-Type"] = "application/json" },
    })
end

ngx.timer.at(0, post, url, body)
