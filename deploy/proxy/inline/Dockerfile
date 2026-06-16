# Mir[AI]ge inline enforcement proxy (OpenResty = nginx + Lua + lua-resty-redis).
# Sits in front of the protected app; routes flagged sessions/IPs to the Ghost
# Shell (Redis flag set) and mirrors request metadata to Sentinel.

# Builder: install lua-resty-http (opm only ships in the -fat image).
FROM openresty/openresty:alpine-fat AS build
RUN opm get ledgetech/lua-resty-http

# Runtime: slim OpenResty + the installed lib + our config.
FROM openresty/openresty:alpine
COPY --from=build /usr/local/openresty/site /usr/local/openresty/site

COPY deploy/proxy/inline/nginx.conf /usr/local/openresty/nginx/conf/nginx.conf
COPY deploy/proxy/inline/flag_router.lua /usr/local/openresty/lua/flag_router.lua
COPY deploy/proxy/inline/mirror.lua /usr/local/openresty/lua/mirror.lua
COPY deploy/proxy/inline/canary.lua /usr/local/openresty/lua/canary.lua
COPY deploy/proxy/inline/canary_manifest.json /usr/local/openresty/lua/canary_manifest.json

# Run as a non-root user. nginx (master + workers) only needs to write its pid
# (/run/openresty.pid) and the temp dirs under the nginx prefix; logs go to
# stdout/stderr and it listens on 8080 (>1024), so no root is required.
RUN addgroup -S app && adduser -S -G app -u 10001 app \
    && chown -R app:app /usr/local/openresty/nginx /run
USER app

EXPOSE 8080
