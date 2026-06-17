# ── Stage 1 · build the SPA console ───────────────────────────────────
FROM node:26-alpine AS web
WORKDIR /web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

# ── Stage 2 · the BFF, serving the API + the built console ─────────────
FROM python:3.12-slim
WORKDIR /app

COPY services/api/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY services/shared/ ./services/shared/
COPY services/api/ ./services/api/
# the red-team launcher shells out to `python -m services.attack_simulator.attack`
COPY services/attack_simulator/ ./services/attack_simulator/
COPY --from=web /web/dist /app/web

RUN useradd --create-home --uid 10001 app && chown -R app /app
USER app

ENV PYTHONPATH=/app
ENV WEB_DIR=/app/web
EXPOSE 8000

CMD ["uvicorn", "services.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
