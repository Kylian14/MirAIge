FROM python:3.14-slim

WORKDIR /app

# libgomp1 : runtime OpenMP requis par xgboost (Tier 1 · ADR-003) — absent de l'image slim
RUN apt-get update && apt-get install -y --no-install-recommends libgomp1 \
    && rm -rf /var/lib/apt/lists/*

COPY services/sentinel/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY services/shared/ ./services/shared/
COPY services/sentinel/ ./services/sentinel/

RUN useradd --create-home --uid 10001 app && chown -R app /app
USER app

ENV PYTHONPATH=/app
EXPOSE 8001

CMD ["uvicorn", "services.sentinel.main:app", "--host", "0.0.0.0", "--port", "8001"]
