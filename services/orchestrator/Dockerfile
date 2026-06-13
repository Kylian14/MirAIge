FROM python:3.12-slim

WORKDIR /app

COPY services/orchestrator/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY services/shared/ ./services/shared/
COPY services/orchestrator/ ./services/orchestrator/

RUN useradd --create-home --uid 10001 app && chown -R app /app
USER app

ENV PYTHONPATH=/app
EXPOSE 8002

CMD ["uvicorn", "services.orchestrator.main:app", "--host", "0.0.0.0", "--port", "8002"]
