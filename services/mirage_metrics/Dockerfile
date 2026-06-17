FROM python:3.14-slim

WORKDIR /app

COPY services/mirage_metrics/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY services/shared/ ./services/shared/
COPY services/mirage_metrics/ ./services/mirage_metrics/

RUN useradd --create-home --uid 10001 app && chown -R app /app
USER app

ENV PYTHONPATH=/app
EXPOSE 8004

CMD ["uvicorn", "services.mirage_metrics.main:app", "--host", "0.0.0.0", "--port", "8004"]
