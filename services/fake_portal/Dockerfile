FROM python:3.14-slim

WORKDIR /app

COPY services/fake_portal/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY services/shared/ ./services/shared/
COPY services/fake_portal/ ./services/fake_portal/

RUN useradd --create-home --uid 10001 app && chown -R app /app
USER app

ENV PYTHONPATH=/app
EXPOSE 8080

CMD ["uvicorn", "services.fake_portal.main:app", "--host", "0.0.0.0", "--port", "8080", "--no-server-header"]
