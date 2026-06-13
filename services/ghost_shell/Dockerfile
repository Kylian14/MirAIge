FROM python:3.12-slim

WORKDIR /app

COPY services/ghost_shell/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY services/shared/ ./services/shared/
COPY services/ghost_shell/ ./services/ghost_shell/

RUN useradd --create-home --uid 10001 app && chown -R app /app
USER app

ENV PYTHONPATH=/app
EXPOSE 8080

CMD ["uvicorn", "services.ghost_shell.main:app", "--host", "0.0.0.0", "--port", "8080", "--no-server-header"]
