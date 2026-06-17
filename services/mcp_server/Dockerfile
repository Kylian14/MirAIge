FROM python:3.14-slim

WORKDIR /app

COPY services/mcp_server/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY services/shared/ ./services/shared/
COPY services/mcp_server/ ./services/mcp_server/

RUN useradd --create-home --uid 10001 app && chown -R app /app
USER app

ENV PYTHONPATH=/app
EXPOSE 8003

CMD ["uvicorn", "services.mcp_server.server:app", "--host", "0.0.0.0", "--port", "8003"]
