# ingest — move homelab knowledge (WordPress, Gitea, MetaMCP) into AnythingLLM
# and show what landed. Single small FastAPI app; no build steps beyond pip.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    INGEST_DB=/data/ingest.db

WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY app.py /app/app.py
COPY templates /app/templates

EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s \
  CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/healthz', timeout=3)"

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080", "--no-access-log"]
