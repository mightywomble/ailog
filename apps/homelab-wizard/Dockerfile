FROM python:3.12-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-client curl ca-certificates git \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY *.py ./
COPY web ./web
ENV PYTHONUNBUFFERED=1 \
    WIZ_SETTINGS=/data/settings.json \
    WIZ_SSH_KEY=/data/ssh/id_ed25519
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --retries=3 --start-period=25s \
  CMD python3 -c "import urllib.request;urllib.request.urlopen('http://localhost:8080/healthz',timeout=3)"
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]
