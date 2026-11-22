FROM python:3.12-slim
# SAF-174: remove the Entrust Root CA that expires 2026-11-27 from the trust
# store. ca-certificates still ships it, so a rebuild alone does not clear it.
RUN sed -i '/Entrust_Root_Certification_Authority\.crt$/d' /etc/ca-certificates.conf \
 && rm -f /usr/share/ca-certificates/mozilla/Entrust_Root_Certification_Authority.crt \
 && update-ca-certificates --fresh \
 && test ! -e /etc/ssl/certs/Entrust_Root_Certification_Authority.pem


ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    STATUS_DB=/data/status.db

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py collect.py store.py apps.json ./
COPY templates ./templates
COPY static ./static

RUN mkdir -p /data
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/healthz', timeout=3)"

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080", "--no-access-log"]
