FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-client \
    && rm -rf /var/lib/apt/lists/*

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    AILOG_BIND=0.0.0.0 \
    AILOG_PORT=5001

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt \
    && ansible-galaxy collection install --no-cache-dir \
        ansible.posix:1.5.4 community.docker:3.10.4 community.general:8.6.0

COPY . /app

EXPOSE 5001

CMD ["python3", "app.py"]
