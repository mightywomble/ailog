FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-client git \
    && rm -rf /var/lib/apt/lists/*

# git is for the estate checkout (estate/git.py): the app commits a version bump
# to homelab-ops and lets CI deploy it, so it needs a real git, not a wrapper.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    AILOG_BIND=0.0.0.0 \
    AILOG_PORT=5001

WORKDIR /app

COPY requirements.txt /app/requirements.txt
# ansible-runner drives the remediation catalog; the collections back the
# roles in remediations/. --no-cache is ansible-galaxy's flag (not pip's).
RUN pip install --no-cache-dir -r /app/requirements.txt \
    && ansible-galaxy collection install --no-cache \
        ansible.posix:1.5.4 community.docker:3.10.4 community.general:8.6.0

COPY . /app

EXPOSE 5001

CMD ["python3", "app.py"]
