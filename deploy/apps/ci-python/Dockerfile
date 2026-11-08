# Toolchain image for the Python jobs in .gitea/workflows/ci.yml.
#
# Why this exists: those jobs used actions/setup-python@v5, which downloads the
# interpreter from
#   https://github.com/actions/python-versions/releases/download/...
# From the build server that path answers HTTP 504 while github.com itself, the
# GitHub API, PyPI and nodejs.org all answer normally, so the jobs failed
# intermittently (the same commit passed or failed depending on the run).
# Everything they need is baked in here instead, and served from zot, so a CI
# run needs no interpreter download at all.
#
# It carries node on purpose: a `container:` job runs JavaScript actions
# (actions/checkout) inside this image, so node has to be on PATH.
#
# Versions are pinned to what the unpinned installs resolved to when this image
# was introduced, so a lint failure means the code changed - not that a tool
# updated itself. Bump them deliberately.
FROM python:3.12-slim

ARG NODE_VERSION=20.18.1

# git + ca-certificates: actions/checkout and pip. curl/xz: the node tarball.
RUN set -eu; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
      git ca-certificates curl xz-utils; \
    rm -rf /var/lib/apt/lists/*

# node from nodejs.org, not apt: Debian trixie's sqv policy rejects the
# NodeSource key ("SHA1 is not considered secure"), and the distro node is too
# old for actions/checkout@v4.
RUN set -eu; \
    curl -fsSL -o /tmp/node.tar.xz \
      "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-x64.tar.xz"; \
    tar -xJf /tmp/node.tar.xz -C /usr/local --strip-components=1 --no-same-owner; \
    rm -f /tmp/node.tar.xz; \
    node --version; npm --version

# What ci.yml used to install per run. ansible-lint pulls ansible-core, which is
# where ansible-playbook comes from.
RUN pip install --no-cache-dir \
      "pytest==9.2.0" \
      "pytest-cov==7.1.0" \
      "ruff==0.17.4" \
      "yamllint==1.38.0" \
      "ansible-lint==26.11.0"

# The app's own dependencies come from requirements.txt in the job: they belong
# to the repo and must never go stale inside an image.
CMD ["python3"]
