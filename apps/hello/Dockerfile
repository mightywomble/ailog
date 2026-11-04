# Example app for the homelab build pipeline.
# Serves a static page on port 8080 so the default smoke test
# (container starts and keeps running) passes.
FROM python:3.12-alpine
WORKDIR /www
RUN printf 'homelab build pipeline says hello (v4)\n' > index.html
EXPOSE 8080
CMD ["python", "-m", "http.server", "8080"]
