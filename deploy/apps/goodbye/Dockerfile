# Second example app for the homelab build pipeline (multi-image demo).
# Serves a static page on port 8081; this app ships a custom test.sh so the
# build workflow runs it instead of the default start-and-stay-up smoke test.
FROM python:3.12-alpine
WORKDIR /www
RUN printf 'goodbye from the homelab build pipeline (v1)\n' > index.html
EXPOSE 8081
CMD ["python", "-m", "http.server", "8081"]
