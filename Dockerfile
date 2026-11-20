FROM python:3.11-slim AS base
LABEL maintainer="Soxoj <soxoj@protonmail.com>"
WORKDIR /app
RUN pip install --no-cache-dir --upgrade pip
RUN apt-get update && \
    apt-get install --no-install-recommends -y \
      build-essential \
      python3-dev \
      pkg-config \
      libcairo2-dev \
      libxml2-dev \
      libxslt1-dev \
    && rm -rf /var/lib/apt/lists/* /tmp/*
COPY . .
RUN YARL_NO_EXTENSIONS=1 python3 -m pip install --no-cache-dir .
# For production use, set FLASK_HOST to a specific IP address for security
ENV FLASK_HOST=0.0.0.0

# Web UI variant: auto-launches the web interface on $PORT
FROM base AS web
RUN pip install --no-cache-dir '.[pdf]'
ENV PORT=5000
ENV PYTHONUNBUFFERED=1
EXPOSE 5000
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD python3 -c "import os, urllib.request; urllib.request.urlopen('http://127.0.0.1:' + os.environ.get('PORT', '5000') + '/', timeout=5)"
ENTRYPOINT ["sh", "-c", "exec maigret --web \"$PORT\""]

# Default variant (last stage = `docker build .` target): CLI, backwards-compatible
FROM base AS cli
ENTRYPOINT ["maigret"]
