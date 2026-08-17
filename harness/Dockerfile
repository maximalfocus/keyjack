# Verification harness image: Python 3.13 + Playwright (headless Chromium) + dev tooling.
# Built from the pinned Playwright image (browsers + system deps preinstalled), with a
# uv-managed Python 3.13 layered on top so the whole project runs on one interpreter.
FROM mcr.microsoft.com/playwright/python:v1.55.0-noble

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PATH="/opt/venv/bin:${PATH}"

RUN pip install --no-cache-dir uv

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
COPY tests ./tests
COPY harness/verify.sh /usr/local/bin/verify.sh

# A Python 3.13 venv that reuses the image's preinstalled browsers (/ms-playwright).
RUN uv venv --python 3.13 /opt/venv \
    && uv pip install --python /opt/venv/bin/python -e ".[dev]" \
    && chmod +x /usr/local/bin/verify.sh

CMD ["/usr/local/bin/verify.sh"]
