# Secure application image. Python 3.13, dependencies resolved with uv inside the build.
FROM python:3.13-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

RUN pip install --no-cache-dir uv

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN uv pip install --system --no-cache .

# Run non-root with an unprivileged, well-known uid.
RUN useradd --uid 10001 --create-home appuser
USER appuser

EXPOSE 8000
# --factory builds the app per process from the environment, avoiding import-time side effects.
CMD ["uvicorn", "keyjack.apps.secure:create_secure_app", "--factory", \
     "--host", "0.0.0.0", "--port", "8000"]
