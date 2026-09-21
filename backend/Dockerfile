FROM python:3.12-slim AS analysis-tools
COPY tools/install_anchore.py /tmp/install_anchore.py
RUN python /tmp/install_anchore.py

FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
COPY alembic ./alembic
COPY alembic.ini ./alembic.ini

EXPOSE 8000
CMD ["sh", "-c", "alembic upgrade head && uvicorn app.main:app --host 0.0.0.0 --port 8000"]

FROM base AS analysis-worker
COPY --from=analysis-tools /opt/analysis-tools /opt/analysis-tools
RUN mkdir -p /var/lib/eolwatch/analysis /var/cache/eolwatch
CMD ["python", "-m", "app.worker"]

# Run with the repository mounted at /workspace so tests can read sample fixtures.
FROM base AS test
COPY requirements-dev.txt .
RUN pip install --no-cache-dir -r requirements-dev.txt
WORKDIR /workspace
CMD ["python", "-m", "pytest", "-q", "-p", "no:cacheprovider"]

# The default image remains the API; only the worker needs analysis binaries.
FROM base AS api
