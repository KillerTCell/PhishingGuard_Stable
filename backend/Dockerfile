# ============================================================
# PhishGuard — Multi-Stage Dockerfile
# Stage 1: builder  — install all Python dependencies
# Stage 2: final    — lean runtime image, no build tools
# ============================================================

# ── Stage 1: builder ─────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build

# System deps required to compile some Python packages (e.g. asyncpg, cryptography)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
# spacy==3.7.4 requires typer<0.10.0 but fastapi-cli requires typer>=0.12.3.
# Install everything else first, then spacy without its optional CLI deps
# (PhishGuard only uses spacy's Python API, never its CLI).
RUN grep -v '^spacy' requirements.txt > /tmp/requirements-no-spacy.txt \
    && pip install --no-cache-dir --prefix=/install -r /tmp/requirements-no-spacy.txt \
    && pip install --no-cache-dir --prefix=/install --no-deps spacy==3.7.4

# Download spaCy model into the prefix so it is copied to final stage.
# Use pip install directly because --prefix=/install puts packages there but not
# the python binary, so `python -m spacy download` can't find the prefix.
RUN pip install --no-cache-dir --prefix=/install \
    "en_core_web_sm @ https://github.com/explosion/spacy-models/releases/download/en_core_web_sm-3.7.1/en_core_web_sm-3.7.1-py3-none-any.whl"


# ── Stage 2: final ───────────────────────────────────────────
FROM python:3.12-slim AS final

WORKDIR /app

# curl is required for the HEALTHCHECK command
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    libpq5 \
    && rm -rf /var/lib/apt/lists/*

# Copy installed packages from builder (no build tools in final image)
COPY --from=builder /install/lib /usr/local/lib
COPY --from=builder /install/bin /usr/local/bin

# Copy application source
COPY app/      ./app/
COPY ml/       ./ml/
COPY alembic/  ./alembic/
COPY alembic.ini .

# Non-root user for security
RUN addgroup --system phishguard && adduser --system --ingroup phishguard phishguard
RUN chown -R phishguard:phishguard /app
USER phishguard

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8000/api/v1/health || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
