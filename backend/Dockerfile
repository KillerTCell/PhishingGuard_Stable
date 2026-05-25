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
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# Download spaCy model into the prefix so it is copied to final stage
RUN /install/bin/python -m spacy download en_core_web_sm


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
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
