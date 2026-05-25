# ============================================================
# PhishGuard — Makefile
# Targets: dev test migrate seed worker lint train evaluate
# ============================================================

.PHONY: dev test migrate seed worker beat lint train evaluate \
        build up down logs shell clean help

# ── Development ───────────────────────────────────────────────
dev:
	docker compose up --build

build:
	docker compose build

up:
	docker compose up -d

down:
	docker compose down

logs:
	docker compose logs -f api worker beat

shell:
	docker compose exec api bash

# ── Testing ───────────────────────────────────────────────────
test:
	pytest --cov=app --cov-fail-under=80 -v $(ARGS)

test-nlp:
	pytest --cov=app/services/nlp_pipeline --cov-fail-under=80 tests/test_nlp.py -v

test-unit:
	pytest tests/ -m "not integration" -v

test-integration:
	pytest tests/ -m integration -v

# ── Database ──────────────────────────────────────────────────
migrate:
	alembic upgrade head

migrate-down:
	alembic downgrade -1

migrate-history:
	alembic history --verbose

seed:
	python app/seed.py

# ── Celery ────────────────────────────────────────────────────
worker:
	celery -A app.tasks.celery_app worker \
		-Q analysis,digest,forwarding,export,maintenance,imap \
		--loglevel=info \
		--concurrency=4

beat:
	celery -A app.tasks.celery_app beat --loglevel=info

# ── Code Quality ──────────────────────────────────────────────
lint:
	mypy --strict app/
	bandit -r app/ -ll

typecheck:
	mypy --strict app/

security:
	bandit -r app/ -ll

# ── Machine Learning ─────────────────────────────────────────
train:
	python ml/train.py

evaluate:
	python ml/evaluate.py

# ── TLS (dev only) ───────────────────────────────────────────
certs:
	bash nginx/ssl/generate-dev-cert.sh

# ── Cleanup ───────────────────────────────────────────────────
clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	rm -rf .mypy_cache .pytest_cache htmlcov .coverage

# ── Help ──────────────────────────────────────────────────────
help:
	@echo "PhishGuard Makefile targets:"
	@echo "  dev          — docker compose up --build (full stack)"
	@echo "  test         — pytest with 80% coverage gate"
	@echo "  migrate      — alembic upgrade head"
	@echo "  seed         — load initial DB data"
	@echo "  worker       — start Celery worker (all queues)"
	@echo "  beat         — start Celery Beat scheduler"
	@echo "  lint         — mypy --strict + bandit"
	@echo "  train        — train Random Forest model"
	@echo "  evaluate     — evaluate model metrics (F1 gate)"
	@echo "  certs        — generate dev TLS cert (nginx/ssl/)"
	@echo "  clean        — remove cache and compiled files"
