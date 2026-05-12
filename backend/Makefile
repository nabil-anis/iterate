.PHONY: help install dev test lint clean build run docker-up docker-down migrate

help:
	@echo "Available commands:"
	@echo "  make install     - Install Python dependencies"
	@echo "  make dev         - Run development server"
	@echo "  make test        - Run test suite"
	@echo "  make lint        - Run linters"
	@echo "  make clean       - Clean build artifacts"
	@echo "  make build       - Build Docker image"
	@echo "  make run         - Run production server"
	@echo "  make docker-up   - Start all Docker services"
	@echo "  make docker-down - Stop all Docker services"
	@echo "  make migrate     - Run database migrations"

install:
	pip install -r requirements.txt
	pip install -r requirements-dev.txt 2>/dev/null || true

dev:
	uvicorn platform.main:app --host 0.0.0.0 --port 8000 --reload

test:
	pytest tests/ -v --cov=platform --cov-report=term --cov-report=html

lint:
	flake8 platform/ --count --statistics
	mypy platform/ --ignore-missing-imports || true

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	rm -rf .pytest_cache/
	rm -rf htmlcov/
	rm -rf .coverage coverage.xml

build:
	docker build -t cybersec-platform:latest .

run:
	uvicorn platform.main:app --host 0.0.0.0 --port 8000 --workers 4

docker-up:
	docker-compose up -d --build

docker-down:
	docker-compose down -v

migrate:
	alembic upgrade head

migration-create:
	@read -p "Migration name: " name; alembic revision --autogenerate -m "$$name"

worker:
	celery -A platform.worker worker --loglevel=info --concurrency=4

flower:
	celery -A platform.worker flower --port=5555
