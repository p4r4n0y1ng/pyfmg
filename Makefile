# Makefile for pyFMG development and testing
.PHONY: help install install-dev test test-unit test-integration test-coverage lint format clean build upload docs

# Default target
help:
	@echo "Available targets:"
	@echo "  install       - Install package for production"
	@echo "  install-dev   - Install package with development dependencies"
	@echo "  test          - Run all tests"
	@echo "  test-unit     - Run unit tests only"
	@echo "  test-integration - Run integration tests only"
	@echo "  test-coverage - Run tests with coverage report"
	@echo "  lint          - Run code quality checks"
	@echo "  format        - Format code with black and isort"
	@echo "  clean         - Clean build artifacts"
	@echo "  build         - Build package"
	@echo "  upload        - Upload package to PyPI"
	@echo "  docs          - Generate documentation"

# Installation targets
install:
	pip install -e .

install-dev:
	pip install -r requirements-dev.txt
	pip install -e .

# Testing targets
test:
	pytest tests/ -v

test-unit:
	pytest tests/ -m "unit or not integration" -v

test-integration:
	pytest tests/ -m "integration" -v

test-coverage:
	pytest tests/ --cov=pyFMG --cov-report=html --cov-report=term --cov-report=xml

test-live:
	@echo "Running live tests - ensure FMG_HOST, FMG_USER, FMG_PASS are set"
	pytest tests/ -m "live" -v

# Code quality targets
lint:
	flake8 pyFMG/ tests/
	mypy pyFMG/ --ignore-missing-imports
	bandit -r pyFMG/

format:
	black pyFMG/ tests/
	isort pyFMG/ tests/

format-check:
	black --check pyFMG/ tests/
	isort --check-only pyFMG/ tests/

# Build and distribution targets
clean:
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf htmlcov/
	rm -rf .coverage
	rm -rf .pytest_cache/
	rm -rf .tox/
	find . -type d -name __pycache__ -delete
	find . -type f -name "*.pyc" -delete

build: clean
	python setup.py sdist bdist_wheel

upload: build
	twine upload dist/*

upload-test: build
	twine upload --repository-url https://test.pypi.org/legacy/ dist/*

# Documentation targets
docs:
	cd docs && make html

docs-clean:
	cd docs && make clean

# Development targets
dev-setup: install-dev
	pre-commit install

pre-commit:
	pre-commit run --all-files

# CI/CD simulation
ci: install-dev lint test-coverage
	@echo "CI pipeline completed successfully"

# Security checks
security:
	bandit -r pyFMG/ -f json -o bandit-report.json
	safety check --json --output safety-report.json

# Performance testing
perf-test:
	pytest tests/ -m "slow" -v --durations=10

# Multi-environment testing
test-tox:
	tox

# Docker testing (if you want to add Docker-based testing)
docker-test:
	docker build -t pyfmg-test -f Dockerfile.test .
	docker run --rm pyfmg-test

# Quick development cycle
quick-test: format-check test-unit

# Full validation (what CI should run)
validate: install-dev format-check lint test security
	@echo "Full validation completed successfully"