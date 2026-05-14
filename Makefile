.PHONY: test lint format-check checks

test:
	python -m pytest

lint:
	python -m ruff check .

format-check:
	python -m ruff format --check .

checks: test lint format-check
