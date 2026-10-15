VENV ?= .venv
BIN := $(VENV)/bin

.PHONY: lint schema format typecheck test itest clean

lint:
	$(BIN)/ruff check .
	$(BIN)/ruff format --check .
	$(MAKE) schema

schema:
	$(BIN)/pytest tests/unit/test_bundle.py -q -k sample --no-cov
	$(BIN)/check-jsonschema --schemafile docs/reference/bundle.schema.json tests/fixtures/bundle_sample.json

format:
	$(BIN)/ruff check --fix .
	$(BIN)/ruff format .

typecheck:
	$(BIN)/mypy src

test:
	$(BIN)/pytest --cov --cov-report=term-missing

itest:
	scripts/itest.sh

clean:
	rm -rf build dist htmlcov .coverage .mypy_cache .ruff_cache .pytest_cache
	find . -name __pycache__ -not -path './$(VENV)/*' -prune -exec rm -rf {} +
	rm -rf src/*.egg-info
