VENV ?= .venv
BIN := $(VENV)/bin

.PHONY: lint schema format typecheck test itest rpm clean

lint:
	$(BIN)/ruff check .
	$(BIN)/ruff format --check .
	$(MAKE) schema

schema:
	f=$$(mktemp) && SENTRY_BUNDLE_SAMPLE=$$f $(BIN)/pytest tests/unit/test_bundle.py -q -k sample --no-cov \
		&& $(BIN)/check-jsonschema --schemafile docs/reference/bundle.schema.json $$f; rc=$$?; rm -f $$f; exit $$rc

format:
	$(BIN)/ruff check --fix .
	$(BIN)/ruff format .

typecheck:
	$(BIN)/mypy src

test:
	$(BIN)/pytest --cov --cov-report=term-missing

itest:
	scripts/itest.sh

VERSION := $(shell sed -n 's/^__version__ = "\(.*\)"/\1/p' src/sentry_v2/__init__.py)
TOPDIR := $(CURDIR)/rpmbuild
CONTAINER ?= podman
RPM_BUILDDEPS := rpm-build python3-devel pyproject-rpm-macros systemd-rpm-macros \
	selinux-policy-devel bzip2 python3-setuptools python3-wheel

# Builds the SRPM and RPMs into rpmbuild/. Uses rpmbuild directly on an EL
# host, otherwise a Rocky 10 container (pyproject-rpm-macros is in CRB).
rpm:
	rm -rf $(TOPDIR) && mkdir -p $(TOPDIR)/SOURCES $(TOPDIR)/SPECS $(TOPDIR)/stage/sentry-v2-$(VERSION)
	tar -cf - --exclude=__pycache__ --exclude='*.egg-info' src tests packaging pyproject.toml README.md LICENSE \
		| tar -xf - -C $(TOPDIR)/stage/sentry-v2-$(VERSION)
	tar -czf $(TOPDIR)/SOURCES/sentry-v2-$(VERSION).tar.gz -C $(TOPDIR)/stage sentry-v2-$(VERSION)
	rm -rf $(TOPDIR)/stage
	cp packaging/sentry-v2.spec $(TOPDIR)/SPECS/
	if command -v rpmbuild >/dev/null; then \
		rpmbuild -ba --define '_topdir $(TOPDIR)' $(TOPDIR)/SPECS/sentry-v2.spec; \
	else \
		$(CONTAINER) run --rm -v $(TOPDIR):/root/rpmbuild:Z docker.io/rockylinux/rockylinux:10 bash -ec \
			'dnf -y -q --enablerepo=crb install $(RPM_BUILDDEPS) && rpmbuild -ba /root/rpmbuild/SPECS/sentry-v2.spec'; \
	fi

clean:
	rm -rf build dist htmlcov .coverage .mypy_cache .ruff_cache .pytest_cache
	find . -name __pycache__ -not -path './$(VENV)/*' -prune -exec rm -rf {} +
	rm -rf src/*.egg-info rpmbuild
