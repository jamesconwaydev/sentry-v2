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
# Build dependencies come from the spec (dnf builddep on the SRPM), so the
# list cannot drift. CRB is where pyproject-rpm-macros lives. The spec also
# uses %generate_buildrequires, so rpmbuild exits 11 until the dynamic ones
# are installed too; loop on that.
# Installing needs root, so a non-root host is expected to have them.
SPEC := $(TOPDIR)/SPECS/sentry-v2.spec
RB := rpmbuild --define "_topdir $(TOPDIR)"
RPM_BUILD := set -e; \
	if [ $$(id -u) -eq 0 ]; then \
		dnf -y -q install dnf-plugins-core; \
		$(RB) -bs $(SPEC) >/dev/null; \
		dnf -y -q --enablerepo=crb builddep $(TOPDIR)/SRPMS/sentry-v2-*.src.rpm; \
	fi; \
	rc=0; $(RB) -ba $(SPEC) || rc=$$?; \
	while [ $$rc -eq 11 ]; do \
		dnf -y -q --enablerepo=crb builddep $(TOPDIR)/SRPMS/*.buildreqs.nosrc.rpm; \
		rm -f $(TOPDIR)/SRPMS/*.buildreqs.nosrc.rpm; \
		rc=0; $(RB) -ba $(SPEC) || rc=$$?; \
	done; exit $$rc

# Builds the SRPM and RPMs into rpmbuild/. Uses rpmbuild directly on an EL
# host, otherwise a Rocky 10 container (pyproject-rpm-macros is in CRB).
rpm:
	rm -rf $(TOPDIR) && mkdir -p $(TOPDIR)/SOURCES $(TOPDIR)/SPECS $(TOPDIR)/stage/sentry-v2-$(VERSION)
	tar -cf - --exclude=__pycache__ --exclude='*.egg-info' src tests packaging cockpit pyproject.toml README.md LICENSE \
		| tar -xf - -C $(TOPDIR)/stage/sentry-v2-$(VERSION)
	tar -czf $(TOPDIR)/SOURCES/sentry-v2-$(VERSION).tar.gz -C $(TOPDIR)/stage sentry-v2-$(VERSION)
	rm -rf $(TOPDIR)/stage
	cp packaging/sentry-v2.spec $(TOPDIR)/SPECS/
	if command -v rpmbuild >/dev/null; then \
		$(RPM_BUILD); \
	else \
		$(CONTAINER) run --rm -v $(TOPDIR):$(TOPDIR):Z docker.io/rockylinux/rockylinux:10 bash -ec \
			'dnf -y -q install rpm-build make bzip2 tar && $(RPM_BUILD)'; \
	fi

clean:
	rm -rf build dist htmlcov .coverage .mypy_cache .ruff_cache .pytest_cache
	find . -name __pycache__ -not -path './$(VENV)/*' -prune -exec rm -rf {} +
	rm -rf src/*.egg-info rpmbuild
