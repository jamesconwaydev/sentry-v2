# SPDX-FileCopyrightText: Copyright the Sentry-v2 contributors
# SPDX-License-Identifier: Apache-2.0
VENV ?= .venv
BIN := $(VENV)/bin

.PHONY: lint schema format typecheck test itest rpm rpm-here clean requirements

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
# rpmbuild records the directory it builds in inside the packages, so every
# build uses this one path and copies the results to rpmbuild/ afterwards.
RPMTOP := /var/tmp/sentry-v2-rpmbuild
RPM_SOURCES := src tests packaging cockpit pyproject.toml README.md LICENSE
CONTAINER ?= podman
# Build dependencies come from the spec (dnf builddep on the SRPM), so the
# list cannot drift. CRB is where pyproject-rpm-macros lives. The spec also
# uses %generate_buildrequires, so rpmbuild exits 11 until the dynamic ones
# are installed too; loop on that.
# Installing needs root, so a non-root host is expected to have them.
SPEC := $(RPMTOP)/SPECS/sentry-v2.spec
# The rest pin build time, host and file mtimes to the %changelog date, so a
# rebuild of the same tree gives the same RPMs.
RB := rpmbuild --define "_topdir $(RPMTOP)" \
	--define "source_date_epoch_from_changelog 1" \
	--define "use_source_date_epoch_as_buildtime 1" \
	--define "clamp_mtime_to_source_date_epoch 1" \
	--define "_buildhost reproducible"
RPM_BUILD := set -e; \
	if [ $$(id -u) -eq 0 ]; then \
		dnf -y -q install dnf-plugins-core; \
		$(RB) -bs $(SPEC) >/dev/null; \
		dnf -y -q --enablerepo=crb builddep $(RPMTOP)/SRPMS/sentry-v2-*.src.rpm; \
	fi; \
	rc=0; $(RB) -ba $(SPEC) || rc=$$?; \
	while [ $$rc -eq 11 ]; do \
		dnf -y -q --enablerepo=crb builddep $(RPMTOP)/SRPMS/*.buildreqs.nosrc.rpm; \
		rm -f $(RPMTOP)/SRPMS/*.buildreqs.nosrc.rpm; \
		rc=0; $(RB) -ba $(SPEC) || rc=$$?; \
	done; exit $$rc

# Builds the SRPM and RPMs into rpmbuild/. Uses rpmbuild directly on an EL
# host, otherwise a Rocky 10 container (pyproject-rpm-macros is in CRB). The
# container does the whole build, tarball included: another host's zlib
# compresses differently, and a bind-mounted build tree can lose a chmod.
rpm:
	rm -rf $(TOPDIR) && mkdir -p $(TOPDIR)
	if command -v rpmbuild >/dev/null; then \
		$(MAKE) rpm-here; \
	else \
		COPYFILE_DISABLE=1 tar c --no-xattrs $(RPM_SOURCES) Makefile scripts/source-tarball.py | \
		$(CONTAINER) run --rm -i -v $(TOPDIR):/out:Z docker.io/rockylinux/rockylinux:10 bash -ec \
			'mkdir /src && tar x -C /src && dnf -y -q install rpm-build make bzip2 tar python3 && make -C /src rpm-here TOPDIR=/out'; \
	fi

rpm-here:
	rm -rf $(RPMTOP) && mkdir -m 0700 $(RPMTOP) && mkdir $(RPMTOP)/SOURCES $(RPMTOP)/SPECS
	python3 scripts/source-tarball.py $(RPMTOP)/SOURCES/sentry-v2-$(VERSION).tar.gz sentry-v2-$(VERSION) $(RPM_SOURCES)
	cp packaging/sentry-v2.spec $(RPMTOP)/SPECS/
	$(RPM_BUILD)
	cp -r $(RPMTOP)/RPMS $(RPMTOP)/SRPMS $(TOPDIR)/

clean:
	rm -rf build dist htmlcov .coverage .mypy_cache .ruff_cache .pytest_cache
	find . -name __pycache__ -not -path './$(VENV)/*' -prune -exec rm -rf {} +
	rm -rf src/*.egg-info rpmbuild

# CI and the release workflow install only these hash-pinned files. Run after
# changing the dev extra in pyproject.toml or requirements/release.in.
requirements:
	uv pip compile pyproject.toml --extra dev --generate-hashes --universal --python-version 3.12 -q -o requirements/dev.txt
	uv pip compile requirements/release.in --generate-hashes --universal --python-version 3.12 -q -o requirements/release.txt
