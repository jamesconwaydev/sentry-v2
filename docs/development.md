# Development

The package imports and tests on any platform with Python 3.12, including
macOS. The two distro bindings are only needed on a real EL10 host.

## Setting up

```console
$ git clone https://github.com/jamesconwaydev/sentry-v2.git
$ cd sentry-v2
$ uv venv -p 3.12 .venv
$ uv pip install -e '.[dev]'
```

Without `uv`:

```console
$ python3.12 -m venv .venv
$ .venv/bin/pip install -e '.[dev]'
```

## Checks

```console
$ make lint typecheck test
```

| Target | Runs |
|---|---|
| `lint` | `ruff check`, `ruff format --check`, and a check that a freshly built bundle validates against `docs/reference/bundle.schema.json`. |
| `typecheck` | `mypy --strict` over `src`. |
| `test` | The unit tests with coverage. The build fails under 90 % line coverage. |
| `format` | Applies `ruff` fixes and formatting. |

CI runs the same checks on every pull request; the tests run in a Rocky
Linux 10 container with the distro bindings installed.

The unit tests need no root and no systemd. They use fixture cgroup trees,
captured journal and audit records, an in-memory systemd, local HTTP and
syslog servers, and a hand-driven clock. A few tests also keep the docs
honest: every configuration key must appear in
[configuration.md](configuration.md), every policy example in
[policies.md](policies.md) must load, the example in
[bundles.md](bundles.md) must match the schema, and relative links in the
Markdown must resolve.

## Integration tests on a Rocky host

Tests marked `integration` talk to the real system bus and need root on an
EL10 host. They're skipped by default.

On the host, create a virtual environment that can see the distro bindings,
then run the marked tests as root:

```console
# dnf install python3-systemd python3-dbus git
$ git clone https://github.com/jamesconwaydev/sentry-v2.git && cd sentry-v2
$ python3 -m venv --system-site-packages .venv
$ .venv/bin/pip install -e '.[dev]'
$ sudo .venv/bin/pytest -m integration tests/integration --no-cov
```

A `make itest` target for this is coming; until then, run
pytest on the host as above.

The tests create throwaway transient units in `sentry-test.slice`, keep any
memory load small, and stop and reset every unit they create, even when a
test fails. Don't run them on a host where something else uses that slice
name.

## Building the RPMs

```console
$ make rpm
```

This builds the SRPM and RPMs into `rpmbuild/`, with `rpmbuild` on an EL
host or in a `rockylinux:10` container elsewhere. `make clean` removes the
build output.

## Making a change

- Branch from `main`; all changes land through a pull request, squash-merged.
- Commit messages follow Conventional Commits (`feat:`, `fix:`, `docs:` and
  so on), subject at most 72 characters.
- Add an entry under `## [Unreleased]` in [CHANGELOG.md](../CHANGELOG.md)
  for anything a user would notice.
- Keep runtime imports to the standard library plus `systemd` and `dbus`,
  and import those two lazily inside the module that needs them. See
  [architecture.md](architecture.md#why-stdlib-only).

## Releasing

1. Set the version in two places: `__version__` in
   `src/sentry_v2/__init__.py` and `upstream_version` in
   `packaging/sentry-v2.spec`. A unit test fails if they differ.
2. Add a `%changelog` entry to the spec.
3. In `CHANGELOG.md`, rename `## [Unreleased]` to the version and date, and
   start a new empty `Unreleased` section.
4. Merge that through a pull request.
5. Tag the merge commit and push the tag:

   ```console
   $ git tag -s v0.1.0 -m 'v0.1.0'
   $ git push origin v0.1.0
   ```

   The release workflow runs on `v*` tags and publishes the RPMs and Python
   packages to the GitHub release.
