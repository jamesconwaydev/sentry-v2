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

Tests marked `integration` run against the installed RPMs on an EL10 host:
the real daemon, the system bus, kernel PSI triggers, the audit stream and
the SELinux module, enforcing. They're skipped by default.

From your checkout, with SSH access to a host where your user has
passwordless sudo and the RPM build dependencies are installed (see
[Building the RPMs](#building-the-rpms)):

```console
$ make itest HOST=rocky@test-host.example.com
```

`scripts/itest.sh` copies the tree to `~/sentry-v2-itest` on the host,
builds the RPMs there with `make rpm`, installs all three, writes the test
configuration and policies from `tests/integration/config` to
`/etc/sentry-v2`, starts the daemon and runs the suite as root from a
throwaway virtual environment in `/tmp`. Afterwards it copies the daemon's
journal and the run's audit records to `itest-artifacts/<timestamp>/` and
removes the RPMs, the configuration and the state directory.

| Variable | Default | Meaning |
|---|---|---|
| `HOST` | the project's test host | The test host, as `user@host`. |
| `KEEP` | `0` | `1` leaves everything installed and running, for poking at by hand. The next run removes it first. |
| `PYTEST_ARGS` | empty | Extra pytest arguments, such as `-k throttle`. |

The tests start their units in `sentry-test.slice`, and every enforcing
test policy matches only those units. Memory load stays under 100 MiB, and
each test stops, resets and deletes what it created, even when it fails.
Don't run the suite on a host where something else uses that slice name or
`sentry-itest-*` unit names. `test_avc_correlation.py` loads a small
SELinux module, `sentry_test`, and removes it again; `test_cli_and_control.py`
creates and deletes a system user, `sv2-itest`.

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

   The tag builds and publishes the GitHub release. The release workflow
   accepts only `vMAJOR.MINOR.PATCH` tags, checks that the tag,
   `__version__` and the spec agree, takes the notes from the matching
   `CHANGELOG.md` section, builds the RPMs, wheel and sdist, writes
   `SHA256SUMS`, attests their provenance, and creates the release with
   all of them attached.

   The same workflow can upload the wheel and sdist to PyPI through trusted
   publishing. That job runs once the maintainer has set up the trusted
   publisher on PyPI and set the repository variable `PYPI_PUBLISH` to
   `true`. Until then the Python packages are only on the GitHub release.
