# Contributing to Sentry-v2

Thanks for looking. Sentry-v2 is a small project with one maintainer, so a good bug report or a focused pull request goes a long way.

Not sure where to start? Open a [Discussion](https://github.com/jamesconwaydev/sentry-v2/discussions) and tell us what you're trying to do. Issues labelled `good first issue` and `help wanted` are the easy way in.

## Set up

You need Python 3.12 and [uv](https://docs.astral.sh/uv/).

```sh
git clone https://github.com/jamesconwaydev/sentry-v2.git
cd sentry-v2
uv venv -p 3.12 .venv
uv pip install -e '.[dev]'
```

Then run the three checks CI runs:

```sh
make lint typecheck test
```

The package imports on macOS, because the `systemd` and `dbus` bindings are loaded lazily inside the adapter modules. Keep it that way: no top-level imports of either outside an adapter.

## Integration tests

Unit tests cover the logic. The integration tests exercise the real kernel and systemd, so they need a Rocky Linux 10 host with `psi=1` on the kernel command line and SELinux in enforcing mode.

```sh
make itest
```

Run them on a throwaway VM, not a machine you care about. They create load inside a dedicated `sentry-test.slice` and clean up after themselves, but they do touch cgroups. If you don't have a Rocky 10 box, say so in your pull request and we'll run them for you.

## Ground rules

Sentry-v2 runs as root and changes how other people's services behave, so a few things matter more here than in most projects.

- Dry-run stays the default. Anything new that acts on a system must be off until someone turns it on, and must be reversible and time-boxed.
- Protected targets stay protected. Never weaken the list of units Sentry-v2 refuses to throttle or freeze.
- Runtime dependencies come from the Python standard library, `systemd.journal`, `systemd.daemon` and `dbus`. Nothing from EPEL, and nothing outside BaseOS and AppStream.
- No secrets in bundles or logs.

## Commits and pull requests

We use [Conventional Commits](https://www.conventionalcommits.org/): `fix: stop retrying a revoked throttle`, `feat: add Elastic sink`, `docs: explain policy precedence`. Keep the subject under 72 characters and use the body to say why.

Fork the repo, branch from `main`, and make your change with tests; a bug fix starts with a test that fails. Run `make lint typecheck test`, then open a pull request and fill in the template. Update the docs and CHANGELOG if users will notice.

`main` is protected. Every change lands through a pull request that passes CI, and we squash-merge, so the PR title becomes the commit message on `main`. Write it as a Conventional Commit.

There's no DCO sign-off or CLA. By contributing you agree that your work is released under the project's [AGPL-3.0](LICENSE) licence.

## Reporting bugs and security problems

Bugs go in [issues](https://github.com/jamesconwaydev/sentry-v2/issues/new/choose). If Sentry-v2 acted when it shouldn't have, or failed to act when it should, use the remediation incident form and attach the bundle.

Security problems do not go in public issues. See [SECURITY.md](SECURITY.md).

By taking part you agree to follow our [Code of Conduct](CODE_OF_CONDUCT.md).

## Releases

Releases are cut by the maintainer. The version lives in `src/sentry_v2/__init__.py`, and `pyproject.toml` reads it from there, so the release PR bumps that file, `upstream_version` in `packaging/sentry-v2.spec` and the `policy_module` version in `packaging/selinux/sentry_v2.te`, and adds a `## [x.y.z]` section to the CHANGELOG. Once that's merged, we tag `main` as `vx.y.z` and push the tag. Tags must be plain `vMAJOR.MINOR.PATCH`; we don't publish prereleases.

A first job checks that the tag, `__version__`, the spec and the SELinux module agree and that the CHANGELOG has notes for the version, so a bad tag fails in seconds. Then the workflow builds the RPMs on Rocky 10 and the wheel and sdist, checks the built files carry the tag's version, attests everything, and publishes the GitHub release with the CHANGELOG section as its notes. The PyPI upload, through trusted publishing, runs only once the maintainer has set up the trusted publisher on PyPI and set the repository variable `PYPI_PUBLISH` to `true`; until then the wheel and sdist live on the GitHub release.
