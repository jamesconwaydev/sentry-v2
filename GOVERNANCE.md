# Governance

Sentry-v2 is maintained by one person, so its governance is short. This
page says who decides, how, and who does what.

## How decisions are made

The maintainer decides. Most decisions happen in the open, in an issue, a
Discussion or a pull request, and anyone can argue for or against a
change there. The maintainer weighs that, decides, and says why in the
thread.

Some decisions are settled up front, in [CONTRIBUTING.md](CONTRIBUTING.md),
so contributors don't have to guess: dry-run stays the default, protected
targets stay protected, runtime dependencies come from the EL10 base
repositories only, and nothing lands without tests.

A decision can be reopened with new evidence. A reproducible example
carries the most weight.

## Roles

| Role | Who | Responsibilities |
|---|---|---|
| Maintainer | James Conway ([@jamesconwaydev](https://github.com/jamesconwaydev)) | Triages issues and Discussions; reviews and merges pull requests; keeps CI, dependencies and the integration suite green; cuts releases and publishes them to GitHub and PyPI; handles vulnerability reports as described in [SECURITY.md](SECURITY.md); enforces the [Code of Conduct](CODE_OF_CONDUCT.md). |
| Contributor | Anyone who opens an issue, a Discussion or a pull request | Follows [CONTRIBUTING.md](CONTRIBUTING.md) and the Code of Conduct; signs off commits under the [Developer Certificate of Origin](CONTRIBUTING.md#developer-certificate-of-origin). |

[CODEOWNERS](.github/CODEOWNERS) routes every review to the maintainer.

## Changes to this document

Changes to governance go through a pull request like any other change, and
are announced in the release notes of the next release.
