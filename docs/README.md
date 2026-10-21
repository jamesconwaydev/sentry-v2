# Sentry-v2 documentation

New here? Install it, then run the quickstart. Everything else is for when
you need it.

## Getting started

| Page | Read it to |
|---|---|
| [Installation](installation.md) | Install the RPMs, turn on PSI and give people access. |
| [Quickstart](quickstart.md) | Go from a fresh install to your first bundle, in dry-run. |

## Running it

| Page | Read it to |
|---|---|
| [Policies](policies.md) | Write policies: signals, matching, thresholds, modes, cooldowns. |
| [Actions and safety](actions-and-safety.md) | Know what each action does, how it's undone, and what limits it. |
| [Correlation](correlation.md) | Understand how denials are tied to failures, and the scores. |
| [Bundles](bundles.md) | Read a bundle, and control what gets redacted. |
| [Sinks](sinks.md) | Send bundles to a webhook, syslog, Splunk HEC or Elasticsearch. |
| [Cockpit](cockpit.md) | Use the Cockpit page. |
| [Metrics](metrics.md) | Scrape Prometheus metrics and alert on them. |
| [Troubleshooting](troubleshooting.md) | Fix PSI being off, permission errors, stuck rollbacks and more. |
| [Upgrading](upgrading.md) | Move to a new release and what carries over. |
| [FAQ](faq.md) | Get short answers to common questions. |

## Reference

| Page | Read it to |
|---|---|
| [Configuration](configuration.md) | Look up every key in `sentry-v2.toml`, with its type and default. |
| [sentry-v2ctl](cli.md) | Look up every subcommand, flag and exit code. |
| [Bundle schema](reference/bundle.schema.json) | Validate bundles with JSON Schema. |
| [Hardening and SELinux](hardening.md) | See the unit's sandbox, capabilities and SELinux module. |
| [Security model](security-model.md) | What you can and can't expect in terms of security, and why. |

## Inside it

| Page | Read it to |
|---|---|
| [Architecture](architecture.md) | See the components, the data flow and the threading model. |
| [Development](development.md) | Set up, run the tests, and cut a release. |
