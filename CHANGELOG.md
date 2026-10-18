# Changelog

All notable changes to Sentry-v2 are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Published on PyPI as `sentry-v2`.
- `sentry-v2ctl redact` shows what the configured redaction leaves of a
  file or stdin, so you can check before anything reaches a sink.
- Redaction catches more by default: `--password x` and `--db-password=x`
  style flags, JSON-quoted secrets such as `"Authorization": "Basic …"`,
  HTTP Digest `response=` values and JSON Web Tokens.

## [0.1.0] - 2026-10-15

The first release.

### Added

- Watch cgroup v2 memory, CPU and I/O pressure through kernel PSI triggers,
  with a clear message and the `grubby` fix when PSI is turned off.
- Pick up systemd unit failures from the journal, trusting only messages
  from systemd itself.
- Read SELinux AVC, USER_AVC and SELINUX_ERR denials from the audit netlink
  stream, falling back to `/var/log/audit/audit.log` when netlink isn't
  available.
- Link unit failures to the denials around them, with a confidence score
  and the reasons for each match, and raise incidents for sustained
  pressure and for bursts of denials.
- Write TOML policies that match on pressure, unit failures or denials, with
  per-target cooldowns and strict validation that names the file and key.
- Throttle a unit's `MemoryHigh` and `CPUWeight` at runtime, freeze it with
  early thaw once pressure falls, or back up its files and reload it.
- Keep every action time-boxed and journalled before it's applied, and roll
  it back on expiry, on shutdown and after a crash, without overwriting
  changes someone made by hand in the meantime.
- Stay in dry-run unless both the daemon and the policy say `enforce`, with
  protected units, action limits, a circuit breaker and `pause` on top.
- Build one redacted JSON bundle per incident, described by a published JSON
  Schema (`sentry-v2/bundle/1`).
- Send bundles to disk, to an HMAC-signed webhook with an on-disk spool, to
  RFC 5424 syslog over UDP, TCP or TLS, to Splunk HEC and to Elasticsearch.
- `sentry-v2ctl` to check status, list policies, watch pressure, read
  incidents and bundles, roll back, pause, reload and restore backups, and
  to validate and test policies without the daemon.
- An optional Prometheus endpoint on `127.0.0.1:9787`.
- An RPM with a hardened systemd unit, example policies in dry-run, and the
  `sentry-v2` and `sentry-v2-admin` groups.
- A `sentry-v2-selinux` subpackage with the `sentry_v2` policy module,
  enforcing.
- A Cockpit page for status, incidents and policies.
- Login sessions are protected by default (`user-*.slice`,
  `session-*.scope`, `user@*.service`), so a policy can't throttle you out
  of your own shell.
- `restore` checks everything before it writes anything. Unchanged files
  are skipped, and a changed file outside `/etc/systemd/system` and
  `/run/systemd/system` is refused up front, with the path to copy it back
  from. It also works for units shipped by packages, and recreates missing
  drop-in directories.
- Two new gauges: `sentry_v2_rollbacks_stuck` and `sentry_v2_breaker_open`.
- Redaction also catches API keys, access keys, client secrets and
  `Authorization:` headers.
- A crash replay can't time the service start out: the daemon asks systemd
  for more time while it replays, and a bad config exits with 2 instead of
  restarting in a loop.
- `sentry-v2ctl rollback` takes a unique prefix or suffix of an action ID,
  and waits up to 15 minutes for rollback and restore instead of giving up
  after 10 seconds.
- The action journal is compacted daily, not only at start.
- An integration suite that runs on Rocky 10 with SELinux enforcing.
- Documentation: installation, quickstart, configuration and policy
  reference, safety, correlation, bundles, sinks, CLI, Cockpit, metrics,
  hardening, troubleshooting, architecture and development guides.

[Unreleased]: https://github.com/jamesconwaydev/sentry-v2/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/jamesconwaydev/sentry-v2/releases/tag/v0.1.0
