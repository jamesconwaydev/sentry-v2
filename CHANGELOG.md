# Changelog

All notable changes to Sentry-v2 are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
- Documentation: installation, quickstart, configuration and policy
  reference, safety, correlation, bundles, sinks, CLI, Cockpit, metrics,
  hardening, troubleshooting, architecture and development guides.

[Unreleased]: https://github.com/jamesconwaydev/sentry-v2/commits/main
