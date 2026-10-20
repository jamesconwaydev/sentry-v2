# Changelog

All notable changes to Sentry-v2 are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `examples/demo/`: a script that stages a failure, two SELinux denials
  and a memory hog on a test VM and shows what Sentry-v2 makes of them, in
  dry-run, then cleans up. Two bundles captured from it on a Rocky 10 VM
  sit next to it, with a recording in `assets/demo.gif`.
- An integration test that starts an unrelated denied service in the same
  window as a failing one and checks its denial stays out of the bundle.

### Changed

- The README leads with the demo recording and a real incident, then
  adds a compatibility table, a safety table and a section on false
  positives and failure modes.

### Fixed

- A bundle for a failed unit outside `system.slice` showed pressure for
  `system.slice` once the unit had lost its cgroup. It now reads the unit's
  own slice from systemd, so a service in `sentry-test.slice` gets
  `sentry.slice/sentry-test.slice` and its parents.

## [0.2.1] - 2026-10-19

Nothing in the code changed. This release exists so the packages you
download say Apache-2.0.

### Changed

- Sentry-v2 is now licensed under Apache-2.0 instead of AGPL-3.0-or-later.
  Copies of 0.1.0 and 0.2.0 you already have keep the AGPL terms they came
  with; from 0.2.1 on it's Apache-2.0.

## [0.2.0] - 2026-10-19

Sentry-v2 now notices when it keeps acting on the same unit and stops to
ask, leaves whole slices alone unless you say otherwise, and lets you see
what redaction leaves before anything goes out. One change needs a look
before you upgrade: if a policy of yours throttles a slice on purpose,
set `protection.allow_slices` first.

### Added

- Published on PyPI as `sentry-v2`.
- `sentry-v2ctl redact` shows what the configured redaction leaves of a
  file or stdin, so you can check before anything reaches a sink.
- Redaction catches more by default: `--password x` and `--db-password=x`
  style flags, JSON-quoted secrets such as `"Authorization": "Basic …"`,
  HTTP Digest `response=` values and JSON Web Tokens.
- `sentry-v2ctl policy test --event` takes a saved bundle as well as raw
  events, and replays its trigger and denials through the correlator and
  your policies.
- A flap guard. A unit that gets `limits.flap_actions` (3) enforced
  actions inside `limits.flap_window` (30 minutes) is put on hold: its
  current action expires as normal, new ones are refused, a critical
  `flapping` alert bundle goes out, and `sentry-v2ctl ack UNIT` releases
  it. Holds survive restarts. `status` lists held units and
  `sentry_v2_units_held` counts them.
- The Cockpit page lists held units with **Allow actions again**, and each
  incident's bundle shows a root `ausearch … | audit2allow -w` command for
  its own denials, so you can see why SELinux refused them before you
  change anything.

### Fixed

- An AVC storm could overflow the audit socket and lose denials without a
  trace. The daemon now asks for an 8 MiB receive buffer (capped by
  `net.core.rmem_max`), counts kernel overruns and its own reader-queue
  drops as `audit` events dropped, and shows `overruns` and `rcvbuf` in the
  audit collector's health.

### Changed

- Actions on `.slice` units are refused unless `protection.allow_slices`
  is true. A throttle or freeze on a slice reaches every unit under it, so
  a broad `cgroups` pattern could squeeze far more than one noisy job. If
  a policy of yours throttles a slice on purpose, set it before upgrading.

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

[Unreleased]: https://github.com/jamesconwaydev/sentry-v2/compare/v0.2.1...HEAD
[0.2.1]: https://github.com/jamesconwaydev/sentry-v2/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/jamesconwaydev/sentry-v2/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/jamesconwaydev/sentry-v2/releases/tag/v0.1.0
