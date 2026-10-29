# Changelog

All notable changes to Sentry-v2 are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- A denial from a child process that exited before its cgroup could be
  read now correlates through its parent: `parent pid in unit cgroup` or
  `parent was the unit's main process`, both 0.8. A forked worker that
  hits a denial and dies with the service used to count only on its domain
  and name. AVC events gain `ppid`, `parent_cgroup_at_receipt` and
  `parent_unit_at_receipt`.

### Fixed

- `sentry-v2ctl restore` writes every file to a temporary copy before
  replacing any, so a full disk part-way through restores nothing instead
  of half the unit.
- `restore` no longer follows a symlink below `/etc/systemd/system` or
  `/run/systemd/system`. Recreating a removed drop-in directory used to
  follow one, so a link planted there could send the file elsewhere.
- The webhook writes each bundle to its spool as soon as it's built. Before,
  while it was retrying an endpoint that kept failing, new bundles waited in
  memory behind that retry, and a crash or `kill -9` lost them.
- Webhook retries wait at most 5 minutes between attempts, so an endpoint
  fixed during the retry hour is used within 5 minutes instead of up to
  half an hour later.

## [0.2.8] - 2026-10-28

### Changed

- The configuration is stricter again. Each of these used to load and then
  do nothing, or the wrong thing. They're now refused when the file loads,
  naming the file and key, so check with `sentry-v2ctl policy validate` from
  0.2.8 before you upgrade:
  - a `redaction.patterns` entry that matches the empty string, such as
    `""`, `"x|"` or `"a*"`, which redacted every character of every bundle;
  - a policy with an empty `name`, which left a blank column in
    `sentry-v2ctl policies` and an empty value in the metric labels;
  - an empty string in a policy's `units`, `cgroups` or `scontext_types`,
    which matches nothing, so the policy loaded and never fired.

### Fixed

- `sentry-v2ctl policy test --event` on a missing file said the event was the
  wrong shape instead of naming the file it could not read.
- `sentry-v2ctl policy test --event` on JSON that is not shaped like an event
  raised a Python error instead of naming the problem. The error now names
  the event number, the unknown field or the expected type.

## [0.2.7] - 2026-10-28

### Changed

- The configuration is stricter. Each of these used to load and then fail,
  or quietly do the wrong thing, at run time. They're now refused when the
  file loads, naming the file and key, so check with
  `sentry-v2ctl policy validate` from 0.2.7 before you upgrade:
  - a relative or non-normalised path in `daemon.state_dir`,
    `control.socket`, `sinks.file.dir` or a `ca_file`, which used to resolve
    against `/`. Secret keys (`hmac_key_file`, `token_file`, `api_key_file`,
    `password_file`) still take a bare systemd credential name;
  - an empty `metrics.host`, `sinks.syslog.host` or `sinks.elastic.index`;
  - a sink `url` with no host, such as `https://`;
  - a `sinks.webhook.timeout`, `sinks.file.max_age` or `sinks.file.max_size`
    of zero;
  - an absolute `memory_high` of zero in a throttle;
  - a duration or size with a trailing newline, non-ASCII digits, or a value
    too large to be finite.

### Added

- Man pages: `sentry-v2(8)` and `sentry-v2ctl(8)`, installed by the RPM.
  `sentry-v2 --help` now describes `--config` and `--policies` too.
- Each release ships its build provenance as
  `sentry-v2-<version>.intoto.jsonl`, so `gh attestation verify --bundle`
  works offline. Releases 0.1.0 to 0.2.6 have it attached too.
- Coverage-guided fuzzing of the audit, PSI, config-value and redaction
  parsers with ClusterFuzzLite and Atheris, on pull requests and weekly.
- GOVERNANCE.md, a security model with the threat model and assurance case
  (docs/security-model.md), an upgrade guide (docs/upgrading.md) and a
  roadmap (docs/roadmap.md).
- Contributions need a Developer Certificate of Origin sign-off
  (`git commit -s`), checked in CI.

### Fixed

- Redaction removes the whole of a quoted secret flag or pair, such as
  `--password "two words"` or `token='a b'`. Before, everything after the
  first space was left in the bundle.
- A zero `sinks.file.max_age` or `max_size` made the file sink prune every
  bundle, including the one it had just written.
- A zero `sinks.webhook.timeout` left the socket non-blocking, so every
  delivery failed with `BlockingIOError`.
- An empty `metrics.host` made the metrics endpoint listen on every
  interface, and its warning printed a blank address.
- A non-number `--limit` on `incidents` says `must be a whole number, not
  'abc'` instead of naming the private `_positive` helper.

## [0.2.6] - 2026-10-20

### Fixed

- An audit record whose `pid` held non-ASCII digits (such as `²`, which
  Python's `isdigit()` accepts) raised while being assembled, so its whole
  record group was dropped. The PID is now read only from ASCII digits.
  Found by the new fuzz tests.

## [0.2.5] - 2026-10-20

### Fixed

- The Cockpit page said a throttle or freeze rolls back "now" when it had
  up to a minute left. It now says "in under a minute", or "just now" for
  something that has passed.

### Added

- Property-based fuzz tests, with Hypothesis, for every parser that reads
  input the daemon doesn't control.

### Changed

- CI and the release workflow install their Python tools from hash-pinned
  requirement files (`make requirements` regenerates them).

## [0.2.4] - 2026-10-20

### Changed

- A throttle's rollback now looks at each value on its own. Before, if
  you changed `CPUWeight` by hand during a throttle, the whole rollback was
  skipped and `MemoryHigh` stayed at the throttled value until the next
  reboot, while the record said `rolled_back`. Now your `CPUWeight` stays,
  `MemoryHigh` goes back, and the note names the value left alone.

### Fixed

- A daemon that was killed or crashed while holding a throttle or freeze,
  and then couldn't start again (for example because its configuration no
  longer loaded), left that unit throttled or frozen until someone fixed
  it. The unit now runs `sentry-v2 --rollback-only` after every stop, which
  puts everything back straight away and falls back to the default settings
  if the configuration is broken.
- In a denial storm the daemon can read denials seconds late. A failure
  was finalised a second after it happened, before its own denials had
  been read, and a denied process that had exited by then had no cgroup
  left to match. On a 1-vCPU test VM a failing service's denial was missed
  this way. A failure now waits until the audit stream has been read past
  its window (at most 30 s, after which the bundle says
  `audit_caught_up: false`), and a denial from a process that has exited
  still matches if its PID was the unit's main process.

## [0.2.3] - 2026-10-20

### Added

- `examples/demo/run.sh sibling` stages a harder case: two instances of
  one service, both denied, one failing.

### Changed

- A denial whose process was in another unit's cgroup when it arrived is
  no longer scored against a failure. Two instances of a template unit
  share a binary and a domain, so a sibling's denial used to be linked at
  0.76. Denials whose cgroup couldn't be read still score on domain and
  name.

### Fixed

- The README's images and links now work on PyPI as well as GitHub.
- The RPM installs the licence to `/usr/share/licenses/sentry-v2/`, where
  `rpm -qL` and auditors look for it.

## [0.2.2] - 2026-10-20

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

[Unreleased]: https://github.com/jamesconwaydev/sentry-v2/compare/v0.2.8...HEAD
[0.2.8]: https://github.com/jamesconwaydev/sentry-v2/compare/v0.2.7...v0.2.8
[0.2.7]: https://github.com/jamesconwaydev/sentry-v2/compare/v0.2.6...v0.2.7
[0.2.6]: https://github.com/jamesconwaydev/sentry-v2/compare/v0.2.5...v0.2.6
[0.2.5]: https://github.com/jamesconwaydev/sentry-v2/compare/v0.2.4...v0.2.5
[0.2.4]: https://github.com/jamesconwaydev/sentry-v2/compare/v0.2.3...v0.2.4
[0.2.3]: https://github.com/jamesconwaydev/sentry-v2/compare/v0.2.2...v0.2.3
[0.2.2]: https://github.com/jamesconwaydev/sentry-v2/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/jamesconwaydev/sentry-v2/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/jamesconwaydev/sentry-v2/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/jamesconwaydev/sentry-v2/releases/tag/v0.1.0
