# Security review, November 2026

James Conway, maintainer. Reviewed 2 November 2026.

I took each promise in the [security model](security-model.md), found the
code that's meant to keep it, and tried to break it as each actor in the
threat model: a local user, anyone on loopback, members of the two groups,
and a Cockpit session. Five findings came out of it. The medium one is fixed. The low and
informational ones are listed with their fix, and their status is kept up
to date in the table below.

## What I reviewed

- **Code:** `main` at `52a1e23`, which is 0.2.9 plus the unreleased changes
  up to the reproducible RPM build. Line numbers below are from that commit.
- **Read in full:** `docs/security-model.md`, `docs/hardening.md`,
  `SECURITY.md`, `docs/actions-and-safety.md`, the "Matching targets" part
  of `docs/policies.md`, and `src/sentry_v2/control.py`, `commands.py`,
  `metrics.py`, `actions.py`, `bundle.py`, `reporting.py`, `cgroupfs.py`,
  `collectors/audit.py`, `collectors/journal.py`, every file in `sinks/`,
  the sink, metrics and control parts of `config.py` and `config_types.py`,
  the executor's action path (`executor.py` 180-330), the policy matcher and
  protected list (`policy.py`), the correlator's AVC and PSI paths
  (`correlate.py`), the Cockpit page's transport and DOM helpers, the
  systemd unit and the SELinux module.
- **Run:** the unit suite (660 passed, 2 skipped), and a local check of
  F1's matching logic. Nothing ran on a live host. The sandbox claims were
  checked against systemd's source and the `systemd.exec` documentation.

## Do the security requirements hold?

| # | Requirement | Holds? | Notes |
|---|---|---|---|
| R1 | Changes nothing until both `daemon.mode` and the policy's `mode` are `enforce` | Yes | `policy.py:115` `effective_mode`; the executor's `_mode_for` also forces dry-run while paused or the breaker is open. |
| R2 | What it changes, it puts back | Yes | `executor.py:273-274` journals `planned` before `apply`; `ExecStopPost=--rollback-only` in the unit. |
| R3 | Some things are never touched | Now yes | The protected list held, but a PSI target could be a user's cgroup standing in for a system unit. Fixed in #140; see F1. No restart, stop or kill path exists. |
| R4 | Runs with as little as it can | Yes, with a gap | One capability (`CAP_AUDIT_READ`), `NoNewPrivileges`, its own enforcing `sentry_v2_t` domain. `ProtectKernelTunables=` isn't set; see F4. |
| R5 | Only chosen people can talk to it, and changes are logged with the caller | Yes | `control.py:160-166` checks every request; `control.py:260` logs uid, pid, command and arguments. |
| R6 | Network output is protected | Yes | `sinks/http.py:18-22` verifies certificates with TLS 1.2 minimum; `config.py:310-316` and `sinks/http.py:31` refuse `http://`; `sinks/webhook.py:110-117` signs timestamp and body. Syslog's `transport` became required in #137. |
| R7 | Bundles are redacted before they leave | Yes, within the documented limits | `bundle.py:133-171` scrubs before any sink, the file sink included. Redaction is pattern-based, as documented. |
| R8 | The release you download is the one that was built | Not checked | Supply chain was out of scope this time. |

## Where the boundaries are

From least trusted to most:

1. **Any local process.** It can write to the journal, trigger SELinux
   denials, create pressure, and, with a systemd user manager, create and
   name cgroups in its own delegated subtree. So can a container or a
   service with `Delegate=yes`, under its own cgroup.
2. **Loopback.** Anyone on the host reaches the metrics endpoint when it's
   on. It has no authentication.
3. **Members of `sentry-v2`.** Read status, incidents and full bundles.
4. **Members of both groups, and Cockpit sessions with administrative
   access.** Roll back, acknowledge, pause, resume, reload and restore. The
   Cockpit page asks for `superuser: "try"`, so an administrative session
   talks to the daemon as root.
5. **Root and `/etc/sentry-v2`.** Out of scope by design.

| Crossing | Input | What checks it |
|---|---|---|
| Local process to daemon | Journal entries | Only entries with a trusted `_PID=1` and `UNIT=` count (`collectors/journal.py:68-69`, `:129`). |
| Local process to daemon | Kernel AVC records | Length-checked netlink parsing (`collectors/audit.py:132-143`); queue capped at 10,000 with counted drops. |
| Local process to daemon | USER_AVC records | Only trailing fields trusted; possibly truncated records dropped and counted (`collectors/audit.py:97-129`). Sending one needs `CAP_AUDIT_WRITE`. |
| Local process to daemon | Cgroup names and pressure | Matched against policy patterns. Since #140 a cgroup is a unit only if everything above it is a slice. |
| Local process to daemon | Text in journal lines, command lines and AVC fields | Redacted before bundles leave; JSON-encoded on output; the Cockpit page inserts text nodes only. |
| Loopback to daemon | HTTP requests to `/metrics` | 4 KiB header cap, 5 s header timeout, no connection cap (F2). |
| Groups to daemon | Control socket requests | `SO_PEERCRED` and `SO_PEERGROUPS` at connect; a permission check per request; 64 KiB line cap; 5 min idle timeout; 8 connections per uid and 32 in total for non-admins. |
| Admins to daemon | `restore` | Id format, ownership and mode of each backup, manifest paths confined to `files/`, every hash checked, writes confined to two unit directories, no symlinks followed below them (`commands.py:94-117`, `:256-337`). |
| Daemon to systemd | D-Bus calls | Protected list, slice gate, limits, flap guard and breaker (`executor.py:242-260`). |
| Daemon to filesystem | `backup_reload` copies | Sources come from systemd and the policy. Copies follow symlinks and have no size limit (F3). |
| Daemon to network | Bundles | Redaction, TLS verification, HMAC. Syslog over UDP or TCP is plain text, and since #137 only when you ask for it. |

## Findings

Severity is for how Sentry-v2 is deployed: a root daemon, local attackers,
policies written by admins. None of these can be reached without a local
account, a PSI or `backup_reload` policy written a particular way, or the
metrics endpoint turned on.

| | Finding | Severity | Status |
|---|---|---|---|
| F1 | A user's cgroup could stand in for a system unit | Medium | Fixed in #140 |
| F2 | The metrics endpoint has no connection limit | Low | Fixed in #143 |
| F3 | `backup_reload` follows symlinks, has no size limit and copies on the event loop | Low | Open |
| F4 | `ProtectKernelTunables=` isn't set | Informational | Open |
| F5 | The peer-group fallback reads `/proc/<pid>/status` | Informational | Fixed in #142 |

### F1. A user's cgroup could stand in for a system unit

For a PSI incident, the unit to act on was the last part of the cgroup path,
if it ended in `.service`, `.scope` or `.slice`. Nothing checked that the
cgroup belonged to the system unit with that name, and the protected list
looks only at names. So `sshd.service` was safe, but `postgresql.service`
wasn't.

A local user could run `systemd-run --user --unit=app-web.service` with a
memory hog, which creates
`user.slice/user-1000.slice/user@1000.service/app.slice/app-web.service`.
An enforcing policy with `cgroups = ["app-*.service"]`, which is how
`docs/policies.md` says to match a unit wherever it sits, would then
throttle or freeze the system's `app-web.service` for up to 30 minutes,
again after every cooldown. A pattern like `system.slice/*.service` had the
same hole through a container runtime's delegated tree, because `*` crosses
slashes.

**Fixed in #140.** `CgroupFS.unit_of` now returns a unit only if every
component above it ends in `.slice`. Anything inside another unit's tree can
still notify, but its throttles and freezes fail with `no unit target`.
`docs/policies.md` says so.

### F2. The metrics endpoint has no connection limit

`metrics.py:303-308` starts the server without a cap, and the unit sets no
`LimitNOFILE=`, so the daemon has the default soft limit of 1024. Each
connection can hold a descriptor for 5 s, so about 200 new connections a
second from any local user keeps the daemon at its limit. Binding to
`127.0.0.1` doesn't help against local users.

While it's at the limit, the control socket stops accepting, sinks can't
open sockets and bundles are dropped (and counted). It's a denial of
service, not an unsafe action: a failed `planned` journal write stops the
action, and rollbacks use the D-Bus connection that's already open. The
control socket doesn't have this problem because it caps connections.

The endpoint is off by default. **Fixed in #143:** the server closes any
connection past 16 open ones. Aborting, rather than closing, a connection
that stops reading is PR #127.

### F3. `backup_reload` follows symlinks, has no size limit and copies on the event loop

`actions.py:91-112` copies with `shutil.copyfile`, then reads the whole copy
back to hash it, and the executor calls it directly at
`executor.py:277-278`.

Say an enforcing `backup_reload` policy names `/etc/myapp/app.conf`, and
`/etc/myapp` is owned by the service's own account. That account can swap
the file for a huge one or a symlink to one, then crash its service to
trigger the policy. The copy blocks the event loop long enough for the
watchdog to kill the daemon, the hash can exceed `MemoryMax=192M`, and the
copy fills `/var/lib`. A symlink can pull any file root can read into the
backup, but backups are root-only `0700` and `restore` won't write outside
the unit directories, so nothing leaks. You lose monitoring until systemd
restarts the daemon; `ExecStopPost` rolls back what was in force.

**Fix:** open each source with `O_NOFOLLOW`, require a regular file, cap
the size at 1 MiB, hash while copying, and run the backup in
`asyncio.to_thread`.

### F4. `ProtectKernelTunables=` isn't set

`ProtectSystem=strict` leaves `/proc/sys` and most of `/sys` writable; this
is the setting that covers them. The daemon never writes `/proc/sys`, and
the only part of `/sys` it writes is `/sys/fs/cgroup`, which this setting
leaves alone.

On a host with the SELinux module loaded it changes nothing, because
`sentry_v2_t` can only read sysctls. Without the module, a compromised
daemon could change sysctls, but it can already reach root through systemd,
as the security model says. So this is tidiness and a better
`systemd-analyze security` score, not a new path. **Fix:** add
`ProtectKernelTunables=yes`, confirm with `make itest` that PSI triggers
still register, and list it in `docs/hardening.md`.

### F5. The peer-group fallback reads `/proc/<pid>/status`

If `SO_PEERGROUPS` fails, `control.py:75-78` reads the client's groups from
`/proc/<pid>/status` for the pid recorded at connect. If that client has
exited and the pid has been reused, those are someone else's groups.

The RHEL 10 kernel supports `SO_PEERGROUPS`, so reaching the fallback takes
an account in more than 1024 groups, and then winning a pid-reuse race
against a member of `sentry-v2-admin`. That's not realistic on a supported
system. **Fixed in #142:** the fallback now trusts only the primary gid.

### Documentation that didn't match the code

Fixed in the same change that published this review:

- `docs/hardening.md` left `ack` out of the admin-only commands.
- `docs/security-model.md` said Cockpit always talks to the daemon as the
  logged-in user. An administrative session talks as root.
- `docs/security-model.md` said the daemon never follows a symlink. That's
  true of `restore`, not of `backup_reload` (F3).
- `docs/security-model.md` still said syslog defaults to UDP after #137
  made `transport` required.

## Documented limits, checked again

| Limit | Still holds? | Evidence |
|---|---|---|
| USER_AVC records over 1000 bytes are dropped and counted | Yes | `collectors/audit.py:49`, `:112-113`, counted at `:177-184`, shown as `user_avc_truncated`. |
| The SELinux module can't stop a compromised daemon reaching root through systemd | Yes | `sentry_v2.te:131`, `:141` and `:147` grant starting and managing units. |
| A mid-write OS error can leave a partial restore | Yes, narrower than before | Since #129 everything is staged first, so only an `os.replace` failure after staging leaves a partial restore, and the error lists what was restored. |
| Syslog sends plain text only when asked | Yes, since #137 | `transport` has no default; a config without it fails with `sinks.syslog.transport: is required`. |
| The metrics server and control socket close, not abort, on a write timeout | Yes | `metrics.py:324` and `:359`, `control.py:176` and `:210`. PRs #126 and #127 change that. |

## What I didn't cover

- The supply chain: CI workflows, release signing, provenance and
  dependency pinning (R8).
- The D-Bus layer in `systemd.py`, beyond how the executor calls it, and
  the rollback retry logic after `executor.py:330`.
- The PSI collector's trigger handling and the state journal, in detail.
- The Elasticsearch and Splunk sinks, beyond their shared HTTPS code.
- Whether the correlator ties each denial to the right incident, except
  where that decides which unit is acted on.
- The CLI, beyond output escaping and `policy test --event`, which runs as
  the caller and crosses no privilege boundary.
- Anything on a live host. F2 and F3's impacts are reasoned from the code,
  not reproduced.
- How far the correlator's event buffer grows in a long AVC storm. It's
  bounded by time (60 s), not count. That's worth a load test, but I
  couldn't show a problem from the code alone, so it isn't a finding.
