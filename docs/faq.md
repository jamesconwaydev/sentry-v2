# FAQ

## Will installing it change anything on my host?

No. The service isn't enabled on install, and once you start it, the daemon
and every shipped policy are in dry-run. It watches, correlates and writes
bundles. Nothing is throttled, frozen or reloaded until you set
`daemon.mode` and a policy's `mode` to `enforce`.

## What's the worst it can do in enforce mode?

Throttle a unit's memory and CPU, freeze it, or reload it, within the
limits you set: by default at most five throttles or freezes at once, one
freeze at a time, none longer than 30 minutes, and never on the protected
units (SSH, journald, D-Bus, logind, auditd, systemd's own services, the
top-level slices, itself, and whatever you add). Throttles and freezes
always expire and are rolled back on stop, and straight after a crash or a
kill, even if the daemon can't start again. See
[actions-and-safety.md](actions-and-safety.md).

## Does it restart services?

No. The only lifecycle call it makes is a reload (`backup_reload`), and
only after backing up the unit's files.

## Why didn't my PSI policy fire?

Usually one of these:

- PSI is off. `sentry-v2ctl status` says `state=disabled`. See
  [troubleshooting.md](troubleshooting.md#psi-is-disabled).
- The pattern doesn't match. A pattern with `/` matches the full cgroup
  path, one without matches only the unit name. See
  [policies.md](policies.md#matching-targets).
- The stall didn't last for `sustained`.
- The cooldown for that unit hasn't run out.

`sentry-v2ctl policy test` with a sample event shows which of these it is.

## Why must the PSI window be a multiple of 2 seconds?

The kernel only lets processes without `CAP_SYS_RESOURCE` register triggers
with windows in 2-second steps. The unit drops that capability on purpose,
so the validator holds you to what the kernel will accept.

## Does correlation prove SELinux caused the failure?

No. It tells you which denials happened around the failure and how strongly
each one is tied to the unit, with the reasons. A 0.94 from "pid in unit
cgroup" and "comm matches ExecStart" is a strong lead, not a verdict. See
[correlation.md](correlation.md).

## What happens when it gets it wrong?

A linked denial is a lead, not a verdict. Here's where the scoring can
mislead you, and what happens when something underneath fails.

- **A denial from a process that's already gone.** The cgroup is read when
  the denial arrives. If the process has exited by then, its PID still
  counts when it was the unit's main process; otherwise only the domain
  and name can, and a sibling running the same binary in the same domain
  (two instances of a template unit, say) can score 0.76 against the wrong
  one. The reasons show it: no `pid in unit cgroup`. When the cgroup is
  known and belongs to another unit, the denial is left out.
- **A denial storm.** On a busy host the daemon can fall seconds behind the
  audit stream. A failure waits until audit has been read past its window,
  for up to 30 s; after that it goes out with `audit_caught_up: false`, and
  denials may be missing from it.
- **Timing.** Only denials from 5 s before to 1 s after the failure count.
  A service that's denied early and dies later needs a wider
  `correlation.before`.
- **Dropped records.** `USER_AVC` records over 1000 bytes are dropped and
  counted in `user_avc_truncated`; denials the kernel drops before the
  daemon reads them show up as `overruns`. Both are in `sentry-v2ctl
  status`.
- **The daemon crashes or is killed.** systemd runs
  `sentry-v2 --rollback-only` as soon as it exits, which puts back every
  throttle and freeze still on record, then restarts the daemon after 5 s.
  If the daemon can't come back, say because its configuration no longer
  loads, the rollback has already happened. If the rollback itself can't
  reach systemd, the next start tries again.
- **A rollback fails.** It's retried 10 times. Then the record is marked
  `rollback_failed`, a critical bundle goes to every sink, and no new
  action touches that unit until you retry with `sentry-v2ctl rollback ID`.
- **systemd keeps refusing.** Three failed systemd calls in ten minutes
  trip the circuit breaker, and everything runs in dry-run for fifteen.
- **The host reboots.** Throttles are runtime-only, so they're gone with
  the reboot whatever else happened.

More of this, with the fixes, is in [Troubleshooting](troubleshooting.md)
and [Actions and safety](actions-and-safety.md).

## Why Python, and why no dependencies from PyPI?

Python 3.12 and the two bindings it needs (`python3-systemd` and
`python3-dbus`) are all in EL10's base repositories, so the RPM installs on
a stock host with nothing extra. See
[architecture.md](architecture.md#why-stdlib-only).

## Does it work on EL9, Debian or Ubuntu?

EL10 is the only supported target. The code is plain Python against
systemd and cgroup v2, but the unit, the SELinux module and the packaging
are written and tested for EL10.

## Is the SELinux module enforcing?

Yes. The integration suite runs with the `sentry_v2_t` domain enforcing
and fails on any denial for it. See [hardening.md](hardening.md#enforcing).

## Can I edit policies from Cockpit?

No. The Cockpit page shows policies read-only. Edit the files, validate,
and reload.

## Can it manage several hosts?

No. It's one daemon per host. Send bundles from every host to the same
webhook, syslog collector, Splunk or Elasticsearch to see them together.

## How do I report a bug or a security problem?

Bugs go to [GitHub issues](https://github.com/jamesconwaydev/sentry-v2/issues).
Report security problems privately through the repository's security
advisories, not in a public issue.
