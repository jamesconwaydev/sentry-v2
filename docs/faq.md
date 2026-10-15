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
always expire and are rolled back on stop and after a crash. See
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

## Does it use eBPF?

No. PSI comes from the kernel's own trigger interface, failures from the
systemd journal, and denials from the audit netlink stream.

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

Not yet. The `sentry_v2_t` domain is permissive in this release, so
denials are logged and nothing is blocked. See
[hardening.md](hardening.md#selinux).

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
