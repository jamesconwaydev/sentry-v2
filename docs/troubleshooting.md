# Troubleshooting

Start with these two commands. Most problems show up in one of them.

```console
$ sentry-v2ctl status
$ journalctl -u sentry-v2 -b --no-pager | tail -50
```

## PSI is disabled

This is the most common one. EL kernels are built with PSI turned off
unless you ask for it at boot.

**Symptoms**

- `sentry-v2ctl status` shows the PSI collector as
  `state=disabled, hint=PSI is off: run 'grubby --update-kernel=ALL --args=psi=1' and reboot`.
- The journal has the same line as a warning at startup.
- `sentry-v2ctl top` shows no cgroups, and PSI policies never fire.
- The kernel files refuse to be read:

  ```console
  $ cat /proc/pressure/memory
  cat: /proc/pressure/memory: No such file or directory
  ```

The journal and audit collectors keep working, so unit failures and
denials are still handled.

**Fix**

```console
# grubby --update-kernel=ALL --args=psi=1
# reboot
```

**Check**

```console
$ cat /proc/pressure/memory
some avg10=0.00 avg60=0.00 avg300=0.00 total=1234567
full avg10=0.00 avg60=0.00 avg300=0.00 total=987654
$ sentry-v2ctl status | grep psi
psi        state=ok, triggers=6, restarts=0, last_error=None
```

`triggers` counts the kernel triggers registered across all matching
cgroups. If it's 0 with PSI on, no cgroup matches your policies' `cgroups`
patterns yet; see [policies.md](policies.md#matching-targets).

## Denials come from the audit log, not netlink

**Symptoms**

- `sentry-v2ctl status` shows `source=logfile` for the audit collector.
- The journal has
  `audit netlink unavailable (...); tailing the audit log instead`.

This means the audit multicast socket couldn't be bound, almost always
because `CAP_AUDIT_READ` has been removed, for example by a drop-in that
overrides `CapabilityBoundingSet=`. Denials still arrive, polled from
`/var/log/audit/audit.log` a few times a second, so this is a degraded mode
rather than a failure.

```console
$ systemctl cat sentry-v2 | grep -n CapabilityBoundingSet
$ grep CapBnd /proc/$(systemctl show -p MainPID --value sentry-v2)/status
```

Remove the override and restart. If the health also shows `error=...`, the
log file itself can't be read; check that `auditd` is running and the file
exists.

## Permission denied

**Symptoms**

```console
$ sentry-v2ctl status
permission denied on /run/sentry-v2/control.sock; join the sentry-v2 group (sentry-v2-admin to change anything) and log in again
$ echo $?
3
```

or, for a change you're not allowed to make, an error from the daemon that
names what's missing, also with exit code 3:

```console
$ sentry-v2ctl pause
error: permission denied: pause needs uid 0 or group sentry-v2-admin
```

**Fix**

```console
# usermod -aG sentry-v2 alice                   # read-only
# usermod -aG sentry-v2,sentry-v2-admin alice   # read and change
```

Log out and back in, then check with `id`. An admin needs both groups:
`sentry-v2` to get into `/run/sentry-v2`, `sentry-v2-admin` to change
anything.

## Too many connections

**Symptom**: `error: too many connections`.

Users who aren't root or in `sentry-v2-admin` can hold 8 connections each
and 32 between them. Usually something is leaving connections open, such
as a script that runs `sentry-v2ctl top` in a loop or a dashboard that never
closes its socket. Idle connections are closed after 5 minutes.

## A collector keeps restarting

**Symptom**: `restarts` climbing in `sentry-v2ctl status`, with the reason
in `last_error`, and `collector <name> stopped (...); restarting in Ns` in
the journal.

The daemon restarts a stopped collector with backoff, from 1 s up to 60 s.
The journal line before it has the traceback. For the journal collector
it's usually the journal itself (`journalctl --verify`); for audit, see
[the audit fallback](#denials-come-from-the-audit-log-not-netlink).

## A rollback is stuck

**Symptoms**

- A critical bundle with `incident.alert = "rollback_failed"`.
- `giving up on rolling back <action> <unit>` at critical level in the
  journal.
- New actions on that unit fail with `rollback pending`.

The full procedure is in
[actions-and-safety.md](actions-and-safety.md#stuck-rollbacks). In short:
fix the cause, then `sentry-v2ctl rollback <full id>`.

## The configuration won't reload

**Symptom**: `sentry-v2ctl reload` prints an error, or `status` shows
`last reload failed: …`.

The running daemon kept its previous configuration. A sink secret that
can't be read also fails a reload. Run the validator to see a
configuration error with the file and key:

```console
$ sentry-v2ctl policy validate
invalid: 20-unit-failure-notify.toml: policy[0].when.units: only matches protected units
```

## The webhook spool keeps growing

**Symptoms**

```console
# ls /var/lib/sentry-v2/spool/webhook | wc -l
412
$ journalctl -u sentry-v2 -g webhook --since -1h
```

Bundles stay spooled when delivery keeps failing in a way that might be
fixed: a wrong URL (404), a wrong key (401 or 403), a redirect, a TLS
error, or the receiver being down. The journal line says which. Fix the
endpoint or the key and the backlog drains, oldest first, on the next bundle
or the next restart.

Bundles the receiver rejects outright (400, 413, 415, 422) are not kept, so
they won't pile up. The spool is capped at 10 000 files or 512 MiB, after
which the oldest are deleted. Every bundle also stays in the file sink, so
nothing is lost while you sort it out.

Common causes:

- The receiver checks the signature against a different key, or against a
  re-serialised body instead of the raw bytes. See
  [sinks.md](sinks.md#verifying-the-signature).
- A private CA that isn't in `ca_file`.
- The key file was replaced but the daemon wasn't reloaded. Secrets are
  read at startup and on every reload, so run `systemctl reload sentry-v2`
  after rotating one.

## Events are being dropped

**Symptom**: `sentry_v2_events_dropped_total` rises, or `status --json`
shows non-zero `events_dropped`.

The correlator fell behind a flood of events. Raise `daemon.queue_size`,
and if `audit` is the collector dropping, look for the denial storm behind
it: `ausearch -m AVC -ts recent`.

## SELinux denials from sentry_v2_t

The domain is enforcing (see [hardening.md](hardening.md#enforcing)), so a
denial means something the daemon tried failed: a sink that can't connect,
a throttle that comes back as `AccessDenied`, a file it can't read. It
also means the policy module is missing a rule.

Denials come from two places. The kernel logs AVC records for files and
sockets. systemd logs USER_AVC records when it refuses one of the daemon's
D-Bus calls, and those carry systemd's own context as the sender, so
`ausearch -se` misses them. Search by the daemon's context instead:

```console
# ausearch -m AVC,USER_AVC -ts today | grep 'scontext=system_u:system_r:sentry_v2_t'
# ausearch -m AVC,USER_AVC -ts today --raw | grep 'scontext=system_u:system_r:sentry_v2_t' | audit2allow
```

Keep the `grep` in the second command: without it, `audit2allow` writes
rules for every denial on the host since midnight, not just the daemon's.

Please open an issue with the `ausearch` output and what the daemon was
doing at the time. Don't load the `audit2allow` output as a local module
unless you need to; it tends to grant more than the daemon needs.

The daemon's own collector sees these denials too, so a misbehaving rule
can also show up as `avc` incidents with `sentry_v2_t` as the target.
