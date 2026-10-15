# Correlation

When a service dies, the first question is usually "did SELinux do that?"
The correlator answers it by gathering the denials around the failure,
scoring each one against the failed unit, and writing the matches and the
reasons into the bundle.

It also turns raw PSI trigger firings into `psi` incidents and spots bursts
of denials on their own. All three incident kinds come from one in-memory
buffer of recent events.

## The event buffer

Collectors feed one bounded queue (`daemon.queue_size`, 10 000 events). If
the correlator falls behind, the oldest event is dropped and counted per
collector in `sentry_v2_events_dropped_total` and in
`sentry-v2ctl status`.

The correlator keeps the last `correlation.retention` (60 s) of events,
ordered by timestamp. Events arriving slightly out of order are slotted in
where they belong.

## Unit failures and their denials

When systemd reports a failure, the correlator waits `after` (1 s) for late
denials, then looks at every denied AVC in the window:

```text
[failure − before − 999 µs,  failure + after]
     default: 5 s before            1 s after
```

The extra 999 µs is because audit timestamps are truncated to the
millisecond, so a denial can look up to a millisecond earlier than it was.
Granted (`avc: granted`) records are ignored.

### Scoring

Each denial is scored on three signals:

| Reason in the bundle | Weight | When it applies |
|---|---|---|
| `pid in unit cgroup` | 0.9 | The denied process was in the failed unit's cgroup when the denial was received. |
| `scontext type matches unit domain` | 0.6 | The denial's source type (for example `httpd_t`) is the unit's SELinux domain. |
| `comm matches ExecStart` | 0.4 | The process name or executable matches one of the unit's `ExecStart` binaries. |

The weights combine as independent evidence:
`confidence = 1 − (1 − w₁)(1 − w₂)…`

| Signals present | Confidence |
|---|---|
| cgroup, domain and comm | 0.976 |
| cgroup and domain | 0.96 |
| cgroup and comm | 0.94 |
| cgroup only | 0.9 |
| domain and comm | 0.76 |
| domain only | 0.6 |
| comm only | 0.4 |

Denials scoring under `min_confidence` (0.5) are left out, so with the
defaults a name match alone never makes it into a bundle. A correlation
at 0.8 or above makes the bundle's severity at least `warning`.

The cgroup is read from `/proc/<pid>/cgroup` the moment the denial arrives,
because by the time the unit has failed the process is usually gone.

For the name check, systemd's `(name)` form of a process about to exec is
unwrapped, and executables under `/usr/lib/systemd/` are ignored: a denied
exec is reported against `systemd-executor`, which says nothing about the
service.

### Learned domains

The unit's domain comes from what the daemon already knows about it. When
it doesn't know, the correlator learns it from the unit's own most recent
denial before the one being scored. A denial never vouches for itself.
Learned domains are kept for up to 4096 units.

### One incident per failure

systemd often logs both "job failed" and "unit failed" for a single start.
Events with the same unit and invocation id collapse into one incident, and
the unit failure's result wins because that's what `results` filters on.
Other events from the same invocation, such as the process exit, are
attached as `related`.

## PSI episodes

A kernel PSI trigger fires at most once per window while a stall lasts. The
correlator groups the firings for one cgroup and one trigger into an
episode:

- The episode starts at the first firing.
- It continues while firings arrive no more than two windows apart (and at
  least 2 s), so a short lull doesn't reset it.
- When the time from the first firing reaches a policy's `sustained`, one
  `psi` incident opens for that policy's `sustained` value. The same
  episode won't open another for that value.

The incident carries the latest periodic samples (taken every 5 s) for the
cgroup and its ancestors as `related`, so the bundle shows whether the
pressure was local or slice-wide.

## AVC bursts

Denials don't need a failure to be interesting. When `avc_burst` (5) denied
AVCs from one source domain arrive within `before` (5 s), an `avc`
incident opens with the triggering denial and the rest of the burst. That
domain then stays quiet for `retention` (60 s), so a denial storm makes one
incident a minute, not one per denial.

## USER_AVC records

Userspace object managers such as `dbus-broker` and systemd report their
own denials as `USER_AVC` records. Those records embed text the calling
process chose, so the collector trusts less of them:

- Only the trailing fields that the object manager appends (`scontext`,
  `tcontext`, `tclass`, `permissive`) and an unquoted `pid` or `spid` are
  used.
- `comm` and `exe` are never taken from a USER_AVC, so the
  `comm matches ExecStart` reason never applies to one.
- systemd's USER_AVC carries no trusted pid, so it can't score
  `pid in unit cgroup` either.
- libselinux formats these records into a 1024-byte buffer. A record whose
  text reaches 1000 bytes may have lost its trailing fields, so it's
  dropped rather than misread. Drops are counted in the audit collector's
  `user_avc_truncated` health field and logged at most once a minute.

## Where denials come from

The audit collector joins the kernel's audit multicast group over netlink,
which needs `CAP_AUDIT_READ` (the unit grants it). If the socket can't be
bound, it falls back to following `/var/log/audit/audit.log`, starting at
the end of the file and following rotation. `sentry-v2ctl status` shows
which one is in use as `source=netlink` or `source=logfile`.

The journal isn't used for denials: EL ships with
`systemd-journald-audit.socket` disabled, so they don't reach it.
