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

Denials can be lost earlier than that, in an AVC storm. The kernel queues
audit records on the netlink socket until the daemon reads them, and when
that buffer fills it drops them and tells the reader with `ENOBUFS`. The
daemon asks for an 8 MiB buffer, and the kernel grants at most
`net.core.rmem_max` (about 208 KiB on EL10 out of the box; the audit
collector's `rcvbuf` health field shows what you got). Each overrun, and
each record the reader sheds when its own 10 000-record queue is full,
counts as an `audit` drop. The overruns alone show as `overruns`.

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

Each denial is scored on three signals: where the process was, its domain
and its name. Only one of the four "where" reasons counts for a denial,
the first that applies:

| Reason in the bundle | Weight | When it applies |
|---|---|---|
| `pid in unit cgroup` | 0.9 | The denied process was in the failed unit's cgroup when the denial was received. |
| `pid was the unit's main process` | 0.9 | The process had already exited, so its cgroup couldn't be read, but its PID is the unit's last main PID (`ExecMainPID`, which systemd keeps after the process exits). Used only when the cgroup is unknown. |
| `parent pid in unit cgroup` | 0.8 | The process had already exited, but its parent (`ppid` from the audit record) was in the unit's cgroup. A child starts in its parent's cgroup; the parent can move it elsewhere, which is why this counts for less. |
| `parent was the unit's main process` | 0.8 | Both had exited, but the parent's PID is the unit's last main PID. |
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

If that cgroup belongs to a different unit, the denial isn't scored at all.
Two instances of a template unit (`app@a`, `app@b`) run the same binary in
the same domain, so without this rule a denial from `app@b` would score
0.76 against `app@a`'s failure on domain and name alone. When the cgroup
couldn't be read, because the process had already exited, the daemon reads
its parent's cgroup instead, and the unit's last main PID, the domain and
the name still count. A forked worker that hits a denial and dies straight
away is the usual case.

### When the daemon falls behind the audit stream

On a busy host, especially a small one where auditd and setroubleshootd
are also working through a denial storm, the daemon can read denials
seconds after the kernel logged them. On a 1-vCPU Rocky 10 test VM it fell
8.8 s behind. Two things would go wrong if the correlator didn't allow for
it: the failure would be finalised before its denials arrived, and a
denied process that had exited in the meantime would have no cgroup left
to read.

Most of that delay is in the kernel's own audit queue, upstream of the
daemon's socket, so an empty socket proves nothing. The audit collector
tracks the newest audit timestamp it has read instead, of any record type:
the kernel sends records in order, so everything older has arrived. Only
after a quiet second with nothing waiting does it count as caught up to
now. A failure is finalised once that point is past the end of its window,
plus 0.2 s. If audit is more than 30 s behind, the failure
goes out anyway with `incident.audit_caught_up` set to `false`, which means
denials may be missing from it. The second problem is what the
`pid was the unit's main process` reason is for.

For the name check, systemd's `(name)` form of a process about to exec is
unwrapped, and executables under `/usr/lib/systemd/` are ignored: a denied
exec is reported against `systemd-executor`, which says nothing about the
service.

### Learned domains

The correlator learns a unit's SELinux domain from the unit's own most
recent denial before the one being scored, so a denial never vouches for
itself. Learned domains are kept for up to 4096 units. A unit with no
earlier denial in memory has no known domain, and this reason can't apply.

The `ExecStart` binaries come from systemd. The daemon fetches a unit's
properties in the background when it sees a journal event for it, and
caches them for 60 s, so they're usually ready by the time the failure is
scored.

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
