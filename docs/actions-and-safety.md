# Actions and safety

In short:

- Nothing changes until `daemon.mode` and the policy's `mode` both say
  `enforce`.
- Every throttle and freeze has a fixed duration and is undone when it
  expires, when the daemon stops, and after a crash.
- Every enforced action is written to disk before systemd is asked to do
  anything.
- Protected units are never touched, and limits and a circuit breaker cap
  how much can happen at once.

## The actions

| Action | Apply | Undo |
|---|---|---|
| `throttle` | `SetUnitProperties(unit, runtime=true, MemoryHigh=…, CPUWeight=…)` | Writes back the values captured before apply, if nobody has changed them since. |
| `freeze` | `FreezeUnit(unit)`: every process in the unit's cgroup stops. | `ThawUnit(unit)`, at expiry or early once pressure falls. |
| `backup_reload` | Copies the unit's files to a backup directory, then `ReloadUnit(unit, "replace")`. | Never automatic. Run `sentry-v2ctl restore <backup id>`. |
| `notify` | Nothing on the host. | Nothing to undo. |

### `throttle`

Before it changes anything, the daemon reads the unit's current
`MemoryHigh` and `CPUWeight` and keeps them as the values to restore. A
`memory_high` percentage is worked out at that moment from the unit's
`memory.current`, and never goes below 32 MiB. The change is runtime-only:
it lives under `/run` and is gone after a reboot even if every other
safeguard failed.

On rollback the daemon reads the properties again. If any value it wrote
has changed since, someone else made that change on purpose, so it's left
alone and the record notes `changed since; left as is`. Otherwise the
original values are written back exactly as systemd reported them,
including "unset".

### `freeze`

A freeze is refused if the unit isn't active (`unit inactive`) or is
already frozen or freezing (`already frozen`).

While a unit is frozen, the daemon checks pressure every 5 s and thaws it
early once the parent cgroup's `some` avg10 for the policy's resource drops
below `release_below`. It reads the parent because the frozen unit itself
reads calm; a unit directly under the root reads `/proc/pressure` instead.
If pressure can't be read, the freeze simply runs to expiry. Early thaw
only applies to `psi` policies.

### `backup_reload`

The unit's fragment file, its drop-ins and any `paths` from the policy are
copied, with mode and modification time, to:

```text
/var/lib/sentry-v2/backups/<unit>/<YYYYmmddTHHMMSSZ>/
├── MANIFEST.sha256
└── files/
    ├── usr/lib/systemd/system/app-web.service
    ├── etc/systemd/system/app-web.service.d/override.conf
    └── etc/app-web/app.conf
```

The manifest is in `sha256sum` format, so you can check a backup by hand:

```console
# cd /var/lib/sentry-v2/backups/app-web.service/20261014T031502Z
# sha256sum -c MANIFEST.sha256
```

Then the unit is reloaded. A unit without `ExecReload=` fails with
`unit has no ExecReload`. The backup id, `<unit>/<timestamp>`, is in the
action record's `backup_id`. To put the files back:

```console
$ sentry-v2ctl restore app-web.service/20261014T031502Z
```

The daemon checks every file against the manifest first and refuses the
whole restore on a mismatch, or if the backup directory isn't owned by root
or is writable by anyone else. Then it writes each file back atomically and
tells you what to run next, `systemctl daemon-reload && systemctl reload
<unit>`. It never reloads anything itself.

## What happens to each action

Every action gets a record in `/var/lib/sentry-v2/state/actions.jsonl`. The
journal is append-only and fsynced after every write; each line is one
transition and the newest line for an id wins.

| Status | Meaning |
|---|---|
| `planned` | Written, with the values to restore, before the D-Bus call. |
| `applied` | systemd accepted the change. Throttles and freezes now have an `expires_at`. |
| `rolled_back` | Undone. `error` may carry a note, such as `unit gone`, `unit inactive` or `changed since; left as is`. |
| `failed` | Not applied. `error` says why: `protected`, `limit`, `already active`, `rollback pending`, `unit not found`, `no unit target` and so on. |
| `rollback_failed` | Every rollback attempt failed. See [Stuck rollbacks](#stuck-rollbacks). |
| `dry_run` | What would have happened, with `params` showing what would have been written. |

Each record also has `mode` (what was actually used) and `configured_mode`
(what the policy asked for). A record with `configured_mode = "enforce"` and
`mode = "dry-run"` was held back by the master switch, a pause or the
breaker.

### When an apply call goes wrong

If a throttle or freeze call fails in a way that might still have taken
effect (a timeout, a dropped bus, anything unexpected), the record is not
just marked failed. It stays active and is rolled back straight away,
because restoring values and thawing are both safe to repeat. Errors that
systemd raises before changing anything, such as access denied or invalid
arguments, are simply `failed`.

A failed action never stops the next one in the same policy.

## Expiry

Each throttle and freeze is undone at `expires_at`. The daemon keeps a
second, monotonic deadline for the same moment, so a wall-clock jump can't
stretch an action. Whichever comes first wins.

## Stopping the daemon

On `SIGTERM` (including `systemctl stop` and package upgrades) the daemon
refuses new actions, waits for any apply already in flight, then rolls back
every active throttle and freeze before it exits.

### How long a stop can take

One rollback makes up to 10 attempts with 1, 2, 4, 8, 16, 32, 60, 60 and 60
seconds between them: 243 s of backoff. Each attempt can also wait up to
10 s for D-Bus, so one record can take about 343 s. Retries for different
records overlap, but D-Bus calls go one at a time, so N records that all
time out take at most 243 s + N × 100 s.

With the default `max_active_actions = 5`, that's 743 s, and the unit's
`TimeoutStopSec=780s` allows for it. If you raise `max_active_actions`, raise
`TimeoutStopSec` in a drop-in too:

```ini
# /etc/systemd/system/sentry-v2.service.d/stop-timeout.conf
[Service]
# 10 actions: 243 + 10 * 100 = 1243 s, plus headroom
TimeoutStopSec=1300s
```

## Crash recovery

On start, the daemon replays the journal before any collector runs, so no
new incident can race with a leftover action:

- A throttle or freeze still `planned` or `applied` is rolled back at once.
  A `planned` one may or may not have reached systemd, and rolling back is
  harmless either way.
- An interrupted `backup_reload` is marked `failed` with `interrupted`.
- A `rollback_failed` record is not retried. Its target stays blocked until
  you act (next section).
- Closed records older than 7 days are compacted away. `rollback_failed`
  records are kept at any age.

A crash halfway through writing a line leaves a partial last line, which is
cut off with a warning. Throttles are runtime-only, so a reboot clears them
regardless.

## Stuck rollbacks

When all 10 attempts fail, the record becomes `rollback_failed`, the daemon
logs at critical level, and a critical alert bundle goes to every sink.
From then on, new throttles and freezes on that target are refused with
`rollback pending`, so nothing stacks a second change on a unit whose first
one is still in force.

To clear it:

1. Find the record.

   ```console
   $ sentry-v2ctl actions
   ```

2. Look at the unit and fix whatever stopped the rollback (often D-Bus or
   the unit itself).

   ```console
   $ systemctl show app-web.service -p MemoryHigh -p CPUWeight -p FreezerState
   ```

3. Retry the rollback with the full id.

   ```console
   $ sentry-v2ctl rollback 01923f4e-8a7b-7c3d-9e2f-1a2b3c4d5e6f
   rolled back 01923f4e-8a7b-7c3d-9e2f-1a2b3c4d5e6f  throttle on app-web.service
   ```

A successful retry clears the block. `sentry-v2ctl rollback --all` covers
active actions only; a stuck one needs its id.

## Limits

| Check | Default | Error when hit |
|---|---|---|
| Throttles and freezes in force | `max_active_actions = 5` | `limit` |
| Freezes in force | `max_concurrent_freezes = 1` | `limit` |
| One action of a kind per unit | always | `already active` |
| Target has a stuck rollback | always | `rollback pending` |
| Longest throttle or freeze | `max_action_duration = "30m"` | rejected at load time |

The one-per-unit rule matters for rollback: a second throttle would capture
the first one's values as "previous" and restore the wrong thing.

In dry-run, limits are checked against the actions really in force, which
dry-run never adds to. So a dry-run bundle shows a `limit` refusal only if
enforced actions already fill the limit; a burst of dry-run incidents
doesn't count its own would-be throttles. Protection checks and cooldowns,
on the other hand, are previewed exactly as enforce mode would apply them.

## The circuit breaker

Errors from systemd count towards the breaker, apart from the ones it
raises before doing anything. When `breaker_failures` (3) of them land within `breaker_window`
(10 minutes), every policy is forced to dry-run for `breaker_cooldown` (15
minutes) and a critical `breaker_open` alert bundle goes out. Refusals such
as `protected` or `limit` don't count, and neither do access denied,
masked units, invalid arguments, inactive units or a missing `ExecReload=`.

`sentry-v2ctl status --json` shows whether the breaker is open, until when, and the recent failure count.

## Pause

```console
$ sentry-v2ctl pause
paused
$ sentry-v2ctl resume
resumed
```

Pause forces dry-run for new actions until you resume or the daemon
restarts. Collectors, correlation and bundles
carry on, and actions already in force keep their timers and roll back on
schedule. To undo everything now as well, follow with
`sentry-v2ctl rollback --all`.
