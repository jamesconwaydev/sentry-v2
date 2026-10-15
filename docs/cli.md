# sentry-v2ctl

`sentry-v2ctl` talks to the running daemon over its control socket, and
checks policies offline without it.

```console
$ sentry-v2ctl status
$ sentry-v2ctl --json incidents --limit 10
$ sentry-v2ctl policy validate
```

## Global options

These work before or after the subcommand.

| Option | Default | Meaning |
|---|---|---|
| `--socket PATH` | `/run/sentry-v2/control.sock` | The control socket. Match `control.socket` if you changed it. |
| `--json` | off | Print the daemon's JSON reply instead of a table. |
| `-h`, `--help` | | Help for the command. |

Status words (`applied`, `failed`, `dry_run` and so on) are coloured when
output is a terminal. Set `NO_COLOR=1` to turn that off. Control
characters from the daemon or from files are replaced with `?` before they
reach your terminal.

## Who can run what

| Commands | Needs |
|---|---|
| `status`, `top`, `incidents`, `show`, `actions`, `policies` | root, or membership of `sentry-v2` |
| `rollback`, `pause`, `resume`, `reload`, `restore` | root, or membership of both `sentry-v2` and `sentry-v2-admin` |
| `policy validate`, `policy test` | read access to the configuration files; no daemon needed |

```console
# usermod -aG sentry-v2,sentry-v2-admin alice
```

Group changes apply from your next login.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success. |
| 1 | The command failed: invalid configuration, an error from the daemon, an unreadable event file, or a reply the client didn't understand. |
| 2 | The daemon isn't running (no socket), or the command line was wrong. |
| 3 | Permission denied, on the socket or by the daemon. |

A refused command names what it needs, for example
`error: permission denied: rollback needs uid 0 or group sentry-v2-admin`.
A user who isn't root or in the admin group can hold at most 8 connections
at once (32 across all such users); past that the daemon answers
`too many connections`. An idle connection is closed after 5 minutes.

```console
$ sentry-v2ctl status
sentry-v2 is not running (no socket at /run/sentry-v2/control.sock)
$ echo $?
2
```

## Daemon commands

### status

Daemon version, run state, mode, uptime, collector health and active
actions. A failed reload shows up here as `last reload failed: …`.

```console
$ sentry-v2ctl status
sentry-v2 0.1.0  running for 2h14m  mode dry-run

COLLECTOR  HEALTH
psi        state=ok, triggers=6, restarts=0, last_error=None
journal    state=ok, restarts=0, last_error=None
audit      source=netlink, user_avc_truncated=0, restarts=0, last_error=None

no active actions
```

The three collectors are `psi`, `journal` and `audit`. If one stops or
crashes, the daemon restarts it with backoff (1 s doubling to 60 s), and
`restarts` and `last_error` say so. A PSI collector that finds PSI turned
off in the kernel reports `state=disabled` and is left stopped.

`--json` adds the breaker state, sink failure and drop counts, and events
dropped per collector.

### top

Cgroups under the most pressure, from the daemon's latest samples. On a
terminal it refreshes every second until you press Ctrl-C.

| Option | Default | Meaning |
|---|---|---|
| `--once` | off | Print one snapshot and exit. Implied when output isn't a terminal. |
| `--sort {avg10,cgroup}` | `avg10` | Highest avg10 first, or alphabetical by cgroup. |

```console
$ sentry-v2ctl top --once
CGROUP                             RESOURCE  KIND  AVG10  AVG60  AVG300
system.slice/batch-report.service  memory    full  22.50  9.10   2.00
```

### incidents

Recent incidents, newest first. The daemon keeps the latest 500 in
memory, so the list starts empty after a restart; the bundles themselves
stay on disk.

| Option | Default | Meaning |
|---|---|---|
| `--since TIME` | none | Only incidents after this RFC 3339 time, such as `2026-10-17T00:00:00Z`. |
| `--unit UNIT` | none | Only incidents whose target is this unit, or a cgroup path ending in it. |
| `--limit N` | 50 | How many to show. Must be 1 or more. |

### show ID

Print a bundle as indented JSON. The id is the one in the `ID` column of
`incidents`, which is the bundle's own id; the bundle is read from the file
sink's directory, so `show` works for any bundle still on disk, even from
before a restart. An unknown id fails with `error: no such bundle`.

```console
$ sentry-v2ctl show 0199f2a1-8150-7d44-a2b6-0c1d2e3f4a5b | jq '.correlations[].reasons'
```

### actions

Active throttles and freezes, then the last 100 action records, newest
first. The recent list is kept in memory and starts empty after a
restart; the full history is in `/var/lib/sentry-v2/state/actions.jsonl`. The `WHEN`
column shows the expiry when a record has one and the record time
otherwise.
The `ID` column shows the first 8 characters; `--json` has the full ids,
which `rollback` needs.

### policies

The policies the daemon has loaded, with each one's own mode, the mode it
actually runs in once the daemon's `mode` is applied, its signal, its
actions and the file it came from. If the last reload was rejected, the
error follows the table, and the policies shown are the ones still running.

```console
$ sentry-v2ctl policies
NAME                      MODE     EFFECTIVE  SIGNAL       ACTIONS           SOURCE
memory-pressure-throttle  dry-run  dry-run    psi          throttle, notify  /etc/sentry-v2/policies.d/10-memory-pressure-throttle.toml
unit-failure-notify       dry-run  dry-run    unit_failed  notify            /etc/sentry-v2/policies.d/20-unit-failure-notify.toml
```

### rollback ID | --all

Undo an action now. Give either an action id or `--all`.

| Form | Effect |
|---|---|
| `rollback ID` | Roll back that action. Also retries a `rollback_failed` one and, on success, clears the block on its target. |
| `rollback --all` | Roll back every active throttle and freeze. |

```console
$ sentry-v2ctl rollback --all
rolled back 0199f2b4-1d2e-7a00-8c11-2f3e4d5c6b7a  throttle on batch-report.service
```

An unknown id fails with `error: no such action` and exit code 1.

### pause, resume

`pause` forces dry-run for new actions while everything else keeps running.
Active actions keep their timers. `resume` turns it back off. A pause lasts
until `resume` or the next restart of the daemon.

### reload

Re-read the configuration and policies; `systemctl reload sentry-v2` does
the same. An invalid configuration (or a sink secret that can't be read) is
rejected, the old one stays live, and the error is printed. What a reload
does and doesn't change is in
[configuration.md](configuration.md#applying-changes).

### restore BACKUP_ID

Put back the files a `backup_reload` action saved. The id has the form
`<unit>/<YYYYmmddTHHMMSSZ>` and is in the action record's `backup_id`.

```console
$ sentry-v2ctl restore app-web.service/20261014T031502Z
```

Before writing anything, the daemon checks every file against the backup's
`MANIFEST.sha256` and refuses a backup directory that isn't owned by root
or is writable by anyone else. It then puts each file back atomically and
prints the paths, followed by what to run next:

```text
restored:
/etc/systemd/system/app-web.service
/etc/systemd/system/app-web.service.d/override.conf
run systemctl daemon-reload && systemctl reload app-web.service
```

It doesn't reload anything itself. The unit's sandbox only lets the daemon
write under `/etc/systemd/system` and `/run/systemd/system`. A backed-up
file anywhere else, such as one from a policy's `paths`, makes the restore
stop with `Read-only file system` once it reaches that file; the error
lists what was restored before it. Copy such files back by hand from the
backup directory.

## Offline commands

The daemon binary can check the configuration too, and lists each policy
with its effective mode:

```console
$ sentry-v2 --check
/etc/sentry-v2/sentry-v2.toml: OK, 3 policies, daemon mode dry-run
  memory-pressure-throttle: dry-run (effective dry-run) from /etc/sentry-v2/policies.d/10-memory-pressure-throttle.toml
  unit-failure-notify: dry-run (effective dry-run) from /etc/sentry-v2/policies.d/20-unit-failure-notify.toml
  io-pressure-freeze-batch: dry-run (effective dry-run) from /etc/sentry-v2/policies.d/30-io-pressure-freeze-batch.toml
```

It takes the same `--config` and `--policies` options and exits 2 on an
invalid configuration.

`policy validate` and `policy test` load the configuration directly, so they
work before the daemon is installed as a service, in CI, or on a laptop.

| Option | Default | Meaning |
|---|---|---|
| `--config FILE` | `/etc/sentry-v2/sentry-v2.toml` | The global file. |
| `--policies DIR` | `/etc/sentry-v2/policies.d` | The policies directory. |

### policy validate

```console
$ sentry-v2ctl policy validate
ok: 3 policies
$ sentry-v2ctl policy validate --json
{"valid": true, "policies": 3}
```

On failure it prints `invalid: <file>: <key>: <reason>` to stderr and exits
1. With `--json` it also prints `{"valid": false, "error": "…"}` to stdout.

### policy test

Feed one event, or a list, through the correlator and the policy engine and
print the actions that would be planned:

```console
$ echo '{"kind": "unit_failed", "unit": "app-billing.service", "result": "core-dump"}' > /tmp/fail.json
$ sentry-v2ctl policy test --event /tmp/fail.json
POLICY               TARGET               ACTION  PARAMS  MODE
unit-failure-notify  app-billing.service  notify          dry-run
```

`MODE` is the effective mode from `daemon.mode` and the policy's `mode`.
Pause and the breaker only exist in the running daemon, so they don't
apply here. If nothing matches, it prints `no policy matches this event`.

Each event is a JSON object with a `kind` and that kind's fields. `ts_us`
(microseconds since the epoch) is optional and defaults to now.

| `kind` | Required fields | Optional fields |
|---|---|---|
| `unit_failed` | `unit` | `result`, `exit_code`, `exit_status`, `invocation_id`, `main_pid` |
| `psi` | `cgroup`, `resource`, `avg10`, `avg60`, `avg300`, `total_us`, `triggered`, `stall_us`, `window_us` | `pressure` (`some` or `full`, default `full`) |
| `avc` | `serial`, `denied`, `perms`, `scontext`, `scontext_type`, `tcontext`, `tclass` | `comm`, `exe`, `pid`, `permissive`, `cgroup_at_receipt`, `unit_at_receipt`, `raw` |

For a `psi` event, `stall_us` and `window_us` must match a policy's
`threshold` exactly (for `300ms/2s`, `300000` and `2000000`). A single PSI
event is replayed back over the policy's `sustained` period, so one event
is enough to test a PSI policy.

To test correlation, pass a list: denials followed by the failure, with
`ts_us` values a second or two apart.
