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
| `status`, `top`, `incidents`, `show`, `actions` | root, or membership of `sentry-v2` |
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
psi        state=ok, triggers=6
journal    state=ok
audit      source=netlink, user_avc_truncated=0

no active actions
```

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

Recent incidents, newest first.

| Option | Default | Meaning |
|---|---|---|
| `--since TIME` | none | Only incidents after this RFC 3339 time, such as `2026-10-17T00:00:00Z`. |
| `--unit UNIT` | none | Only incidents for this unit. |
| `--limit N` | 50 | How many to show. Must be 1 or more. |

### show ID

Print the full bundle for an incident, as indented JSON. Take the id from
`incidents`.

```console
$ sentry-v2ctl show 0199f2a1-7c00-7a3e-8b1d-4e5f6a7b8c9d | jq '.correlations[].reasons'
```

### actions

Active throttles and freezes, then the last 100 action records. The `WHEN`
column shows the expiry when a record has one and the record time
otherwise.
The `ID` column shows the first 8 characters; `--json` has the full ids,
which `rollback` needs.

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
Active actions keep their timers. `resume` turns it back off.

### reload

Re-read the configuration and policies, like `systemctl reload sentry-v2`.
An invalid configuration is rejected, the old one stays live, and the error
is printed.

### restore BACKUP_ID

Put back the files a `backup_reload` action saved. The id has the form
`<unit>/<YYYYmmddTHHMMSSZ>` and is in the action record's `backup_id`.

```console
$ sentry-v2ctl restore app-web.service/20261014T031502Z
```

The daemon prints the restored paths and a note. Reload systemd and the unit
yourself if unit files came back.

## Offline commands

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
