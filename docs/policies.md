# Writing policies

A policy says: when this signal shows up for these targets, do these
actions, in this mode, and then leave the same target alone for a while.
Policies live in `/etc/sentry-v2/policies.d/*.toml`, are loaded in lexical
order, and are checked as strictly as the global file. An unknown key is an
error.

Every example on this page loads cleanly with `sentry-v2ctl policy validate`.

## The shape of a policy

```toml
[[policy]]
name = "memory-pressure-throttle"   # required, unique across all files
mode = "dry-run"                    # "dry-run" (default) or "enforce"
cooldown = "10m"                    # default "5m"

[policy.when]                       # required: what to match
signal = "psi"
resource = "memory"
kind = "full"
threshold = "300ms/2s"
sustained = "10s"
cgroups = ["system.slice/batch-*.service"]

[[policy.do]]                       # at least one: what to do, in order
action = "throttle"
memory_high = "80%"
cpu_weight = 50
duration = "5m"

[[policy.do]]
action = "notify"
```

| Key | Type | Default | Meaning |
|---|---|---|---|
| `name` | string | required | Shown in bundles, metrics and `sentry-v2ctl`. A duplicate name is an error that names the file where it first appeared. |
| `mode` | `"dry-run"` or `"enforce"` | `"dry-run"` | This policy's half of the [two switches](#modes). |
| `cooldown` | duration | `"5m"` | After the policy fires for a target, it ignores that target for this long. |
| `when` | table | required | The match. Its keys depend on `signal`. |
| `do` | array of tables | required | One or more actions, run in order. |

## Signals

### `psi`: sustained pressure on a cgroup

```toml
[[policy]]
name = "cpu-pressure-notify"

[policy.when]
signal = "psi"
resource = "cpu"
kind = "some"
threshold = "500ms/2s"
sustained = "30s"
cgroups = ["system.slice/*.service"]

[[policy.do]]
action = "notify"
```

| Key | Type | Default | Meaning |
|---|---|---|---|
| `resource` | `"memory"`, `"cpu"` or `"io"` | required | Which pressure file to watch. |
| `kind` | `"some"` or `"full"` | `"some"` | `some`: at least one task was stalled. `full`: every non-idle task was. `full` is quieter and a stronger sign of trouble. |
| `threshold` | `"<stall>/<window>"` | required | Fire when tasks are stalled for at least `stall` within any `window`. |
| `sustained` | duration | `"5s"` | How long the stall has to keep going before an incident opens. |
| `cgroups` | list of patterns | required | Which cgroups to watch. See [Matching targets](#matching-targets). |

#### The threshold rules

The kernel registers one trigger per cgroup for each distinct
`(resource, kind, threshold)`. The values have to be ones it accepts:

- `window` is between 500 ms and 10 s (the kernel's own limit), and
- `window` is a multiple of 2 s, so in practice `2s`, `4s`, `6s`, `8s` or
  `10s`. Shorter or odd windows need `CAP_SYS_RESOURCE`, and the unit drops
  that capability on purpose.
- `stall` is above zero and no longer than `window`.

A threshold that breaks a rule fails validation with the reason:

```console
$ sentry-v2ctl policy validate
invalid: 10-memory.toml: policy[0].when.threshold: window must be a multiple of 2s (shorter or odd windows need CAP_SYS_RESOURCE)
```

#### How `sustained` is measured

A kernel trigger fires at most once per window while the stall lasts.
Sentry-v2 groups those firings into an episode. The episode stays open as
long as firings keep arriving no more than two windows apart (and never
less than 2 s apart), and `sustained` counts from its first firing. Once
the episode has run for `sustained`, one incident opens; the same episode
won't open another for the same `sustained` value.

Two policies with the same trigger but different `sustained` values share
the kernel trigger and fire at their own points in the episode.

The `psi` match is exact: an incident matches a policy only if the resource,
kind, threshold and `sustained` are all the same.

### `unit_failed`: a service fell over

```toml
[[policy]]
name = "unit-failure-notify"
cooldown = "15m"

[policy.when]
signal = "unit_failed"
units = ["app-*.service", "batch-*.service"]
results = ["signal", "core-dump", "watchdog", "timeout"]

[[policy.do]]
action = "notify"
```

| Key | Type | Default | Meaning |
|---|---|---|---|
| `units` | list of patterns | required | Which units to match. |
| `results` | list of strings | `[]` (any) | Only match these results. For a unit failure this is systemd's `UNIT_RESULT`, such as `exit-code`, `signal`, `core-dump`, `watchdog`, `timeout` or `oom-kill`. A failed start job that never produced a unit failure carries the job result instead, such as `failed` or `timeout`. |

Only messages that systemd itself (PID 1) writes to the journal count, so
another process can't forge a failure by logging `UNIT=`. User units are
ignored. When systemd logs both "job failed" and "unit failed" for one
start, you get one incident, carrying the unit failure's result.

The incident waits `correlation.after` (1 s by default) so late SELinux
denials can be attached. See [correlation.md](correlation.md).

### `avc`: a burst of SELinux denials

```toml
[[policy]]
name = "httpd-denials"

[policy.when]
signal = "avc"
scontext_types = ["httpd_t"]
min_count = 3

[[policy.do]]
action = "notify"
```

| Key | Type | Default | Meaning |
|---|---|---|---|
| `scontext_types` | list of strings | `[]` (any) | Only count denials from these SELinux domains. |
| `min_count` | integer | `1` | Matching denials the burst must contain. It can't be more than `correlation.avc_burst`, because a burst incident opens as soon as that many denials arrive. |

An `avc` incident opens when `correlation.avc_burst` denials (5 by default)
from one domain arrive within `correlation.before` (5 s). After that, the
domain is quiet for `correlation.retention` (60 s) so one storm makes one
incident.

An `avc` incident's target is a domain, not a unit, so only `notify` does
anything useful here. A throttle or freeze on it is recorded as failed with
`no unit target`.

## Matching targets

`cgroups` and `units` take shell-style patterns (`*`, `?`, `[abc]`),
matched case-sensitively. Where the `/` is decides what they match:

| Pattern | Matches against | Example match |
|---|---|---|
| Contains `/` | The whole cgroup path under `/sys/fs/cgroup` | `system.slice/batch-*.service` matches `system.slice/batch-nightly.service` but not `machine.slice/batch-x.service`. |
| No `/` | Only the last path component, the unit name | `batch-*.service` matches `batch-nightly.service` wherever it sits. |

A `*` in a pattern with `/` also matches across slashes, so
`system.slice/*` matches nested cgroups too.

PSI patterns are resolved against the cgroup tree every 30 s, so a unit
that starts later is picked up, and triggers on cgroups that vanish are
closed.

For a `psi` incident, the action target is the last path component if it
ends in `.service`, `.scope` or `.slice`. A pattern that matches a
non-unit cgroup can still notify, but its throttles and freezes fail with
`no unit target`.

## Thresholds you can start from

| Goal | `resource` / `kind` | `threshold` | `sustained` |
|---|---|---|---|
| A job thrashing memory | `memory` / `full` | `300ms/2s` | `10s` |
| A noisy disk neighbour | `io` / `some` | `400ms/2s` | `15s` |
| CPU starvation worth knowing about | `cpu` / `some` | `500ms/2s` | `30s` |

Run them in dry-run for a few days and read the bundles before you tighten
anything.

## Actions

Each `[[policy.do]]` table has an `action` key and that action's settings.
What each action does to the system, and how it's undone, is in
[actions-and-safety.md](actions-and-safety.md).

| `action` | Keys | Notes |
|---|---|---|
| `throttle` | `memory_high` (size or percentage), `cpu_weight` (1 to 10000), `duration` (required) | Needs at least one of `memory_high` and `cpu_weight`. A percentage is taken of the unit's `memory.current` when the action runs. |
| `freeze` | `duration` (required), `release_below` (0 to 100) | `release_below` is the avg10 percentage that ends the freeze early. It defaults to half the trigger's stall ratio. |
| `backup_reload` | `paths` (list of absolute, normalised paths) | Backs up the unit's files plus `paths`, then reloads the unit. |
| `notify` | none | Changes nothing. The bundle for a matched incident goes to the sinks whatever actions ran, so a policy whose only action is `notify` is how you ask for a bundle and nothing else. |

`duration` must be above zero and no longer than
`limits.max_action_duration` (30 minutes by default).

```toml
[[policy]]
name = "io-pressure-freeze-batch"
cooldown = "30m"

[policy.when]
signal = "psi"
resource = "io"
kind = "some"
threshold = "400ms/2s"
sustained = "15s"
cgroups = ["system.slice/batch-*.service", "system.slice/backup-*.service"]

[[policy.do]]
action = "freeze"
duration = "2m"
release_below = 10

[[policy.do]]
action = "notify"
```

```toml
[[policy]]
name = "reload-app-on-failure"

[policy.when]
signal = "unit_failed"
units = ["app-web.service"]
results = ["watchdog"]

[[policy.do]]
action = "backup_reload"
paths = ["/etc/app-web/app.conf"]
```

## Modes

Two switches decide whether anything changes on the host:

| `daemon.mode` | policy `mode` | Effective mode |
|---|---|---|
| `dry-run` | `dry-run` | dry-run |
| `dry-run` | `enforce` | dry-run |
| `enforce` | `dry-run` | dry-run |
| `enforce` | `enforce` | enforce |

Both default to `dry-run`. On top of that, `sentry-v2ctl pause` and a
tripped circuit breaker force dry-run for every policy until they clear.

Dry-run runs the whole pipeline: matching, cooldowns, protection checks,
limits and the bundle. It stops just before the D-Bus call. The action
record says `dry_run` and shows what would have been written, so a dry-run
bundle is a faithful preview.

`sentry-v2ctl policy test` shows the effective mode for each planned action,
and the Cockpit Policies page shows it for each loaded policy.

## Cooldown

The cooldown is per policy and per target. It's stamped when the policy's
actions are planned, not when they finish or succeed, and dry-run stamps it
too. So `cooldown = "15m"` on a unit-failure policy means one bundle per unit
per 15 minutes, however fast the unit crash-loops. Reloading the
configuration keeps cooldown history.

## Protected units

Some units are never throttled, frozen or reloaded, whatever a policy says:
`init.scope`, `-.slice`, `system.slice`, `user.slice`, `sshd.service`,
`systemd-journald.service`, `dbus-broker.service`, `dbus.service`,
`systemd-logind.service`, `auditd.service`, `sentry-v2.service` and every
`systemd-*.service`, plus anything in `protection.protected`.

There are two checks:

- At load time, a `cgroups` or `units` list whose patterns can only match
  protected units fails with `only matches protected units`.
- At run time, a resolved target that's protected is skipped and recorded
  as failed with `protected`. Notifications still go out.

## Checking a policy before you trust it

`sentry-v2ctl policy test` runs an event through the correlator and the
policy engine without the daemon, and prints what would happen:

```console
$ cat > /tmp/psi.json <<'EOF'
{"kind": "psi", "cgroup": "system.slice/batch-report.service",
 "resource": "memory", "pressure": "full",
 "avg10": 22.5, "avg60": 9.1, "avg300": 2.0, "total_us": 81234567,
 "triggered": true, "stall_us": 300000, "window_us": 2000000}
EOF
$ sentry-v2ctl policy test --event /tmp/psi.json
POLICY                    TARGET                             ACTION    PARAMS                                       MODE
memory-pressure-throttle  system.slice/batch-report.service  throttle  memory_high=80% cpu_weight=50 duration=5m0s  dry-run
memory-pressure-throttle  system.slice/batch-report.service  notify                                                 dry-run
```

The event formats are in [cli.md](cli.md#policy-test).
