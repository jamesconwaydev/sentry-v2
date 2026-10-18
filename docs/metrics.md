# Metrics

Sentry-v2 can serve Prometheus metrics in the text exposition format
(version 0.0.4). It's off by default.

## Turning it on

```toml
[metrics]
enabled = true
host = "127.0.0.1"
port = 9787
```

```console
# systemctl reload sentry-v2
$ curl -s http://127.0.0.1:9787/metrics | grep '^sentry_v2_incidents_total'
sentry_v2_incidents_total{kind="unit_failed"} 4.0
```

The endpoint answers `GET /metrics` only. Anything else gets 404 or 405,
and a client that takes more than 5 s to send its request headers gets
408. There's no authentication and no TLS, which is why it binds to
loopback by default. Binding to another address works but logs a warning;
if you need remote scraping, put an authenticating proxy in front or scrape
through an SSH tunnel.

The SELinux subpackage labels TCP port 9787 for the daemon. If you use
another port, label it too (see [hardening.md](hardening.md#selinux)).

## Metric reference

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `sentry_v2_psi_avg10` | gauge | `cgroup`, `resource`, `kind` | The latest 10-second pressure average, in percent, for each watched cgroup, from the 5-second samples. A cgroup that misses three samples in a row (15 seconds) drops out, so a stopped unit disappears quickly. |
| `sentry_v2_actions_total` | counter | `policy`, `action`, `mode`, `result` | Actions attempted. `mode` is the mode actually used (`dry-run` or `enforce`); `result` is the record's status when the incident was handled: `applied`, `failed`, `dry_run`, or `planned` for an apply whose outcome was unknown and is being rolled back. |
| `sentry_v2_actions_active` | gauge | | Throttles and freezes awaiting rollback. |
| `sentry_v2_rollbacks_stuck` | gauge | | Units whose rollback failed for good. Each one refuses new actions until you run `sentry-v2ctl rollback` on it. |
| `sentry_v2_units_held` | gauge | | Units on hold after `limits.flap_actions` actions inside `limits.flap_window`. Each refuses new actions until you run `sentry-v2ctl ack` on it. |
| `sentry_v2_breaker_open` | gauge | | 1 while the circuit breaker forces dry-run after repeated systemd failures, otherwise 0. |
| `sentry_v2_incidents_total` | counter | `kind` | Incidents opened: `unit_failed`, `psi` or `avc`. |
| `sentry_v2_avc_correlated_total` | counter | | Denials linked to an incident. |
| `sentry_v2_events_dropped_total` | counter | `collector` | Events dropped because the event queue was full. |
| `sentry_v2_sink_failures_total` | counter | `sink` | Failed deliveries per sink. Updated every 0.25 s from the sinks' own counts. |
| `sentry_v2_build_info` | gauge | `version` | Always 1, labelled with the running version. |
| `sentry_v2_metrics_render_errors_total` | counter | | Metrics skipped because they failed to render. One broken metric never takes down the whole scrape. |

Counters without labels appear as 0 from the first scrape. Labelled series
appear the first time they're incremented.

## Alerts worth having

```yaml
groups:
  - name: sentry-v2
    rules:
      - alert: SentryV2DroppingEvents
        expr: increase(sentry_v2_events_dropped_total[10m]) > 0
        annotations:
          summary: "sentry-v2 is dropping {{ $labels.collector }} events; raise daemon.queue_size"
      - alert: SentryV2SinkFailing
        expr: increase(sentry_v2_sink_failures_total[30m]) > 3
        annotations:
          summary: "sentry-v2 cannot deliver to {{ $labels.sink }}"
      - alert: SentryV2RollbackStuck
        expr: sentry_v2_rollbacks_stuck > 0
        annotations:
          summary: "a sentry-v2 rollback failed; see sentry-v2ctl actions"
      - alert: SentryV2UnitHeld
        expr: sentry_v2_units_held > 0
        annotations:
          summary: "sentry-v2 keeps acting on the same unit; see sentry-v2ctl status"
      - alert: SentryV2BreakerOpen
        expr: sentry_v2_breaker_open == 1
        annotations:
          summary: "sentry-v2 has forced dry-run after repeated systemd failures"
      - alert: SentryV2ActionsEnforced
        expr: increase(sentry_v2_actions_total{mode="enforce"}[5m]) > 0
        annotations:
          summary: "sentry-v2 enforced {{ $labels.action }} for policy {{ $labels.policy }}"
```

A rollback that fails for good and a tripped circuit breaker also send a
critical bundle to every sink. The gauges are there so you can see the
state persist: the bundle arrives once, while the gauge stays up until
someone deals with it.
