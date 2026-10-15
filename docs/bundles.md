# Diagnostic bundles

Every incident produces one bundle, whether or not a policy matched it: a
single JSON document
with what happened, what the host looked like at the time, which SELinux
denials were linked to it and why, and what the daemon did about it. The
point is that whoever opens it at 3am doesn't have to go and collect any of
that by hand.

Bundles always land on disk and go to whichever other [sinks](sinks.md) you
turn on.

## Where to find them

```console
# ls /var/lib/sentry-v2/bundles/2026/10/17/
0199f2a1-8150-7d44-a2b6-0c1d2e3f4a5b.json
$ sentry-v2ctl incidents --limit 5
$ sentry-v2ctl show 0199f2a1-8150-7d44-a2b6-0c1d2e3f4a5b
```

Files are named by the bundle id, which is a UUIDv7, so listing a day's
directory lists bundles in the order they were written. The `ID` column of
`sentry-v2ctl incidents` is that bundle id, and `sentry-v2ctl show` reads
the bundle back from the file sink's directory. The incident list itself
lives in memory (the latest 500) and starts empty after a restart; the
files stay until retention removes them.

## The schema

The schema id is `sentry-v2/bundle/1`, published as JSON Schema in
[reference/bundle.schema.json](reference/bundle.schema.json). Validate a
bundle against it with any JSON Schema tool:

```console
$ check-jsonschema --schemafile docs/reference/bundle.schema.json bundle.json
```

| Field | Type | Meaning |
|---|---|---|
| `schema` | string | Always `sentry-v2/bundle/1`. A breaking change gets a new id. |
| `id` | UUID | The bundle's own id. |
| `ts` | RFC 3339, UTC | When the bundle was built, to the microsecond. |
| `severity` | `info`, `warning`, `critical` | See [Severity](#severity). |
| `host` | object | `hostname`, `machine_id`, `kernel`, `os_release` (the `PRETTY_NAME`). |
| `incident` | object | `id`, `kind` (`unit_failed`, `psi`, `avc` or `alert`), `ts_us`, `target`, the `trigger` event, `related` events, `correlations`, and for PSI the `sustained` period it outlasted. |
| `context` | object | `psi`: pressure for the incident's cgroup and each parent, keyed by cgroup path, then resource, then `some`/`full`. `unit`: the unit's systemd properties (or `null`). `journal`: the unit's last 50 journal lines this boot, oldest first. |
| `correlations` | array | The scored denials, each with `avc`, `confidence` and `reasons`. The same list as `incident.correlations`, at the top level so it's easy to query. |
| `decision` | object | `policy` and `mode` of the first planned action, and `actions`: every action record for this incident. With no matching policy, `policy` and `mode` are `null` and `actions` is empty. |

Timestamps inside events (`ts_us`) are microseconds since the epoch.
Timestamps in action records (`applied_at`, `expires_at`, `ts`) are seconds
since the epoch.

### Severity

| Severity | When |
|---|---|
| `critical` | An action's rollback failed, or it's an alert bundle. |
| `warning` | An enforced action was applied or rolled back, or a correlation scored 0.8 or more. |
| `info` | Everything else, including every dry-run with weak or no correlations. |

### Alert bundles

Two events produce a bundle without an incident: a rollback that gave up
(`rollback_failed`) and the circuit breaker opening (`breaker_open`). They
have `severity = "critical"`, `incident.kind = "alert"`, the alert name in
`incident.alert`, and for a failed rollback the action record in
`decision.actions`.

## An example

A billing service fails a second after SELinux stops it reading its config
file. The denial came from a process in the unit's cgroup with the right
name, so it scores 0.94, and the bundle is a `warning`. The policy is still
in dry-run, so the only action is a `notify` marked `dry_run`. Note the
`[REDACTED]` in the first journal line, where the service logged its
database URL with the password in it.

The unit had already failed and lost its cgroup, so `context.psi` shows the
parent slice. `memory_high` and `cpu_weight` are systemd's raw values;
18446744073709551615 (2⁶⁴ − 1) means "not set".

```json
{
  "schema": "sentry-v2/bundle/1",
  "id": "0199f2a1-8150-7d44-a2b6-0c1d2e3f4a5b",
  "ts": "2026-10-17T01:20:01.214503Z",
  "severity": "warning",
  "host": {
    "hostname": "web-01.example.com",
    "machine_id": "4c4c4544004e3510804ab4c04f4e3332",
    "kernel": "6.12.0-55.el10.x86_64",
    "os_release": "Rocky Linux 10.0 (Red Quartz)"
  },
  "incident": {
    "id": "0199f2a1-7c00-7a3e-8b1d-4e5f6a7b8c9d",
    "kind": "unit_failed",
    "ts_us": 1792200000000000,
    "target": "app-billing.service",
    "trigger": {
      "ts_us": 1792200000000000,
      "source": "journal",
      "unit": "app-billing.service",
      "kind": "failed",
      "result": "exit-code",
      "exit_code": null,
      "exit_status": null,
      "invocation_id": "6f1c2a9e0b5d4f3a8e7c1b2d3f4a5b6c",
      "main_pid": null
    },
    "related": [],
    "correlations": [
      {
        "avc": {
          "ts_us": 1792199998800000,
          "source": "audit",
          "serial": 48213,
          "denied": true,
          "perms": [
            "read"
          ],
          "scontext": "system_u:system_r:billing_t:s0",
          "scontext_type": "billing_t",
          "tcontext": "system_u:object_r:etc_t:s0",
          "tclass": "file",
          "comm": "billing-api",
          "exe": "/usr/bin/billing-api",
          "pid": 4121,
          "permissive": false,
          "cgroup_at_receipt": "system.slice/app-billing.service",
          "unit_at_receipt": "app-billing.service",
          "raw": "verdict=denied perms=read pid=4121 comm=billing-api name=billing.conf scontext=system_u:system_r:billing_t:s0 tcontext=system_u:object_r:etc_t:s0 tclass=file permissive=0"
        },
        "confidence": 0.94,
        "reasons": [
          "pid in unit cgroup",
          "comm matches ExecStart"
        ]
      }
    ],
    "sustained": null
  },
  "context": {
    "psi": {
      "system.slice": {
        "memory": {
          "some": {
            "avg10": 0.0,
            "avg60": 0.12,
            "avg300": 0.05,
            "total_us": 912334
          },
          "full": {
            "avg10": 0.0,
            "avg60": 0.02,
            "avg300": 0.01,
            "total_us": 301220
          }
        }
      }
    },
    "unit": {
      "memory_high": 18446744073709551615,
      "cpu_weight": 18446744073709551615,
      "freezer_state": "running",
      "active_state": "failed",
      "main_pid": 0,
      "fragment_path": "/etc/systemd/system/app-billing.service",
      "drop_in_paths": [],
      "exec_start": [
        "/usr/bin/billing-api"
      ],
      "cgroup": "system.slice/app-billing.service"
    },
    "journal": [
      {
        "ts_us": 1792199998700000,
        "priority": 6,
        "message": "connecting to postgres[REDACTED]db.internal/billing"
      },
      {
        "ts_us": 1792199998750000,
        "priority": 3,
        "message": "open /etc/billing/billing.conf: permission denied"
      },
      {
        "ts_us": 1792199999999000,
        "priority": 3,
        "message": "app-billing.service: Main process exited, code=exited, status=1/FAILURE"
      }
    ]
  },
  "correlations": [
    {
      "avc": {
        "ts_us": 1792199998800000,
        "source": "audit",
        "serial": 48213,
        "denied": true,
        "perms": [
          "read"
        ],
        "scontext": "system_u:system_r:billing_t:s0",
        "scontext_type": "billing_t",
        "tcontext": "system_u:object_r:etc_t:s0",
        "tclass": "file",
        "comm": "billing-api",
        "exe": "/usr/bin/billing-api",
        "pid": 4121,
        "permissive": false,
        "cgroup_at_receipt": "system.slice/app-billing.service",
        "unit_at_receipt": "app-billing.service",
        "raw": "verdict=denied perms=read pid=4121 comm=billing-api name=billing.conf scontext=system_u:system_r:billing_t:s0 tcontext=system_u:object_r:etc_t:s0 tclass=file permissive=0"
      },
      "confidence": 0.94,
      "reasons": [
        "pid in unit cgroup",
        "comm matches ExecStart"
      ]
    }
  ],
  "decision": {
    "policy": "unit-failure-notify",
    "mode": "dry-run",
    "actions": [
      {
        "id": "0199f2a1-80e8-7f12-9c3a-1b2c3d4e5f60",
        "policy": "unit-failure-notify",
        "action": "notify",
        "target": "app-billing.service",
        "mode": "dry-run",
        "configured_mode": "dry-run",
        "status": "dry_run",
        "previous": {},
        "params": {},
        "applied_at": null,
        "expires_at": null,
        "error": null,
        "incident_id": "0199f2a1-7c00-7a3e-8b1d-4e5f6a7b8c9d",
        "backup_id": null
      }
    ]
  }
}
```

## Redaction

Bundles are built from journal lines, unit properties and audit records,
which is exactly where passwords and tokens leak. Before a bundle goes
anywhere, matches of these patterns are replaced with `[REDACTED]`:

| What | Pattern |
|---|---|
| Authorization headers, with the scheme | `(?i)authorization:\s*\S+(?:\s+\S+)?` |
| Bearer tokens | `(?i)bearer\s+[a-z0-9._~+/-]+=*` |
| Credentials in URLs | `://[^/\s:@]+:[^/\s@]+@` |
| AWS access key ids | `AKIA[0-9A-Z]{16}` |
| PEM private keys | `-----BEGIN … PRIVATE KEY-----` through the matching `END` line, or to the end of the text if it's cut off |
| Secret pairs | `(?i)(password\|passwd\|secret\|token\|api[_-]?key\|access[_-]?key\|client[_-]?secret)=\S+` |

They're applied to:

- every string in `context.unit` and `context.journal`,
- the `raw` audit text of the trigger, related events and correlations,
- the `error` text of each action record.

Ids, SELinux contexts, unit names and cgroup paths are left alone so the
bundle stays usable.

### Adding your own

Add Python regular expressions to `[redaction]`:

```toml
[redaction]
patterns = [
  'internal-api-key-[A-Za-z0-9]{32}',
  '(?i)x-api-key:\s*\S+',
]
```

Every pattern must compile or the configuration is rejected. Use TOML
literal strings (single quotes) so backslashes reach the regex engine
unchanged. Set `use_defaults = false` to drop the built-in patterns and use
only yours.

### Limits worth knowing

- The whole match is replaced. The URL pattern takes the `://` with it, so
  `postgres://billing:hunter2@db` becomes `postgres[REDACTED]db`, and an
  `Authorization:` header loses its name along with up to two words after it.
- Patterns run in order on each string, one after another. A later pattern
  sees the earlier replacements.
- Only the fields listed above are scrubbed. The parsed AVC fields beside
  `raw` (such as `comm` and `exe`) are not, though they rarely hold
  secrets.
- A secret that doesn't match a pattern goes out as is. Redaction is a
  safety net, not a guarantee; keep secrets out of command lines and logs
  in the first place.
- A slow, backtracking pattern runs on every string in every bundle. Keep
  patterns anchored on a literal prefix where you can.
