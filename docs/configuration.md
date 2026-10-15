# Configuration reference

Sentry-v2 reads one global file, `/etc/sentry-v2/sentry-v2.toml`, and every
`*.toml` file in `/etc/sentry-v2/policies.d/`. This page covers the global
file. Policies have their own page: [policies.md](policies.md).

The RPM installs a commented copy of the global file with every default
spelled out. You can delete any line and get the same behaviour.

## How the file is checked

Validation is strict, and the first problem stops the load:

- An unknown key or section is an error, so a typo never silently falls back
  to a default.
- Every error names the file and the key path, for example
  `sentry-v2.toml: limits.max_active_actions: must be between 1 and 1000`.
- A secret written inline (`token`, `password`, `api_key`, `hmac_key` or
  `secret` inside a sink) is rejected with
  `secrets must be given as <key>_file`.

Check a change before you apply it:

```console
$ sentry-v2ctl policy validate
ok: 3 policies
```

Then apply it with `systemctl reload sentry-v2` or `sentry-v2ctl reload`. If
the new files don't validate, the daemon keeps running on the old ones and
`sentry-v2ctl status` shows the error.

## Value formats

| Format | Looks like | Rules |
|---|---|---|
| Duration | `"150ms"`, `"10s"`, `"5m"`, `"1.5h"`, `"30d"` | A number and exactly one unit: `us`, `ms`, `s`, `m`, `h`, `d`. Always a string. |
| Size | `"512M"`, `"1G"`, `"80%"` | Digits with an optional binary suffix `K`, `M`, `G`, `T` (1024-based), or a percentage above 0 and at most 100. Some keys accept only absolute sizes. |
| Path | `"/etc/sentry-v2/webhook.key"` | A string. Secret files have extra rules, covered under [Secrets](#secrets). |

## `[daemon]`

| Key | Type | Default | Meaning |
|---|---|---|---|
| `log_level` | string | `"info"` | One of `debug`, `info`, `warning`, `error`. |
| `state_dir` | path | `"/var/lib/sentry-v2"` | Where the action journal, bundles, spool and backups live. The unit only makes `/var/lib/sentry-v2` writable, so change this only if you also change the unit. |
| `queue_size` | integer, 1 to 10000000 | `10000` | Events waiting for the correlator. When it's full the oldest event is dropped and counted in `sentry_v2_events_dropped_total`. |
| `mode` | `"dry-run"` or `"enforce"` | `"dry-run"` | The master switch. An action is enforced only when this and the policy's own `mode` are both `"enforce"`. |

## `[limits]`

| Key | Type | Default | Meaning |
|---|---|---|---|
| `max_active_actions` | integer, 1 to 1000 | `5` | Throttles and freezes in force at once, across all policies. Further actions are refused with `limit`. |
| `max_concurrent_freezes` | integer, 0 to 1000 | `1` | Freezes in force at once. `0` disables freezing. |
| `max_action_duration` | duration | `"30m"` | The longest `duration` any throttle or freeze may ask for. Policies asking for more fail validation. |
| `breaker_failures` | integer, 1 to 1000 | `3` | systemd failures that trip the circuit breaker. |
| `breaker_window` | duration | `"10m"` | The window those failures must fall within. |
| `breaker_cooldown` | duration | `"15m"` | How long the tripped breaker forces dry-run. |

Raising `max_active_actions` lengthens the worst-case shutdown time. See
[actions-and-safety.md](actions-and-safety.md#how-long-a-stop-can-take)
before you do.

## `[protection]`

| Key | Type | Default | Meaning |
|---|---|---|---|
| `protected` | list of strings | `[]` | Unit name patterns (`fnmatch` style, case-sensitive) that are never throttled, frozen or reloaded, on top of the built-in list. |

The built-in list can't be turned off: `init.scope`, `-.slice`,
`system.slice`, `user.slice`, `sshd.service`, `systemd-journald.service`,
`dbus-broker.service`, `dbus.service`, `systemd-logind.service`,
`auditd.service`, `sentry-v2.service` and `systemd-*.service`.

The example config ships with `protected = ["nginx.service"]` as a
placeholder. Replace it with the services you can least afford to stall.

## `[correlation]`

| Key | Type | Default | Meaning |
|---|---|---|---|
| `retention` | duration | `"60s"` | How long events stay in memory for matching. |
| `before` | duration | `"5s"` | How far before a unit failure a denial can be and still count. Also the window an AVC burst is counted over. |
| `after` | duration | `"1s"` | How long after a unit failure the correlator waits for late denials before it finalises the incident. |
| `min_confidence` | number, 0 to 1 | `0.5` | Denials scoring below this are left out of the bundle. |
| `avc_burst` | integer, 1 to 1000000 | `5` | Denials from one SELinux domain within `before` that raise an `avc` incident. |

The scoring behind `min_confidence` is described in
[correlation.md](correlation.md).

## `[redaction]`

| Key | Type | Default | Meaning |
|---|---|---|---|
| `patterns` | list of regex strings | `[]` | Extra Python regular expressions. Each match is replaced with `[REDACTED]`. Every pattern must compile. |
| `use_defaults` | boolean | `true` | Keep the built-in patterns. Set to `false` to use only yours. |

What gets scrubbed, and what doesn't, is in
[bundles.md](bundles.md#redaction).

## `[sinks]`

The file sink is always on. The other four turn on when their table is
present. Full behaviour, retries and examples are in [sinks.md](sinks.md).

### `[sinks.file]`

| Key | Type | Default | Meaning |
|---|---|---|---|
| `dir` | path | `<state_dir>/bundles` | Bundles are written to `<dir>/YYYY/MM/DD/<id>.json`. |
| `max_age` | duration | `"30d"` | Bundles older than this are deleted. |
| `max_size` | absolute size | `"1G"` | Once the directory is bigger than this, the oldest bundles go first. Percentages are rejected. |

### `[sinks.webhook]`

| Key | Type | Default | Meaning |
|---|---|---|---|
| `url` | string | required | Must start with `https://`. |
| `hmac_key_file` | path | required | File holding the HMAC-SHA256 signing key. |
| `ca_file` | path | none | PEM bundle to trust instead of the system CAs. |
| `timeout` | duration | `"10s"` | Per-request timeout. |

### `[sinks.syslog]`

| Key | Type | Default | Meaning |
|---|---|---|---|
| `host` | string | `"127.0.0.1"` | Collector host name or address. |
| `port` | integer, 1 to 65535 | `514` | Collector port. Use 6514 for TLS by convention. |
| `transport` | `"udp"`, `"tcp"` or `"tls"` | `"udp"` | How messages travel. |
| `ca_file` | path | none | PEM bundle for `tls`. Ignored for `udp` and `tcp`. |

### `[sinks.splunk_hec]`

| Key | Type | Default | Meaning |
|---|---|---|---|
| `url` | string | required | Must start with `https://`. `/services/collector/event` is appended if missing. |
| `token_file` | path | required | File holding the HEC token. |
| `index` | string | none | Splunk index. Leave it out to use the token's default. |
| `ca_file` | path | none | PEM bundle to trust instead of the system CAs. |

### `[sinks.elastic]`

| Key | Type | Default | Meaning |
|---|---|---|---|
| `url` | string | required | Must start with `https://`. `/_bulk` is appended if missing. |
| `index` | string | required | Index or data stream name. |
| `api_key_file` | path | none | File holding an Elasticsearch API key (the encoded form). |
| `username` | string | none | Basic-auth user name. |
| `password_file` | path | none | File holding the basic-auth password. |
| `ca_file` | path | none | PEM bundle to trust instead of the system CAs. |

Give exactly one of `api_key_file` or the pair `username` and
`password_file`.

## `[metrics]`

| Key | Type | Default | Meaning |
|---|---|---|---|
| `enabled` | boolean | `false` | Serve Prometheus metrics at `http://<host>:<port>/metrics`. |
| `host` | string | `"127.0.0.1"` | Bind address. A non-loopback address works but logs a warning. |
| `port` | integer, 1 to 65535 | `9787` | Bind port. The SELinux subpackage labels 9787 only; label any other port yourself (see [hardening.md](hardening.md#selinux)). |

The metric list is in [metrics.md](metrics.md).

## `[control]`

| Key | Type | Default | Meaning |
|---|---|---|---|
| `socket` | path | `"/run/sentry-v2/control.sock"` | The control socket `sentry-v2ctl` and Cockpit talk to. |
| `group` | string | `"sentry-v2"` | Members can read status, incidents and bundles. |
| `admin_group` | string | `"sentry-v2-admin"` | Members can also roll back, pause, resume, reload and restore. |

Admins need both groups: `group` gets them through `/run/sentry-v2`, and
`admin_group` lets them change things.

```console
# usermod -aG sentry-v2,sentry-v2-admin alice
```

## Policies

Policies are loaded from `/etc/sentry-v2/policies.d/*.toml` in lexical
order, which is why the examples use number prefixes. Each file holds
`[[policy]]` tables and nothing else; together they make up the daemon's
`policies` list. Names must be unique across
all files. The full reference is [policies.md](policies.md).

## Secrets

Every secret is a path to a file, never the value itself. When the daemon
starts it opens each secret file once and refuses it unless it's:

- a regular file,
- owned by root,
- not readable or writable by group or others (mode `0600` or tighter),
- non-empty, UTF-8, and free of control characters (one trailing newline is
  stripped).

```console
# install -m 0600 -o root -g root /dev/null /etc/sentry-v2/webhook.key
# openssl rand -hex 32 > /etc/sentry-v2/webhook.key
```

A relative path names a systemd credential instead. Add a
`LoadCredential=` line to a drop-in and point the sink at the credential's
name:

```ini
# /etc/systemd/system/sentry-v2.service.d/credentials.conf
[Service]
LoadCredential=webhook-hmac:/etc/sentry-v2/webhook.key
```

```toml
[sinks.webhook]
url = "https://hooks.example.com/sentry-v2"
hmac_key_file = "webhook-hmac"
```

`policy validate` doesn't open secret files. A bad secret shows up when the
daemon starts.

## The whole file at a glance

The top-level sections are `daemon`, `limits`, `protection`, `correlation`,
`redaction`, `sinks`, `metrics` and `control`. Each one is optional.
