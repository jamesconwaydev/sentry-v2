# Sinks

A sink is somewhere bundles go. The file sink is always on; the webhook,
syslog, Splunk HEC and Elasticsearch sinks turn on when their table is in
`/etc/sentry-v2/sentry-v2.toml`. Every key is listed in
[configuration.md](configuration.md#sinks).

| Sink | Transport | Retries | Survives a restart |
|---|---|---|---|
| `file` | Local disk | n/a | yes |
| `webhook` | HTTPS POST, HMAC-signed | up to an hour per bundle | yes, spooled to disk |
| `syslog` | RFC 5424 over UDP, TCP or TLS | no | no |
| `splunk_hec` | HTTPS POST | no | no |
| `elastic` | HTTPS `_bulk` | no | no |

## How delivery works

Each sink has its own worker, so a slow sink never holds up another one or
the daemon. The webhook writes every bundle to its spool on disk the moment
it's built, even while it's retrying an older one, so a crash loses nothing.
The other sinks keep an in-memory queue of 1000 and drop bundles when it's
full. Drops and failures are counted per sink in `sentry-v2ctl status` and
in `sentry_v2_sink_failures_total`.

When the daemon stops, sinks get 5 s to deliver what they have. After that,
the webhook's bundles wait in its spool for the next start and the others'
are dropped.

On an SELinux host, the policy module may refuse a sink on an unusual
port even when the network allows it: the sink fails with a permission
error and the audit log has a denial. See
[hardening.md](hardening.md#sinks-on-other-ports) to label the port or add
a local rule.

All HTTPS sinks verify the server certificate against the system trust
store, or against `ca_file` if you give one, and require TLS 1.2 or later.
Plain `http://` URLs are rejected at load time.

Secrets are always files. See
[configuration.md](configuration.md#secrets) for the ownership and mode
rules.

## File

```toml
[sinks.file]
dir = "/var/lib/sentry-v2/bundles"
max_age = "30d"
max_size = "1G"
```

Each bundle is written atomically to `<dir>/YYYY/MM/DD/<id>.json` (UTC date,
mode `0600`). At most once a minute, after a write, the sink deletes bundles
older than `max_age`, then the oldest ones until the directory is under
`max_size`.

## Webhook

```toml
[sinks.webhook]
url = "https://hooks.example.com/sentry-v2"
hmac_key_file = "/etc/sentry-v2/webhook.key"
# ca_file = "/etc/pki/tls/certs/internal-ca.pem"
timeout = "10s"
```

Each bundle is POSTed as `application/json` with two extra headers:

| Header | Value |
|---|---|
| `X-Sentry-V2-Timestamp` | Unix time in seconds, as a string. |
| `X-Sentry-V2-Signature` | `sha256=` followed by the hex HMAC-SHA256 of `<timestamp>.<body>`, keyed with the contents of `hmac_key_file`. |

### Verifying the signature

Sign the exact bytes you received, compare in constant time, and reject old
timestamps so a captured request can't be replayed:

```python
import hashlib
import hmac
import time

MAX_SKEW = 300  # seconds


def verify(key: bytes, headers: dict[str, str], body: bytes) -> bool:
    ts = headers.get("X-Sentry-V2-Timestamp", "")
    sig = headers.get("X-Sentry-V2-Signature", "")
    if not ts.isdigit() or abs(time.time() - int(ts)) > MAX_SKEW:
        return False
    expected = hmac.new(key, ts.encode() + b"." + body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(sig, f"sha256={expected}")
```

`key` is the file's contents without the trailing newline, exactly as the
daemon reads it. A quick test from a shell, with `body.json` as the request
body:

```console
$ ts=$(date +%s)
$ sig=$(printf '%s.' "$ts" | cat - body.json | openssl dgst -sha256 -hmac "$(cat webhook.key)" -r | cut -d' ' -f1)
$ curl -sS https://hooks.example.com/sentry-v2 \
    -H 'Content-Type: application/json' \
    -H "X-Sentry-V2-Timestamp: $ts" -H "X-Sentry-V2-Signature: sha256=$sig" \
    --data-binary @body.json
```

### Retries and the spool

Every bundle is written to `/var/lib/sentry-v2/spool/webhook/` before the
first attempt and deleted only once it's delivered, so a crash or restart
loses nothing. Delivery is oldest first: each send also drains anything
spooled earlier, and the spool is drained again when the daemon starts.

| Response | What happens |
|---|---|
| 2xx | Delivered; removed from the spool. |
| 400, 413, 415, 422 | The receiver rejected this bundle, and sending it again won't help. It's dropped from the spool and counted as a failure. |
| Any other status (3xx, 401, 403, 404, 5xx), timeouts, connection and TLS errors | Retried with exponential backoff and jitter (waits of 1 s, 2 s, 4 s and so on, never more than 5 minutes apart) for up to an hour. Then it stays spooled for the next send or the next start. |

401, 403 and 404 stay spooled on purpose: they're usually a wrong URL or
key, and once you fix that, the backlog goes through.

The spool is capped at 10 000 files and 512 MiB. Past either, the oldest
bundles are deleted with a warning.

## Syslog

```toml
[sinks.syslog]
host = "logs.example.com"
port = 6514
transport = "tls"
ca_file = "/etc/pki/tls/certs/internal-ca.pem"
```

Each bundle is one RFC 5424 message, facility `daemon`, app name
`sentry-v2`, message id `BUNDLE`, with the whole bundle as JSON in MSG and a
structured-data element for filtering:

```text
<28>1 2026-10-17T01:20:01.214503Z web-01 sentry-v2 - BUNDLE [sentry-v2@32473 id="0199f2a1-8150-7d44-a2b6-0c1d2e3f4a5b" severity="warning" policy="unit-failure-notify" unit="app-billing.service"] {"schema":"sentry-v2/bundle/1",...}
```

| Bundle severity | Syslog severity |
|---|---|
| `critical` | 2 (crit) |
| `warning` | 4 (warning) |
| `info` | 6 (info) |

`unit` is the incident's target, which for a `psi` incident is a cgroup
path and for an `avc` incident a domain.

Over UDP, a name that resolves to several addresses gets the message on the
first one only, and nothing tells the daemon if nobody's listening there.
`localhost` is the usual trap: it's often `::1` first, while the collector
listens on `127.0.0.1`. Give an address, or use `tcp` or `tls`, which try each
address in turn.

| `transport` | Framing | Size |
|---|---|---|
| `udp` | One datagram per bundle | Cut to 8192 bytes, with `truncated="1"` added to the structured data. The JSON in a cut message won't parse. |
| `tcp` | Octet counting (RFC 6587) | Whole bundle |
| `tls` | Octet counting over TLS | Whole bundle |

Use TCP or TLS if you want whole bundles. A new connection is opened for
each bundle.

## Splunk HEC

```toml
[sinks.splunk_hec]
url = "https://splunk.example.com:8088"
token_file = "/etc/sentry-v2/hec.token"
index = "linux"
```

Bundles go to `/services/collector/event` (added to `url` if it's not
there) with `Authorization: Splunk <token>`, sourcetype
`sentry-v2:bundle`, the event time taken from the bundle's `ts`, and `index`
if you set one.

Two things catch people out, both seen on Splunk 10.6:

- **A misspelt `index` looks like success.** Splunk answers `200 Success`
  and then drops the event, so the sink counts no failure. Its only sign is a
  message in Splunk itself: `Received event for unconfigured/disabled/deleted
  index`. Send one bundle and search for it before you rely on this.
- **Splunk's default certificate won't verify.** It names no host, so
  `ca_file` alone isn't enough, and the sink has no switch to skip the check.
  Give HEC a certificate that names the host in `url`.

```spl
index=linux sourcetype="sentry-v2:bundle"
| spath severity | search severity=warning
| spath incident.target | table ts severity incident.target
```

## Elasticsearch

```toml
[sinks.elastic]
url = "https://es.example.com:9200"
index = "sentry-v2"
api_key_file = "/etc/sentry-v2/es.key"
```

Or with basic auth:

```toml
[sinks.elastic]
url = "https://es.example.com:9200"
index = "logs-sentry_v2-default"
username = "sentry-v2"
password_file = "/etc/sentry-v2/es.password"
```

Each bundle is sent to `/_bulk` as a `create` with the bundle id as `_id`,
plus an `@timestamp` copied from `ts`, which data streams require. If a
bundle with that id is already indexed (409), it counts as delivered. Any
other per-item error is a failure.

`api_key_file` holds the encoded API key, the value you'd put after
`Authorization: ApiKey`.

## Failures

The syslog, Splunk HEC and Elasticsearch sinks make one attempt per bundle.
If it fails, the failure is logged and counted, and the bundle is still
safe in the file sink. If you need guaranteed delivery to a remote system,
use the webhook.

```console
$ sentry-v2ctl status --json | jq .sinks
{
  "failures": {"splunk_hec": 3},
  "dropped": {}
}
```
