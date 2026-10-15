# Quickstart

From a fresh install to your first diagnostic bundle in about ten minutes,
without changing anything on the host. Everything here runs in dry-run.

You need an EL10 host with root access. If Sentry-v2 isn't installed yet,
follow [installation.md](installation.md) first, including turning on PSI.

## 1. Look at what ships

The package installs a global configuration and three example policies:

```console
$ ls /etc/sentry-v2/policies.d/
10-memory-pressure-throttle.toml  20-unit-failure-notify.toml  30-io-pressure-freeze-batch.toml
```

| Policy | Watches | Would do |
|---|---|---|
| `memory-pressure-throttle` | Memory stalls in `system.slice/batch-*.service` | Throttle the job's memory and CPU for 5 minutes |
| `unit-failure-notify` | `app-*` and `batch-*` services dying from a signal, core dump, watchdog or timeout | Send a bundle |
| `io-pressure-freeze-batch` | I/O stalls from batch and backup services | Freeze the job for up to 2 minutes |

All three are in dry-run, and so is the daemon.

## 2. Protect what matters on this host

Open `/etc/sentry-v2/sentry-v2.toml` and set the units that must never be
throttled or frozen. The shipped value, `nginx.service`, is only an
example:

```toml
[protection]
protected = ["postgresql.service", "nginx.service"]
```

## 3. Add a policy of your own

Copy an example, then give it a new name (names must be unique) and point
it at your services:

```console
# cd /etc/sentry-v2/policies.d
# cp 20-unit-failure-notify.toml 50-myapp-notify.toml
# sed -i -e 's/^name = .*/name = "myapp-notify"/' \
         -e 's/^units = .*/units = ["myapp-*.service"]/' 50-myapp-notify.toml
```

## 4. Validate

```console
$ sentry-v2ctl policy validate
ok: 4 policies
```

A mistake is reported with the file and the key, and the exit code is 1:

```console
invalid: 50-myapp-notify.toml: policy[0].name: duplicate policy name 'unit-failure-notify' (first defined in 20-unit-failure-notify.toml)
```

## 5. Start the daemon

```console
# systemctl enable --now sentry-v2
$ sentry-v2ctl status
sentry-v2 0.1.0  running for 4s  mode dry-run

COLLECTOR  HEALTH
...
```

Check each collector's health. PSI should say `state=ok`; if it says
`state=disabled`, go back to [Turn on PSI](installation.md#turn-on-psi).

## 6. Make something fail

Start a throwaway service that kills itself. Its name matches
`app-*.service` and the result, `signal`, is one the example policy cares
about:

```console
# systemd-run --unit app-demo.service sh -c 'kill -KILL $$'
```

After a second or two:

```console
$ sentry-v2ctl incidents --limit 1
ID                                    WHEN    SEVERITY  KIND         TARGET            POLICY
0199f2a1-7c00-7a3e-8b1d-4e5f6a7b8c9d  3s ago  info      unit_failed  app-demo.service  unit-failure-notify
$ sentry-v2ctl show 0199f2a1-7c00-7a3e-8b1d-4e5f6a7b8c9d | less
```

The same bundle is on disk under `/var/lib/sentry-v2/bundles/`. What each
field means is in [bundles.md](bundles.md).

Clean up:

```console
# systemctl reset-failed app-demo.service
```

## 7. Let it run, then decide

Leave everything in dry-run for a few days. Each bundle's `decision.actions`
shows exactly what would have been done, including actions refused for
hitting a limit or a protected unit.

When the bundles for a policy look right, turn on both switches: the
daemon's and that policy's.

```toml
# /etc/sentry-v2/sentry-v2.toml
[daemon]
mode = "enforce"
```

```toml
# /etc/sentry-v2/policies.d/10-memory-pressure-throttle.toml
[[policy]]
name = "memory-pressure-throttle"
mode = "enforce"
```

```console
$ sentry-v2ctl policy validate && sudo systemctl reload sentry-v2
```

Other policies stay in dry-run until you switch them too. If anything goes
wrong, `sentry-v2ctl pause` stops new actions at once and
`sentry-v2ctl rollback --all` undoes the ones in force.

## Next

- [policies.md](policies.md): write policies for your own services.
- [sinks.md](sinks.md): send bundles to a webhook, syslog, Splunk or Elasticsearch.
- [actions-and-safety.md](actions-and-safety.md): what enforce mode can and can't do.
