# The Cockpit page

If you already manage hosts through Cockpit, the Sentry-v2 page shows the
daemon's state next to everything else and lets you roll back, pause or
reload without opening a terminal. It talks to the same control socket as
`sentry-v2ctl`, so it can see and do exactly what the CLI can.

## Installing

The page ships as its own package, `sentry-v2-cockpit`, built from the same
spec as the daemon and published alongside it on the
[Releases](https://github.com/jamesconwaydev/sentry-v2/releases) page. It
needs Cockpit 300 or later (`cockpit-system`):

```console
# dnf install ./sentry-v2-cockpit-0.2.0-*.noarch.rpm
```

The files go to `/usr/share/cockpit/sentry-v2/`. It's plain JavaScript and
CSS with no build step and nothing running on the server. Reload Cockpit in
the browser and **Sentry-v2** appears under **Tools**.

## What it shows

### Overview

Refreshes every 5 seconds.

- Banners for the mode, a pause, an open circuit breaker and a failed
  reload, with **Pause remediation** or **Resume**.
- Daemon: mode, breaker, version, uptime, sink delivery problems and
  dropped events.
- Collectors: the health of PSI, the journal and SELinux audit,
  including PSI being off and the audit log fallback.
- Needs attention: rollbacks that failed, with a **Retry** button for
  each. It only appears when there's something in it.
- Held for acting too often: units the [flap guard](actions-and-safety.md#units-that-keep-coming-back)
  put on hold, with **Allow actions again** for each (the same as
  `sentry-v2ctl ack`). It only appears when a unit is held.
- Active actions: every throttle and freeze in force, when it was
  applied and when it rolls back, with **Roll back** (asks you to confirm).
- Pressure: avg10, avg60 and avg300 for every watched cgroup, with a
  gauge and a trend.

### Incidents

The latest incidents, newest first, filterable by unit and severity. New
ones appear as they happen, through a subscription to the daemon.

Select an incident to open its bundle: what happened, the likely related
SELinux denials with their confidence and the reasons they're linked, a
root command that pulls those exact denials from the audit log and runs
them through `audit2allow -w` so you can see why they were refused, the
decision and the actions taken, the journal lines around the incident, and
the raw bundle JSON.

### Policies

Every loaded policy with its signal, actions, configured mode and effective
mode, a banner if the last reload failed, and **Reload configuration**.

There's no button to load a policy fix. The daemon's SELinux domain can't
load policy, and it shouldn't: `audit2allow` output loaded unread is how a
mislabelled file turns into a permanent hole. The command is there so you
can read the answer and decide.

Policies are read-only here on purpose. Edit the files under
`/etc/sentry-v2/policies.d/`, check them with `sentry-v2ctl policy
validate`, then reload from this tab or with `systemctl reload sentry-v2`.

## Permissions

The page connects to the control socket as your Cockpit user, or as root
when administrative access is turned on in Cockpit's top bar. The daemon
then applies the usual rules:

| Your Cockpit session | You can |
|---|---|
| Administrative access on | Everything. |
| Limited access, member of `sentry-v2` | View every tab. |
| Limited access, member of `sentry-v2` and `sentry-v2-admin` | Also roll back, allow held units again, pause, resume and reload. |
| Limited access, neither group | Nothing; the page says you don't have access. |

A refused change shows the daemon's reason and a hint about the admin
group. To give someone the page without full admin rights:

```console
# usermod -aG sentry-v2,sentry-v2-admin alice
```

They need to log out of Cockpit and back in for the new groups to apply.

If the daemon isn't running, the page says so and keeps retrying, so it
comes back by itself once you start the service.
