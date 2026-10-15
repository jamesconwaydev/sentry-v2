# The Cockpit page

If you already manage hosts through Cockpit, the Sentry-v2 page shows the
daemon's state next to everything else and lets you roll back or pause
without opening a terminal. It talks to the same control socket as
`sentry-v2ctl`, so it can see and do exactly what the CLI can.

## Installing

The page ships as its own package, `sentry-v2-cockpit`, alongside the
daemon packages on the [Releases](https://github.com/jamesconwaydev/sentry-v2/releases)
page:

```console
# dnf install ./sentry-v2-cockpit-0.1.0-*.noarch.rpm
```

It's plain JavaScript with no build step and no server component. Reload
Cockpit in the browser and **Sentry-v2** appears in the menu.

## What it shows

| Tab | Shows | You can |
|---|---|---|
| Overview | Daemon version, mode and uptime; whether it's paused; collector health; current PSI readings; active throttles and freezes with their expiry. | Roll back an action; pause and resume. |
| Incidents | Recent incidents, newest first. Select one to read its full bundle, including correlated denials with their scores and reasons. | Read. |
| Policies | Every loaded policy with its signal, actions, configured mode and effective mode, and the last reload error if there was one. | Read. |

Policies are read-only on purpose. Edit the files under
`/etc/sentry-v2/policies.d/`, check them with `sentry-v2ctl policy validate`,
and reload.

## Permissions

The page opens the control socket as your Cockpit user, or as root when
you've turned on administrative access in Cockpit. The daemon then applies
the usual rules:

| Your Cockpit session | You can |
|---|---|
| Administrative access on | Everything. |
| Limited access, member of `sentry-v2` | View every tab. |
| Limited access, member of `sentry-v2` and `sentry-v2-admin` | Also roll back, pause and resume. |
| Limited access, neither group | Nothing; the page reports permission denied. |

To give someone the page without full admin rights:

```console
# usermod -aG sentry-v2,sentry-v2-admin alice
```

They need to log out of Cockpit and back in for the new groups to apply.
