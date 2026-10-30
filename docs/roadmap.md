# Roadmap

What Sentry-v2 plans to do, and not do, from November 2026 to October 2027.
It's a statement of intent from a one-maintainer project, not a schedule.
Plans change in the open: through an issue or Discussion, then an update to
this page.

## What stays the same

These won't change, because the project depends on them:

- Dry-run is the default for the daemon and every shipped policy.
- Every action is reversible and time-boxed, and protected units stay
  protected.
- Runtime dependencies come only from the Python standard library and the
  EL10 base repositories.

## Planned

- **OpenSSF Best Practices silver**, then gold where it's realistic for a
  small project.
- **Per-policy slice permission.** `allow_slices` is global today; letting
  one policy act on slices without opening them to all of them.

## Being considered

These might happen if users ask for them:

- A COPR or other dnf repository, so installs and upgrades don't need
  manual RPM downloads.
- AlmaLinux, RHEL and CentOS Stream 10 in the integration suite, alongside
  Rocky Linux.

## Not planned

- **Other distributions or older releases:** no EL9, Debian or Ubuntu, and
  no cgroup v1.
- **eBPF capture.** Security events are Aegis-v2's job; Sentry-v2 stays
  with PSI, systemd and SELinux audit.
- **Applying SELinux policy changes,** automatically or from a Cockpit
  button. Sentry-v2 shows the `audit2allow` explanation; a person decides.
- **Restarting, stopping or killing services.**
- **Managing several hosts from one place.** It stays one daemon per host;
  send bundles from every host to the same sink to see them together.
- **Editing policies from Cockpit.** Policies stay in files you can review
  and version.
- **Dependencies from PyPI or EPEL at runtime.**
