# Installing Sentry-v2

Sentry-v2 runs on EL10: Rocky Linux 10, AlmaLinux 10, RHEL 10 and CentOS
Stream 10. It needs cgroup v2 (the EL10 default), SELinux in any mode, and
packages from BaseOS and AppStream only. No EPEL.

## From the RPM (recommended)

Download the packages for the latest release from
[GitHub Releases](https://github.com/jamesconwaydev/sentry-v2/releases):

| Package | What it is |
|---|---|
| `sentry-v2-<version>.noarch.rpm` | The daemon, `sentry-v2ctl`, the unit and the example configuration. |
| `sentry-v2-selinux-<version>.noarch.rpm` | The `sentry_v2` SELinux policy module. Recommended on any host running SELinux. |

With the GitHub CLI:

```console
$ gh release download --repo jamesconwaydev/sentry-v2 --pattern 'sentry-v2-*.noarch.rpm'
```

Install both:

```console
# dnf install ./sentry-v2-0.1.0-*.noarch.rpm ./sentry-v2-selinux-0.1.0-*.noarch.rpm
```

`dnf` pulls in `python3`, `python3-systemd` and `python3-dbus` from the base
repositories.

The package does not enable or start the service. That's deliberate: read
the configuration first. Then continue with [Turn on PSI](#turn-on-psi).

### What gets installed

| Path | Contents |
|---|---|
| `/usr/bin/sentry-v2` | The daemon. |
| `/usr/bin/sentry-v2ctl` | The command-line client. |
| `/usr/lib/systemd/system/sentry-v2.service` | The hardened unit. See [hardening.md](hardening.md). |
| `/etc/sentry-v2/sentry-v2.toml` | The global configuration, every default written out. |
| `/etc/sentry-v2/policies.d/*.toml` | Three example policies, all in dry-run. |
| `/var/lib/sentry-v2/` | State: action journal, bundles, spool and backups (mode `0700`). |
| `/run/sentry-v2/` | The control socket (created at start). |

The package also creates two groups: `sentry-v2` (read access to the
control socket) and `sentry-v2-admin` (permission to change things).

Your edits to files under `/etc/sentry-v2` survive upgrades. An upgrade
restarts a running service, and a restart rolls back every active throttle
and freeze first.

## Turn on PSI

EL kernels have Pressure Stall Information turned off unless it's asked
for at boot. Check:

```console
$ cat /proc/pressure/memory
```

If that prints `Operation not supported`, turn it on and reboot:

```console
# grubby --update-kernel=ALL --args=psi=1
# reboot
```

Afterwards the same `cat` prints two lines, `some` and `full`. Without PSI
the daemon still runs, and unit failures and SELinux denials are still
handled; only the PSI collector stays off.

## Let people use the CLI

```console
# usermod -aG sentry-v2 alice                   # can read status and bundles
# usermod -aG sentry-v2,sentry-v2-admin bob     # can also roll back, pause, reload
```

The change applies from their next login.

## From source

To build the RPMs yourself, on an EL10 host or anywhere with Podman:

```console
$ git clone https://github.com/jamesconwaydev/sentry-v2.git
$ cd sentry-v2
$ make rpm
$ ls rpmbuild/RPMS/noarch/
```

On an EL host `make rpm` calls `rpmbuild` directly. Elsewhere it builds in
a `rockylinux:10` container (set `CONTAINER=docker` to use Docker).

## From PyPI

Tagged releases publish the Python package to PyPI as `sentry-v2`. It
gives you the daemon and `sentry-v2ctl` but none of the system pieces:
no unit, no groups, no SELinux module, no example configuration. Use it for
running `sentry-v2ctl policy validate` in CI, or if you package things your
own way.

The two system bindings don't come from PyPI. Install them from the distro
first, then create a virtual environment that can see them:

```console
# dnf install python3-systemd python3-dbus
$ python3 -m venv --system-site-packages ~/.venvs/sentry-v2
$ ~/.venvs/sentry-v2/bin/pip install sentry-v2
```

`sentry-v2ctl policy validate` and `policy test` don't need the bindings at
all, so on a laptop or a CI runner a plain `pip install sentry-v2` is
enough for those.

## Uninstalling

```console
# systemctl disable --now sentry-v2
# dnf remove sentry-v2 sentry-v2-selinux
```

Stopping the service rolls back every active action. State in
`/var/lib/sentry-v2` (bundles, backups, the action journal) is left behind
for you to keep or delete.

## Next

[Quickstart](quickstart.md): from a fresh install to your first bundle.
