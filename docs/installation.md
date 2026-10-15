# Installing Sentry-v2

Sentry-v2 runs on EL10: Rocky Linux 10, AlmaLinux 10, RHEL 10 and CentOS
Stream 10. It needs cgroup v2 (the EL10 default), SELinux in any mode, and
packages from BaseOS and AppStream only. No EPEL.

## From the RPM (recommended)

Download the packages for the latest release from
[GitHub Releases](https://github.com/jamesconwaydev/sentry-v2/releases).
The first tagged release is on its way; until then, build the RPMs from
source (see [From source](#from-source)) and install them the same way.

| Package | What it is |
|---|---|
| `sentry-v2-<version>.noarch.rpm` | The daemon, `sentry-v2ctl`, the unit and the example configuration. |
| `sentry-v2-selinux-<version>.noarch.rpm` | The `sentry_v2` SELinux policy module. Recommended on any host running SELinux. |
| `sentry-v2-cockpit-<version>.noarch.rpm` | Optional. The Cockpit page; see [cockpit.md](cockpit.md). |

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

If that prints `No such file or directory`, turn it on and reboot. The
guard skips both steps on a host that already has PSI:

```console
# test -e /proc/pressure/memory || { grubby --update-kernel=ALL --args=psi=1 && reboot; }
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

On an EL10 box, install the build tools (`pyproject-rpm-macros` is in
CRB), then build:

```console
# dnf install --enablerepo=crb git make rpm-build python3-devel pyproject-rpm-macros \
    systemd-rpm-macros selinux-policy-devel bzip2 python3-setuptools python3-wheel
$ git clone https://github.com/jamesconwaydev/sentry-v2.git
$ cd sentry-v2
$ make rpm
$ ls rpmbuild/RPMS/noarch/
sentry-v2-0.1.0-1.el10.noarch.rpm  sentry-v2-cockpit-0.1.0-1.el10.noarch.rpm  sentry-v2-selinux-0.1.0-1.el10.noarch.rpm
# dnf install ./rpmbuild/RPMS/noarch/sentry-v2-0.1.0-*.noarch.rpm \
    ./rpmbuild/RPMS/noarch/sentry-v2-selinux-0.1.0-*.noarch.rpm
```

The exact dist tag in the file names depends on your EL10 minor release.
On a machine without `rpmbuild`, `make rpm` builds in a `rockylinux:10`
container with Podman instead (set `CONTAINER=docker` to use Docker).

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
