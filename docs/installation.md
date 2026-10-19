# Installing Sentry-v2

Sentry-v2 runs on EL10: Rocky Linux 10, AlmaLinux 10, RHEL 10 and CentOS
Stream 10. It needs cgroup v2 (the EL10 default), SELinux in any mode, and
packages from BaseOS and AppStream only. No EPEL.

## From the RPM (recommended)

Download the RPMs from the
[v0.2.0 release](https://github.com/jamesconwaydev/sentry-v2/releases/tag/v0.2.0)
and check them against `SHA256SUMS` before you install:

```console
$ sha256sum -c SHA256SUMS --ignore-missing
```

Every file also carries build provenance. If you have the `gh` CLI, confirm
a download came from this repository's release workflow:

```console
$ gh attestation verify <file> --repo jamesconwaydev/sentry-v2
```

Prefer to build it yourself? See [From source](#from-source).

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
# dnf install ./sentry-v2-0.2.0-*.noarch.rpm ./sentry-v2-selinux-0.2.0-*.noarch.rpm
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
sentry-v2-0.2.0-1.el10.noarch.rpm  sentry-v2-cockpit-0.2.0-1.el10.noarch.rpm  sentry-v2-selinux-0.2.0-1.el10.noarch.rpm
# dnf install ./rpmbuild/RPMS/noarch/sentry-v2-0.2.0-*.noarch.rpm \
    ./rpmbuild/RPMS/noarch/sentry-v2-selinux-0.2.0-*.noarch.rpm
```

The exact dist tag in the file names depends on your EL10 minor release.
On a machine without `rpmbuild`, `make rpm` builds in a `rockylinux:10`
container with Podman instead (set `CONTAINER=docker` to use Docker).

## From PyPI

Sentry-v2 is on PyPI as [`sentry-v2`](https://pypi.org/project/sentry-v2/).
On EL10 the RPM is still the one to use. It brings the unit file, the
sysusers and tmpfiles entries, the SELinux module and the Cockpit page, and
pip brings none of them.

pip earns its place in three spots: development, CI policy checks, and your
own packaging. `sentry-v2ctl policy validate` and `sentry-v2ctl policy test`
work anywhere, with no daemon and no root.

The daemon imports `systemd` and `dbus`, and pip can't install those, so
take them from the distro first:

```console
# dnf install python3-systemd python3-dbus
# python3 -m venv --system-site-packages /opt/sentry-v2 && /opt/sentry-v2/bin/pip install sentry-v2
```

Both `sentry-v2` and `sentry-v2ctl` land in `/opt/sentry-v2/bin`. To run the
daemon from a pip install you supply the unit file, the groups, the runtime
directory and the SELinux module yourself. The files to start from are in
[`packaging/`](https://github.com/jamesconwaydev/sentry-v2/tree/main/packaging).

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
