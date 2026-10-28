<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/jamesconwaydev/sentry-v2/main/assets/header-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/jamesconwaydev/sentry-v2/main/assets/header-light.svg">
  <img alt="Sentry-v2: a pressure trace climbs past a trigger line, the noisy unit is throttled, pressure falls away, and the throttle is rolled back when it expires." src="https://raw.githubusercontent.com/jamesconwaydev/sentry-v2/main/assets/header-light.svg" width="100%">
</picture>

[![CI](https://img.shields.io/github/actions/workflow/status/jamesconwaydev/sentry-v2/ci.yml?branch=main&label=CI)](https://github.com/jamesconwaydev/sentry-v2/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/jamesconwaydev/sentry-v2?sort=semver)](https://github.com/jamesconwaydev/sentry-v2/releases)
[![PyPI](https://img.shields.io/pypi/v/sentry-v2)](https://pypi.org/project/sentry-v2/)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)](https://github.com/jamesconwaydev/sentry-v2/blob/main/LICENSE)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/jamesconwaydev/sentry-v2/badge)](https://securityscorecards.dev/viewer/?uri=github.com/jamesconwaydev/sentry-v2)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/15751/badge)](https://www.bestpractices.dev/projects/15751)
[![Discussions](https://img.shields.io/github/discussions/jamesconwaydev/sentry-v2)](https://github.com/jamesconwaydev/sentry-v2/discussions)

When a service dies on an EL10 box, the reason is usually already on the
host. It's just in three places. The journal has the failure, the audit log
has the AVC denials, and `/proc/pressure` knows the box was short on memory
at the time. Sentry-v2 reads all three as they happen, ties each unit
failure to the denials that actually belong to it, and writes the lot up as
one redacted JSON bundle.

If you let it, it'll also throttle or freeze the job that's crowding
everyone else out, and put it back when the time's up. It won't do that
until you've switched it on twice: once for the daemon, once for the
policy.

![Sentry-v2 running its demo on a Rocky Linux 10 test VM: two services are denied the same file, one dies, its denial is linked at 0.976 and the other is left out, and a memory hog gets a dry-run throttle.](https://raw.githubusercontent.com/jamesconwaydev/sentry-v2/main/assets/demo.gif)

That's [`examples/demo/run.sh`](https://github.com/jamesconwaydev/sentry-v2/tree/main/examples/demo)
on Rocky Linux 10 with SELinux enforcing. Two services are denied the same
file in the same second, and one of them dies. Sentry-v2 links the dead one
to its own denial at 0.976, because the PID was in the unit's cgroup, the
domain is the unit's and the binary matches `ExecStart`. The other denial
stays out of the bundle. Here's
[the bundle it wrote](https://github.com/jamesconwaydev/sentry-v2/blob/main/examples/demo/incident-unit-failed.json).

## What you get

- **Failures linked to their denials**, scored, with the reasons spelled
  out. A denial from a process in another unit's cgroup isn't counted, even
  when it's the same binary in the same domain.
- **Pressure from PSI triggers**, so the kernel wakes Sentry-v2 the moment
  a cgroup crosses the stall threshold you set.
- **Actions you can take back**: a runtime `MemoryHigh` and `CPUWeight`
  throttle, freeze and thaw, or a backup of the unit's files and a reload.
  Every action is written to disk before systemd sees it. Throttles and
  freezes expire on their own, and roll back on stop and after a crash.
- **Bundles where you already look**: on disk, an HMAC-signed webhook,
  RFC 5424 syslog, Splunk HEC or Elasticsearch.
- **Packaged for EL10**: an RPM with a hardened unit, its own enforcing
  SELinux domain, `sentry-v2ctl`, a Cockpit page and an optional
  Prometheus endpoint. Nothing at runtime comes from outside BaseOS and
  AppStream.

## Install

Rocky Linux, AlmaLinux, RHEL or CentOS Stream 10. Grab the RPMs from the
[latest release](https://github.com/jamesconwaydev/sentry-v2/releases/latest),
check them, and install:

```console
$ sha256sum -c SHA256SUMS --ignore-missing
$ gh attestation verify sentry-v2-0.2.6-1.el10.noarch.rpm --repo jamesconwaydev/sentry-v2
# dnf install ./sentry-v2-0.2.6-*.noarch.rpm ./sentry-v2-selinux-0.2.6-*.noarch.rpm
```

EL kernels ship with PSI off. This turns it on, and only reboots a host
that doesn't have it yet:

```console
# test -e /proc/pressure/memory || { grubby --update-kernel=ALL --args=psi=1 && reboot; }
```

Only want to check policies in CI? `pip install sentry-v2` gets you
`sentry-v2ctl policy validate` without the daemon.

## Quick start

The RPM drops three example policies in `/etc/sentry-v2/policies.d`, all in
dry-run. Copy one, check it, start the daemon:

```console
# cd /etc/sentry-v2/policies.d
# cp 20-unit-failure-notify.toml 50-myapp.toml
# sed -i 's/^name = .*/name = "myapp-notify"/' 50-myapp.toml
# sentry-v2ctl policy validate
ok: 4 policies
# systemctl enable --now sentry-v2
# sentry-v2ctl status
sentry-v2 0.2.6  running for 3s  mode dry-run

COLLECTOR  HEALTH
psi        state=ok, triggers=0, restarts=0, last_error=None
journal    state=ok, restarts=0, last_error=None
audit      source=netlink, user_avc_truncated=0, overruns=0, rcvbuf=425984, restarts=0, last_error=None
```

Then break something on purpose and read what it wrote. The
[quickstart](https://github.com/jamesconwaydev/sentry-v2/blob/main/docs/quickstart.md)
walks you through it.

## What it won't do

It never restarts, stops or kills a service, and it never touches SELinux
policy or booleans. `audit2allow` is still your call. SSH, journald,
D-Bus, logind, auditd, your login sessions and Sentry-v2 itself are
protected, and so are whole slices unless you say otherwise. A unit that
needs three actions in half an hour is put on hold until a person looks
at it. And in dry-run, where it starts, it changes nothing at all.

The full rules are in
[Actions and safety](https://github.com/jamesconwaydev/sentry-v2/blob/main/docs/actions-and-safety.md),
and where the scoring can mislead you is in
[the FAQ](https://github.com/jamesconwaydev/sentry-v2/blob/main/docs/faq.md#what-happens-when-it-gets-it-wrong).

## Documentation

Everything else, from every config key to the bundle schema, is in
[docs/](https://github.com/jamesconwaydev/sentry-v2/blob/main/docs/README.md).
For recipes that start from a problem on your host, like tying a dying
service to its denials or throttling a batch job that starves the box, see
the [wiki](https://github.com/jamesconwaydev/sentry-v2/wiki).

## Contributing

Questions and ideas go in
[Discussions](https://github.com/jamesconwaydev/sentry-v2/discussions). If
you'd like to write some code, the
[good first issues](https://github.com/jamesconwaydev/sentry-v2/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22)
each name the file, the test and when it's done, and none of them needs
root or a test VM. [CONTRIBUTING.md](https://github.com/jamesconwaydev/sentry-v2/blob/main/CONTRIBUTING.md)
has the rest.

## License

[Apache-2.0](https://github.com/jamesconwaydev/sentry-v2/blob/main/LICENSE).
Maintained by James Conway ([@jamesconwaydev](https://github.com/jamesconwaydev));
how decisions get made is in
[GOVERNANCE.md](https://github.com/jamesconwaydev/sentry-v2/blob/main/GOVERNANCE.md).
