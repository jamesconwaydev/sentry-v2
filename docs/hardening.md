# Hardening and SELinux

Sentry-v2 runs as root because it has to: it registers PSI triggers on
root-owned cgroup files, joins the audit stream, writes unit files back on
a restore and asks systemd to change units. What it doesn't need, the unit
takes away, down to a single capability.

Check the result on your host with:

```console
$ systemd-analyze security sentry-v2.service
```

## Capabilities

```ini
CapabilityBoundingSet=CAP_AUDIT_READ
NoNewPrivileges=yes
```

`CAP_AUDIT_READ` lets the daemon join the audit netlink multicast group,
where SELinux denials arrive. Without it the daemon falls back to polling
`/var/log/audit/audit.log`, which works but adds most of a second of
delay to each denial.

Root without `CAP_DAC_OVERRIDE` or `CAP_DAC_READ_SEARCH` still owns the
files it touches: the journal, unit files and drop-ins, the cgroup tree,
`/var/lib/sentry-v2`. The `/proc/<pid>/cgroup` and `/proc/<pid>/status`
entries it reads are world-readable, so it doesn't need `CAP_SYS_PTRACE`
either.

### How the set was chosen

The unit started with three capabilities. The integration suite
(`make itest`, see [development.md](development.md#integration-tests-on-a-rocky-host))
was run on Rocky Linux 10.2 with the SELinux module enforcing, dropping
each capability in turn through a drop-in:

| Bounding set | Result | Verdict |
|---|---|---|
| `CAP_AUDIT_READ CAP_SYS_PTRACE CAP_DAC_READ_SEARCH` | 28 passed | Starting point. |
| `CAP_AUDIT_READ CAP_DAC_READ_SEARCH` | 28 passed | `CAP_SYS_PTRACE` isn't needed. |
| `CAP_AUDIT_READ CAP_SYS_PTRACE` | 28 passed | `CAP_DAC_READ_SEARCH` isn't needed. |
| `CAP_SYS_PTRACE CAP_DAC_READ_SEARCH` | 27 passed, 1 failed | `CAP_AUDIT_READ` is needed: the audit collector logged `audit netlink unavailable ([Errno 1] Operation not permitted)` and fell back to the log file, so `test_audit_collector_uses_netlink` failed. Correlation still worked through the fallback. |
| `CAP_AUDIT_READ` | 28 passed | Shipped. |

What the smaller set gives up: a `backup_reload` `paths` entry that root
doesn't own and can't read by mode, such as a `0600` file owned by a
service account, fails to back up with `Permission denied`, and a PSI
trigger on a cgroup delegated to another user can't be registered. Neither
case is in the suite. If you need one, add the capability back with a
drop-in:

```ini
# /etc/systemd/system/sentry-v2.service.d/caps.conf
[Service]
CapabilityBoundingSet=CAP_DAC_READ_SEARCH
```

Assignments add up, so this keeps `CAP_AUDIT_READ`. The SELinux module
doesn't allow `dac_read_search` either, so on an SELinux host you need a
local module for it too.

Everything else is dropped, including `CAP_SYS_ADMIN`, `CAP_NET_ADMIN`
and `CAP_SYS_RESOURCE`. The last one is why PSI trigger windows must be a
multiple of 2 s; see [policies.md](policies.md#the-threshold-rules).

Changes to units go through systemd over D-Bus, so the daemon never writes
cgroup limits itself. The one cgroup write it makes is registering PSI
triggers on `*.pressure` files.

## The unit's sandbox

| Setting | Value | Why |
|---|---|---|
| `Type` | `notify-reload` | The daemon tells systemd when it's ready, only after crash replay and every component are running. `systemctl reload` sends `SIGHUP`, and the daemon reports `RELOADING=1` and `READY=1` around the reload, so `systemctl reload` waits for it to finish. |
| `WatchdogSec` | `30s` | The event loop pings the watchdog itself, so a hung loop gets the daemon restarted. |
| `Restart` | `on-failure` | A crash comes back after `RestartSec=5s`, and replay undoes anything left in force. |
| `RestartPreventExitStatus` | `2` | The daemon exits 2 when it can't load its configuration. Restarting won't fix that, so systemd leaves it failed instead of looping. |
| `TimeoutStopSec` | `780s` | Room to roll back five stuck actions on stop. See [actions-and-safety.md](actions-and-safety.md#how-long-a-stop-can-take). |
| `TimeoutStartSec` | `780s` | Start replays the journal first, and rolling back what a crash left behind can take as long as a stop. While replay runs the daemon sends `EXTEND_TIMEOUT_USEC` every 30 s, so systemd waits for it either way; this is the backstop. |
| `ProtectSystem` | `strict` | The whole filesystem is read-only to the daemon... |
| `ReadWritePaths` | `/var/lib/sentry-v2 /sys/fs/cgroup -/etc/systemd/system -/run/systemd/system` | ...apart from its state, the cgroup tree where PSI triggers are registered, and the two unit directories `sentry-v2ctl restore` writes back to. |
| `StateDirectory` | `sentry-v2`, mode `0700` | The action journal, bundles, spool and backups. |
| `RuntimeDirectory` | `sentry-v2`, mode `0750` | Holds the control socket. |
| `ConfigurationDirectory` | `sentry-v2` | `/etc/sentry-v2`. |
| `Group` | `sentry-v2` | systemd gives the runtime directory to this group, which is how group members reach the socket. |
| `UMask` | `0077` | Files the daemon creates are private by default. |
| `ProtectHome` | `yes` | Home directories are invisible. |
| `PrivateTmp` | `yes` | Its own `/tmp`. |
| `PrivateDevices` | `yes` | No access to physical devices. |
| `ProtectKernelModules`, `ProtectKernelLogs`, `ProtectClock`, `ProtectHostname` | `yes` | It never needs to touch any of these. |
| `RestrictAddressFamilies` | `AF_UNIX AF_NETLINK AF_INET AF_INET6` | Unix sockets for D-Bus, the journal and the control socket; netlink for audit; IP for sinks and metrics. |
| `RestrictNamespaces`, `RestrictRealtime`, `RestrictSUIDSGID`, `LockPersonality` | `yes` | Closes off features it doesn't use. |
| `MemoryDenyWriteExecute` | `yes` | No writable and executable memory. CPython doesn't need it. |
| `SystemCallArchitectures` | `native` | No 32-bit syscall entry points. |
| `SystemCallFilter` | `@system-service` | The standard allow list for services, with `EPERM` for anything else. |
| `Slice` | `system.slice` | Runs where it can be seen and managed like any service. |
| `MemoryMin` / `MemoryMax` | `48M` / `192M` | Protected from reclaim when the host is under the memory pressure it's there to fix, and capped if it ever misbehaves. |
| `OOMScoreAdjust` | `-900` | The OOM killer picks almost anything else first. |
| `CPUWeight` | `1000` | Gets CPU promptly when the host is starved. |

### Deliberately left off

| Setting | Why it isn't set |
|---|---|
| `User=` / `DynamicUser=` | PSI triggers are written to root-owned cgroup files, restores write root-owned unit files, and systemd only lets root change units without a polkit prompt. The bounding set above limits what root can do instead. |
| `ProtectControlGroups=` | It would make `/sys/fs/cgroup` read-only, and PSI triggers are registered by writing to it. |
| `PrivateNetwork=` | Sinks talk to remote hosts. |

## Socket permissions

The control socket is `/run/sentry-v2/control.sock`, mode `0660`, owner
`root:sentry-v2`, inside `/run/sentry-v2` (mode `0750`, group `sentry-v2`).
The daemon creates the socket with a restrictive umask, so it never exists
with looser permissions, then sets the group and mode. For each request it
checks the caller's uid and groups (from `SO_PEERCRED` and the kernel's
peer group list):

| Caller | Can |
|---|---|
| root | Everything. |
| Member of `sentry-v2` | Read: `status`, `psi`, `incidents`, `show`, `actions`, `policies`, `subscribe`. |
| Member of `sentry-v2` and `sentry-v2-admin` | Also change things: `rollback`, `pause`, `resume`, `reload`, `restore`. |
| Anyone else | Nothing; the directory keeps them out. |

Membership of `sentry-v2-admin` alone would pass the daemon's check, but
the socket's group and the directory keep a non-member of `sentry-v2` out,
so admins need both groups. If `control.group` names a group that doesn't
exist, the socket falls back to the admin group, and with neither group it
is `0600`, root only.

Every change made through the socket is logged with the caller, for example
`control: uid 1000 pid 4242 ran rollback {'all': True}`.

To stop one user from tying up the socket, callers that aren't root or in
the admin group are limited to 8 connections each and 32 between them;
extra connections get `too many connections`. Idle connections close
after 5 minutes, and a request line can be at most 64 KiB.

The RPM creates both groups. Bundles can contain journal lines and command
lines, so treat `sentry-v2` membership as read access to diagnostic data.

## SELinux

The `sentry-v2-selinux` subpackage installs the `sentry_v2` policy module:

| Type | For |
|---|---|
| `sentry_v2_t` | The daemon's domain. |
| `sentry_v2_exec_t` | `/usr/bin/sentry-v2` |
| `sentry_v2_conf_t` | `/etc/sentry-v2(/.*)?` |
| `sentry_v2_var_lib_t` | `/var/lib/sentry-v2(/.*)?` |
| `sentry_v2_var_run_t` | `/run/sentry-v2(/.*)?` |
| `sentry_v2_unit_file_t` | `/usr/lib/systemd/system/sentry-v2.service` |
| `sentry_v2_metrics_port_t` | TCP 9787, labelled with `semanage` when the package installs. |

### Enforcing

The `sentry_v2_t` domain is enforcing. The integration suite runs with the
module loaded and fails on any AVC or USER_AVC for the domain, and every
rule in `sentry_v2.te` names the part of the daemon, and where one
exists the test, that needs it.

Check that the daemon is in its domain:

```console
$ ps -eZ | grep sentry_v2_t
system_u:system_r:sentry_v2_t:s0   1234 ?        00:00:03 sentry-v2
```

Two things the policy allows that are worth knowing:

- Unit control covers every unit. For file-backed units the module lets the
  daemon start (`SetUnitProperties` is checked as start), stop (freeze and
  thaw) and reload. Transient units, such as `systemd-run` services and
  scopes, have no unit file, so systemd checks them against its own context.
  The module grants `init_t:system { start stop }` so they can be throttled
  and frozen, but not reload, so `backup_reload` on a transient unit is
  refused. Which units the daemon actually touches is decided by your
  policies and the protected list, not by SELinux.
- Restore can write any unit file. `sentry-v2ctl restore` writes files back
  under `/etc/systemd/system` and `/run/systemd/system`, so the module allows
  managing unit files. The unit's `ReadWritePaths=` keeps that to those two
  directories.

### What the module doesn't stop

The module confines files, sockets and capabilities: a compromised daemon
can't read home directories, connect to arbitrary ports or load kernel
modules. It can't stop the daemon reaching root through systemd, because
the remediation itself needs the grants that make that possible. With
`init_t:system start` it can ask systemd for a transient unit
(`StartTransientUnit`) that runs any command as root, outside
`sentry_v2_t`. With the unit-file rules it can write a unit under
`/etc/systemd/system` and then start it. Moving restore elsewhere wouldn't
close this, since the transient-unit path remains.

So treat `sentry_v2_t` as a domain that can become root, and guard what
reaches it: the configuration in `/etc/sentry-v2`, membership of
`sentry-v2-admin`, and the hosts its sinks talk to. What SELinux adds is
that anything outside the daemon's normal file and network access is
refused and logged as a denial.

Sink secrets given as systemd credentials (`LoadCredential=`, see
[configuration.md](configuration.md)) were checked once by hand, enforcing:
a webhook `hmac_key_file` loaded from `/run/credentials`, and the webhook
connecting out to port 8443. The rule that allows this,
`init_read_pid_files`, is wider than credentials: it lets the daemon read
every `init_var_run_t` file, which includes much of `/run/systemd`. File
modes still apply, so it can only read what root can read without a DAC
override. The automated suite doesn't reach the outbound
sinks (webhook, syslog, Splunk HEC, Elasticsearch); their rules are written
from the ports they use. If a sink fails with a permission
error, look for a denial; see
[troubleshooting.md](troubleshooting.md#selinux-denials-from-sentry_v2_t).

### Sinks on other ports

The module lets the daemon connect to HTTPS ports (`http_port_t`: 80, 443,
8443 and a few more), Elasticsearch's 9200, syslog's 514/udp, 601 and 6514,
and any port nobody has labelled in 1024–32767 or 61000–65535. A sink on a
port that already has another label is denied: 8080 is `http_cache_port_t`,
and 514/tcp is `rsh_port_t`. Check a port with:

```console
# semanage port -l | grep -w 8080
http_cache_port_t              tcp      8080, 8118, 8123, 10001-10010
```

A port with no label can be given one the daemon may use:

```console
# semanage port -a -t http_port_t -p tcp 40443
```

For a port the base policy already labels, `semanage port -a` fails with
`already defined`, and `semanage port -m` would relabel it for every other
service as well. Allow the daemon that one type with a small local module
instead:

```text
# sentry_v2_local.te
module sentry_v2_local 1.0;
require { type sentry_v2_t; type http_cache_port_t; class tcp_socket name_connect; }
allow sentry_v2_t http_cache_port_t:tcp_socket name_connect;
```

```console
# checkmodule -M -m -o sentry_v2_local.mod sentry_v2_local.te
# semodule_package -o sentry_v2_local.pp -m sentry_v2_local.mod
# semodule -i sentry_v2_local.pp
```

### Using another metrics port

```console
# semanage port -a -t sentry_v2_metrics_port_t -p tcp 9900
```
