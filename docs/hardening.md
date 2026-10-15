# Hardening and SELinux

Sentry-v2 runs as root because it has to: it reads every service's `/proc`
entries, joins the audit stream and asks systemd to change units. What it
doesn't need, the unit takes away.

Check the result on your host with:

```console
$ systemd-analyze security sentry-v2.service
```

## Capabilities

```ini
CapabilityBoundingSet=CAP_AUDIT_READ CAP_SYS_PTRACE CAP_DAC_READ_SEARCH
NoNewPrivileges=yes
```

| Capability | Why |
|---|---|
| `CAP_AUDIT_READ` | Joining the audit netlink multicast group, where SELinux denials arrive. Without it the daemon falls back to reading `/var/log/audit/audit.log`. |
| `CAP_SYS_PTRACE` | Reading `/proc/<pid>/cgroup` and similar entries of processes owned by other services, to attribute a denial to a unit. |
| `CAP_DAC_READ_SEARCH` | Reading unit drop-ins, journals and backed-up files whatever their mode. |

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
| `TimeoutStopSec` | `780s` | Room to roll back five stuck actions on stop. See [actions-and-safety.md](actions-and-safety.md#how-long-a-stop-can-take). |
| `ProtectSystem` | `strict` | The whole filesystem is read-only to the daemon... |
| `ReadWritePaths` | `/var/lib/sentry-v2 /sys/fs/cgroup` | ...apart from its state and the cgroup tree, where PSI triggers are registered. |
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
| `User=` / `DynamicUser=` | The audit stream, other services' `/proc` entries and systemd's unit-control calls all need root. The bounding set above limits what root can do instead. |
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

### Current status: permissive

The `sentry_v2_t` domain is declared permissive in this release. Denials
are logged and nothing is blocked, while the policy is proven against the
integration suite on EL10. Expect it to switch to enforcing in a later
release; the changelog will say when.

Check that the daemon is in its domain:

```console
$ ps -eZ | grep sentry_v2_t
system_u:system_r:sentry_v2_t:s0   1234 ?        00:00:03 sentry-v2
```

If you see denials for `sentry_v2_t`, please report them; see
[troubleshooting.md](troubleshooting.md#selinux-denials-from-sentry_v2_t).

### Using another metrics port

```console
# semanage port -a -t sentry_v2_metrics_port_t -p tcp 9900
```
