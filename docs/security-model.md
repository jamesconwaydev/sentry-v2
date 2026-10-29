# Security model

What you can and can't expect from Sentry-v2 in terms of security, and the
case for why those expectations hold. The mechanisms themselves are
described in [Hardening and SELinux](hardening.md) and
[Actions and safety](actions-and-safety.md); this page ties them together.

## What you can expect

- **It changes nothing until you say so.** The daemon and every shipped
  policy start in dry-run. An action is enforced only when `daemon.mode`
  and the policy's `mode` are both `enforce`.
- **What it changes, it puts back.** Throttles and freezes have an expiry
  and are written to disk, with the values to restore, before systemd is
  touched. They're rolled back at expiry, on stop, and after a crash, even
  if the daemon can't start again (`ExecStopPost=sentry-v2
  --rollback-only`). Throttles are runtime-only, so a reboot clears them
  regardless.
- **Some things are never touched.** SSH, journald, D-Bus, logind,
  auditd, systemd's own services, the top-level slices, login sessions and
  Sentry-v2 itself are protected, plus anything you add. It never restarts,
  stops or kills a service, and never changes SELinux policy or booleans.
- **It runs with as little as it can.** Root, but with one capability
  (`CAP_AUDIT_READ`), `NoNewPrivileges`, a systemd sandbox and its own
  SELinux domain, `sentry_v2_t`.
- **Only the people you choose can talk to it.** The control socket checks
  every caller's uid and groups. Members of `sentry-v2` can read; only
  members of both `sentry-v2` and `sentry-v2-admin` (or root) can change
  anything, and each change is logged with the caller.
- **Network output is protected in transit.** HTTPS sinks verify the
  server certificate and require TLS 1.2 or later; plain `http://` URLs
  are rejected. Webhook bundles are signed with HMAC-SHA256. Secrets can
  come from files or systemd credentials, separate from the configuration.
- **Bundles are redacted before they leave the daemon,** for the common
  shapes of password flags, URL credentials, `Authorization` headers,
  JSON-quoted secrets, Digest and JWTs.
- **The release you download is the one that was built.** RPMs, wheel and
  sdist come with `SHA256SUMS` and GitHub build-provenance attestations;
  tags are signed; PyPI publishing uses trusted publishing.

## What you can't expect

- **Protection from root.** Anyone who is root on the host can change
  Sentry-v2's configuration, stop it, or use systemd directly.
- **Containment of a compromised daemon.** `sentry_v2_t` can reach root
  through systemd, because remediation needs those grants (see
  [What the module doesn't stop](hardening.md#what-the-module-doesnt-stop)).
  Guard what reaches the daemon: `/etc/sentry-v2`, membership of
  `sentry-v2-admin`, and the hosts its sinks talk to.
- **Perfect redaction.** Redaction is pattern-based. A secret in a shape no
  pattern knows will reach the bundle. `sentry-v2ctl redact` shows what a
  given text would look like; see [Bundles](bundles.md#redaction) for the
  known gaps.
- **Proof of cause.** A linked SELinux denial is evidence with stated
  reasons, not a verdict; see [Correlation](correlation.md).
- **Every denial, under any load.** The kernel can drop audit records in a
  storm, and USER_AVC records over 1000 bytes are dropped. Both are
  counted in `sentry-v2ctl status`.
- **Encryption for syslog over UDP or TCP.** Use `transport = "tls"` when
  syslog crosses an untrusted network. The default is UDP, for
  compatibility with the usual local rsyslog.
- **Authentication on the metrics endpoint.** It's off by default and binds
  to localhost when on; anyone who can reach it can read the metrics.

## Assurance case

### Threat model

| Actor | What they can do | What they're after |
|---|---|---|
| An unprivileged local user or service | Write to the journal; trigger SELinux denials; send USER_AVC records if it has `CAP_AUDIT_WRITE`; consume memory, CPU and I/O | Get Sentry-v2 to act against a service it shouldn't, crash or stall the daemon, or smuggle a secret or misleading text into a bundle |
| A member of `sentry-v2` | Read status, incidents and bundles | Read diagnostic data, which can include command lines and journal text |
| A member of `sentry-v2-admin` and `sentry-v2` | Roll back, pause, resume, reload, restore backups | Is trusted to operate it; every change is logged |
| A network attacker between the host and a sink | See or alter traffic | Read bundles, forge or replay deliveries |
| A sink endpoint | Receive bundles; answer with any status | Learn host details; stall delivery |
| Someone attacking the supply chain | Tamper with dependencies, CI or release artifacts | Ship a modified Sentry-v2 |

Root on the host is out of scope: it can do anything Sentry-v2 can.

### Trust boundaries

```text
            untrusted text                            trusted
  journal ──────────────┐                     /etc/sentry-v2 (root-owned)
  audit (AVC, USER_AVC) ┼──▶ collectors ──▶ correlator ──▶ policy ──▶ executor ──▶ systemd (D-Bus)
  cgroup pressure ──────┘     parse, bound,                          limits, protection,
                              count drops                            journal before acting
                                                   │
  control socket clients ──(uid/gid check)──▶ commands         bundles ──(redact)──▶ sinks ──(TLS, HMAC)──▶ network
  Cockpit (as the logged-in user) ──────────────┘
```

1. **Kernel and journal input into the collectors.** Journal messages and
   USER_AVC text are written by arbitrary processes. Everything crossing
   here is parsed defensively, size-bounded and fuzzed.
2. **Control socket.** Clients are other local users. Every request is
   checked against the caller's uid and groups, rate- and size-limited.
3. **Daemon to systemd.** The only path to changing a unit. Actions pass
   the protection list, the limits, the flap guard and the circuit breaker
   first.
4. **Daemon to the network.** Bundles are redacted before they cross;
   HTTPS sinks verify certificates; webhooks are signed.
5. **Source to release.** Changes reach `main` only through pull requests
   with required checks; releases are built in CI, attested and published
   without stored PyPI tokens.

### Secure design principles applied

- **Least privilege:** one capability, a sandboxed unit, a dedicated
  SELinux domain, two groups for read and change.
- **Fail-safe defaults:** dry-run everywhere; slices off limits unless
  `protection.allow_slices`; HTTPS-only for HTTP sinks; certificate
  verification on; the metrics endpoint off.
- **Complete mediation:** every control-socket request is checked, not
  just the connection.
- **Separation of privilege:** enforcing needs two switches; changing
  anything over the socket needs two groups.
- **Economy of mechanism:** the daemon uses the Python standard library and
  two distro bindings only; no shell and no subprocesses; no pickle or
  YAML parsing.
- **Open design:** every mechanism is documented and the source is public;
  nothing relies on being hidden.
- **Recoverability:** actions are journalled before they're applied and
  undone on stop, crash and expiry.

### Common weaknesses and how they're countered

| Weakness | Countermeasure |
|---|---|
| Improper input validation (CWE-20) | Audit, netlink, journal and pressure parsers return or raise only what their callers handle; property-based fuzz tests enforce this (`tests/unit/test_fuzz.py`). Record, line and request sizes are bounded. |
| OS command injection (CWE-78) | The daemon starts no processes and runs no shell. Units are changed through typed D-Bus calls. |
| Path traversal and links (CWE-22, CWE-59) | `restore` writes only under `/etc/systemd/system` and `/run/systemd/system` and refuses changed files elsewhere. Below those roots it never follows a symlink, whether the directory exists or it creates it. |
| Uncontrolled resource consumption (CWE-400) | Bounded event and audit queues with counted drops; per-user and total connection limits on the socket; idle timeouts; action limits, flap guard and circuit breaker. |
| Sensitive information in output (CWE-532, CWE-200) | Redaction before any sink, the file sink included; secrets read from files or systemd credentials, never logged. |
| Improper certificate validation (CWE-295) | System trust store or `ca_file`, TLS 1.2 minimum, hostname checks on. |
| Broken or risky cryptography (CWE-327) | Only standard-library HMAC-SHA256 and TLS; no home-made cryptography. |
| Race conditions in remediation (CWE-362) | One lock around action state; records fsynced before systemd is called; rollback is idempotent and replayed on start. |
| Incorrect default permissions (CWE-276) | The socket is created under a restrictive umask, then given its group and mode. State directories are `0700` and `0750`. |
| Supply-chain compromise | Actions pinned by SHA and Python tools by hash in CI; signed tags; build provenance; CodeQL and OpenSSF Scorecard on every push. |

### How it's checked

- Unit tests (90% line coverage minimum) and fuzz tests on every pull
  request; CodeQL on every push.
- An integration suite on a Rocky Linux 10 host with SELinux enforcing,
  including a check that the daemon itself causes no SELinux denials.
- Reproducible demonstrations in [`examples/demo/`](../examples/demo).

Report a vulnerability privately, as described in
[SECURITY.md](../SECURITY.md).
