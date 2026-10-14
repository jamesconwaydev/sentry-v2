# Security policy

Sentry-v2 runs as root on your servers, so we take reports seriously and would rather hear about a problem privately than read about it in an issue.

## Supported versions

| Version | Supported |
| ------- | --------- |
| 0.1.x   | Yes       |

Once a newer minor version ships, we'll fix security problems in the latest release only, and say so here.

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting: <https://github.com/jamesconwaydev/sentry-v2/security/advisories/new>.

Don't open a public issue or discussion. Include what you found, the version, how to reproduce it, and what an attacker gains. A rough proof of concept is plenty.

## What counts

Because the daemon is privileged, these are squarely in scope:

- Privilege escalation through the daemon, its control socket or its files.
- Escapes from the systemd sandbox or the shipped SELinux policy.
- Authentication or authorisation bypass on the control socket.
- Secrets leaking into diagnostic bundles, logs or sink payloads.
- Forged or replayable webhook signatures.
- Ways to make Sentry-v2 throttle or freeze a protected unit.

Bugs that need root on the host already, or a policy file the administrator wrote on purpose, are usually not vulnerabilities. If you're unsure, report it anyway and we'll tell you.

## What to expect

This is a one-person project, so these are goals and not promises. We aim to acknowledge a report within a week, tell you whether we agree it's a vulnerability within two weeks, and ship a fix for confirmed issues within 90 days. We'll credit you in the advisory unless you'd rather we didn't.
