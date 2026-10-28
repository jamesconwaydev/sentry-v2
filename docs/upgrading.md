# Upgrading

Sentry-v2 supports the latest release only, so the upgrade path is to
move to it. Within 0.x, upgrades are a package update: configuration
carries over, and anything that changes behaviour is listed in the
[CHANGELOG](../CHANGELOG.md) under **Changed**.

## From an RPM install

Download the new RPMs from the
[releases page](https://github.com/jamesconwaydev/sentry-v2/releases), check
them as in [Installation](installation.md#from-the-rpm-recommended), then:

```console
# dnf upgrade ./sentry-v2-*.noarch.rpm ./sentry-v2-selinux-*.noarch.rpm
```

Add `./sentry-v2-cockpit-*.noarch.rpm` if you use the Cockpit page.

What happens:

- Your files in `/etc/sentry-v2` are kept. They're marked as
  configuration, so if a new version ships a changed default file, the new
  one is saved next to yours as `.rpmnew` and yours stays in force.
- A running daemon is restarted. Stopping it rolls back every active
  throttle and freeze first, so nothing stays applied across the upgrade.
- The SELinux module is replaced in the same transaction.

Then check the configuration still loads and the daemon is healthy:

```console
# sentry-v2ctl policy validate
# sentry-v2ctl status
```

## From PyPI

```console
# /opt/sentry-v2/bin/pip install --upgrade sentry-v2
# systemctl restart sentry-v2
```

## Before you upgrade

Read the CHANGELOG entries between your version and the new one. Changes
that could need you to act are under **Changed**. For example, 0.2.7 and
0.2.8 refuse some values that used to load, such as relative paths, empty
hosts and empty patterns; in 0.2.4 a throttle's rollback started treating each value
separately; and in 0.2.0 actions on slices began to need
`protection.allow_slices`.

If a new version can't load your configuration, the daemon exits with
status 2 and stays down, and `sentry-v2ctl policy validate` names the file
and key. Throttles and freezes from before the upgrade are rolled back
either way.

## Going back

Downgrading works the same way, with `dnf downgrade` or
`pip install sentry-v2==X.Y.Z`. Configuration written for a newer version
can use keys an older one doesn't know; `policy validate` will say which.
