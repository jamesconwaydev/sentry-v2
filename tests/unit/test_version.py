import sentry_v2


def test_version_is_semver():
    major, minor, patch = sentry_v2.__version__.split(".")
    assert all(p.isdigit() for p in (major, minor, patch))
