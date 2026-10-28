from pathlib import Path

import pytest

from sentry_v2.config import ConfigError, load_config
from sentry_v2.policy import (
    AvcWhen,
    BackupReload,
    Freeze,
    Notify,
    PsiWhen,
    Throttle,
    UnitFailedWhen,
)
from sentry_v2.units import Percent

FIXTURES = Path(__file__).parent.parent / "fixtures" / "config"


def write(tmp_path: Path, name: str, text: str) -> Path:
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


def load(tmp_path: Path, main: str = "", **policies: str):  # type: ignore[no-untyped-def]
    m = write(tmp_path, "main.toml", main)
    for name, text in policies.items():
        write(tmp_path, f"pol/{name.replace('_', '-')}.toml", text)
    return load_config(m, tmp_path / "pol")


def err(tmp_path: Path, main: str = "", **policies: str) -> str:
    with pytest.raises(ConfigError) as e:
        load(tmp_path, main, **policies)
    return str(e.value)


def policy_text(when: str = "", extra: str = "", do: str = 'action = "notify"') -> str:
    when = when or 'signal = "unit_failed"\nunits = ["batch-*.service"]'
    return f'[[policy]]\nname = "p"\n{extra}\n[policy.when]\n{when}\n[[policy.do]]\n{do}\n'


def test_minimal_defaults() -> None:
    cfg = load_config(FIXTURES / "minimal.toml", FIXTURES / "nope")
    assert cfg.policies == ()
    assert cfg.daemon.mode == "dry-run"
    assert cfg.limits.max_action_duration == 1800.0
    assert cfg.sinks.file.max_age == 30 * 86400 and cfg.sinks.file.max_size == 1024**3
    assert cfg.sinks.webhook is None
    assert cfg.metrics.enabled is False and cfg.metrics.port == 9787
    assert cfg.correlation.avc_burst == 5
    assert cfg.protection.allow_slices is False


def test_full_global_config() -> None:
    cfg = load_config(FIXTURES / "full.toml", FIXTURES / "nope")
    assert cfg.daemon.log_level == "debug" and cfg.daemon.queue_size == 500
    assert cfg.limits.max_action_duration == 600.0
    assert cfg.protection.protected == ("nginx.service",)
    assert cfg.protection.allow_slices is True
    assert cfg.redaction.patterns == (r"secret-\d+",)
    assert cfg.sinks.file.max_age == 7 * 86400 and cfg.sinks.file.max_size == 512 * 1024**2
    assert cfg.sinks.webhook and cfg.sinks.webhook.timeout == 10.0
    assert cfg.sinks.syslog and cfg.sinks.syslog.transport == "tls"
    assert cfg.sinks.splunk_hec and cfg.sinks.splunk_hec.index is None
    assert cfg.sinks.elastic and cfg.sinks.elastic.username == "sentry"
    assert cfg.metrics.enabled and cfg.control.group == "ops"


def test_policies_load() -> None:
    cfg = load_config(FIXTURES / "minimal.toml", FIXTURES / "policies.d")
    names = [p.name for p in cfg.policies]
    assert names == ["memory-hog", "crashloop", "denials"]
    mem, crash, den = cfg.policies
    assert mem.mode == "enforce" and mem.cooldown == 600.0
    assert mem.when == PsiWhen(
        "memory", "full", 300_000, 2_000_000, 10.0, ("system.slice/*.service",)
    )
    assert mem.actions == (Throttle(Percent(80.0), 50, 300.0), Notify())
    assert crash.mode == "dry-run" and crash.cooldown == 300.0
    assert crash.when == UnitFailedWhen(("batch-*.service",), ("watchdog", "timeout"))
    assert crash.actions == (Freeze(120.0, 5.0), BackupReload((Path("/etc/batch"),)))
    assert den.when == AvcWhen(("httpd_t",), 3)


def test_unknown_section(tmp_path: Path) -> None:
    assert err(tmp_path, "[daemn]\nx = 1") == "main.toml: daemn: unknown section"


def test_unknown_key(tmp_path: Path) -> None:
    assert err(tmp_path, "[daemon]\nlevel = 1") == "main.toml: daemon.level: unknown key"


def test_bad_policy_mode(tmp_path: Path) -> None:
    got = err(tmp_path, x=policy_text(extra='mode = "enforcing"'))
    assert got == "x.toml: policy[0].mode: must be 'dry-run' or 'enforce'"


def test_duplicate_policy_names(tmp_path: Path) -> None:
    got = err(tmp_path, **{"10_a": policy_text(), "20_b": policy_text()})
    assert got.startswith("20-b.toml: policy[0].name: duplicate")


def test_throttle_needs_duration(tmp_path: Path) -> None:
    got = err(tmp_path, x=policy_text(do='action = "throttle"\ncpu_weight = 10'))
    assert got == "x.toml: policy[0].do[0].duration: is required"


def test_duration_over_limit(tmp_path: Path) -> None:
    do = 'action = "freeze"\nduration = "2h"'
    assert "at most max_action_duration" in err(tmp_path, x=policy_text(do=do))
    assert "at most" in err(
        tmp_path,
        '[limits]\nmax_action_duration = "1m"',
        x=policy_text(do='action = "freeze"\nduration = "5m"'),
    )


def test_throttle_needs_a_knob(tmp_path: Path) -> None:
    got = err(tmp_path, x=policy_text(do='action = "throttle"\nduration = "1m"'))
    assert got == "x.toml: policy[0].do[0].action: throttle needs memory_high or cpu_weight"


@pytest.mark.parametrize(
    ("when", "key"),
    [
        ('signal = "unit_failed"\nunits = ["sshd.service"]', "units"),
        ('signal = "unit_failed"\nunits = ["systemd-*.service", "sshd.service"]', "units"),
        (
            'signal = "psi"\nresource = "cpu"\nthreshold = "300ms/2s"\ncgroups = ["system.slice/sshd.service"]',
            "cgroups",
        ),
    ],
)
def test_only_protected(tmp_path: Path, when: str, key: str) -> None:
    got = err(tmp_path, x=policy_text(when=when))
    assert got == f"x.toml: policy[0].when.{key}: only matches protected units"


def test_wide_globs_and_extra_protection(tmp_path: Path) -> None:
    ok = 'signal = "unit_failed"\nunits = ["*.service"]'
    assert load(tmp_path, x=policy_text(when=ok)).policies
    bad = 'signal = "unit_failed"\nunits = ["nginx.service"]'
    got = err(tmp_path, '[protection]\nprotected = ["nginx.service"]', x=policy_text(when=bad))
    assert got.endswith("only matches protected units")


def test_inline_secret(tmp_path: Path) -> None:
    got = err(tmp_path, '[sinks.webhook]\nurl = "https://a.example"\ntoken = "abc"')
    assert got == "main.toml: sinks.webhook.token: secrets must be given as token_file"


@pytest.mark.parametrize("window", ["150ms/20s", "150ms/100ms", "3s/2s", "150ms", "x/2s"])
def test_bad_thresholds(tmp_path: Path, window: str) -> None:
    when = f'signal = "psi"\nresource = "io"\nthreshold = "{window}"\ncgroups = ["a.service"]'
    assert err(tmp_path, x=policy_text(when=when)).startswith("x.toml: policy[0].when.threshold:")


@pytest.mark.parametrize("threshold", ["150ms/1s", "300ms/3s", "100ms/500ms"])
def test_window_must_be_a_multiple_of_2s(tmp_path: Path, threshold: str) -> None:
    when = f'signal = "psi"\nresource = "io"\nthreshold = "{threshold}"\ncgroups = ["a.service"]'
    got = err(tmp_path, x=policy_text(when=when))
    assert got == (
        "x.toml: policy[0].when.threshold: window must be a multiple of 2s"
        " (shorter or odd windows need CAP_SYS_RESOURCE)"
    )


@pytest.mark.parametrize(
    ("main", "key"),
    [
        ('[sinks.webhook]\nurl = "http://a.example"', "sinks.webhook.url"),
        ("[sinks.webhook]", "sinks.webhook.url"),
        ('[sinks.webhook]\nurl = "https://a.example"', "sinks.webhook.hmac_key_file"),
        (
            '[sinks.webhook]\nurl = "https://a.example"\nhmac_key_file = "k"',
            "sinks.webhook.hmac_key_file",
        ),
        (
            '[sinks.webhook]\nurl = "https://a.example"\nhmac_key_file = "/k/./x"',
            "sinks.webhook.hmac_key_file",
        ),
        ('[daemon]\nstate_dir = "state"', "daemon.state_dir"),
        ('[daemon]\nstate_dir = "/var/./state"', "daemon.state_dir"),
        ('[sinks.file]\ndir = "bundles"', "sinks.file.dir"),
        ('[control]\nsocket = "run/sv2.sock"', "control.socket"),
        (
            '[sinks.webhook]\nurl = "https://a.example"\nhmac_key_file = "/k"\nallow_insecure_http = true',
            "sinks.webhook.allow_insecure_http",
        ),
        ('[sinks.pager]\nurl = "https://a"', "sinks.pager"),
        ('[limits]\nbreaker_cooldown = "0s"', "limits.breaker_cooldown"),
        ('[correlation]\nbefore = "0s"', "correlation.before"),
        ('[sinks.splunk_hec]\nurl = "https://a"', "sinks.splunk_hec.token_file"),
        ('[sinks.elastic]\nurl = "https://a"\nindex = "i"', "sinks.elastic.api_key_file"),
        (
            '[sinks.elastic]\nurl = "https://a"\nindex = "i"\napi_key_file = "/k"\nusername = "u"\npassword_file = "/p"',
            "sinks.elastic.api_key_file",
        ),
        (
            '[sinks.elastic]\nurl = "https://a"\nindex = "i"\nusername = "u"',
            "sinks.elastic.username",
        ),
        ('[sinks.syslog]\ntransport = "smtp"', "sinks.syslog.transport"),
        ('[sinks.file]\nmax_size = "5%"', "sinks.file.max_size"),
        ('[redaction]\npatterns = ["("]', "redaction.patterns"),
        ("[metrics]\nport = 0", "metrics.port"),
        ("[limits]\nbreaker_window = 5", "limits.breaker_window"),
        ("[daemon]\nqueue_size = true", "daemon.queue_size"),
        ('[daemon]\nlog_level = "loud"', "daemon.log_level"),
        ("[correlation]\nmin_confidence = 2", "correlation.min_confidence"),
        ("sinks = 3", "sinks"),
        ("[metrics]\nenabled = 1", "metrics.enabled"),
        ('[protection]\nprotected = "x"', "protection.protected"),
    ],
)
def test_global_errors(tmp_path: Path, main: str, key: str) -> None:
    got = err(tmp_path, main)
    assert got.startswith(f"main.toml: {key}:"), got


@pytest.mark.parametrize(
    ("text", "key"),
    [
        ("[[policy]]\nname = 1", "policy[0].name"),
        ('[[policy]]\nname = "p"', "policy[0].when"),
        ('[[policy]]\nname = "p"\ncooldown = "x"', "policy[0].cooldown"),
        ('[[policy]]\nname = "p"\n[policy.when]\nsignal = "avc"', "policy[0].do"),
        (
            '[[policy]]\nname = "p"\n[policy.when]\nsignal = "avc"\nx = 1\n[[policy.do]]\naction = "notify"',
            "policy[0].when.x",
        ),
        ('[[policy]]\nname = "p"\n[policy.when]\nsignal = "disk"', "policy[0].when.signal"),
        (
            '[[policy]]\nname = "p"\n[policy.when]\nsignal = "avc"\n[[policy.do]]\naction = "notify"\nx = 1',
            "policy[0].do[0].x",
        ),
        (
            '[[policy]]\nname = "p"\n[policy.when]\nsignal = "unit_failed"\nunits = []\n[[policy.do]]\naction = "notify"',
            "policy[0].when.units",
        ),
        ("policy = 3", "policy"),
        ("oops = 1", "oops"),
        ('[[policy]]\nname = "p"\nwhen = 3', "policy[0].when"),
    ],
)
def test_policy_errors(tmp_path: Path, text: str, key: str) -> None:
    got = err(tmp_path, x=text)
    assert got.startswith(f"x.toml: {key}:"), got


def test_avc_min_count_capped_by_burst_size(tmp_path: Path) -> None:
    when = 'signal = "avc"\nmin_count = 6'
    got = err(tmp_path, x=policy_text(when=when))
    assert got == "x.toml: policy[0].when.min_count: must be at most correlation.avc_burst (5)"
    cfg = load(tmp_path, "[correlation]\navc_burst = 6", x=policy_text(when=when))
    assert cfg.policies[0].when == AvcWhen(min_count=6)


def test_unreadable_files(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match=r"nope.toml: \(file\): cannot read"):
        load_config(tmp_path / "nope.toml", tmp_path)
    assert "(file): cannot read" in err(tmp_path, "[daemon")


def test_policy_mode_kept_as_configured(tmp_path: Path) -> None:
    cfg = load(tmp_path, "", a=policy_text(extra='mode = "enforce"'))
    assert cfg.daemon.mode == "dry-run" and cfg.policies[0].mode == "enforce"


def test_file_sink_dir_follows_state_dir(tmp_path: Path) -> None:
    assert load(tmp_path, '[daemon]\nstate_dir = "/x"').sinks.file.dir == Path("/x/bundles")
    cfg = load(tmp_path, '[daemon]\nstate_dir = "/x"\n[sinks.file]\ndir = "/y"')
    assert cfg.sinks.file.dir == Path("/y")


@pytest.mark.parametrize("path", ["etc/nginx.conf", "/etc/../root/x", "/etc//nginx.conf", "/etc/"])
def test_backup_paths_absolute_and_normalised(tmp_path: Path, path: str) -> None:
    got = err(tmp_path, x=policy_text(do=f'action = "backup_reload"\npaths = ["{path}"]'))
    assert got.startswith("x.toml: policy[0].do[0].paths: ")
    assert "absolute, normalised" in got
