"""Keep the docs honest: config keys, policy examples, the example bundle and links."""

import dataclasses
import json
import re
import types
import typing
from pathlib import Path

import jsonschema
import pytest

from sentry_v2.config import load_config
from sentry_v2.config_types import Config

ROOT = Path(__file__).parents[2]
DOCS = ROOT / "docs"
DEMO = ROOT / "examples" / "demo"
REPO_URL = (
    r"^https://(github\.com/jamesconwaydev/sentry-v2/(blob|tree)/main/"
    r"|raw\.githubusercontent\.com/jamesconwaydev/sentry-v2/main/)"
)
PAGES = sorted([ROOT / "README.md", ROOT / "CHANGELOG.md", *DOCS.glob("*.md"), DEMO / "README.md"])


def _fields(cls: type, prefix: str = "") -> list[str]:
    """Dotted names of every field under `cls`, recursing into nested dataclasses."""
    out = []
    for f in dataclasses.fields(cls):
        name = f"{prefix}{f.name}"
        out.append(name)
        hint = typing.get_type_hints(cls)[f.name]
        args = typing.get_args(hint) if isinstance(hint, types.UnionType) else (hint,)
        for arg in args:
            if dataclasses.is_dataclass(arg) and isinstance(arg, type):
                out += _fields(arg, f"{name}.")
    return out


def test_every_config_key_is_documented() -> None:
    text = (DOCS / "configuration.md").read_text()
    # a key appears as `name` in its section's table; a section as [dotted.name]
    missing = [
        n
        for n in _fields(Config)
        if f"`{n.rsplit('.', 1)[-1]}`" not in text and f"[{n}]" not in text
    ]
    assert not missing, f"configuration.md does not mention: {missing}"


def test_field_walk_reaches_nested_sinks() -> None:
    names = _fields(Config)
    assert "sinks.webhook.hmac_key_file" in names
    assert "sinks.elastic.password_file" in names


def _blocks(page: Path, lang: str) -> list[str]:
    return re.findall(rf"```{lang}\n(.*?)```", page.read_text(), re.S)


@pytest.mark.parametrize(
    "block", [b for b in _blocks(DOCS / "policies.md", "toml") if "[[policy]]" in b]
)
def test_policy_examples_load(block: str, tmp_path: Path) -> None:
    (tmp_path / "sentry-v2.toml").write_text("")
    (tmp_path / "policies.d").mkdir()
    (tmp_path / "policies.d" / "10-example.toml").write_text(block)
    cfg = load_config(tmp_path / "sentry-v2.toml", tmp_path / "policies.d")
    assert cfg.policies


def test_demo_policies_load_and_never_enforce(tmp_path: Path) -> None:
    (tmp_path / "sentry-v2.toml").write_text("")
    cfg = load_config(tmp_path / "sentry-v2.toml", DEMO)
    assert [p.name for p in cfg.policies] == ["demo-app-failed", "demo-memory-throttle"]
    assert {p.mode for p in cfg.policies} == {"dry-run"}


def test_example_bundle_matches_schema() -> None:
    schema = json.loads((DOCS / "reference" / "bundle.schema.json").read_text())
    (example,) = _blocks(DOCS / "bundles.md", "json")
    jsonschema.validate(json.loads(example), schema)


def test_demo_bundles_match_schema() -> None:
    schema = json.loads((DOCS / "reference" / "bundle.schema.json").read_text())
    bundles = sorted(DEMO.glob("incident-*.json"))
    assert len(bundles) == 2
    for path in bundles:
        jsonschema.validate(json.loads(path.read_text()), schema)


def _slug(heading: str) -> str:
    """GitHub's anchor for a heading."""
    text = re.sub(r"[`*]", "", heading.strip().lower())
    return re.sub(r"[^\w\- ]", "", text).replace(" ", "-")


def _anchors(page: Path) -> set[str]:
    text = re.sub(r"```.*?```", "", page.read_text(), flags=re.S)
    return {_slug(h) for h in re.findall(r"^#{1,6} (.+)$", text, re.M)}


@pytest.mark.parametrize("page", PAGES, ids=lambda p: str(p.relative_to(ROOT)))
def test_relative_links_resolve(page: Path) -> None:
    text = re.sub(r"```.*?```", "", page.read_text(), flags=re.S)
    broken = []
    for target in re.findall(r"\]\(([^)\s]+)\)", text) + re.findall(
        r'(?:srcset|src)="([^"]+)"', text
    ):
        # The README uses absolute links so they work on PyPI too; check the
        # ones into this repository as if they were relative.
        base = ROOT if re.match(REPO_URL, target) else page.parent
        target = re.sub(REPO_URL, "", target)
        if re.match(r"[a-z]+:", target):
            continue
        path, _, anchor = target.partition("#")
        dest = (base / path).resolve() if path else page
        if not dest.exists() or (anchor and dest.suffix == ".md" and anchor not in _anchors(dest)):
            broken.append(target)
    assert not broken, f"{page.name}: broken links {broken}"
