"""The Cockpit page: a valid manifest, files that exist, and nothing Cockpit's CSP blocks."""

import json
import re
from html.parser import HTMLParser
from pathlib import Path

COCKPIT = Path(__file__).resolve().parents[2] / "cockpit"
# Provided by Cockpit itself at runtime, not shipped in the package.
COCKPIT_PROVIDED = {"../base1/cockpit.js"}


class _Page(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.refs: list[str] = []
        self.inline_scripts: list[str] = []
        self.styled: list[str] = []
        self.handlers: list[str] = []
        self._in_script = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = dict(attrs)
        if "style" in a:
            self.styled.append(tag)
        self.handlers += [k for k in a if k.startswith("on")]
        if tag == "style":
            self.styled.append("<style>")
        if tag == "script":
            self._in_script = True
            if a.get("src"):
                self.refs.append(a["src"] or "")
        if tag == "link" and a.get("href"):
            self.refs.append(a["href"] or "")

    def handle_endtag(self, tag: str) -> None:
        if tag == "script":
            self._in_script = False

    def handle_data(self, data: str) -> None:
        if self._in_script and data.strip():
            self.inline_scripts.append(data)


def _page() -> _Page:
    p = _Page()
    p.feed((COCKPIT / "index.html").read_text())
    return p


def test_manifest_is_valid_and_its_pages_exist() -> None:
    manifest = json.loads((COCKPIT / "manifest.json").read_text())
    assert manifest["version"] == 0
    assert manifest["name"] == "sentry-v2"
    assert manifest["tools"], "the page must be listed under Tools"
    for key, entry in manifest["tools"].items():
        assert entry["label"] == "Sentry-v2"
        assert (COCKPIT / entry.get("path", f"{key}.html")).is_file()


def test_index_references_exist() -> None:
    refs = _page().refs
    assert "../base1/cockpit.js" in refs
    for ref in refs:
        if ref not in COCKPIT_PROVIDED:
            assert (COCKPIT / ref).is_file(), ref


def test_index_has_nothing_inline_for_csp_to_block() -> None:
    page = _page()
    assert page.inline_scripts == []
    assert page.styled == []
    assert page.handlers == []


def test_assets_load_nothing_from_the_network() -> None:
    for path in COCKPIT.iterdir():
        assert not re.search(r"https?://", path.read_text()), path.name
