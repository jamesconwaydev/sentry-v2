#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright the Sentry-v2 contributors
# SPDX-License-Identifier: Apache-2.0
"""Write the RPM source tarball so that the same tree gives the same bytes.

    source-tarball.py OUT PREFIX PATH...

Run from the repository root. Entries are sorted, owned by root, given
0644 or 0755, and stamped with the date of the newest %changelog entry in
the spec, so neither the checkout's mtimes nor the umask nor the build
time leak into the SRPM.
"""

import calendar
import gzip
import re
import sys
import tarfile
import time
from pathlib import Path

SPEC = Path("packaging/sentry-v2.spec")
SKIP = {"__pycache__"}


def changelog_epoch(spec: str) -> int:
    m = re.search(r"^%changelog\s*\n\* \w{3} (\w{3} \d{1,2} \d{4})", spec, re.M)
    if not m:
        raise SystemExit(f"{SPEC}: no %changelog entry to date the tarball")
    return calendar.timegm(time.strptime(m.group(1), "%b %d %Y"))


def walk(path: Path) -> list[Path]:
    if path.is_dir():
        kids = (walk(p) for p in sorted(path.iterdir()))
        return [path, *(p for k in kids for p in k)]
    return [path]


def skipped(path: Path) -> bool:
    return any(part in SKIP or part.endswith(".egg-info") for part in path.parts)


def main(out: str, prefix: str, *paths: str) -> None:
    mtime = changelog_epoch(SPEC.read_text())

    def norm(info: tarfile.TarInfo) -> tarfile.TarInfo:
        info.uid = info.gid = 0
        info.uname = info.gname = "root"
        info.mtime = mtime
        info.mode = 0o755 if info.isdir() or info.mode & 0o100 else 0o644
        return info

    files = [p for top in sorted(paths) for p in walk(Path(top)) if not skipped(p)]
    # No name or time in the gzip header either.
    with (
        open(out, "wb") as raw,
        gzip.GzipFile("", "wb", fileobj=raw, mtime=0) as gz,
        tarfile.open(fileobj=gz, mode="w", format=tarfile.PAX_FORMAT) as tar,
    ):
        top = tarfile.TarInfo(prefix)
        top.type = tarfile.DIRTYPE
        tar.addfile(norm(top))
        for p in files:
            info = norm(tar.gettarinfo(p, f"{prefix}/{p.as_posix()}"))
            if info.isfile():
                with p.open("rb") as f:
                    tar.addfile(info, f)
            else:
                tar.addfile(info)


if __name__ == "__main__":
    if len(sys.argv) < 4:
        raise SystemExit(__doc__)
    main(*sys.argv[1:])
