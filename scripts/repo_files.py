"""Shared helpers for the repository-wide CI checks (check_docsify_links.py,
check_repo_hygiene.py): the set of tracked files and a robust reader.

The universe is `git ls-files`, i.e. exactly what actions/checkout puts in the Pages
artifact, so an untracked local file never makes a link look valid and never trips a
content check. A tracked file that cannot be read from disk (for example a local
antivirus quarantine of a security reference page) is read from the git index instead,
so a local run checks the same content CI does.
"""
from __future__ import annotations

import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_NOTED: set = set()


def tracked_files() -> list[str]:
    try:
        out = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, capture_output=True,
                             check=True).stdout.decode("utf-8")
        return [p for p in out.split("\0") if p]
    except (OSError, subprocess.CalledProcessError):
        files = []
        for d, dirs, fs in os.walk(ROOT):
            dirs[:] = [x for x in dirs if x != ".git"]
            for f in fs:
                files.append(os.path.relpath(os.path.join(d, f), ROOT).replace(os.sep, "/"))
        return sorted(files)


def read_bytes(rel: str) -> bytes | None:
    try:
        with open(os.path.join(ROOT, rel), "rb") as f:
            return f.read()
    except OSError as e:
        try:
            blob = subprocess.run(["git", "show", ":" + rel], cwd=ROOT, capture_output=True,
                                  check=True).stdout
        except (OSError, subprocess.CalledProcessError):
            print("WARNING: could not read " + rel + " (" + str(e) + "); skipped", file=sys.stderr)
            return None
        if rel in _NOTED:
            return blob
        _NOTED.add(rel)
        print("NOTE: " + rel + " unreadable on disk (" + e.__class__.__name__ + "); checked the "
              "git index copy", file=sys.stderr)
        return blob


def read_text(rel: str) -> str | None:
    b = read_bytes(rel)
    if b is None:
        return None
    t = b.decode("utf-8", errors="replace")
    t = t[1:] if t.startswith("\ufeff") else t     # a BOM is not content (browsers drop it)
    return t.replace("\r\n", "\n")
