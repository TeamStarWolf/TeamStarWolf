#!/usr/bin/env python3
"""Shared helpers for the generators that rebuild data/ from a pinned upstream file.

A pin is a dict with: label, url (a versioned URL that names the release), bytes,
sha256 and env (an environment variable that may name a local copy instead). read()
returns the pinned bytes, fetched or read from the local copy, and aborts unless the
size and SHA-256 match the pin, so a changed upstream file never reaches the data.

write_text() and committed() keep each file's line ending: the bytes are written with
the ending the file on disk already uses (CRLF for a new file, as the rest of the
library's Windows-edited data does), and checks compare LF-normalized bytes, so a
result does not depend on the checkout's core.autocrlf setting.
"""
from __future__ import annotations

import hashlib
import os
import sys
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
USER_AGENT = "teamstarwolf-library-build (+https://github.com/TeamStarWolf/TeamStarWolf)"
FETCH_ATTEMPTS = 3


def log(tool: str, msg: str) -> None:
    print("[" + tool + "] " + msg, file=sys.stderr)


def read(tool: str, pin: dict, override: str | None = None) -> bytes:
    """The bytes of one pinned input: an explicit path or env override, else the URL."""
    src = override or os.environ.get(pin["env"])
    if src:
        log(tool, "reading " + pin["label"] + " from " + src)
        with open(src, "rb") as f:
            raw = f.read()
    else:
        src = pin["url"]
        log(tool, "fetching " + pin["label"] + " from " + src)
        req = urllib.request.Request(src, headers={"User-Agent": USER_AGENT})
        raw = b""
        for attempt in range(1, FETCH_ATTEMPTS + 1):
            try:
                with urllib.request.urlopen(req, timeout=180) as resp:  # noqa: S310 (fixed URL, hash-checked)
                    raw = resp.read()
                break
            except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
                if attempt == FETCH_ATTEMPTS:
                    raise
                log(tool, "fetch attempt " + str(attempt) + " failed (" + str(exc) + "); retrying")
    digest = hashlib.sha256(raw).hexdigest()
    if digest != pin["sha256"] or len(raw) != pin["bytes"]:
        sys.exit(
            "[" + tool + "] INTEGRITY FAILURE (" + pin["label"] + "): " + src + "\n"
            "  expected sha256 " + pin["sha256"] + " (" + format(pin["bytes"], ",") + " bytes)\n"
            "  actual   sha256 " + digest + " (" + format(len(raw), ",") + " bytes)\n"
            "  Nothing was written. Use the pinned file, or re-pin deliberately.")
    return raw


def lf(raw: bytes) -> bytes:
    return raw.replace(b"\r\n", b"\n")


def committed(rel: str) -> bytes | None:
    path = os.path.join(ROOT, rel)
    if not os.path.exists(path):
        return None
    with open(path, "rb") as f:
        return f.read()


def eol_of(rel: str) -> str:
    raw = committed(rel)
    if raw is None:
        return "\r\n"
    return "\r\n" if b"\r\n" in raw else "\n"


def encode(rel: str, text: str) -> bytes:
    """text (LF line endings) as the bytes to write to rel, in rel's line ending."""
    eol = eol_of(rel)
    if eol != "\n":
        text = text.replace("\n", eol)
    return text.encode("utf-8")


def write_text(rel: str, text: str) -> bool:
    """Write text (LF line endings) to rel in its existing ending; True if it changed."""
    new = encode(rel, text)
    old = committed(rel)
    if old is not None and lf(old) == lf(new):
        return False
    with open(os.path.join(ROOT, rel), "wb") as f:
        f.write(new)
    return True


def drift(rel: str, text: str) -> bool:
    """True when the committed rel differs from text (LF-normalized comparison)."""
    old = committed(rel)
    return old is None or lf(old) != text.encode("utf-8")
