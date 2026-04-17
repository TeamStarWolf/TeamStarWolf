#!/usr/bin/env python3
"""Build a compact Black Hat Arsenal dataset for the TeamStarWolf profile repo."""

from __future__ import annotations

import csv
import re
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse

import requests


REPO = "toolswatch/blackhat-arsenal-tools"
BRANCH = "master"
TREE_URL = f"https://api.github.com/repos/{REPO}/git/trees/{BRANCH}?recursive=1"
RAW_BASE = f"https://raw.githubusercontent.com/{REPO}/{BRANCH}"
ROOT = Path(__file__).resolve().parent.parent
OUT_CSV = ROOT / "data" / "blackhat_arsenal_tools.csv"

SECTION_RE = re.compile(r"^###\s+(.*?)\s*$", re.M)
IMAGE_RE = re.compile(r"!\[[^\]]*\]\([^)]+\)")
LINK_RE = re.compile(r"\[([^\]]+)\]\((https?://[^)]+)\)")
RAW_URL_RE = re.compile(r"https?://[^\s<>\"]+")


def fetch_json(url: str) -> dict:
    response = requests.get(url, timeout=60, headers={"User-Agent": "TeamStarWolf Arsenal Dataset"})
    response.raise_for_status()
    return response.json()


def fetch_text(url: str) -> str:
    response = requests.get(url, timeout=60, headers={"User-Agent": "TeamStarWolf Arsenal Dataset"})
    response.raise_for_status()
    return response.text


def clean_title(text: str) -> str:
    text = IMAGE_RE.sub("", text).strip()
    text = LINK_RE.sub(r"\1", text)
    text = text.lstrip("#").strip()
    return " ".join(text.split())


def flatten_text(text: str) -> str:
    text = IMAGE_RE.sub("", text)
    text = LINK_RE.sub(r"\1", text)
    text = re.sub(r"<br\s*/?>", " ", text, flags=re.I)
    text = text.replace("\r", "\n")
    text = text.replace("\t", " ")
    lines = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        line = re.sub(r"^[*-]\s*", "", line)
        lines.append(line)
    return " ; ".join(lines)


def clean_url(url: str) -> str | None:
    url = url.strip().strip("(),")
    url = url.replace("<br", "")
    url = url.replace("\\", "")
    if " " in url or not url.startswith(("http://", "https://")):
        return None
    try:
        parsed = urlparse(url)
    except ValueError:
        return None
    if not parsed.scheme or not parsed.netloc:
        return None
    url = url.rstrip("/")
    if "github.com/" in url.lower() and url.lower().endswith(".git"):
        url = url[:-4]
    return url


def extract_urls(text: str) -> list[str]:
    urls: list[str] = []
    scrubbed = text
    for _, target in LINK_RE.findall(text):
        cleaned = clean_url(target)
        if cleaned:
            urls.append(cleaned)
        scrubbed = scrubbed.replace(target, " ")
    for raw_url in RAW_URL_RE.findall(scrubbed):
        cleaned = clean_url(raw_url)
        if cleaned:
            urls.append(cleaned)
    seen: set[str] = set()
    unique: list[str] = []
    for url in urls:
        if url not in seen:
            seen.add(url)
            unique.append(url)
    return unique


def split_sections(markdown: str) -> dict[str, str]:
    parts = SECTION_RE.split(markdown)
    sections: dict[str, str] = {}
    for index in range(1, len(parts), 2):
        header = parts[index].strip().lower()
        content = parts[index + 1].strip() if index + 1 < len(parts) else ""
        sections[header] = content
    return sections


def first_url(urls: Iterable[str], *, include_github: bool | None = None) -> str:
    for url in urls:
        is_github = "github.com/" in url.lower()
        if include_github is None or is_github is include_github:
            return url
    return ""


def is_project_url(url: str) -> bool:
    host = urlparse(url).netloc.lower()
    blocked = (
        "twitter.com",
        "x.com",
        "linkedin.com",
        "youtube.com",
        "youtu.be",
        "discord.gg",
        "facebook.com",
        "slideshare.net",
        "raw.githubusercontent.com",
        "rawgit.com",
        "github.com",
    )
    return all(block not in host for block in blocked)


def extract_twitter_handles(urls: Iterable[str]) -> list[str]:
    handles: list[str] = []
    for url in urls:
        lower = url.lower()
        if "twitter.com/" not in lower and "x.com/" not in lower:
            continue
        handle = url.rstrip("/").split("/")[-1]
        handle = handle.split("?")[0].split("#")[0]
        if handle and handle.lower() not in {"share", "intent", "search"}:
            handles.append(f"@{handle}")
    return dedupe(handles)


def dedupe(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result


def markdown_paths(tree: dict) -> list[str]:
    paths = []
    for item in tree.get("tree", []):
        path = item.get("path", "")
        if item.get("type") != "blob":
            continue
        if not path.endswith(".md") or "/" not in path or path == "tool_name.md":
            continue
        paths.append(path)
    return sorted(paths)


def build_rows() -> list[dict[str, str]]:
    tree = fetch_json(TREE_URL)
    rows: list[dict[str, str]] = []
    for path in markdown_paths(tree):
        markdown = fetch_text(f"{RAW_BASE}/{path}")
        lines = markdown.splitlines()
        if not lines:
            continue
        title = clean_title(lines[0])
        sections = split_sections(markdown)
        code_urls = extract_urls(sections.get("code", ""))
        social_urls = extract_urls(sections.get("social media", ""))
        session_urls = [
            url
            for url in extract_urls(sections.get("black hat sessions", ""))
            if "blackhat.com/" in url.lower() or "toolswatch.org/" in url.lower()
        ]
        all_urls = dedupe(code_urls + social_urls + session_urls)
        lead_developers = flatten_text(
            sections.get(
                "lead developers",
                sections.get("lead developer", sections.get("lead developer(s)", "")),
            )
        )

        rows.append(
            {
                "tool_name": title or Path(path).stem.replace("_", " "),
                "arsenal_category": path.split("/")[0],
                "source_markdown_path": path,
                "source_markdown_url": f"https://github.com/{REPO}/blob/{BRANCH}/{path}",
                "github_repo_url": first_url(code_urls, include_github=True),
                "project_url": first_url(url for url in code_urls if is_project_url(url))
                or first_url(url for url in social_urls if is_project_url(url)),
                "black_hat_session_urls": " | ".join(session_urls),
                "twitter_handles": " | ".join(extract_twitter_handles(social_urls)),
                "youtube_urls": " | ".join(
                    url
                    for url in all_urls
                    if "youtube.com/" in url.lower() or "youtu.be/" in url.lower()
                ),
                "lead_developers": lead_developers,
            }
        )
    return rows


def write_csv(rows: list[dict[str, str]]) -> None:
    OUT_CSV.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "tool_name",
        "arsenal_category",
        "source_markdown_path",
        "source_markdown_url",
        "github_repo_url",
        "project_url",
        "black_hat_session_urls",
        "twitter_handles",
        "youtube_urls",
        "lead_developers",
    ]
    with OUT_CSV.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    rows = build_rows()
    write_csv(rows)
    categories = {}
    github_backed = 0
    twitter_backed = 0
    youtube_backed = 0
    for row in rows:
        categories[row["arsenal_category"]] = categories.get(row["arsenal_category"], 0) + 1
        github_backed += int(bool(row["github_repo_url"]))
        twitter_backed += int(bool(row["twitter_handles"]))
        youtube_backed += int(bool(row["youtube_urls"]))

    print(f"Wrote {len(rows)} Black Hat Arsenal tools to {OUT_CSV}")
    print(f"GitHub-backed entries: {github_backed}")
    print(f"Entries with Twitter/X handles: {twitter_backed}")
    print(f"Entries with direct YouTube links: {youtube_backed}")
    for category, count in sorted(categories.items()):
        print(f"{category}: {count}")


if __name__ == "__main__":
    main()
