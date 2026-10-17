# Research

Drafted with an AI assistant from the sources cited; checked against them on 2026-10-17.

> Working notes and catalogues that feed the library: conference and training indexes, tool-coverage studies, the curated GitHub Stars Lists, and field notes from building projects in public. These pages are hand-written; two small datasets and the scripts that built them sit beside them.

## What is here

| Path | Contents |
|---|---|
| [CONFERENCE_TALKS.md](/research/CONFERENCE_TALKS.md) | Where to find talks, slides, papers, and code from the main security conferences (Black Hat, DEF CON, BSides, CCC, USENIX, and others) |
| [BLACK_HAT_ARSENAL_CROSSWALK.md](/research/BLACK_HAT_ARSENAL_CROSSWALK.md) | How the Black Hat Arsenal tools index maps onto this library's reading and tooling lists |
| [HTB_MACHINE_INDEX.md](/research/HTB_MACHINE_INDEX.md) | Retired Hack The Box machines with official writeups, by difficulty, OS, and the skills each teaches |
| [HTB_TRACKS.md](/research/HTB_TRACKS.md) | Hack The Box learning tracks, mapped to disciplines and certifications |
| [KALI_TOOL_COVERAGE.md](/research/KALI_TOOL_COVERAGE.md) | The Kali Linux tool catalogue compared with the curated Stars Lists and [STARRED_REPOS.md](/STARRED_REPOS.md) |
| [CURATED_STARS_LISTS.md](/research/CURATED_STARS_LISTS.md) | What each of the TeamStarWolf GitHub Stars Lists holds |
| [FIELD_NOTES.md](/research/FIELD_NOTES.md) | Append-only writeups of what building and hardening projects surfaced |
| `data/blackhat_arsenal_tools.csv` | The Black Hat Arsenal snapshot behind the crosswalk |
| `data/library.json` | A normalized index of the starred repositories, channels, accounts, and reading lists |
| `scripts/build_blackhat_arsenal_dataset.py` | Builds the Arsenal CSV from the `toolswatch/blackhat-arsenal-tools` repository through the GitHub API |
| `scripts/build_library_index.py` | Builds `data/library.json` from the catalogue pages |
| `create_starred_lists.py` | Creates or updates the GitHub Stars Lists from the sections of [STARRED_REPOS.md](/STARRED_REPOS.md) |

## How it is generated

The Markdown pages are written by hand and checked by the same link and encoding gates as the rest of the library. The datasets are snapshots, rebuilt by hand when their source changes; CI does not run these scripts.

- `build_blackhat_arsenal_dataset.py` needs the third-party `requests` package and network access to the GitHub API.
- `build_library_index.py` reads input files with names this repository has never used (for example `Starred GitHub Repositories.md`); the catalogues here are `STARRED_REPOS.md` and `YOUTUBE_CHANNELS.md`. It does not run against this tree until its input names are updated. `data/library.json` was last committed on 2026-04-17.
- `create_starred_lists.py` prints a plan by default. With `--apply` it writes public Stars Lists to whichever GitHub account `gh` is signed in to, so run it only on the account you mean to change.

## How to use it

- Use these pages as finding aids: each one points at the primary source (the conference archive, the Hack The Box catalogue, the Kali tool index) that you should read for current details.
- Counts on these pages (machines, tracks, tools, list sizes) are snapshots taken when each page was written; the upstream catalogues move.
- For security material you can act on, start from the [reference index](/INDEX.md) or the [learning paths](/disciplines/README.md) instead.
