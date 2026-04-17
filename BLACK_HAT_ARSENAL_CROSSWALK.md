# Black Hat Arsenal Crosswalk

This page shows how the [official Black Hat Arsenal tools repository](https://github.com/toolswatch/blackhat-arsenal-tools) can strengthen the TeamStarWolf educational library.

The goal is not to mirror Arsenal entry-for-entry. The goal is to turn a conference tool index into useful next steps for starring repos, following maintainers, finding demo videos, and pairing books with hands-on tooling.

## Source Snapshot

- Source repo: [toolswatch/blackhat-arsenal-tools](https://github.com/toolswatch/blackhat-arsenal-tools)
- Generated dataset: [data/blackhat_arsenal_tools.csv](data/blackhat_arsenal_tools.csv)
- Builder script: [scripts/build_blackhat_arsenal_dataset.py](scripts/build_blackhat_arsenal_dataset.py)
- Current snapshot in this repo: 103 tool pages across 19 Arsenal categories
- GitHub-backed entries: 97
- Entries with Twitter/X handles: 85
- Entries with direct YouTube links: 5

| Arsenal category | Tools |
|---|---:|
| `network_defense` | 11 |
| `frameworks` | 10 |
| `exploitation` | 8 |
| `malware_research` | 8 |
| `network_attacks` | 8 |
| `vulnerability_assessment` | 8 |
| `webapp_security` | 7 |
| `hardware_iot` | 6 |
| `mobile_hacking` | 6 |
| `red_team` | 6 |
| `cryptography` | 4 |
| `cloud` | 3 |
| `code_assessment` | 3 |
| `forensics` | 3 |
| `hardening` | 3 |
| `osint` | 3 |
| `phishing` | 2 |
| `ics_scada` | 1 |
| `reverse_engineering` | 3 |

## Where It Fits In This Repo

| TeamStarWolf page | Best use of Arsenal data |
|---|---|
| [CURATED_STARS_LISTS.md](CURATED_STARS_LISTS.md) | Expand list descriptions with tool-first examples that come from a known conference catalog instead of random repo browsing |
| [STARRED_REPOS.md](STARRED_REPOS.md) | Maintain a clear review queue of strong Arsenal repos that are not yet part of the starred index |
| [TWITTER_FOLLOW_LIST.md](TWITTER_FOLLOW_LIST.md) | Pull in maintainer and project feeds tied directly to tools, not just general commentary accounts |
| [YOUTUBE_CHANNELS.md](YOUTUBE_CHANNELS.md) | Build a short watch path from Arsenal-linked channels, playlists, and demos |
| [CYBERSECURITY_BOOK_LIST.md](CYBERSECURITY_BOOK_LIST.md) | Pair books with concrete tools so the reading list becomes easier to lab against |

## High-Signal Review Queue

These are good candidates to review for future starring because they appear in Black Hat Arsenal but are not currently listed in [STARRED_REPOS.md](STARRED_REPOS.md).

| Area | Candidate repos |
|---|---|
| Cloud labs and assessment | [AWSGoat](https://github.com/ine-labs/AWSGoat), [AzureGoat](https://github.com/ine-labs/AzureGoat) |
| Offensive and post-exploitation | [Merlin](https://github.com/Ne0nd0g/merlin), [MailSniper](https://github.com/dafthack/MailSniper) |
| Mobile testing | [Needle](https://github.com/mwrlabs/needle) |
| Malware and DFIR | [FLOSS](https://github.com/fireeye/flare-floss), [inVtero.net](https://github.com/ShaneK2/inVtero.net), [siembol](https://github.com/G-Research/siembol) |
| AppSec and exposure work | [OWASP Dependency-Check](https://github.com/jeremylong/DependencyCheck), [OWTF](https://github.com/owtf/owtf), [CrowdSec](https://github.com/crowdsecurity/crowdsec) |
| Embedded, hardware, and OT | [EMBA](https://github.com/e-m-b-a/emba), [JTAGulator](https://github.com/grandideastudio/jtagulator), [DYODE](https://github.com/wavestone-cdt/dyode) |

## Maintainers And Project Feeds

These are useful tool-first accounts to follow when you want more signal from builders and operators.

- [@Ne0nd0g](https://twitter.com/Ne0nd0g) - Merlin C2 and operator tradecraft
- [@dafthack](https://twitter.com/dafthack) - MailSniper and Microsoft-focused offensive tooling
- [@patrickwardle](https://twitter.com/patrickwardle) - Objective-See tooling and macOS security
- [@ajinabraham](https://twitter.com/ajinabraham) - MobSF maintainer and mobile testing
- [@leonjza](https://twitter.com/leonjza) - objection maintainer and mobile instrumentation
- [@securefirmware](https://twitter.com/securefirmware) - EMBA and firmware analysis
- [@joegrand](https://twitter.com/joegrand) - hardware tooling including JTAGulator
- [@williballenthin](https://twitter.com/williballenthin) - FLOSS and reverse engineering support tooling
- [@qtc_de](https://twitter.com/qtc_de) - Remote Method Guesser and Java/RMI attack surface work
- [@Crowd_Security](https://twitter.com/Crowd_Security) - CrowdSec project feed
- [@faradaysec](https://twitter.com/faradaysec) - Faraday collaborative pentest platform
- [@zaproxy](https://twitter.com/zaproxy) - ZAP project feed
- [@owtfp](https://twitter.com/owtfp) - OWTF offensive web testing

## Direct Video Trail

Arsenal entries only expose a handful of direct YouTube links, so this list stays intentionally small.

- [Black Hat Official YouTube](https://www.youtube.com/@BlackHatOfficialYT) - best starting point for searching Arsenal session titles from the dataset
- [Faraday channel](https://www.youtube.com/channel/UCnHpyTi7zRQ9A4U4Ldc65YQ) - collaborative pentest platform walkthroughs
- [OWTF channel](https://www.youtube.com/user/owtfproject) - offensive web testing workflow demos
- [GEF playlist](https://www.youtube.com/playlist?list=PLjAuO31Rg972WeMvdR_57Qu-aVM8T6DkQ) - debugger workflow material tied to GEF
- [MI-X demo](https://www.youtube.com/watch?v=2FsnsJ0mr68) - vulnerability assessment demo from the Arsenal entry
- [Remote Method Guesser demo](https://youtu.be/t_aw1mDNhzI) - focused demo for Java/RMI attack surface work

## Book Pairings

Use these when you want to turn the reading list into a lab track.

| Study area | Read with | Then open |
|---|---|---|
| Cloud security | cloud and infrastructure sections in [CYBERSECURITY_BOOK_LIST.md](CYBERSECURITY_BOOK_LIST.md) | [Prowler](https://github.com/prowler-cloud/prowler), [AWSGoat](https://github.com/ine-labs/AWSGoat), [AzureGoat](https://github.com/ine-labs/AzureGoat) |
| Offensive and red team | *The Hacker Playbook 3*, *Advanced Penetration Testing*, *RTFM* | [Merlin](https://github.com/Ne0nd0g/merlin), [MailSniper](https://github.com/dafthack/MailSniper), [Legion](https://github.com/GoVanguard/legion) |
| Web and AppSec | *The Web Application Hacker's Handbook*, *Bug Bounty Bootcamp* | [ZAP](https://github.com/zaproxy/zaproxy), [OWTF](https://github.com/owtf/owtf), [OWASP Dependency-Check](https://github.com/jeremylong/DependencyCheck) |
| Mobile security | the mobile section in [CYBERSECURITY_BOOK_LIST.md](CYBERSECURITY_BOOK_LIST.md) plus OWASP MASTG | [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF), [objection](https://github.com/sensepost/objection), [Needle](https://github.com/mwrlabs/needle) |
| Malware and DFIR | *Practical Malware Analysis*, *The Art of Memory Forensics* | [FLOSS](https://github.com/fireeye/flare-floss), [inVtero.net](https://github.com/ShaneK2/inVtero.net), [siembol](https://github.com/G-Research/siembol) |
| Hardware, firmware, and OT | the hardware and OT sections in [CYBERSECURITY_BOOK_LIST.md](CYBERSECURITY_BOOK_LIST.md) | [EMBA](https://github.com/e-m-b-a/emba), [JTAGulator](https://github.com/grandideastudio/jtagulator), [DYODE](https://github.com/wavestone-cdt/dyode) |

## Notes

- Black Hat Arsenal is a discovery layer, not a quality ranking.
- Some entries are older. Treat the dataset as a starting point, then verify project freshness and maintenance before relying on a tool.
- When a tool has both a GitHub repo and a project page, prefer the project docs first and the repo second.
