<p align="center">
  <img src="assets/brand/starwolf64-banner-1280.png" width="100%" alt="STARWOLF 64 logotype: green-to-yellow chrome lettering on a dark blue plate, a red and white wolf head at the left, a red streak over the letters, and a red star holding the number 64">
</p>

<p align="center">An open cybersecurity reference library, cross-referenced to MITRE ATT&amp;CK.</p>

<p align="center">Drafted with an AI assistant from the sources cited; checked against them on 2026-10-17.</p>

<div align="center">

[Website](https://teamstarwolf.github.io/TeamStarWolf/) | [Browse references](INDEX.md) | [Explore ATT&CK](mitre/README.md) | [ATTACK-Navi](https://teamstarwolf.github.io/ATTACK-Navi/) | [Data and Navigator layers](data/README.md) | [Contribute](CONTRIBUTING.md)

[![Link Check](https://github.com/TeamStarWolf/TeamStarWolf/actions/workflows/link-check.yml/badge.svg?branch=main)](https://github.com/TeamStarWolf/TeamStarWolf/actions/workflows/link-check.yml)
[![Validate Data Files](https://github.com/TeamStarWolf/TeamStarWolf/actions/workflows/validate-data.yml/badge.svg?branch=main)](https://github.com/TeamStarWolf/TeamStarWolf/actions/workflows/validate-data.yml)
[![CodeQL](https://github.com/TeamStarWolf/TeamStarWolf/actions/workflows/github-code-scanning/codeql/badge.svg?branch=main)](https://github.com/TeamStarWolf/TeamStarWolf/actions/workflows/github-code-scanning/codeql)
[![Deploy site](https://github.com/TeamStarWolf/TeamStarWolf/actions/workflows/pages/pages-build-deployment/badge.svg)](https://github.com/TeamStarWolf/TeamStarWolf/actions/workflows/pages/pages-build-deployment)

</div>

## Start here

| I want to... | Go to |
|---|---|
| Learn a discipline | [Learning paths](disciplines/README.md) |
| Write detections or hunt | [Technique Detection Library](detections/TECHNIQUE_DETECTION_LIBRARY.md) |
| Assess ATT&CK coverage | [Run a coverage gap assessment](guides/RUN_A_COVERAGE_GAP_ASSESSMENT.md) |
| Respond to an incident | [Incident Response Reference](INCIDENT_RESPONSE_REFERENCE.md) |
| Manage vulnerabilities | [Vulnerability Management Reference](VULNERABILITY_MANAGEMENT_REFERENCE.md) |
| Secure AI systems | [AI Security Reference](AI_SECURITY_REFERENCE.md) |

New here? [How to use this library](guides/HOW_TO_USE_THIS_LIBRARY.md) shows what lives where, and the [website](https://teamstarwolf.github.io/TeamStarWolf/) renders the same files with search.

## What's inside

<!-- stats:start (written by scripts/build_stats.py; do not edit) -->
| What | Count | Contents | Start at |
|---|---:|---|---|
| Reference documents | 155 | One topic each: its terms, tooling, and the frameworks and guidance that apply | [Reference index](INDEX.md) |
| How-to guides | 21 | One task, step by step, with the time it takes, what you need, and what you produce | [Guides](guides/README.md) |
| Learning paths | 47 | An order of study for one discipline, with training, tools, books, and certifications | [Learning paths](disciplines/README.md) |
| Framework pages | 2,930 | One page per ATT&CK, CAPEC, D3FEND, ATLAS, and F3 object, generated from MITRE data | [Framework pages](mitre/README.md) |
<!-- stats:end -->

Where a published mapping exists, a technique page links the NIST SP 800-53 controls, MITRE detection strategies and analytics, CAPEC attack patterns, and D3FEND countermeasures that relate to it. The same relationships ship as JSONL files and ATT&CK Navigator layers. [About the data](ABOUT_THE_DATA.md) gives their sources, the ATT&CK version each part is built from (v19.2 for the data and framework pages), and what CI checks. The library also holds [vendor tool pages](tools/README.md), [AI tooling notes](ai-tooling/README.md), [case studies](case-studies/README.md), [tools research](tools-research/README.md), and [research notes](research/README.md).

## Projects

| Project | What it is |
|---|---|
| [TeamStarWolf](https://github.com/TeamStarWolf/TeamStarWolf) | This library: hand-written references, generated framework pages, and mapping data, published as a [website](https://teamstarwolf.github.io/TeamStarWolf/). |
| [ATTACK-Navi](https://github.com/TeamStarWolf/ATTACK-Navi) | A browser-based workbench for the Enterprise, ICS, and Mobile ATT&CK matrices, with views for detection coverage, threat intelligence, vulnerability exposure, and compliance. It needs no backend: [live app](https://teamstarwolf.github.io/ATTACK-Navi/). |
| [cybersecurity-resources](https://github.com/TeamStarWolf/cybersecurity-resources) | A bookmark collection weighted toward vulnerability management and threat intelligence, released under CC0. |

## Accuracy and use

The references summarize third-party frameworks, standards, and publications, and they can fall behind upstream changes, so check the primary source before relying on a detail, particularly version-specific facts, regulatory requirements, and anything you intend to run. Offensive techniques and tooling are described for authorized testing, education, and defensive research; do not use them against systems you do not have permission to test. The vendor-to-control mappings are this library's own editorial assessments, not vendor statements or evidence of coverage.

MITRE ATT&CK, ATLAS, CAPEC, CWE, D3FEND, EMB3D, Engage, F3, and FiGHT are maintained by The MITRE Corporation. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE. The TeamStarWolf name and STARWOLF 64 art are naming and art only, never a claim about people, affiliations, or capability. Star Fox is a Nintendo trademark; this project is not affiliated with or endorsed by Nintendo.

## Cloning on Windows

Microsoft Defender quarantines MALWARE_ANALYSIS_REFERENCE.md on checkout because it quotes evasion snippets as analysis samples, which leaves a tracked file deleted in `git status`. Follow [Cloning on Windows](CONTRIBUTING.md#cloning-on-windows) before cloning, and never commit that deletion.

## Contributing, license, and citation

Corrections and additions are welcome through [issues](https://github.com/TeamStarWolf/TeamStarWolf/issues) and pull requests; see [CONTRIBUTING](CONTRIBUTING.md), the [voice guide](docs/VOICE.md), the [code of conduct](CODE_OF_CONDUCT.md), and the [security policy](SECURITY.md). Changes are recorded in the [changelog](CHANGELOG.md). Original content is released under the [MIT License](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/LICENSE); data and text drawn from MITRE and other sources stay under their owners' terms, listed in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). To cite the library, use [CITATION.cff](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/CITATION.cff) or the "Cite this repository" button on the repository page.
