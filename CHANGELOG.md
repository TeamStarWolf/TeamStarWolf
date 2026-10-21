# Changelog

All notable changes to this library are recorded here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). This project groups work
by the date its pull requests merged to `main` rather than by tagged release.

## Unreleased

### Added
- Header cards on every root reference and learning path, written into the page by
  `scripts/build_doc_meta.py` from `data/doc_meta.yaml`, so GitHub and the site show the
  same card: who the page is for, its level, its reading time (its words at 230 a minute),
  "Read this when" and "Start at" (at most 3 links), then in a "More about this page" fold
  "Pairs with", the matching learning path, the last recorded correction (what that pull
  request changed on the page) and the owner's last review ("No review recorded yet" until
  one is recorded; "Due for review" when the text changed more than 90 days after it).
  Learning paths get "Read this when" and "Start at" rows too. Pages that overlap get a
  folded "Which page should I read?" table. Long appendices and tables fold into `<details>`, and
  the generated technique detail and detection strategy pages fold each technique's body
  under its heading; on the site a link into a fold opens it. Key takeaways are drafted in
  `data/doc_takeaways.draft.yaml` for owner review and appear on a page only once moved to
  `data/doc_takeaways.yaml`. CI fails when a card is stale or a takeaway's quote is no
  longer in its section
- Cross-links between the hand-written and generated halves of the library, written into
  the Markdown by `scripts/build_crosslinks.py` from `docs/crosslinks.json`, so they work on
  GitHub and on the site: a "Matching reference" line on each learning path that has one,
  a "Related pages" footer on each root reference (its domain hub, its learning path, the
  pages in its "Pairs with" row and linked references from the same hub group, less any
  page the reference's own closing related or see-also section already links), a
  "(local)" link after each MITRE ID link in the CAPEC, ATT&CK technique and ATT&CK
  software atlases, and a "Library references" block on each `mitre/` page with a link to
  the technique's section in the detection strategy and technique detail pages and the
  hand-written pages that link to it or to its MITRE entry. CI fails when a block is stale
- Site navigation rebuilt around sections instead of one link per page: a short root
  sidebar (Start, guides and learning paths, domains, frameworks, operate and data, tools,
  case studies and research, about), nested sidebars for the guides, learning paths, vendor
  tools, AI tooling and framework folders, and a breadcrumb trail on hand-written pages.
  All of it is written by `scripts/build_site_nav.py` from `docs/site_nav.json`, and CI
  fails when a hand-written page is in no nav section. The changelog, security policy, code
  of conduct and third-party notices are now reachable from the site
- Domain hubs (`hubs/`): one page per domain listing its references with a one-line summary
  and a reading time, the matching learning paths and how-to guides, and related framework
  pages. The homepage's "Browse by domain" cards link to them
- Explore (`explore.md`): the ATT&CK techniques, groups, software, campaigns and
  mitigations, CAPEC attack patterns, D3FEND countermeasures, ATLAS techniques and
  mitigations, and F3 techniques that have a page (tactics are a filter, not rows),
  in one table filterable by kind, tactic, platform, software type and CAPEC abstraction
  and severity, searchable by ID, name or alias, with connection counts. Built from the
  JSONL files in `data/` by `scripts/build_explore.py`
- Tools Research section (`tools-research/`): documentation-verified studies of security
  products and their integrations, with confidence labels, original figures, and PDF
  downloads. First two studies: ServiceNow Unified Security Exposure Management (USEM)
  with Tenable and Wiz, and ServiceNow Vulnerability Response, Configuration Compliance
  and Container Vulnerability Response with Tenable and Wiz, both verified against
  ServiceNow's official documentation repository (Brazil release, September 2026).
  Linked from the sidebar, homepage, README, and index
- Tools Research: Tool Manuals and Repositories, a verified directory of official manuals,
  API references, release notes, ServiceNow Store and Splunkbase listings, GitHub
  organizations, repositories and GitHub Pages sites for ServiceNow, Armis and the MITRE
  threat-informed defense ecosystem, every link checked on 2026-10-08, with a table of dead
  or moved links to avoid. Cross-links the Security Tool Documentation index for Tenable,
  Wiz, Snyk, Invicti, Zafran and Splunk
- Case Studies section (`case-studies/`): evidence-graded studies of how the threat
  landscape is changing, written from primary sources, with original figures and PDF
  downloads. First study: AI Threats in the Cybersecurity Industry, a 2026 case study of
  six threat classes (AI-orchestrated intrusions, deepfake social engineering, AI-native
  malware, prompt injection, the AI software supply chain, and machine-speed vulnerability
  discovery), each event graded Confirmed, Reported, or Demonstrated, with sources checked
  as of 7 October 2026. Linked from the sidebar, homepage, README, and index
- AI Tooling (`ai-tooling/`), under AI & Emerging Tech: a practical guide to AI tools and LLMs.
  A grouped index of 46 tools and model platforms (model APIs, local inference, vector
  databases, agent frameworks, MCP and A2A, coding agents, workflow builders, evaluation,
  observability, guardrails, AI red teaming), a one-page manual for each with quick start and
  security notes citing verified CVEs and incidents, a nine-module learning path, and six local,
  defensive labs. Facts checked against official sources on 8 October 2026
- Case Studies: a 16-slide PowerPoint deck for the AI Threats 2026 case study
  (`case-studies/slides/`), with each slide's sources in its speaker notes, linked
  from the study page and the Case Studies hub

## 2026-09-26

### Added
- MITRE enriched pages: remaining frameworks in `mitre/`: 14 tactic hub pages,
  156 D3FEND countermeasure pages (each with the ATT&CK techniques it counters), 615
  CAPEC attack-pattern pages (mapped to ATT&CK + CWE, grouped by severity), and 170
  ATLAS AI/ML technique pages + 35 ATLAS mitigations, completing "one page per MITRE
  object" alongside the technique/mitigation pages. All internal links verified (0 broken)
- MITRE cross-framework crosswalk (`mitre/crosswalk.md`): technique <-> mitigation <->
  NIST 800-53 <-> D3FEND <-> CAPEC in one place, including a per-mitigation rollup of NIST
  families and D3FEND countermeasures (the join not expressed elsewhere)
- MITRE enriched per-object pages in `mitre/`: a browsable, ATT&CK-Navigator-style
  page for each object: 691 technique pages (tactics, platforms, mitigations, D3FEND
  countermeasures, CAPEC, NIST 800-53, detection strategies, and Team Star Wolf corpus
  prevalence where observed) and 44 mitigation pages with concrete how-to-implement
  guidance, mapped NIST families, and the techniques each counters. Cross-framework
  relationships (ATT&CK <-> Mitigation <-> D3FEND <-> CAPEC <-> NIST) in one place
- 16 step-by-step how-to guides in `guides/`, with a grouped hub: start-to-finish
  procedures (triage a CVE, build a detection, respond to ransomware, harden Windows/
  macOS, assess M365 with ScubaGear, run a purple-team exercise, start a vuln-mgmt
  program, and more), each with prerequisites, checkpoints, and links into the references (#18)
- Threat Report Almanac: an annotated index of the major annual threat reports,
  organized by methodology basis, with a critical-reading method and reading calendar (#18)
- Six program-layer references: Vulnerability Prioritization (SSVC/KEV/EPSS/VEX),
  Data Security, LOTL Detection, Edge & Network Device Security, Cyber Resilience & BCDR,
  and Security Data Engineering; CTEM reference expanded in depth (#15)
- A plain-English orientation block ("In one minute / Read this when / Start at /
  Pairs with") at the top of every reference document (#17)
- A dedicated site homepage (`HOME.md`) and the STARWOLF64 banner on both the README
  and the docsify cover (#16, #19, #20)

### Changed
- Redesigned the landing experience: navigation-first homepage, refreshed cover, tighter
  GitHub-facing README (#16)

## 2026-09-25

### Added
- Eight specialized-domain references: SPARTA (space systems), MITRE FiGHT (telecom/5G),
  MITRE EMB3D (embedded devices), Insider Threat program, macOS security, SaaS security,
  Post-Quantum migration, and Ransomware defense & resilience (#11)
- Viasat KA-SAT (2022) and Salt Typhoon (2024-2025) added to Notable Incidents (#13)

### Fixed
- Corrected ML-DSA and SLH-DSA signature sizes to the FIPS 204 / FIPS 205 final values (#12)
- Restructured the sidebar into coherent sections; repaired navbar clicks and the
  `/navigator/` 404 (#14)
- Reworked in-repo linking so shared navigation and body links resolve correctly on both
  GitHub and the docsify site (#8, #9, #10)

## 2026-08-28

### Added
- MITRE ATLAS (AI threats) and MITRE Engage (deception) references
- Redesigned the docs site: dark, branded, full-text searchable (#7)

## 2026-08-17

### Added
- CTEM (Continuous Threat Exposure Management) and MITRE F3 Fight Fraud Framework references (#6)

## 2026-08-16

### Added
- MITRE ATT&CK knowledge base: technique atlas, threat groups, mitigations, and datasets (#2)
- ICS and Mobile ATT&CK atlases; Software and Campaigns references (#3)
- Per-technique detail pages for all 691 ATT&CK Enterprise techniques (#4)
- Detection-engineering content and the completed CWE / CAPEC / D3FEND knowledge graph (#5)

## 2026-08-15

### Added
- Initial threat-informed defense layer, profile page, and coverage data (#1)
