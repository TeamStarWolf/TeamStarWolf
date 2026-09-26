# Changelog

All notable changes to this library are recorded here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). This project groups work
by the date its pull requests merged to `main` rather than by tagged release.

## 2026-09-26

### Added
- **16 step-by-step how-to guides** in `guides/`, with a grouped hub — start-to-finish
  procedures (triage a CVE, build a detection, respond to ransomware, harden Windows/
  macOS, assess M365 with ScubaGear, run a purple-team exercise, start a vuln-mgmt
  program, and more), each with prerequisites, checkpoints, and links into the references (#18)
- **Threat Report Almanac** — an annotated index of the major annual threat reports,
  organized by methodology basis, with a critical-reading method and reading calendar (#18)
- **Six program-layer references** — Vulnerability Prioritization (SSVC/KEV/EPSS/VEX),
  Data Security, LOTL Detection, Edge & Network Device Security, Cyber Resilience & BCDR,
  and Security Data Engineering; **CTEM reference expanded** in depth (#15)
- A **plain-English orientation block** ("In one minute / Read this when / Start at /
  Pairs with") at the top of every reference document (#17)
- A dedicated site homepage (`HOME.md`) and the **STARWOLF64 banner** on both the README
  and the docsify cover (#16, #19, #20)

### Changed
- Redesigned the landing experience: navigation-first homepage, refreshed cover, tighter
  GitHub-facing README (#16)

## 2026-09-25

### Added
- **Eight specialized-domain references** — SPARTA (space systems), MITRE FiGHT (telecom/5G),
  MITRE EMB3D (embedded devices), Insider Threat program, macOS security, SaaS security,
  Post-Quantum migration, and Ransomware defense & resilience (#11)
- Viasat KA-SAT (2022) and Salt Typhoon (2024–2025) added to Notable Incidents (#13)

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
