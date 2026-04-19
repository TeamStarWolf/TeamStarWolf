# Purple Teaming & Adversary Simulation

> Bridging offensive and defensive security — using structured adversary emulation exercises to test, validate, and continuously improve detection and response capabilities.

## What Purple Team Engineers Do

- Design and execute adversary emulation plans based on threat intelligence and ATT&CK
- Coordinate joint red/blue exercises: run attacks, observe detection in real time, tune detections
- Validate detection coverage: confirm which ATT&CK techniques generate alerts and which don't
- Operate Breach and Attack Simulation (BAS) platforms for continuous automated testing
- Build and maintain adversary emulation libraries (Atomic Red Team, custom scripts)
- Produce detection gap reports and drive remediation roadmaps
- Run tabletop exercises for IR teams against realistic threat scenarios
- Measure and track detection KPIs: MTTD, detection rate by tactic, false negative rate

---

## Core Frameworks & Standards

| Framework | Purpose |
|---|---|
| [MITRE ATT&CK](https://attack.mitre.org/) | Adversary behavior taxonomy — the lingua franca of purple teaming |
| [MITRE ENGAGE](https://engage.mitre.org/) | Adversary engagement and deception framework |
| [TIBER-EU](https://www.ecb.europa.eu/paym/cyber-resilience/tiber-eu/html/index.en.html) | ECB threat intelligence-based red teaming framework |
| [CBEST (Bank of England)](https://www.bankofengland.co.uk/financial-stability/operational-resilience-of-the-financial-sector/cbest-implementation-guide) | UK financial sector red teaming |
| [PTES (Penetration Testing Execution Standard)](http://www.pentest-standard.org/index.php/Main_Page) | Comprehensive pentest methodology |
| [Atomic Red Team](https://atomicredteam.io/) | Open library of ATT&CK-mapped test procedures |
| [Purple Team Exercise Framework (PTEF)](https://github.com/scythe-io/purple-team-exercise-framework) | Structured purple team methodology |

---

## Free & Open-Source Tools

### Adversary Emulation & Simulation

| Tool | Purpose | Notes |
|---|---|---|
| [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) | ATT&CK-mapped attack tests | YAML-defined; thousands of techniques; Invoke-AtomicRedTeam runner |
| [CALDERA](https://github.com/mitre/caldera) | Automated adversary emulation | MITRE-built; agent-based; adversary profiles |
| [Invoke-AtomicRedTeam](https://github.com/redcanaryco/invoke-atomicredteam) | PowerShell ART runner | Run Atomic tests; log results; integrate with SIEM |
| [Prelude Operator](https://www.prelude.org/) | Adversary simulation platform | Free community tier; ATT&CK-mapped TTPs |
| [Sliver](https://github.com/BishopFox/sliver) | C2 framework for red/purple | Modern C2; use in controlled lab environments |
| [Metasploit](https://www.metasploit.com/) | Exploitation framework | Use for controlled technique emulation |
| [Empire](https://github.com/BC-SECURITY/Empire) | C2 + post-exploitation | PowerShell/Python agents; detection testing |

### Detection Validation

| Tool | Purpose | Notes |
|---|---|---|
| [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) | Coverage visualization | Map tested vs. detected techniques |
| [Sigma](https://sigmahq.io/) | Detection rules | Write/test detection rules against emulation results |
| [Splunk Attack Range](https://github.com/splunk/attack_range) | Detection testing lab | Automated lab deployment for Splunk detection testing |
| [DetectionLab](https://github.com/clong/DetectionLab) | Purple team lab | Pre-built Windows domain with logging stack |
| [VECTR](https://github.com/SecurityRiskAdvisors/VECTR) | Purple team tracking | Track exercises, coverage, findings |
| [Purple Team ATT&CK Automation (PTAA)](https://github.com/praetorian-inc/purple-team-attack-automation) | Automated ATT&CK testing | Python-based ATT&CK technique runner |

### Threat Intelligence for Emulation

| Tool | Purpose | Notes |
|---|---|---|
| [MISP](https://www.misp-project.org/) | Threat intel platform | Feed purple team scenarios with real threat data |
| [OpenCTI](https://www.opencti.io/) | Structured CTI | ATT&CK-mapped threat actor profiles |
| [TRAM](https://github.com/center-for-threat-informed-defense/tram) | Threat report ATT&CK mapper | Map CTI reports to ATT&CK techniques |

---

## Commercial Platforms

| Vendor | Capability | Notes |
|---|---|---|
| [SCYTHE](https://www.scythe.io/) | Enterprise BAS + purple team | Threat actor emulation; PTEF framework |
| [Cymulate](https://cymulate.com/) | Breach and Attack Simulation | Continuous automated security validation |
| [AttackIQ](https://attackiq.com/) | BAS platform | ATT&CK-aligned; Fire Drill scenarios |
| [Mandiant Security Validation](https://www.mandiant.com/advantage/security-validation) | BAS + purple team | Mandiant threat intelligence-driven |
| [XM Cyber](https://www.xmcyber.com/) | Attack path simulation | Continuous exposure management |
| [Picus Security](https://www.picussecurity.com/) | BAS platform | Simulate, measure, remediate |
| [PlexTrac](https://plextrac.com/) | Purple team reporting | Findings management + ATT&CK mapping |

---

## Exercise Methodology

### Purple Team Exercise Flow

```
1. PLAN
   ├── Define threat actors (based on threat intel)
   ├── Select ATT&CK techniques to test
   └── Define success criteria (detect / alert / respond)

2. EXECUTE (Red + Blue Together)
   ├── Red team runs technique
   ├── Blue team monitors in real time
   ├── Document: was it detected? Alert fired? Response triggered?
   └── Adjust detection if missed → retest immediately

3. ANALYZE
   ├── ATT&CK Navigator heatmap: green (detected) / red (missed)
   ├── Calculate detection rate by tactic
   └── Identify highest-risk gaps

4. REMEDIATE
   ├── Write/tune Sigma rules for missed techniques
   ├── Retest after rule deployment
   └── Track improvement over time
```

### Detection Outcome Matrix

| Technique Tested | Alert Fired | Root Cause | Priority |
|---|---|---|---|
| T1059.001 (PowerShell) | Yes | — | Baseline |
| T1055 (Process Injection) | No | Log source missing | P1 — Add Sysmon |
| T1003.001 (LSASS Dump) | Yes | — | Baseline |
| T1562.001 (Disable AV) | No | Rule not deployed | P1 — Deploy Sigma rule |

---

## ATT&CK Coverage

Purple teaming directly improves coverage across ALL tactics by identifying detection gaps. Key focus areas:

- **Defense Evasion** — typically the most undercovered tactic; emulation reveals blind spots
- **Execution** — scripting interpreters; Living off the Land (LotL) techniques
- **Credential Access** — LSASS dumping, Kerberoasting, credential harvesting
- **Lateral Movement** — PSExec, WMI, RDP, SMB — commonly missed without specific rules
- **Command & Control** — C2 beaconing, DNS tunneling, HTTPS C2

---

## Certifications

| Certification | Issuer | Focus |
|---|---|---|
| [GDAT](https://www.giac.org/certifications/defending-advanced-threats-gdat/) | GIAC | Defending Advanced Threats |
| [CRTO (Certified Red Team Operator)](https://training.zeropointsecurity.co.uk/courses/red-team-ops) | Zero Point Security | Red team C2 operations (Cobalt Strike) |
| [CRTL (Certified Red Team Lead)](https://training.zeropointsecurity.co.uk/courses/red-team-ops-ii) | Zero Point Security | Red team leadership and advanced TTPs |
| [GPEN](https://www.giac.org/certifications/penetration-tester-gpen/) | GIAC | Penetration testing fundamentals |
| [PNPT](https://www.tcm-sec.com/pnpt/) | TCM Security | Practical network penetration testing |
| [ATT&CK Fundamentals Badge](https://mad20.io/course-library/) | MAD20 | MITRE ATT&CK fundamentals |

---

## Learning Resources

| Resource | Type | Notes |
|---|---|---|
| [Atomic Red Team Documentation](https://atomicredteam.io/) | Reference | 800+ ATT&CK-mapped test procedures |
| [The C2 Matrix](https://www.thec2matrix.com/) | Reference | Compare C2 frameworks by feature |
| [Red Team Development & Operations (Joe Vest)](https://redteam.guide/) | Book | Comprehensive red team operations guide |
| [Adversary Emulation Library (CTID)](https://github.com/center-for-threat-informed-defense/adversary_emulation_library) | Free | Full adversary emulation plans (APT3, APT29, etc.) |
| [SCYTHE Purple Team Resources](https://www.scythe.io/purple-team) | Blog | Purple team methodology and case studies |
| [Detection Engineering Weekly](https://www.detectionengineering.net/) | Newsletter | Detection validation and purple team news |

---

## Related Disciplines

- [Detection Engineering](detection-engineering.md) — Building the detections purple team validates
- [Security Operations](security-operations.md) — Blue team side of purple exercises
- [Offensive Security](offensive-security.md) — Red team techniques used in emulation
- [Threat Intelligence](threat-intelligence.md) — Drives threat-actor-based emulation scenarios
- [Active Defense & Deception](active-defense-deception.md) — Testing deception efficacy in purple exercises
