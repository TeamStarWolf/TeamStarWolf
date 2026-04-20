# Purple Teaming & Adversary Simulation

Purple teaming is a structured security methodology that unites offensive (red) and defensive (blue) teams in a real-time, collaborative feedback loop. Unlike traditional red team engagements where attackers operate in isolation and defenders discover findings after the fact, purple teaming means both teams are present simultaneously: the red team executes adversary techniques while the blue team monitors detection tools in real time, validates alert firing, and tunes detections on the spot. Purple teaming is not a standalone team — it is a methodology, a mindset, and a process that any organization with red and blue capabilities can adopt. Security engineers, detection engineers, threat hunters, and incident responders all practice purple teaming techniques. Its value is highest when an organization already has a SIEM/EDR and wants to systematically validate that their investments catch real-world adversary behavior.

---

## Where to Start

| Level | Description | Free Resource |
|---|---|---|
| Beginner | Learn the MITRE ATT&CK framework, understand tactic/technique structure, and run your first Atomic Red Team test in a lab VM. | [ATT&CK Getting Started](https://attack.mitre.org/resources/getting-started/) |
| Intermediate | Build a purple team exercise using the Purple Team Exercise Framework (PTEF): scope a threat actor, select 10 techniques, execute with Atomic Red Team, validate detections, and document gaps. | [Purple Team Exercise Framework (PTEF)](https://github.com/scythe-io/purple-team-exercise-framework) |
| Advanced | Deploy CALDERA for automated adversary emulation, build custom adversary profiles from CTI reports, operate a C2 framework (Sliver or Havoc) in a lab, and drive ATT&CK coverage heatmaps with VECTR. | [MITRE CALDERA](https://github.com/mitre/caldera) |

---

## Free Training

| Platform | URL | What You Learn |
|---|---|---|
| MITRE ATT&CK | https://attack.mitre.org/resources/getting-started/ | ATT&CK framework structure, navigator, and use cases |
| Atomic Red Team | https://atomicredteam.io/ | Running ATT&CK-mapped tests, interpreting results |
| MITRE CALDERA | https://github.com/mitre/caldera | Automated adversary emulation, agent-based C2 |
| MITRE CTID | https://github.com/center-for-threat-informed-defense | Adversary emulation plans, threat-informed defense research |
| AttackIQ Academy | https://www.academy.attackiq.com/ | BAS concepts, ATT&CK alignment, detection validation |
| Detection Engineering Weekly | https://www.detectionengineering.net/ | Practical detection validation and purple team techniques |
| TryHackMe Red Team Path | https://tryhackme.com/paths | Hands-on offensive technique practice in controlled labs |
| SANS Cyber Aces | https://www.sans.org/cyberaces/ | Foundational skills for blue and red team participants |

---

## Tools & Repositories

| Tool | Purpose | Link |
|---|---|---|
| Atomic Red Team | 900+ ATT&CK-mapped YAML attack tests | https://github.com/redcanaryco/atomic-red-team |
| CALDERA | Automated adversary emulation platform (MITRE-built) | https://github.com/mitre/caldera |
| Invoke-AtomicRedTeam | PowerShell runner for Atomic tests with logging | https://github.com/redcanaryco/invoke-atomicredteam |
| Sliver | Modern open-source C2 framework for red/purple use | https://github.com/BishopFox/sliver |
| Havoc | C2 framework with advanced evasion capabilities | https://github.com/HavocFramework/Havoc |
| Prelude Operator | Adversary simulation platform (free community tier) | https://www.prelude.org/ |
| VECTR | Purple team exercise tracking, coverage, findings | https://github.com/SecurityRiskAdvisors/VECTR |
| ATT&CK Navigator | Coverage heatmap visualization tool | https://mitre-attack.github.io/attack-navigator/ |
| Sigma | Detection rule format for cross-SIEM portability | https://sigmahq.io/ |
| Stratus Red Team | Cloud-native ATT&CK emulation (AWS, Azure, GCP) | https://github.com/DataDog/stratus-red-team |
| Infection Monkey | Automated breach simulation across network segments | https://github.com/guardicore/monkey |
| TRAM | Maps threat reports to ATT&CK techniques via NLP | https://github.com/center-for-threat-informed-defense/tram |
| DetectionLab | Pre-built Windows domain lab with full logging stack | https://github.com/clong/DetectionLab |
| Splunk Attack Range | Automated Splunk detection testing lab | https://github.com/splunk/attack_range |

---

## Commercial Platforms

| Vendor | Capability | Notes |
|---|---|---|
| [SCYTHE](https://www.scythe.io/) | Enterprise BAS + purple team platform | PTEF framework; threat actor emulation library |
| [Cobalt Strike](https://www.cobaltstrike.com/) | Licensed red team C2 framework | Industry-standard adversary simulation; widely emulated by defenders |
| [AttackIQ](https://attackiq.com/) | BAS platform | ATT&CK-aligned; Fire Drill scenarios |
| [Cymulate](https://cymulate.com/) | Breach and Attack Simulation | Continuous automated security validation |
| [Mandiant Security Validation](https://www.mandiant.com/advantage/security-validation) | BAS + purple team | Mandiant threat-intelligence-driven campaigns |
| [XM Cyber](https://www.xmcyber.com/) | Attack path simulation | Continuous exposure management |
| [Picus Security](https://www.picussecurity.com/) | BAS platform | Simulate, measure, remediate |
| [PlexTrac](https://plextrac.com/) | Purple team reporting | Findings management + ATT&CK mapping |

---

## Purple vs. Red vs. Blue vs. BAS

Understanding the methodology differences prevents confusion when scoping engagements:

| Approach | Who Participates | Feedback Loop | Primary Output |
|---|---|---|---|
| Penetration Test | Red team only | Post-engagement report | Vulnerability list |
| Red Team Exercise | Red team (stealth) | Delayed; blue team unaware | Realistic adversary simulation |
| Purple Team Exercise | Red + Blue together | Real-time, technique by technique | Detection gap analysis + tuned rules |
| Breach & Attack Simulation (BAS) | Automated agents | Continuous, no humans required | Coverage metrics over time |
| Adversary Emulation | Red team using CTI profiles | Post-exercise | Realistic threat actor behavior replication |

**Key distinction**: Purple teaming is the structured methodology where detection validation happens in the same session as the attack. BAS tools (Atomic Red Team, CALDERA, Infection Monkey, Stratus Red Team for cloud) automate this at scale but lack the human judgment of a joint exercise.

---

## Purple Team Exercise Structure

A rigorous purple team exercise follows a repeatable lifecycle:

```
1. SCOPING
   Define threat actor profile (based on CTI: industry, TTPs, motivation)
   Select ATT&CK techniques to test (typically 10-20 per exercise)
   Define success criteria: detect / alert / block / respond

2. THREAT PROFILE BUILDING
   Map threat actor to ATT&CK techniques using TRAM or CTI reports
   Build detection hypothesis for each technique
   Document expected log sources and detection logic

3. EXECUTION (Red + Blue Together)
   Red team runs technique with agreed tooling
   Blue team monitors SIEM/EDR in real time
   Document outcome: alert fired / no alert / wrong alert / blocked
   If missed: tune detection -> retest immediately

4. DETECTION GAP ANALYSIS
   ATT&CK Navigator heatmap: green (detected) / red (missed) / yellow (partial)
   Root cause for misses: missing log source / wrong rule logic / telemetry gap
   Prioritize by risk: techniques used by relevant threat actors first

5. REMEDIATION
   Write or tune Sigma rules for missed techniques
   Deploy to SIEM/EDR
   Document remediation in VECTR

6. RETEST
   Re-execute missed techniques after detection deployment to confirm fix
```

---

## Detection Outcome Matrix

Tracking outcomes precisely is critical for measuring program value:

| Outcome | Definition | Priority |
|---|---|---|
| Alert Fired (True Positive) | Correct detection, correct attribution | Baseline; maintain |
| No Alert (False Negative) | Technique executed, nothing fired | P1 — write detection rule |
| Wrong Alert (Misattribution) | Alert fired but wrong technique/context | P2 — tune rule logic |
| Blocked (Prevention) | Endpoint or network control stopped execution | Validate; ensure detection also exists |
| Noisy Alert (False Positive flood) | Too many alerts to be actionable | P2 — tune to reduce noise |

**Key metrics**:
- **Technique coverage %** — percentage of tested ATT&CK techniques with at least one validated detection
- **MTTD per technique** — mean time to detect from execution timestamp to SIEM alert timestamp
- **Detection confidence level** — alert fires reliably across variations of the same technique
- **False negative rate by tactic** — identify which ATT&CK tactics have the weakest detection coverage

---

## ATT&CK Coverage

| Technique ID | Name | Tactic | Relevance |
|---|---|---|---|
| T1566 | Phishing | Initial Access | Primary initial access vector tested in most purple exercises |
| T1059 | Command and Scripting Interpreter | Execution | PowerShell, WMI, cmd — commonly used in emulation and frequently missed |
| T1078 | Valid Accounts | Defense Evasion / Persistence | Credential-based access bypasses many perimeter controls |
| T1003 | OS Credential Dumping | Credential Access | LSASS dump, SAM, NTDS — critical detection gaps identified in most exercises |
| T1021 | Remote Services | Lateral Movement | PSExec, WMI, RDP, SMB — requires specific rule coverage |
| T1055 | Process Injection | Defense Evasion | Classic EDR evasion technique; frequently undetected without Sysmon |
| T1562 | Impair Defenses | Defense Evasion | AV/EDR disable, log tampering — critical to detect before attacker entrenches |
| T1070 | Indicator Removal | Defense Evasion | Log clearing, timestomping — attacker cleanup that removes forensic evidence |

---

## NIST 800-53 Control Alignment

| Control | Family | Relevance |
|---|---|---|
| CA-2 | Security Assessment | Mandates periodic security control testing — purple exercises fulfill this requirement |
| CA-8 | Penetration Testing | Explicit requirement for adversary simulation and pen testing |
| RA-3 | Risk Assessment | Threat-actor-based exercise scope aligns risk assessment with realistic threats |
| SI-4 | System Monitoring | Purple exercises validate that SI-4 monitoring controls detect adversary techniques |
| IR-4 | Incident Handling | Tests whether detection triggers appropriate IR procedures |
| PM-30 | Supply Chain Risk Management | Ensures controls against supply-chain-delivered TTPs are tested |
| AU-6 | Audit Record Review | Validates that audit logs provide sufficient fidelity for detection |
| CA-7 | Continuous Monitoring | BAS platforms provide the continuous monitoring validation CA-7 envisions |
| SA-11 | Developer Security Testing | Adversary emulation validates developer-built security controls |
| SC-7 | Boundary Protection | Lateral movement testing validates boundary control effectiveness |

---

## Certifications

| Certification | Issuer | Focus |
|---|---|---|
| [PNPT (Practical Network Penetration Tester)](https://www.tcm-sec.com/pnpt/) | TCM Security | Practical offensive skills used in purple exercises |
| [CRTO (Certified Red Team Operator)](https://training.zeropointsecurity.co.uk/courses/red-team-ops) | Zero Point Security | C2 operations, adversary TTPs for emulation |
| [CRTL (Certified Red Team Lead)](https://training.zeropointsecurity.co.uk/courses/red-team-ops-ii) | Zero Point Security | Red team leadership and advanced TTPs |
| [GPEN](https://www.giac.org/certifications/penetration-tester-gpen/) | GIAC | Penetration testing fundamentals |
| [GDAT](https://www.giac.org/certifications/defending-advanced-threats-gdat/) | GIAC | Defending Advanced Threats — blue team side |
| [GRTP (GIAC Red Team Professional)](https://www.giac.org/certifications/red-team-professional-grtp/) | GIAC | Advanced red team operations and adversary emulation |
| [ATT&CK Fundamentals Badge](https://mad20.io/course-library/) | MAD20 | MITRE ATT&CK fundamentals |

---

## Learning Resources

| Resource | Type | Notes |
|---|---|---|
| [The Hacker Playbook 3 (Peter Kim)](https://www.thehackerplaybook.com/) | Book | Red team TTPs, C2 ops, lateral movement — essential for exercise design |
| [Purple Team Exercise Framework (PTEF)](https://github.com/scythe-io/purple-team-exercise-framework) | Framework | Scythe-published methodology for running structured exercises |
| [MITRE CTID Adversary Emulation Library](https://github.com/center-for-threat-informed-defense/adversary_emulation_library) | Free | Full emulation plans for APT3, APT29, FIN6, and others |
| [Atomic Red Team Documentation](https://atomicredteam.io/) | Reference | 900+ ATT&CK-mapped test procedures |
| [Red Team Development & Operations (Joe Vest)](https://redteam.guide/) | Book | Comprehensive red team operations guide |
| [The C2 Matrix](https://www.thec2matrix.com/) | Reference | Compare C2 frameworks by feature — essential for tool selection |
| [Detection Engineering Weekly](https://www.detectionengineering.net/) | Newsletter | Detection validation and purple team news |
| [SCYTHE Purple Team Resources](https://www.scythe.io/purple-team) | Blog | Purple team methodology and case studies |
| [AttackIQ Academy](https://www.academy.attackiq.com/) | Free Course | BAS and ATT&CK-driven security validation |

---

## Related Disciplines

- [Detection Engineering](detection-engineering.md) — Building the detections purple team validates; writing Sigma rules for identified gaps
- [Security Operations](security-operations.md) — Blue team side of purple exercises; SIEM/EDR operators who confirm alert firing
- [Offensive Security](offensive-security.md) — Red team techniques and C2 operations used in emulation campaigns
- [Threat Intelligence](threat-intelligence.md) — Drives threat-actor-based emulation scenarios and technique selection
- [Active Defense & Deception](active-defense-deception.md) — Testing deception efficacy and honeypot triggers in purple exercises
- [Incident Response](incident-response.md) — Purple exercises test whether IR playbooks activate correctly on detection
