# Incident Response

Preparing for, detecting, containing, eradicating, and recovering from security incidents through structured investigation and coordinated response.

---

## Where to Start

Incident response is where preparation meets execution under pressure. The discipline spans four phases — preparation, detection and analysis, containment and eradication, and recovery — and your effectiveness in each depends on the work you did before the incident. Start with the Blue Team Field Manual to understand what evidence exists and how to collect it. Practice collecting Windows artifacts with KAPE in a lab environment. Then learn memory forensics with Volatility — it reveals what is running in memory right now, which disk forensics cannot always tell you. Build your case management workflow with TheHive before an incident forces you to improvise one.

| Stage | Focus | Where to Begin |
|---|---|---|
| Foundation | Windows artifacts, event log analysis, IR methodology, evidence handling | BTFM, Antisyphon SOC Core Skills, Blue Team Labs Online |
| Practitioner | Memory forensics, disk forensics, timeline analysis, network forensics | SANS FOR508, HTB Academy DFIR path, LetsDefend |
| Advanced | Malware triage, SOAR automation, large-scale IR, threat-informed response | GCFA, GCFE, eCIR, Eric Zimmerman toolset mastery |

---

## Free Training

- [Antisyphon: SOC Core Skills with John Strand](https://www.antisyphontraining.com/product/soc-core-skills-with-john-strand/) — Pay-what-you-can ($0+); incident triage, log analysis, and response fundamentals
- [BHIS Webcasts](https://www.blackhillsinfosec.com/blog/webcasts/) — Free IR-focused webcasts covering memory forensics, network analysis, and active response techniques
- [BHIS YouTube](https://www.youtube.com/@BlackHillsInformationSecurity) — RITA beaconing analysis, network forensics, and IR walkthroughs from the team behind Active Countermeasures
- [TCM Security](https://www.youtube.com/@TCMSecurityAcademy) — Free YouTube content covering malware analysis and IR concepts
- [TCM Academy Free Tier](https://academy.tcm-sec.com/courses) — 25+ hours of free on-demand content
- [Hack The Box Academy](https://academy.hackthebox.com) — Free Student tier; DFIR path with memory forensics, disk analysis, and network forensics modules
- [Blue Team Labs Online](https://blueteamlabs.online) — Free challenge-based IR and forensics investigations; closest thing to a real investigation in a lab
- [LetsDefend](https://letsdefend.io) — Simulated SOC IR exercises with guided triage workflows
- [13Cubed YouTube](https://www.youtube.com/@13Cubed) — Deep-dive Windows forensics and DFIR technique walkthroughs; free and consistently high quality
- [SANS DFIR Posters](https://www.sans.org/posters) — Free memory forensics, Windows forensics, and SIFT cheat sheets

---

## Tools & Repositories

### Live Forensics & Response
- [velociraptor](https://github.com/Velocidex/velociraptor) — Scalable live endpoint forensics, hunting, and incident response
- [SQLiteHunter](https://github.com/Velocidex/SQLiteHunter) — Hunt SQLite databases across endpoints for artifacts
- [registry_hunter](https://github.com/Velocidex/registry_hunter) — Remote registry forensics at scale
- [uac](https://github.com/mthcht/uac) — Unix-like artifact collector for IR on Linux/macOS
- [Aurora-Incident-Response](https://github.com/cyb3rfox/Aurora-Incident-Response) — Incident response documentation and playbook framework

### Memory Forensics
- [volatility3](https://github.com/volatilityfoundation/volatility3) — Memory forensics framework for analyzing RAM images
- [volatility](https://github.com/volatilityfoundation/volatility) — The original Volatility 2.x framework
- [DAMM](https://github.com/504ensicsLabs/DAMM) — Differential analysis of malware in memory

### Disk & File Forensics
- [autopsy](https://github.com/sleuthkit/autopsy) — Digital forensics platform with a GUI for Sleuth Kit
- [sleuthkit](https://github.com/sleuthkit/sleuthkit) — Command-line tools for disk image analysis

### Windows Forensics
- [KapeFiles](https://github.com/EricZimmerman/KapeFiles) — KAPE artifact collection targets and modules
- [RECmd](https://github.com/EricZimmerman/RECmd) — Registry explorer command-line tool
- [evtx](https://github.com/EricZimmerman/evtx) — Windows EVTX parser by Eric Zimmerman
- [python-evtx](https://github.com/williballenthin/python-evtx) — Pure Python EVTX parser
- [evtx](https://github.com/omerbenamram/evtx) — Fast Rust-based EVTX parser
- [MalConfScan](https://github.com/JPCERTCC/MalConfScan) — Volatility plugin for extracting malware configurations

### Timeline Analysis
- [plaso](https://github.com/log2timeline/plaso) — Log2timeline super timeline creation tool

### Network Forensics
- [rita](https://github.com/activecm/rita) — Detect C2 beaconing through statistical network analysis
- [BeaKer](https://github.com/activecm/BeaKer) — Beaconing visualization with Zeek and Elasticsearch
- [zeek-open-connections](https://github.com/activecm/zeek-open-connections) — Long open connection detection with Zeek
- [zeek-log-transport](https://github.com/activecm/zeek-log-transport) — Zeek log transport tooling
- [threat-hunting-labs](https://github.com/activecm/threat-hunting-labs) — Network-based threat hunting exercises

### Case Management & SOAR
- [TheHive](https://github.com/TheHive-Project/TheHive) — Scalable security incident response platform
- [Cortex](https://github.com/TheHive-Project/Cortex) — Observable analysis and active response engine
- [Cortex-Analyzers](https://github.com/TheHive-Project/Cortex-Analyzers) — Collection of analyzers for IOC enrichment
- [Shuffle](https://github.com/Shuffle/Shuffle) — Open source SOAR platform
- [python-apps](https://github.com/Shuffle/python-apps) — Shuffle automation app library
- [demisto-sdk](https://github.com/demisto/demisto-sdk) — XSOAR/Cortex development SDK
- [content](https://github.com/demisto/content) — Cortex XSOAR playbooks and integrations

### Honeypots & Deception
- [cowrie](https://github.com/cowrie/cowrie) — SSH and Telnet honeypot for capturing attacker behavior
- [tpotce](https://github.com/telekom-security/tpotce) — T-Pot multi-honeypot platform
- [glastopf](https://github.com/mushorg/glastopf) — Web application honeypot
- [conpot](https://github.com/mushorg/conpot) — ICS/SCADA honeypot

---

## Books & Learning

| Book | Author | Why Read It |
|---|---|---|
| Incident Response & Computer Forensics | Luttgens, Pepe & Mandia | The structured IR methodology reference — what to do when the alarm fires |
| The Art of Memory Forensics | Ligh, Case, Levy & Walters | The definitive memory forensics reference |
| Blue Team Field Manual (BTFM) | Clark & Robertson | Quick-reference IR commands for Windows, Linux, and network analysis |
| Applied Incident Response | Steve Anson | Practical IR with Windows artifacts, evidence collection, and TI integration |
| The Practice of Network Security Monitoring | Richard Bejtlich | NSM methodology and building a network-focused IR capability |

---

## Certifications

- **GCFE** (GIAC Certified Forensic Examiner) — Windows forensics artifacts and evidence handling; for practitioners who need to defend findings
- **GCFA** (GIAC Certified Forensic Analyst) — Advanced memory forensics and timeline analysis; the gold standard for forensic IR
- **GCIH** (GIAC Certified Incident Handler) — Detection, containment, and eradication of incidents; broad IR methodology
- **eCIR** (eLearnSecurity Certified Incident Responder) — Practical hands-on IR certification with lab-based assessment
- **BTL1** (Blue Team Labs Level 1) — Accessible hands-on certification covering IR, log analysis, and forensics; great first DFIR credential

---

## Channels

- [13Cubed](https://www.youtube.com/@13Cubed) — DFIR techniques, Windows forensics, and memory analysis walkthroughs; consistently the best free DFIR content available
- [Black Hills Information Security](https://www.youtube.com/@BlackHillsInformationSecurity) — Network IR, beaconing detection, Active Directory forensics, and incident response exercises
- [TCM Security](https://www.youtube.com/@TCMSecurityAcademy) — Malware analysis and IR fundamentals with accessible delivery
- [SANS Institute](https://www.youtube.com/@SansInstitute) — DFIR webinars and technique breakdowns from FOR508 instructors
- [John Hammond](https://www.youtube.com/@_JohnHammond) — Malware analysis, CTF forensics, and IR technique demonstrations

---

## Who to Follow

- [@EricRZimmerman](https://x.com/EricRZimmerman) — Eric Zimmerman; author of the most-used Windows forensic artifact tools
- [@inversecos](https://x.com/inversecos) — DFIR research and threat intelligence
- [@iamnickfury](https://x.com/iamnickfury) — DFIR practitioner and author
- [@jackcr](https://x.com/jackcr) — Jack Crook; DFIR and threat hunting
- [@DFIRScience](https://x.com/DFIRScience) — DFIR Science; forensics guides and walkthroughs
- [@AdrianCrenshaw](https://x.com/AdrianCrenshaw) — Irongeek; security presentations and IR research
- [@volatility](https://x.com/volatility) — Volatility framework updates
- [@REMnuxdotorg](https://x.com/REMnuxdotorg) — REMnux Linux distro for malware analysis

---

## Key Resources

- [ATTACK-Navi](https://teamstarwolf.github.io/ATTACK-Navi/) — Pivot from an incident's observed techniques to threat group attribution, CVE correlation, and detection coverage gaps across the ATT&CK matrix
- [Eric Zimmerman Tools](https://ericzimmerman.github.io) — The most comprehensive free Windows forensic artifact toolkit available
- [REMnux](https://remnux.org) — Free Linux distribution purpose-built for malware analysis and DFIR
- [SANS DFIR Cheat Sheets](https://www.sans.org/posters) — Free reference posters for memory forensics, Windows artifacts, and SIFT
- [SIFT Workstation](https://www.sans.org/tools/sift-workstation/) — Free DFIR Linux environment from SANS
- [Active Countermeasures](https://www.activecountermeasures.com) — RITA beaconing detection tool and free threat hunting resources from the BHIS team
- [Volatility Foundation](https://www.volatilityfoundation.org) — Home of the Volatility memory forensics framework
- [TheHive Project](https://thehive-project.org) — Open source IR platform for case management and observable enrichment
