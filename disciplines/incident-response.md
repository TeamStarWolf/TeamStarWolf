# Incident Response

Incident response is the structured process of detecting, containing, investigating, and recovering from security incidents. Effective IR combines technical forensics — acquiring volatile memory, disk images, network traffic, and logs — with operational coordination, legal considerations, and communication protocols. The discipline spans first-response triage through root cause analysis, and the lessons from each incident should feed directly back into the detection and prevention programs that reduce dwell time on the next intrusion.

Modern IR increasingly means cloud IR, where traditional forensic tools have no foothold and evidence is ephemeral, volatile, or gated behind cloud provider APIs. Practitioners who can only do Windows disk forensics will find themselves blocked in the environments where attackers operate most freely today. Building fluency in at least one cloud provider's logging and forensic capability is now a baseline expectation for IR practitioners entering the job market.

---

## Where to Start

Incident response demands operating system internals knowledge before the forensics makes sense. Understand Windows process structure, registry hives, the Windows Event Log architecture, and Linux filesystem hierarchy before trying to analyze artifacts from them. The DFIR Report publishes real-world incident timelines that are worth reading before any training course — nothing orients a new practitioner faster than seeing what an actual ransomware intrusion looks like from first access through encryption.

| Stage | Focus | Where to Begin |
|---|---|---|
| Foundation | OS internals (Windows/Linux), Windows Event Log analysis, memory concepts, incident handling methodology, chain of custody | SANS IR Summit talks (YouTube), BHIS IR webcasts, TryHackMe SOC and DFIR paths, The DFIR Report blog |
| Practitioner | Memory acquisition and analysis (Volatility 3), disk imaging (FTK Imager), timeline analysis (Plaso/Timesketch), network forensics, log correlation | Volatility Foundation docs, SANS FOR508 previews, 13Cubed YouTube, HTB Academy DFIR path |
| Advanced | Cloud IR (AWS/Azure/GCP), threat hunting during incidents, SOAR playbook development, malware triage during IR, deception integration | SANS FOR572/FOR608/FOR509, CISA IR guides, cloud provider IR documentation, Velociraptor docs |

---

## Free Training

- [SANS Incident Response Summit Talks](https://www.youtube.com/@SansInstitute) — Annual summit recordings covering advanced IR methodology, cloud forensics, threat hunting during incidents, and major breach case studies; free YouTube archive is essential viewing
- [Black Hills Information Security IR Webcasts](https://www.blackhillsinfosec.com/blog/webcasts/) — Free webcasts covering IR methodology, memory forensics, threat hunting, and detection during active incidents from working practitioners
- [Hack The Box Academy DFIR Path](https://academy.hackthebox.com) — Free Student tier covering Windows and Linux forensics, memory analysis, and network forensics with hands-on labs
- [Blue Team Labs Online](https://blueteamlabs.online) — Free investigation challenges covering log analysis, memory forensics, network pcap analysis, and realistic threat hunting scenarios
- [Volatility Foundation Documentation](https://volatilityfoundation.org) — Free documentation and community resources for the leading open-source memory forensics framework; plugin reference and training materials
- [CISA Incident Response Resources](https://www.cisa.gov/resources-tools/resources/incident-response) — Free federal guidance including the CISA Incident Response Playbook, ransomware guides, and cloud forensics guidance for critical infrastructure operators
- [13Cubed YouTube Channel](https://www.youtube.com/@13Cubed) — Exceptional free Windows forensics content covering artifact analysis, Volatility plugin walkthroughs, and incident investigation methodology; among the best free DFIR content available
- [TryHackMe DFIR Path](https://tryhackme.com) — Browser-based incident response and forensics labs with guided paths covering Windows forensics, memory analysis, and network investigation
- [The DFIR Report](https://thedfirreport.com) — Real-world IR case studies with detailed TTP timelines published from actual intrusions; the best source for understanding what ransomware and APT intrusions look like from first access through impact
- [Eric Zimmerman Tools Documentation](https://ericzimmerman.github.io) — Free documentation for the definitive Windows forensic tool suite; KAPE, MFTECmd, and 20+ other tools with usage guides and artifact reference

---

## Tools & Repositories

### Live Forensics & Triage
- [tclahr/uac](https://github.com/tclahr/uac) — Unix-like Artifacts Collector; shell script for live forensic artifact collection from Linux, macOS, AIX, and Solaris without installing tools on the target system; essential for cloud VM triage where you cannot install agents
- [Velocidex/velociraptor](https://github.com/Velocidex/velociraptor) — The modern enterprise IR platform; agent-based remote forensics at scale using the VQL query language; collect live artifacts from thousands of endpoints simultaneously; rapidly displacing older enterprise IR tooling
- [google/grr](https://github.com/google/grr) — Google's Rapid Response remote live forensics framework; agent-based remote acquisition and analysis at enterprise scale
- [CrowdStrike/Forensics](https://github.com/CrowdStrike/Forensics) — CrowdStrike open-source forensics scripts and utilities for Windows artifact collection and IR triage

### Memory Forensics
- [volatilityfoundation/volatility3](https://github.com/volatilityfoundation/volatility3) — The current production memory forensics framework; Python 3, symbol-based analysis, support for Windows, Linux, and macOS; the standard for offline memory dump analysis
- [volatilityfoundation/volatility](https://github.com/volatilityfoundation/volatility) — Volatility 2; still relevant for older Windows systems and an established plugin ecosystem; understand both versions for production IR work
- [ufrisk/MemProcFS](https://github.com/ufrisk/MemProcFS) — Memory Process File System; mounts a memory dump as a browsable virtual file system; reduces the barrier to exploring memory artifacts without requiring Volatility command fluency

### Disk & File System Forensics
- [sleuthkit/sleuthkit](https://github.com/sleuthkit/sleuthkit) — The foundational open-source digital forensics toolkit; file system analysis, deleted file recovery, and timeline generation; the engine underlying Autopsy
- [sleuthkit/autopsy](https://github.com/sleuthkit/autopsy) — GUI digital forensics platform built on The Sleuth Kit; the most accessible open-source forensic investigation platform for disk analysis and case management
- [EricZimmerman](https://github.com/EricZimmerman) — Eric Zimmerman's complete Windows forensic tool suite: KAPE for artifact collection, MFTECmd for MFT parsing, JLECmd for jump list analysis, ShellBagsExplorer, AppCompatCacheParser, and 20+ more; the gold-standard Windows IR toolkit

### Timeline Analysis
- [log2timeline/plaso](https://github.com/log2timeline/plaso) — Plaso super-timeline generator; aggregates hundreds of artifact types into a unified chronological timeline for event reconstruction; essential for complex multi-source incident timelines
- [google/timesketch](https://github.com/google/timesketch) — Collaborative timeline analysis platform built on Elasticsearch; the visualization layer that makes Plaso timelines usable during active investigations

### Network Forensics
- [wireshark/wireshark](https://github.com/wireshark/wireshark) — The universal packet analysis tool; essential for C2 traffic identification, lateral movement evidence, and data exfiltration reconstruction during network forensics
- [zeek/zeek](https://github.com/zeek/zeek) — Network analysis framework generating structured logs from pcap or live traffic; the backbone of NSM-based network forensics and the source for most network-based IR evidence
- [OISF/suricata](https://github.com/OISF/suricata) — IDS/IPS/NSM engine; run post-incident against stored pcap to identify malicious traffic patterns using community and custom rule sets

### SOAR & Case Management
- [TheHive-Project/TheHive](https://github.com/TheHive-Project/TheHive) — Open-source Security Incident Response Platform; case management, task tracking, MISP integration, and collaborative investigation workspace; the most deployed open-source IR case management tool
- [Shuffle/Shuffle](https://github.com/Shuffle/Shuffle) — Open-source SOAR platform with drag-and-drop playbook builder; workflow automation for repetitive IR tasks without commercial SOAR licensing costs
- [ansible/ansible](https://github.com/ansible/ansible) — Automation platform widely used for IR runbook automation; SSH-based, agentless, and excellent for writing repeatable containment and remediation playbooks

### Honeypots & Deception
- [cowrie/cowrie](https://github.com/cowrie/cowrie) — Medium-to-high interaction SSH/Telnet honeypot logging attacker commands, credentials, and file uploads; valuable for early warning and TTP collection against threat actors targeting your environment
- [telekom-security/tpotce](https://github.com/telekom-security/tpotce) — T-Pot all-in-one honeypot platform deploying 20+ honeypot daemons with ELK visualization; the fastest way to stand up a comprehensive honeypot environment for threat collection

---

## Commercial & Enterprise Platforms

| Platform | Role |
|---|---|
| **CrowdStrike Falcon** | Market-leading EDR with fastest response capability; Falcon Forensics for endpoint triage, Falcon OverWatch for 24/7 managed threat hunting, Falcon Complete for fully managed detection and response; the most commonly encountered platform in enterprise IR engagements |
| **SentinelOne Singularity** | EDR and XDR with autonomous response; Storyline reconstructs full attack chains; strong for rapid containment with minimal analyst intervention; Remote Shell for live response |
| **Palo Alto Cortex XSOAR** | The dominant enterprise SOAR platform; playbook automation, case management, and 700+ integration packs; the standard workflow automation platform in mature SOC environments |
| **Splunk SOAR (formerly Phantom)** | SOAR tightly integrated with Splunk SIEM; powerful for organizations already in the Splunk ecosystem; extensive community playbook library |
| **Microsoft Defender XDR** | Integrated XDR across endpoint, identity, email, and cloud; incident correlation across all Microsoft signal sources; strong ROI for Microsoft-heavy environments |
| **Mandiant Managed Defense** | Google-owned MDR service; the gold standard for organizations needing expert IR support without building in-house capability; extensive incident forensics and threat hunting |
| **Velociraptor (open-source, enterprise-ready)** | The fastest-growing open-source IR platform; enterprise-grade remote forensics without licensing costs; increasingly the preferred alternative for sophisticated teams |
| **IBM QRadar SOAR** | Mature SOAR platform from IBM; strong in regulated industries with existing QRadar SIEM investments |
| **Cado Security** | Cloud-native IR platform purpose-built for cloud forensics across AWS, Azure, and GCP; fills the gap left by traditional forensic tools in cloud environments |

---

## NIST 800-53 Control Alignment

NIST SP 800-53 governs IR program structure in U.S. federal environments and sets the baseline for FedRAMP, FISMA, and CMMC compliance. The IR-related controls define the minimum capabilities an organization must demonstrate: a documented IR capability, trained personnel, tested plans, and a process for incorporating lessons learned. This is the governance framework IR practitioners must understand when operating in or selling to regulated sectors.

| Control ID | Control Name | How Incident Response Addresses It |
|---|---|---|
| [IR-1](https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_0/home?element=IR-1) | Incident Response Policy and Procedures | The IR policy and plan document satisfies IR-1; establishes the organizational commitment to IR capability and the procedures for executing it |
| [IR-2](https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_0/home?element=IR-2) | Incident Response Training | IR team training programs, tabletop exercises, and practitioner certification satisfy IR-2; training must be role-based and include simulated exercises |
| [IR-3](https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_0/home?element=IR-3) | Incident Response Testing | Tabletop exercises, red team exercises, and simulated incident drills satisfy IR-3; the requirement to actually test — not just document — the IR plan |
| [IR-4](https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_0/home?element=IR-4) | Incident Handling | The core IR control: requires an incident handling capability covering preparation, detection, analysis, containment, eradication, and recovery; maps directly to the NIST SP 800-61 incident lifecycle |
| [IR-5](https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_0/home?element=IR-5) | Incident Monitoring | SIEM, EDR, and continuous monitoring programs satisfy IR-5; requires tracking and documenting incidents throughout their lifecycle |
| [IR-6](https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_0/home?element=IR-6) | Incident Reporting | Requires reporting incidents to organizational authorities and US-CERT/CISA within defined timeframes; incident ticket systems and escalation procedures satisfy this control |
| [IR-7](https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_0/home?element=IR-7) | Incident Response Assistance | SOAR platforms, IR retainers (Mandiant, CrowdStrike), and CISA coordination satisfy IR-7; requires external IR assistance resources |
| [IR-8](https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_0/home?element=IR-8) | Incident Response Plan | The documented IR plan including scope, roles, communication procedures, and escalation paths satisfies IR-8; must be reviewed and updated annually |
| [AU-6](https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_0/home?element=AU-6) | Audit Record Review, Analysis, and Reporting | Log analysis and SIEM correlation during IR satisfy AU-6; requires reviewing audit logs for indicators of attack and inappropriate activity |
| [SI-4](https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_0/home?element=SI-4) | System Monitoring | EDR, NDR, and SIEM monitoring tools that generate IR alerts satisfy SI-4; the detection capability that triggers the IR process |

---

## ATT&CK Coverage

Incident response is most effective when analysts can map observed behaviors to ATT&CK techniques in real time. This mapping allows responders to predict attacker next steps, identify what evidence to collect, and understand the full scope of an intrusion rather than chasing individual IOCs. MITRE ATT&CK was largely designed by practitioners who build these mental models during investigations.

| Technique | ID | How Incident Response Addresses It |
|---|---|---|
| Initial Access (all sub-techniques) | [TA0001](https://attack.mitre.org/tactics/TA0001/) | First-response forensics determines how attackers entered: email logs for phishing, web server logs for T1190, VPN logs for valid accounts; correctly identifying initial access prevents reinfection after remediation |
| Persistence | [TA0003](https://attack.mitre.org/tactics/TA0003/) | IR analysts hunt for persistence mechanisms — scheduled tasks, registry run keys, WMI subscriptions, cron jobs, startup items — to ensure complete eradication; missing a persistence mechanism means the attacker returns after remediation |
| Defense Evasion | [TA0005](https://attack.mitre.org/tactics/TA0005/) | Memory forensics and process analysis detect evasion techniques like process injection (T1055), timestomping (T1070.006), and log clearing (T1070.001); understanding evasion techniques determines what evidence is trustworthy |
| Credential Access | [TA0006](https://attack.mitre.org/tactics/TA0006/) | Credential dumping artifacts (LSASS memory dumps, SAM database access, DCSync events) are key IR evidence; scope of credential compromise determines password reset requirements across the environment |
| Lateral Movement | [TA0008](https://attack.mitre.org/tactics/TA0008/) | Network forensics (Zeek logs, Windows Security Event 4624/4625, SMB logs) maps attacker movement between systems; critical for scoping the incident and identifying all affected hosts |
| Collection | [TA0009](https://attack.mitre.org/tactics/TA0009/) | File access logs, cloud storage API logs, and DLP telemetry identify data staging and collection before exfiltration; determines what data was compromised for breach notification decisions |
| Exfiltration | [TA0010](https://attack.mitre.org/tactics/TA0010/) | Network traffic analysis, DNS logs, and proxy logs identify data leaving the environment; critical for breach notification scope determination and regulatory reporting |
| Command and Control | [TA0011](https://attack.mitre.org/tactics/TA0011/) | C2 infrastructure identification through network forensics (JA3/JA3S fingerprinting, Zeek SSL logs, DNS queries) enables containment and IOC extraction; blocking C2 is often the first containment action |
| Impact | [TA0040](https://attack.mitre.org/tactics/TA0040/) | Ransomware deployment (T1486), data destruction (T1485), and service disruption (T1489) are the terminal IR scenarios; rapid identification of impact scope drives recovery prioritization and business continuity decisions |

---

## Books & Learning

| Book | Author | Why Read It |
|---|---|---|
| Applied Incident Response | Steve Anson | Practical, hands-on Windows IR from an experienced practitioner; artifact analysis, memory forensics, and detection engineering integration with real investigation examples |
| The Art of Memory Forensics | Ligh, Case, Levy, Walters | The definitive memory forensics reference; covers Volatility, Windows/Linux/macOS memory structures, and malware detection in memory; required reading for DFIR practitioners |
| Incident Response & Computer Forensics (3rd ed.) | Luttgens, Pepe, Mandia | Mandia's foundational IR textbook covering process, methodology, and technical analysis; the standard reference in university and enterprise training programs |
| Digital Forensics with Open Source Tools | Altheide & Carvey | Practical open-source forensics workflows covering disk, registry, log, and network artifact analysis with free tooling |

---

## Learning Resources

| Type | Resource | Notes |
|---|---|---|
| Standard | [NIST SP 800-61r2](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf) | The federal IR standard defining the four-phase lifecycle (Preparation, Detection & Analysis, Containment/Eradication/Recovery, Post-Incident Activity); free and authoritative |
| Framework | [MITRE ATT&CK](https://attack.mitre.org) | Adversary behavior taxonomy; mapping observed TTPs to ATT&CK during an investigation produces structured threat intelligence and reveals attacker intent |
| Playbooks | [CISA IR Playbooks](https://www.cisa.gov/resources-tools/resources/federal-government-cybersecurity-incident-and-vulnerability-response-playbooks) | Federal IR playbooks for ransomware, data exfiltration, and vulnerability exploitation; adaptable templates for non-government organizations |
| Tool | [Velociraptor Documentation](https://docs.velociraptor.app) | The most capable free IR platform; covers deployment, VQL artifact queries, and remote forensic collection at enterprise scale |
| Tool | [Eric Zimmerman Tools](https://ericzimmerman.github.io) | The complete collection of Windows forensic tools with documentation; required bookmark for every Windows DFIR analyst |
| Tool | [Volatility 3 Documentation](https://volatility3.readthedocs.io) | Complete plugin reference and analysis methodology for the industry-standard memory forensics framework |
| Reference | [SANS DFIR Posters](https://www.sans.org/posters/?focus-area=digital-forensics) | Free reference cards covering Windows artifact locations, memory forensics workflow, and evidence collection procedures; printable field references |
| Blog | [The DFIR Report](https://thedfirreport.com) | Real-world intrusion timelines from actual ransomware and APT incidents; the best free resource for understanding what investigations actually look like |
| Course | [13Cubed YouTube](https://www.youtube.com/@13Cubed) | Free, deeply technical Windows forensics and DFIR video content; covers artifact analysis with real examples |
| Course | [Blue Team Labs Online](https://blueteamlabs.online) | Hands-on investigation challenges covering log analysis, memory forensics, and realistic threat scenarios |
| Community | [DFIR.training](https://dfir.training) | Aggregator of DFIR training resources, tools, and certifications maintained by the community |

---

## Certifications

- **GCFE** (GIAC Certified Forensic Examiner) — Windows and browser forensics; digital evidence acquisition and analysis methodology; strong entry-level DFIR credential for practitioners starting in host forensics
- **GCFA** (GIAC Certified Forensic Analyst) — Advanced incident investigation, memory forensics, and threat hunting; one of the most respected DFIR credentials available; pairs with SANS FOR508
- **GCIH** (GIAC Certified Incident Handler) — Incident handling methodology, detection, and response; the broadest IR certification covering the full incident lifecycle
- **eCIR** (eLearnSecurity Certified Incident Responder — INE Security, formerly eLearnSecurity) — Practical hands-on IR certification assessed via simulated incident investigation; strong entry-level credential from INE Security
- **BTL1** (Blue Team Labs Level 1 — Security Blue Team) — Practical SOC and IR certification covering six domain areas; lab-based assessment; strong validation for analysts entering IR roles

---

## Channels

- [13Cubed](https://www.youtube.com/@13Cubed) — The best free Windows forensics and DFIR content on YouTube; deeply technical artifact analysis, Volatility walkthroughs, and investigation methodology
- [Black Hills Information Security](https://www.youtube.com/@BlackHillsInformationSecurity) — IR methodology, threat hunting, and active defense; hundreds of free hours covering the full incident response lifecycle
- [SANS DFIR](https://www.youtube.com/@SansInstitute) — Summit recordings, FOR508/FOR572 previews, and forensics methodology from SANS DFIR course instructors
- [CrowdStrike](https://www.youtube.com/@CrowdStrike) — IR case studies, threat intelligence briefings, and Adversary Universe breakdowns showing real intrusion timelines
- [CISA](https://www.youtube.com/@cisagov) — Federal IR guidance, breach analysis publications, and critical infrastructure incident response advisories

---

## Who to Follow

- [@EricRZimmerman](https://x.com/EricRZimmerman) — Author of the definitive Windows forensic tool suite; Windows artifact analysis depth
- [@attrc](https://x.com/attrc) — Andrew Case; Volatility core developer; memory forensics expertise
- [@iamevltwin](https://x.com/iamevltwin) — Sarah Edwards; macOS forensics and APOLLO artifact analysis
- [@jackcr](https://x.com/jackcr) — Jack Crook; threat hunting methodology and detection-driven IR
- [@jaredcatkinson](https://x.com/jaredcatkinson) — PowerShell forensics and ATT&CK-driven detection and response
- [@MandiantIntel](https://x.com/MandiantIntel) — APT incident findings and IR methodology from the most active IR consulting firm
- [@CrowdStrike](https://x.com/CrowdStrike) — Adversary intelligence and IR case study publications
- [@dfirwizard](https://x.com/dfirwizard) — DFIR practitioner content, investigation methodology, and community challenges

---

## Key Resources

- [ATTACK-Navi](https://teamstarwolf.github.io/ATTACK-Navi/) — During active incidents, pivot from observed indicators and behaviors to ATT&CK techniques, identify the probable tactic sequence, and map detection gaps to close before the next incident
- [The DFIR Report](https://thedfirreport.com) — Real-world IR case studies with full TTP timelines; the most valuable free resource for understanding actual intrusion patterns
- [NIST SP 800-61r2](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf) — Free federal incident handling guide; the governance foundation for IR program design and the compliance baseline for regulated industries
- [SANS DFIR Posters](https://www.sans.org/posters/?focus-area=digital-forensics) — Free reference posters covering Windows artifact locations, memory forensics workflow, and evidence collection procedures
- [CISA IR Playbooks](https://www.cisa.gov/resources-tools/resources/federal-government-cybersecurity-incident-and-vulnerability-response-playbooks) — Federal IR playbooks for ransomware, data exfiltration, and vulnerability exploitation; adaptable for non-government organizations
- [Eric Zimmerman Tools](https://ericzimmerman.github.io) — The complete collection of Windows forensic tools; required bookmark for every Windows DFIR analyst
- [Velociraptor Documentation](https://docs.velociraptor.app) — The most capable free IR platform; documentation covers deployment, VQL queries, and IR artifact collection at scale

---

## Related Disciplines

Incident response sits at the intersection of nearly every security discipline. During an active incident, IR teams call on capabilities across the entire security program — and every other team should feed context into the investigation.

- [threat-intelligence.md](threat-intelligence.md) — Threat intelligence transforms raw IOCs into structured adversary context during an investigation; knowing that a C2 IP belongs to a specific threat actor group immediately expands the scope of investigation to include that actor's known TTPs; post-incident, the findings feed back as new threat intelligence
- [security-operations.md](security-operations.md) — SOC analysts are the first line of detection that triggers IR; the quality of detection content (SIEM rules, EDR detections, alert tuning) directly determines dwell time before an incident is declared; the SOC and IR team operate as a continuous loop where IR findings drive new detection logic
- [vulnerability-management.md](vulnerability-management.md) — Post-incident root cause analysis almost always reveals an unpatched vulnerability or misconfiguration as the initial access vector; IR findings should automatically feed VM remediation priorities; VM data (which hosts have critical unpatched CVEs) helps IR teams scope the blast radius during an active investigation
- [digital-forensics.md](digital-forensics.md) — Forensics is the technical core of incident investigation; IR defines the process and coordination while DFIR practitioners provide the artifact acquisition, analysis, and evidence preservation skills that make investigations defensible in legal proceedings
- [malware-analysis.md](malware-analysis.md) — Malware encountered during incidents (ransomware encryptors, backdoors, loaders, credential stealers) must be analyzed to understand capabilities, persistence mechanisms, and C2 protocols; malware analysis findings directly improve detection signatures and inform the scope of compromise
- [cloud-security.md](cloud-security.md) — Cloud IR requires fundamentally different skills and tools from on-premises IR; cloud providers (AWS, Azure, GCP) have specific forensic capabilities (CloudTrail, Azure Activity Logs, Cloud Audit Logs) and limitations (ephemeral compute, shared responsibility boundaries) that IR practitioners must understand before an incident occurs
- [devsecops.md](devsecops.md) — Software supply chain incidents (compromised CI/CD pipelines, malicious dependencies, build system breaches) require IR teams to investigate developer infrastructure that traditional IR playbooks do not cover; DevSecOps practitioners provide critical context about pipeline architecture, artifact provenance, and deployment processes during these investigations
