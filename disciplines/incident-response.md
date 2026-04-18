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

## Books & Learning

| Book | Author | Why Read It |
|---|---|---|
| Applied Incident Response | Steve Anson | Practical, hands-on Windows IR from an experienced practitioner; artifact analysis, memory forensics, and detection engineering integration with real investigation examples |
| The Art of Memory Forensics | Ligh, Case, Levy, Walters | The definitive memory forensics reference; covers Volatility, Windows/Linux/macOS memory structures, and malware detection in memory; required reading for DFIR practitioners |
| Incident Response & Computer Forensics (3rd ed.) | Luttgens, Pepe, Mandia | Mandia's foundational IR textbook covering process, methodology, and technical analysis; the standard reference in university and enterprise training programs |
| Digital Forensics with Open Source Tools | Altheide & Carvey | Practical open-source forensics workflows covering disk, registry, log, and network artifact analysis with free tooling |

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
