# Digital Forensics

Digital forensics is the application of scientific methods to the identification, preservation, analysis, and presentation of digital evidence. It spans disk forensics (file system analysis, deleted file recovery, timeline reconstruction), memory forensics (live capture of volatile data, malware hunting in RAM), network forensics (packet capture analysis, flow reconstruction), mobile forensics, and cloud forensics. Unlike incident response — which prioritizes rapid containment — forensics prioritizes evidence integrity and legal defensibility. The two disciplines overlap significantly in DFIR (Digital Forensics and Incident Response) roles.

---

## Where to Start

Start with the foundational skill: disk forensics. Learn the evidence handling chain of custody before touching any tools. Then move to memory forensics since most active threats live in RAM, and then to network forensics for traffic analysis.

1. Understand evidence handling: chain of custody, write blockers, hash verification (MD5/SHA-256)
2. Learn the [Sleuth Kit / Autopsy](https://www.autopsy.com/download/) — the most accessible open-source forensic platform
3. Work through [Eric Zimmermann’s tools](https://ericzimmerman.github.io/) — the definitive Windows artifact toolkit
4. Learn [Volatility 3](https://github.com/volatilityfoundation/volatility3) — the standard for memory forensics
5. Practice on [CyberDefenders](https://cyberdefenders.org) — free DFIR challenges with real forensic images
6. Work through [SANS Posters & Cheat Sheets](https://www.sans.org/blog/the-ultimate-list-of-sans-cheat-sheets/) for Windows and Linux forensics quick reference

---

## Free Training

| Resource | What You Learn |
|---|---|
| [CyberDefenders](https://cyberdefenders.org) | Free DFIR challenges: memory dumps, disk images, PCAP analysis, incident reconstruction |
| [Blue Team Labs Online](https://blueteamlabs.online) | Free forensic investigation and log analysis labs |
| [DFIR.training](https://www.dfir.training) | Community-maintained registry of free DFIR tools and training resources |
| [13Cubed YouTube](https://www.youtube.com/@13Cubed) | Windows forensics, Volatility, and DFIR walkthroughs — practitioner-level |
| [TCM Security — Practical Malware Analysis & Triage (free tier)](https://academy.tcm-sec.com) | Malware analysis and basic DFIR methodology |
| [Volatility Foundation Documentation](https://volatility3.readthedocs.io) | Official Volatility 3 plugin reference and usage guides |
| [SANS Digital Forensics Blog](https://www.sans.org/blog/) | Regular posts from SANS instructors on current forensic techniques |
| [OpenSecurity Training 2](https://ost2.fyi) | Advanced x86/x64 and malware analysis courses — free |

---

## Tools & Repositories

### Disk & File System Forensics

| Tool | Purpose | Link |
|---|---|---|
| **Autopsy / Sleuth Kit** | GUI-based disk forensics platform — timeline, file recovery, keyword search | [sleuthkit/autopsy](https://github.com/sleuthkit/autopsy) |
| **Eric Zimmermann Tools (EZ Tools)** | Suite of 30+ Windows artifact parsers: MFT, Registry, LNK, Prefetch, Amcache, ShimCache | [ericzimmerman.github.io](https://ericzimmerman.github.io/) |
| **KAPE** — Kroll Artifact Parser and Extractor | Triage collection and artifact parsing — most widely used in enterprise DFIR | [github.com/EricZimmerman/KapeFiles](https://github.com/EricZimmerman/KapeFiles) |
| **FTK Imager (free)** | Disk imaging, evidence acquisition, hash verification | [AccessData / Exterro](https://www.exterro.com/ftk-product-family/ftk-imager) |
| **Plaso / log2timeline** | Supertimeline generation from disk artifacts, logs, browser history | [log2timeline/plaso](https://github.com/log2timeline/plaso) |
| **Velociraptor** | Endpoint triage, artifact collection, live forensics at scale | [Velocidex/velociraptor](https://github.com/Velocidex/velociraptor) |

### Memory Forensics

| Tool | Purpose | Link |
|---|---|---|
| **Volatility 3** | The standard memory forensics framework — Windows, Linux, macOS | [volatilityfoundation/volatility3](https://github.com/volatilityfoundation/volatility3) |
| **MemProcFS** | Virtual file system over memory dump — browse processes, files, registry from a memory image | [ufrisk/MemProcFS](https://github.com/ufrisk/MemProcFS) |
| **Rekall** (archived) | Memory forensics framework — largely superseded by Volatility 3 | [google/rekall](https://github.com/google/rekall) |

### Network Forensics

| Tool | Purpose | Link |
|---|---|---|
| **Wireshark** | Packet capture analysis — the universal PCAP tool | [wireshark/wireshark](https://github.com/wireshark/wireshark) |
| **NetworkMiner** | Passive network sniffer and PCAP parser — reconstructs files and credentials from traffic | [netresec.com/networkminer](https://www.netresec.com/?page=NetworkMiner) |
| **Zeek (formerly Bro)** | Network protocol analyzer generating structured logs — used heavily in DFIR and NSM | [zeek/zeek](https://github.com/zeek/zeek) |
| **Arkime (formerly Moloch)** | Full-packet capture and PCAP indexing at scale | [arkime/arkime](https://github.com/arkime/arkime) |

### Artifact Analysis & Utilities

| Tool | Purpose | Link |
|---|---|---|
| **Hayabusa** | Windows event log threat hunting and timeline generation | [Yamato-Security/hayabusa](https://github.com/Yamato-Security/hayabusa) |
| **Chainsaw** | Fast Windows event log triage using Sigma rules | [WithSecureLabs/chainsaw](https://github.com/WithSecureLabs/chainsaw) |
| **RegRipper** | Windows Registry artifact extraction and analysis | [keydet89/RegRipper3.0](https://github.com/keydet89/RegRipper3.0) |
| **Hindsight** | Chrome/Chromium browser artifact forensics | [obsidianforensics/hindsight](https://github.com/obsidianforensics/hindsight) |
| **UAC** — Unix-like Artifacts Collector | Triage collection for Linux/macOS/Unix systems | [tclahr/uac](https://github.com/tclahr/uac) |

---

## Commercial & Enterprise Platforms

| Platform | Category | Key Capabilities |
|---|---|---|
| **EnCase Forensic** — OpenText | Disk & Enterprise Forensics | Court-accepted evidence acquisition and analysis, comprehensive Windows/Linux/macOS support |
| **Magnet AXIOM** | All-in-One DFIR | Disk, mobile, cloud, and memory forensics in a single platform; widely used by law enforcement and corporate investigators |
| **Cellebrite UFED** | Mobile Forensics | Industry standard for mobile device extraction — physical, logical, cloud acquisition |
| **Nuix** | Large-Scale Evidence Processing | eDiscovery-grade processing of massive evidence sets; used in high-stakes litigation and government investigations |
| **Oxygen Forensic Detective** | Mobile & Cloud Forensics | Mobile devices, cloud services, drones, and IoT forensics |
| **Exterro (FTK Suite)** | Enterprise DFIR & eDiscovery | Full forensic investigation platform with legal hold and eDiscovery integration |
| **Cado Security** | Cloud & Container Forensics | Automated forensic acquisition for AWS/Azure/GCP — addresses the ephemeral evidence challenge in cloud environments |
| **CrowdStrike Falcon Forensics** | EDR-Based Forensics | Remote forensic collection from CrowdStrike-managed endpoints at enterprise scale |

---

## Books & Learning

| Resource | Focus |
|---|---|
| *The Art of Memory Forensics* — Ligh, Case, Levy & Walters | The definitive memory forensics textbook — Volatility-based, covers Windows/Linux/macOS |
| *File System Forensic Analysis* — Brian Carrier | Deep coverage of FAT, NTFS, ext, HFS+ file systems and their forensic artifacts |
| *Digital Forensics with Open Source Tools* — Altheide & Carvey | Practical open-source forensics methodology |
| *Placing the Suspect Behind the Keyboard* — Brett Shavers | Windows artifact investigation for attribution |
| *Intelligence-Driven Incident Response* — Beyer & Cloppert | Combining forensics with threat intelligence for structured DFIR |
| *Windows Forensics Cookbook* — Scar de Courcier & Others | Practical recipes for Windows artifact analysis |

---

## Certifications

| Certification | Issuer | What It Validates |
|---|---|---|
| **GCFE** — GIAC Certified Forensic Examiner | GIAC/SANS | Windows forensics, artifact analysis, incident timeline reconstruction |
| **GCFA** — GIAC Certified Forensic Analyst | GIAC/SANS | Advanced memory forensics, malware analysis, intrusion investigation |
| **GASF** — GIAC Advanced Smartphone Forensics | GIAC/SANS | Mobile device forensics — iOS and Android acquisition and analysis |
| **GNFA** — GIAC Network Forensic Analyst | GIAC/SANS | Network traffic analysis, protocol dissection, intrusion reconstruction from PCAP |
| **GREM** — GIAC Reverse Engineering Malware | GIAC/SANS | Malware analysis in forensic context — static and dynamic techniques |
| **CCE** — Certified Computer Examiner | ISFCE | Vendor-neutral computer forensics examination certification |
| **CFCE** — Certified Forensic Computer Examiner | IACIS | Law enforcement-focused computer forensics certification |
| **EnCE** — EnCase Certified Examiner | OpenText | EnCase platform proficiency — widely recognized in legal proceedings |

---

## YouTube Channels

| Channel | Focus |
|---|---|
| [13Cubed](https://www.youtube.com/@13Cubed) | Windows forensics, Volatility, KAPE, registry analysis — best free DFIR channel |
| [SANS Digital Forensics](https://www.youtube.com/user/robtlee) | SANS instructor content — memory, disk, and network forensics |
| [CyberDefenders](https://www.youtube.com/@CyberDefenders) | DFIR challenge walkthroughs |
| [John Hammond](https://www.youtube.com/@_JohnHammond) | CTF and forensic challenge walkthroughs |
| [Forensic Focus](https://www.forensicfocus.com/webinars/) | Professional DFIR webinars — mobile, cloud, legal |

---

## Who to Follow

| Handle | Focus |
|---|---|
| [@EricZimmermann](https://twitter.com/EricZimmermann) | Windows forensic artifacts — creator of EZ Tools and KAPE |
| [@hexacorn](https://twitter.com/hexacorn) | Windows internals, persistence research, forensic artifacts |
| [@mattnotmax](https://twitter.com/mattnotmax) | Hayabusa, threat hunting, Windows forensics |
| [@iamevltwin](https://twitter.com/iamevltwin) | macOS and iOS forensics |
| [@TheHexNinja](https://twitter.com/TheHexNinja) | Memory forensics and Volatility |
| [@4n6lady](https://twitter.com/4n6lady) | Forensics practitioner and educator |
| [@forensicmike1](https://twitter.com/forensicmike1) | Mobile forensics practitioner |

---

## Key Resources

- [DFIR.training — Free Tools & Training Registry](https://www.dfir.training)
- [Eric Zimmermann’s Windows Artifact Tools](https://ericzimmerman.github.io/)
- [Volatility 3 Documentation](https://volatility3.readthedocs.io/)
- [SANS FOR508 Poster — Advanced Incident Response](https://www.sans.org/posters/hunt-evil/)
- [Magnet AXIOM Free Training](https://www.magnetforensics.com/training/)
- [CyberDefenders Free Forensic Labs](https://cyberdefenders.org)
- [NIST SP 800-86 — Guide to Integrating Forensic Techniques](https://csrc.nist.gov/publications/detail/sp/800-86/final)
