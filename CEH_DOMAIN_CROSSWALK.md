# CEH Domain Crosswalk

> **The CEH exam names the attack; this library teaches the defense behind it.** EC-Council's Certified Ethical Hacker (CEH v13, exam code 312-50) is built on the public [CEH Exam Blueprint v5.0](https://cert.eccouncil.org/wp-content/uploads/2024/04/CEH-Exam-Blueprint-v5.pdf) — **9 domains, 125 multiple-choice questions, 4 hours**. This page maps each domain onto the reference docs already in this library, but keeps the defender's lens throughout: every attack technique CEH asks you to recognize is here framed as something to detect, map to MITRE ATT&CK, and mitigate. It is an **original study map** built only from the official public blueprint and this library's own pages — not courseware, not a brain dump, and not a substitute for EC-Council's iLabs.

**Related:** [Certifications Reference](CERTIFICATIONS.md) · [Career Paths & Cert Roadmap](CAREER_PATHS.md) · [Penetration Testing Methodology](PENETRATION_TESTING_METHODOLOGY.md) · [Hands-On Labs](LABS.md) · [HackTheBox Learning Tracks](research/HTB_TRACKS.md) · [CTF Methodology](CTF_METHODOLOGY.md) · [Interview Prep](INTERVIEW_PREP.md)

| | |
|---|---|
| **Read this when** | you are studying for the CEH knowledge exam, deciding where in this library to prepare each domain, or checking which topics this library covers versus what needs official EC-Council courseware |
| **Start at** | [At a glance](#at-a-glance) for the domain-and-weight table, [The domain crosswalk](#the-domain-crosswalk) for the per-domain mapping, [Study-plan skeleton](#study-plan-skeleton) to sequence the work |

---

## At a glance

CEH v13 is the current program (released September 23, 2024; v12 is retired, and no v14 has been announced as of this writing). The knowledge exam draws on **20 courseware modules** grouped into **9 exam domains**. Unlike many certifiers, **EC-Council publishes both exact per-domain weights and exact per-sub-domain question counts** in Blueprint v5.0 — both are reproduced below as published.

| Domain | Weight | Questions | Defensive focus in this library |
|---|---|---|---|
| **1. Information Security and Ethical Hacking Overview** | 6% | 7 | Frameworks, ATT&CK-as-methodology, laws and controls |
| **2. Reconnaissance Techniques** | 17% | 21 | OSINT/footprinting, scan and enumeration detection |
| **3. System Hacking Phases and Attack Techniques** | 15% | 19 | Vuln assessment, credential/privesc defense, malware analysis |
| **4. Network and Perimeter Hacking** | 24% | 30 | L2/L3 attacks, phishing, DoS, perimeter and evasion detection |
| **5. Web Application Hacking** | 14% | 18 | OWASP Top 10, injection, secure coding, WAF/detection |
| **6. Wireless Network Hacking** | 5% | 6 | Wi-Fi/Bluetooth encryption, wireless hardening |
| **7. Mobile Platform, IoT, and OT Hacking** | 10% | 12 | Mobile/IoT/OT threat models and ATT&CK atlases |
| **8. Cloud Computing** | 5% | 6 | Cloud/container/K8s attack paths and posture |
| **9. Cryptography** | 5% | 6 | Algorithms, PKI, key management, PQC context |

The **question counts** above are EC-Council's exact figures, not estimates: Blueprint v5.0 publishes a per-sub-domain *Number of Questions* column, and those counts aggregate to the domain totals shown here and sum to exactly 125. They are **published, not derived from the weights** — a naive weight-times-125 calculation would misround several (6% × 125 = 7.5 would round to 8, but the blueprint publishes 7; 10% × 125 = 12.5 would round to 13, but the blueprint publishes 12). The **weights, by contrast, sum to 101%** — a rounding artifact in EC-Council's own blueprint, not an error in this table — so treat the *percentages* as approximate emphasis and the *question counts* as exact. Verify both against the [official blueprint](https://cert.eccouncil.org/wp-content/uploads/2024/04/CEH-Exam-Blueprint-v5.pdf) before you rely on them, since EC-Council revises blueprints between versions.

### Exam format

| Attribute | Knowledge exam | Practical exam (optional) |
|---|---|---|
| **Format** | Multiple choice | Live challenges in a lab range |
| **Items** | 125 questions | 20 challenges |
| **Duration** | 4 hours | 6 hours |
| **Passing score** | 60%–85% (cut score varies by exam form) | 60%–85% |
| **Exam code** | 312-50 | CEH (Practical) |

On the passing score: EC-Council's published exam pages give **60%–85% for both the knowledge exam and the Practical**. For the knowledge exam this is a genuine variable cut score, set per exam form by psychometric analysis. EC-Council does **not** publish a separate fixed cut score for the Practical on its official pages, so this crosswalk reports the official 60%–85% range rather than the specific figures (e.g. a fixed 70% / 14-of-20) that circulate in third-party write-ups but do not appear in EC-Council's own published materials. Confirm the current figure on EC-Council's [CEH (Practical)](https://www.eccouncil.org/train-certify/certified-ethical-hacker-ceh-practical/) page before you rely on it.

The knowledge exam is recognition-and-recall; the optional **Practical** is hands-on and is where legal lab time pays off. For the Practical and for genuine skill (not just the multiple-choice exam), practice only on **legal, authorized platforms** — this library indexes them in [Hands-On Labs](LABS.md), [HackTheBox Learning Tracks](research/HTB_TRACKS.md), and the [CTF Methodology](CTF_METHODOLOGY.md). This crosswalk never points to offensive how-to; it points to the platforms that let you practice within the law.

---

## How to read this crosswalk

Each domain below has four parts:

- **What it tests** — a plain-language summary of the domain's scope, in this library's own words, taken from the public blueprint's domain and sub-domain names (not from any courseware text).
- **In this library** — the reference pages that build the defender's understanding of those techniques. Every link has been verified to exist on disk.
- **Honest gap** — what the exam covers that this library does *not*, so you know where official EC-Council courseware, iLabs, or a wireless/mobile lab is required.
- **Study tip** — the one framing that turns memorization into understanding.

Throughout, the library's advantage over a pure exam-cram is that it pairs each attack with its **MITRE ATT&CK technique, detection telemetry, and mitigation** — see the [ATT&CK Technique Atlas](ATTACK_TECHNIQUE_ATLAS.md), [ATT&CK Mitigations Reference](ATTACK_MITIGATIONS_REFERENCE.md), [D3FEND Countermeasure Reference](D3FEND_REFERENCE.md), and [ATT&CK Detection Strategies](detections/strategies/README.md). Learning the defense alongside the attack is both better security practice and a more durable way to answer CEH's countermeasure questions.

---

## The domain crosswalk

### Domain 1 — Information Security and Ethical Hacking Overview (6%)

**What it tests.** Information-security fundamentals (CIA triad, threats, attack vectors), the hacking methodologies and frameworks CEH leans on (Cyber Kill Chain, MITRE ATT&CK, the classic hacking phases), core security controls, and the laws and standards an ethical hacker works under (authorization, scope, disclosure).

**In this library.**

| Topic | Page |
|---|---|
| **Security frameworks** | [Frameworks](FRAMEWORKS.md) |
| **ATT&CK as the modern methodology** | [Threat-Informed Defense](THREAT_INFORMED_DEFENSE_REFERENCE.md) · [ATT&CK Technique Atlas](ATTACK_TECHNIQUE_ATLAS.md) |
| **Laws, standards, and governance** | [GRC & Compliance](GRC_COMPLIANCE_REFERENCE.md) |
| **Information security controls** | [Enterprise Security Controls](ENTERPRISE_SECURITY_CONTROLS.md) · [Controls Mapping](CONTROLS_MAPPING.md) |
| **Engagement authorization and phases** | [Penetration Testing Methodology](PENETRATION_TESTING_METHODOLOGY.md) |
| **Terminology** | [Glossary](GLOSSARY.md) |

**Honest gap.** EC-Council's exact phrasing of the "phases of hacking," its specific list of information-security laws by region, and its preferred control taxonomy are courseware conventions — confirm the exam's exact terms in official Module 01 material.

**Study tip.** Treat MITRE ATT&CK tactics as the modern, testable replacement for CEH's older "hacking phases" model, and anchor the laws section to the ones you actually operate under. Authorization and scope are the ethical core the exam keeps returning to.

---

### Domain 2 — Reconnaissance Techniques (17%)

**What it tests.** Footprinting and reconnaissance (search engines, web services, social networks, WHOIS, DNS, email, and social-engineering-driven recon), scanning networks (host discovery, port and service discovery, OS fingerprinting, scanning past IDS/firewalls), and enumeration (NetBIOS, SNMP, LDAP, NTP/NFS, SMTP/DNS, and other service enumeration).

**In this library.**

| Topic | Page |
|---|---|
| **Footprinting / passive recon** | [OSINT Reference](OSINT_REFERENCE.md) · [OSINT discipline](disciplines/osint.md) |
| **Protocols behind enumeration** | [Networking Fundamentals](NETWORKING_FUNDAMENTALS.md) · [Network Protocols Reference](NETWORK_PROTOCOLS_REFERENCE.md) |
| **Services that get enumerated** | [Enterprise Infrastructure](ENTERPRISE_INFRASTRUCTURE.md) |
| **Recon/Discovery in ATT&CK** | [ATT&CK Technique Atlas](ATTACK_TECHNIQUE_ATLAS.md) |
| **Detecting scans and enumeration** | [ATT&CK Data Components & Log Sources](ATTACK_DATA_COMPONENTS.md) · [ATT&CK Detection Strategies](detections/strategies/README.md) |
| **Hands-on (legal)** | [Hands-On Labs](LABS.md) · [HackTheBox Learning Tracks](research/HTB_TRACKS.md) |

**Honest gap.** CEH drills specific tool syntax as recognition items (Nmap flag combinations, Recon-ng and theHarvester modules, WHOIS/DNS tooling). The library explains the techniques defensively but does not rehearse the tool-trivia format — that is what official iLabs provide.

**Study tip.** For every recon and enumeration technique, learn the log signature that detects it (a port-scan pattern, an SNMP sweep, a DNS zone-transfer attempt). Knowing what the defender sees is exactly what CEH's "countermeasures" sub-topics reward.

---

### Domain 3 — System Hacking Phases and Attack Techniques (15%)

**What it tests.** Vulnerability analysis (assessment concepts, classification, tools, reports), system hacking (gaining access, password cracking, vulnerability exploitation, privilege escalation, maintaining access and persistence, hiding files, clearing logs), and malware threats (trojans, viruses and worms, fileless malware, APT concepts, malware analysis, anti-malware).

**In this library.**

| Topic | Page |
|---|---|
| **Vulnerability assessment** | [Vulnerability Management](VULNERABILITY_MANAGEMENT_REFERENCE.md) · [Vulnerability Prioritization](VULNERABILITY_PRIORITIZATION_REFERENCE.md) · [CVE Reference](CVE_REFERENCE.md) |
| **Password cracking and its defense** | [Password Security](PASSWORD_SECURITY_REFERENCE.md) |
| **Privilege escalation** | [Privilege Escalation](PRIVESC_REFERENCE.md) |
| **Gaining access / persistence (AD)** | [Active Directory Attack Reference](ACTIVE_DIRECTORY_ATTACK_REFERENCE.md) |
| **Malware threats** | [Malware Analysis](MALWARE_ANALYSIS_REFERENCE.md) · [Malware Families](MALWARE_FAMILIES.md) · [Ransomware Defense](RANSOMWARE_DEFENSE_REFERENCE.md) |
| **Fileless / living-off-the-land** | [LOLBin/LOTL Detection](LOTL_DETECTION_REFERENCE.md) |
| **Detecting system hacking and log clearing** | [Endpoint Security](ENDPOINT_SECURITY_REFERENCE.md) · [ATT&CK Technique Atlas](ATTACK_TECHNIQUE_ATLAS.md) |

**Honest gap.** The exam's tool-recognition items (John/Hashcat modes, steganography utilities, specific rootkit families) and its taxonomy of persistence tricks are courseware-specific — official material covers the exact names and options CEH expects.

**Study tip.** Map each system-hacking step to its ATT&CK technique and the endpoint telemetry that catches it — for example, log clearing is T1070 and shows up as Windows Event ID 1102. The privilege-escalation and persistence chains are covered end-to-end in [Privilege Escalation](PRIVESC_REFERENCE.md) and the AD reference.

---

### Domain 4 — Network and Perimeter Hacking (24%)

This is the **single heaviest domain** — nearly a quarter of the exam. Weight your study time here first.

**What it tests.** Sniffing (MAC, DHCP, ARP-poisoning, spoofing, DNS-poisoning, plus sniffing detection), social engineering (techniques, insider threats, impersonation, identity theft), denial-of-service (DoS/DDoS techniques and botnets), session hijacking (application- and network-level), and evading IDS, firewalls, and honeypots.

**In this library.**

| Topic | Page |
|---|---|
| **Sniffing / L2–L3 attacks (defender's field guide)** | [Network Attacks Reference](NETWORK_ATTACKS_REFERENCE.md) |
| **Sniffing detection / packet analysis** | [Packet Analysis](PACKET_ANALYSIS_REFERENCE.md) · [Network Monitoring](NETWORK_MONITORING_REFERENCE.md) |
| **Perimeter and protocol defenses** | [Network Defense](NETWORK_DEFENSE_REFERENCE.md) · [Network Protocols Security](NETWORK_PROTOCOLS_SECURITY.md) |
| **Social engineering / phishing** | [Social Engineering](SOCIAL_ENGINEERING_REFERENCE.md) · [Email Security](EMAIL_SECURITY_REFERENCE.md) |
| **Insider threats** | [Insider Threat](INSIDER_THREAT_REFERENCE.md) |
| **Honeypots and evasion (both sides)** | [Honeypot & Deception](HONEYPOT_DECEPTION_REFERENCE.md) · [Deception Technology](DECEPTION_TECHNOLOGY_REFERENCE.md) · [MITRE Engage](ENGAGE_REFERENCE.md) |

**Honest gap.** Specific session-hijacking tool names, EC-Council's DDoS-attack taxonomy labels, and its IDS/firewall-evasion tool list are courseware conventions — verify exact terms in official material.

**Study tip.** [Network Attacks Reference](NETWORK_ATTACKS_REFERENCE.md) pairs every Layer 2 and routing attack with the switchport, monitoring, or protocol control that stops it — study the attack and its defense as one unit. Because this domain is 24% of the exam, mastering these attack/defense pairs is the highest-leverage thing you can do.

---

### Domain 5 — Web Application Hacking (14%)

**What it tests.** Hacking web servers (server attacks, attack methodology, patch management), hacking web applications (the full OWASP-style surface: client-side controls, authentication, authorization, access control, session management, injection and input validation, logic flaws, web services, web APIs, webhooks, and web shells), and SQL injection (types, methodology, evasion, countermeasures).

**In this library.**

| Topic | Page |
|---|---|
| **OWASP Top 10 and testing methodology** | [Web Application Security](WEB_APPLICATION_SECURITY_REFERENCE.md) · [Web Application Pentesting](WEB_APPLICATION_PENTESTING.md) |
| **Web services, APIs, webhooks** | [API Security](API_SECURITY_REFERENCE.md) |
| **Client-side controls (CSRF, clickjacking, CORS)** | [Browser Security](BROWSER_SECURITY_REFERENCE.md) |
| **Fixing the flaws (secure coding)** | [Secure Coding](SECURE_CODING_REFERENCE.md) |
| **Underlying weaknesses and patterns** | [CWE Weakness Reference](CWE_REFERENCE.md) · [CAPEC Attack Patterns](CAPEC_REFERENCE.md) |
| **Pipeline detection (SAST/DAST)** | [DevSecOps](DEVSECOPS_REFERENCE.md) |
| **Hands-on (legal)** | [Hands-On Labs](LABS.md) (PortSwigger Web Security Academy, PentesterLab) |

**Honest gap.** The web-server-attack and patch-management modules use EC-Council-specific tool and methodology naming; confirm those in official courseware.

**Study tip.** Work the free, legal **PortSwigger Web Security Academy** labs (indexed in [Hands-On Labs](LABS.md)) once per injection class, and for each one learn the fix in [Secure Coding](SECURE_CODING_REFERENCE.md) and the WAF/detection signature next to the attack. CEH's SQL-injection sub-domain is a full sixth of this domain — give it dedicated time.

---

### Domain 6 — Wireless Network Hacking (5%)

**What it tests.** Wireless concepts and encryption (WEP, WPA, WPA2, WPA3), wireless threats, wireless hacking methodology and tools, Bluetooth hacking, and wireless attack countermeasures and security tools.

**In this library.**

| Topic | Page |
|---|---|
| **Wi-Fi, Bluetooth, RFID/NFC, cellular — attacks and hardening** | [Wireless Security](WIRELESS_SECURITY_REFERENCE.md) |
| **RF/SDR fundamentals** | [SDR & RF Security](SDR_RF_SECURITY_REFERENCE.md) |
| **Protocol-level defenses** | [Network Protocols Security](NETWORK_PROTOCOLS_SECURITY.md) |

**Honest gap.** Aircrack-ng workflow specifics and EC-Council's Bluetooth-attack naming are hands-on and courseware-specific; real wireless practice also needs your own gear (see the home-lab builds in [Hands-On Labs](LABS.md)), since public ranges rarely include RF.

**Study tip.** Learn the encryption evolution WEP → WPA → WPA2 → WPA3 and the exact weakness each generation fixes (IV reuse, KRACK, offline PSK cracking, SAE). That single framing answers most wireless questions in a 5% domain that is easy to over-study.

---

### Domain 7 — Mobile Platform, IoT, and OT Hacking (10%)

**What it tests.** Hacking mobile platforms (Android and iOS attack vectors, mobile device management, security guidelines and tools) and IoT and OT hacking (concepts, attacks, hacking methodology, and countermeasures for both Internet-of-Things and operational-technology environments).

**In this library.**

| Topic | Page |
|---|---|
| **Mobile threat models and techniques** | [Mobile Security](MOBILE_SECURITY_REFERENCE.md) · [Mobile Attack Atlas](MOBILE_ATTACK_ATLAS.md) |
| **IoT and embedded devices** | [Firmware & IoT Security](FIRMWARE_IOT_SECURITY_REFERENCE.md) · [EMB3D Reference](EMB3D_REFERENCE.md) · [Edge & Network Device Security](EDGE_DEVICE_SECURITY_REFERENCE.md) |
| **OT / ICS** | [ICS/OT Security](ICS_OT_SECURITY_REFERENCE.md) · [ICS Attack Atlas](ICS_ATTACK_ATLAS.md) |
| **Specialized OT (automotive)** | [Automotive Security](AUTOMOTIVE_SECURITY_REFERENCE.md) |

**Honest gap.** CEH's specific MDM products, jailbreak/root tooling, and IoT/OT attack-tool names are courseware items; the library covers the threat models and defenses rather than the exam's tool list.

**Study tip.** Treat this as three mini-domains and lean on the ATT&CK-style taxonomies the library already provides — [Mobile Attack Atlas](MOBILE_ATTACK_ATLAS.md) (MITRE Mobile ATT&CK) and [ICS Attack Atlas](ICS_ATTACK_ATLAS.md) (ATT&CK for ICS) — so mobile, IoT, and OT each become a structured technique list instead of scattered facts.

---

### Domain 8 — Cloud Computing (5%)

**What it tests.** Cloud computing concepts, container technology, serverless computing, cloud computing threats, cloud hacking, and cloud security.

**In this library.**

| Topic | Page |
|---|---|
| **Cloud security posture and services** | [Cloud Security](CLOUD_SECURITY_REFERENCE.md) · [Cloud Security Benchmark](CLOUD_SECURITY_BENCHMARK.md) |
| **Cloud attack techniques and IAM paths** | [Cloud Attack Reference](CLOUD_ATTACK_REFERENCE.md) |
| **Containers and Kubernetes** | [Container Security](CONTAINER_SECURITY_REFERENCE.md) · [Kubernetes Security](KUBERNETES_SECURITY_REFERENCE.md) |
| **Cloud network and SaaS posture** | [Cloud Network Security](CLOUD_NETWORK_SECURITY.md) · [SaaS Security](SAAS_SECURITY_REFERENCE.md) |
| **Hands-on (legal)** | [Hands-On Labs](LABS.md) (AWSGoat, AzureGoat, CloudGoat) |

**Honest gap.** CEH keeps cloud largely provider-agnostic; this library goes deeper into AWS/Azure/GCP specifics than the exam requires, and the exam's container-attack naming may differ from the library's. Official courseware sets the exam's exact scope.

**Study tip.** Master two things that recur across CEH cloud items: the **shared-responsibility model** and the **SSRF-to-instance-metadata** privilege path. Practice safely on the deliberately-vulnerable cloud ranges (AWSGoat/AzureGoat) indexed in [Hands-On Labs](LABS.md).

---

### Domain 9 — Cryptography (5%)

**What it tests.** Cryptography concepts, encryption algorithms, cryptography tools, public key infrastructure (PKI), email encryption, disk encryption, cryptanalysis, and cryptography attack countermeasures.

**In this library.**

| Topic | Page |
|---|---|
| **Algorithms, PKI, cryptanalysis** | [Cryptography Reference](CRYPTOGRAPHY_REFERENCE.md) |
| **PKI trust and post-quantum context** | [Post-Quantum Migration](POST_QUANTUM_MIGRATION_REFERENCE.md) |
| **Key management** | [Secrets Management](SECRETS_MANAGEMENT_REFERENCE.md) |
| **Encryption at rest / in transit** | [Data Security](DATA_SECURITY_REFERENCE.md) |

**Honest gap.** Specific cryptography-tool names and EC-Council's list of named crypto attacks are courseware trivia; the library teaches the concepts rather than the exam's tool catalog.

**Study tip.** Memorize the families — symmetric (AES, 3DES), asymmetric (RSA, ECC, Diffie-Hellman), and hashing (SHA-2/3, bcrypt) — with their key sizes and use cases, and the PKI trust chain. CEH cryptography is mostly recognition, not computation.

---

## Honest gaps

Across all nine domains, the recurring gap is the same: **CEH is a tool-and-terminology exam layered on top of concepts, and this library teaches the concepts and their defenses, not the tool-recognition drills.** Where you will need official EC-Council courseware or iLabs regardless of how well this library prepares you:

| Gap | Why the library can't close it | Where to go |
|---|---|---|
| **Exact tool syntax and options** | The library explains techniques defensively, not exam tool-trivia | EC-Council iLabs / official courseware |
| **EC-Council's specific taxonomies** | Phase names, attack categories, and control lists are courseware conventions | Official Module material |
| **Wireless and mobile hands-on** | RF and device attacks need your own gear; public ranges rarely include them | [Home-lab builds in LABS.md](LABS.md) + own hardware |
| **The Practical exam's live challenges** | A hands-on lab exam, not a reading exercise | [HTB tracks](research/HTB_TRACKS.md), [LABS.md](LABS.md), [CTF Methodology](CTF_METHODOLOGY.md) |

None of this is a weakness in the library — it reflects that CEH intentionally tests breadth of attacker tooling, while this library is a defender's reference. The two are complementary: use official courseware for the exam's tool vocabulary, and use this library to actually understand and defend against what those tools do.

---

## Study-plan skeleton

A weight-proportional sequence. Adjust the calendar to your own timeline; the *order* matters more than the week numbers, because it front-loads the heaviest domains and builds concepts before tools.

| Phase | Domains | Focus | Library anchors | Legal hands-on |
|---|---|---|---|---|
| **1 — Foundations** | 1 | Methodology, ATT&CK, laws, authorization | [Frameworks](FRAMEWORKS.md), [Threat-Informed Defense](THREAT_INFORMED_DEFENSE_REFERENCE.md), [Pentest Methodology](PENETRATION_TESTING_METHODOLOGY.md) | — |
| **2 — Recon** | 2 (17%) | Footprinting, scanning, enumeration + their detection | [OSINT](OSINT_REFERENCE.md), [Network Protocols](NETWORK_PROTOCOLS_REFERENCE.md), [Detection Strategies](detections/strategies/README.md) | [LABS](LABS.md), [HTB tracks](research/HTB_TRACKS.md) |
| **3 — Network & perimeter** | 4 (24%) | The heaviest domain: sniffing, SE, DoS, hijacking, evasion | [Network Attacks](NETWORK_ATTACKS_REFERENCE.md), [Social Engineering](SOCIAL_ENGINEERING_REFERENCE.md), [Network Defense](NETWORK_DEFENSE_REFERENCE.md) | [LABS](LABS.md) |
| **4 — System hacking** | 3 (15%) | Vuln assessment, credentials, privesc, malware | [Vuln Management](VULNERABILITY_MANAGEMENT_REFERENCE.md), [Privilege Escalation](PRIVESC_REFERENCE.md), [Malware Analysis](MALWARE_ANALYSIS_REFERENCE.md) | [HTB tracks](research/HTB_TRACKS.md) |
| **5 — Web** | 5 (14%) | OWASP surface, injection, secure fixes | [Web App Security](WEB_APPLICATION_SECURITY_REFERENCE.md), [Secure Coding](SECURE_CODING_REFERENCE.md), [CWE](CWE_REFERENCE.md) | PortSwigger via [LABS](LABS.md) |
| **6 — Platforms** | 7 (10%) | Mobile, IoT, OT | [Mobile Attack Atlas](MOBILE_ATTACK_ATLAS.md), [Firmware & IoT](FIRMWARE_IOT_SECURITY_REFERENCE.md), [ICS/OT](ICS_OT_SECURITY_REFERENCE.md) | [LABS](LABS.md) |
| **7 — The light domains** | 6, 8, 9 (5% each) | Wireless, cloud, cryptography | [Wireless](WIRELESS_SECURITY_REFERENCE.md), [Cloud Security](CLOUD_SECURITY_REFERENCE.md), [Cryptography](CRYPTOGRAPHY_REFERENCE.md) | AWSGoat/AzureGoat via [LABS](LABS.md) |
| **8 — Consolidate** | all | ATT&CK/detection review, gap-fill with official iLabs, mock exams | [ATT&CK Atlas](ATTACK_TECHNIQUE_ATLAS.md), [D3FEND](D3FEND_REFERENCE.md), [CTF Methodology](CTF_METHODOLOGY.md) | Official EC-Council iLabs + [HTB](research/HTB_TRACKS.md) |

**Sequencing logic:** front-load Domains 2, 4, and 3 (56% of the exam combined); build the concept before the tool; and reserve official iLabs for the tool-syntax gaps this library intentionally leaves open. Always practice on authorized platforms only.

---

## Sources

- [Certified Ethical Hacker (CEH) — EC-Council](https://www.eccouncil.org/train-certify/certified-ethical-hacker-ceh/) — current version (v13), exam format, module count
- [CEH (Practical) — EC-Council](https://www.eccouncil.org/train-certify/certified-ethical-hacker-ceh-practical/) — the Practical exam's format, 20 challenges, 6-hour duration, and 60%–85% passing score
- [CEH Exam Blueprint v5.0 (PDF) — EC-Council](https://cert.eccouncil.org/wp-content/uploads/2024/04/CEH-Exam-Blueprint-v5.pdf) — the 9 domains, sub-domains, per-domain weights, and exact per-sub-domain question counts used throughout this page
- [CEH v13 brochure / syllabus — EC-Council](https://www.eccouncil.org/cehv13-brochure/) — courseware modules and program overview
- [MITRE ATT&CK](https://attack.mitre.org/) — the technique taxonomy this crosswalk uses to reframe each domain defensively
- [OWASP](https://owasp.org/) — the web-application weakness framing behind Domain 5

---

*Certified Ethical Hacker, CEH, and the CEH logo are trademarks of the EC-Council. This crosswalk is an independent study aid built solely from EC-Council's public exam blueprint and this library's own pages; it is not affiliated with, authorized by, or endorsed by the EC-Council, reproduces no courseware or exam content, and is no substitute for official EC-Council training. Verify the current domains, weights, and exam format against EC-Council's published blueprint before relying on them.*
