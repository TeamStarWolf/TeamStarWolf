# OSINT

Open Source Intelligence (OSINT) is the discipline of collecting, processing, analyzing, and acting on information derived from publicly available sources. In cybersecurity, OSINT spans everything from pre-engagement reconnaissance to persistent threat actor tracking, brand protection, fraud investigation, and vulnerability surface mapping. The defining constraint is that all sources must be publicly accessible — no unauthorized access, no credential theft, no exploitation. The discipline requires rigorous methodology, strong operational security, and careful legal and ethical awareness.

OSINT is not passive browsing. Professional OSINT work involves structured collection plans, source validation frameworks, link analysis, and documented intelligence products. The same data that helps a red team map an attack surface also helps a threat intelligence analyst track a criminal actor, a fraud investigator build a case, or a security team identify exposed credentials before attackers do. The discipline underlies all of them.

---

## Where to Start

Start with passive reconnaissance against your own infrastructure. Use Shodan to find exposed services, search GitHub for leaked credentials, query DNS records, and review what information your organization exposes publicly. This builds intuition about what adversaries see before engaging any external target. Then learn the OSINT Framework taxonomy to understand the full collection landscape.

| Stage | Focus | Where to Begin |
|---|---|---|
| Foundation | Passive recon methodology, OSINT Framework taxonomy, Google dorking, DNS/WHOIS enumeration, Shodan basics, email and username investigation | OSINT Framework (osintframework.com), Michael Bazzell's OSINT Techniques book (Part 1), TraceLabs CTF practice |
| Practitioner | Maltego graph analysis, SpiderFoot automation, social media investigation, image and geolocation analysis (GEOINT), dark web monitoring, operational security for analysts | Michael Bazzell IntelTechniques courses, Bellingcat investigation guides, SANS FOR578 content |
| Advanced | Threat actor attribution, automated collection pipelines, MISP/OpenCTI integration, corporate intelligence, custom tool development, legal and ethical frameworks for evidence | SANS FOR578 (Cyber Threat Intelligence), Bellingcat advanced workshops, TraceLabs competitions, OSINT Curious deep dives |

---

## Free Training

- [OSINT Framework](https://osintframework.com) — The most comprehensive taxonomy of OSINT tools and techniques organized by target type; the mandatory first reference for any analyst learning the collection landscape; maintained by Justin Nordine
- [Bellingcat](https://www.bellingcat.com) — The world's leading open source investigation outlet; publishes detailed methodology breakdowns alongside every major investigation; the best free resource for geolocation, image analysis, and corporate structure investigation techniques
- [Michael Bazzell's OSINT Podcast (The Privacy, Security, & OSINT Show)](https://inteltechniques.com/podcast.html) — Hundreds of free episodes covering current OSINT tools, techniques, and methodologies; the most practical free OSINT audio content available
- [TraceLabs](https://www.tracelabs.org) — Crowd-sourced missing persons CTF competitions using real OSINT; the most realistic free training environment available; produces actual intelligence for law enforcement while teaching practical collection skills
- [OSINT Curious](https://osintcuriosity.com) — Community-driven OSINT education including the 10 Minute Tip series, webcast recordings, and methodology guides; accessible content across all experience levels
- [Google Dorking Reference](https://www.exploit-db.com/google-hacking-database) — The Google Hacking Database (GHDB) from Exploit-DB; thousands of documented search operator combinations for finding exposed credentials, configuration files, and sensitive data
- [Shodan Fundamentals](https://help.shodan.io) — Free documentation and tutorials for the most powerful internet-facing asset search engine; learning Shodan is mandatory for any OSINT practitioner working in cybersecurity
- [Maltego Community Edition](https://www.maltego.com/downloads/) — Free tier of the leading link analysis and visualization platform; the standard graph analysis tool for professional OSINT investigations; learn transforms and entity relationships before moving to paid tiers

---

## Tools & Repositories

### OSINT Frameworks
- [paterva/maltego](https://www.maltego.com) — The industry-standard graph-based intelligence analysis and visualization platform; connects entities (people, domains, IPs, organizations) through transforms and maps relationships visually; used by intelligence analysts, law enforcement, and corporate investigators worldwide
- [smicallef/spiderfoot](https://github.com/smicallef/spiderfoot) — Automated OSINT collection framework with 200+ modules covering domains, IPs, emails, usernames, and threat intelligence sources; supports passive and active collection modes; runs as a web UI or CLI; the most capable open-source automation framework
- [lanmaster53/recon-ng](https://github.com/lanmaster53/recon-ng) — Modular web reconnaissance framework with a familiar Metasploit-style interface; organized workspaces for structured collection; modules for domain enumeration, contact harvesting, and credential searching
- [laramies/theHarvester](https://github.com/laramies/theHarvester) — Fast email, subdomain, IP, and URL collection from public sources including Google, Bing, LinkedIn, Shodan, and VirusTotal; the standard first-pass passive recon tool for penetration testing and security assessments
- [osintframework.com](https://osintframework.com) — The definitive browser-based taxonomy of OSINT tools organized by intelligence type and collection category; the reference map every analyst should know

### Domain & IP Intelligence
- [Shodan](https://shodan.io) — The most powerful search engine for internet-connected devices and services; indexes banners, certificates, and service metadata from billions of exposed endpoints; essential for external attack surface mapping and asset discovery
- [Censys](https://censys.io) — Internet-wide scanning platform with comprehensive TLS certificate and service data; strong for certificate transparency log analysis, ASN-based asset discovery, and vulnerability surface mapping
- [FOFA](https://fofa.info) — Chinese internet intelligence platform indexing billions of global internet assets; strong coverage for infrastructure not indexed by Shodan or Censys; increasingly used for threat actor infrastructure tracking
- [DNSdumpster](https://dnsdumpster.com) — Free DNS reconnaissance tool mapping subdomains, DNS records, and hosting relationships; fast first-pass for domain enumeration without API keys
- [SecurityTrails](https://securitytrails.com) — Historical DNS and WHOIS data platform; tracks domain registration changes, nameserver pivots, and subdomain evolution over time; essential for tracking threat actor infrastructure reuse
- [VirusTotal](https://www.virustotal.com) — Multi-engine file, URL, domain, and IP analysis platform with graph-based relationship mapping; the standard first pivot for threat indicator enrichment and infrastructure attribution

### Social Media & Identity Intelligence
- [megadose/holehe](https://github.com/megadose/holehe) — Checks whether an email address is registered on 120+ platforms without triggering notifications; essential for identity investigation and account enumeration
- [sherlock-project/sherlock](https://github.com/sherlock-project/sherlock) — Username search across 400+ social networks and platforms; maps digital footprint from a single username pivot; the standard tool for social media identity investigation
- [WebBreacher/WhatsMyName](https://github.com/WebBreacher/WhatsMyName) — Community-maintained username and email existence checking framework; the data source underlying many username search tools; more accurate than Sherlock for many platforms
- [C3n7ral051nt4g3ncy/Maigret](https://github.com/C3n7ral051nt4g3ncy/maigret) — Advanced username OSINT tool collecting profile information and site details from 3000+ platforms; produces detailed reports with collected profile data beyond just existence checking

### Email Intelligence
- [Hunter.io](https://hunter.io) — Email address discovery and verification by domain; finds and validates professional email addresses using pattern matching and verification; 25 free monthly searches; widely used in sales intelligence and OSINT
- [Phonebook.cz](https://phonebook.cz) — Free email, domain, and URL intelligence search across multiple data sources; fast aggregated lookup without API requirements
- [EmailRep.io](https://emailrep.io) — Email reputation and intelligence API scoring trust, breach exposure, and activity signals; free tier available; useful for fraud investigation and phishing analysis

### Image & Geolocation Intelligence
- [ExifTool](https://exiftool.org) — The definitive tool for reading and writing metadata from image, audio, and video files; extracts GPS coordinates, camera information, timestamps, and software metadata from media files
- [Google Lens](https://lens.google.com) — Reverse image search with object and landmark recognition; the most accessible starting point for image-based geolocation and identification
- [Yandex Images](https://yandex.com/images) — Russian reverse image search with facial recognition capabilities significantly stronger than Google for certain demographics; essential for identity verification from photographs
- [GeoSpy](https://geospy.ai) — AI-powered geolocation from photographs; estimates location from visual cues in images; useful for geolocation investigations where manual analysis would be time-consuming
- [Bellingcat Geolocation Tools](https://www.bellingcat.com/resources/how-tos/) — Collection of geolocation methodologies and tools from the most experienced open source geolocation investigators in the world

### Dark Web Intelligence
- [Ahmia.fi](https://ahmia.fi) — Clearnet-accessible Tor hidden service search engine; indexes .onion sites and allows keyword searching without Tor Browser; the accessible starting point for dark web monitoring
- [dark.fail](https://dark.fail) — Curated directory of verified dark web sites with PGP-signed status indicators; the standard reference for identifying legitimate dark web markets and forums versus scam mirrors
- [onionsearch](https://github.com/megadose/OnionSearch) — Multi-engine .onion search aggregator querying multiple Tor search engines simultaneously; faster than manual multi-engine searching

### Threat Intelligence OSINT
- [MISP/MISP](https://github.com/MISP/MISP) — The leading open-source threat intelligence platform; aggregates, correlates, and shares structured threat data in STIX/TAXII format; the standard for community threat intelligence sharing
- [OpenCTI-Platform/opencti](https://github.com/OpenCTI-Platform/opencti) — Open Cyber Threat Intelligence platform with knowledge graph, ATT&CK mapping, and automated ingestion from MISP and commercial feeds; the modern alternative to MISP for structured threat intelligence management
- [URLhaus](https://urlhaus.abuse.ch) — Abuse.ch project tracking malware distribution URLs in real time; free API access; essential for phishing and malware investigation pivots
- [AbuseIPDB](https://www.abuseipdb.com) — Community IP reputation database with reported abuse incidents; free API; useful for rapid IP enrichment and identifying known malicious infrastructure
- [AlienVault OTX](https://otx.alienvault.com) — Open Threat Exchange; free community threat intelligence platform with pulses, IOCs, and ATT&CK-mapped threat reports; API access for automated enrichment

---

## Core Methodology

Effective OSINT work follows a structured cycle. Skipping phases — especially OpSec and objective definition — is where investigations fail or cause harm.

| Phase | Activity | Key Consideration |
|---|---|---|
| **1. Define Objectives** | Establish exactly what intelligence is needed, why, and what actions it will inform | Legal authority, ethical boundaries, proportionality |
| **2. Collection Plan** | Identify sources, tools, and collection sequence; separate passive from active methods | Minimize target footprint; passive before active |
| **3. Collect** | Execute structured collection against defined sources; document everything with timestamps and source attribution | Chain of custody; source reliability rating |
| **4. Process** | Normalize, deduplicate, and structure raw data; convert to analyst-consumable formats | Data quality validation; format standardization |
| **5. Analyze** | Apply link analysis, pattern recognition, and temporal analysis; develop hypotheses | Cognitive bias awareness; confidence levels |
| **6. Report** | Produce intelligence product appropriate to the consumer; separate facts from assessments | Audience-appropriate language; actionability |
| **7. Act** | Consumer acts on intelligence; feedback loop updates collection requirements | Effectiveness measurement; lessons learned |

---

## OpSec for OSINT Analysts

Operational security protects both the analyst and the investigation. Targets that detect active collection can destroy evidence, change behavior, or identify the investigating organization.

- **Sock Puppet Accounts**: Create dedicated investigative personas for platform access; never use personal or organizational accounts for investigation activity; separate personas for separate investigations
- **Virtual Machines**: Conduct all investigation activity in isolated VMs; separate VMs per investigation or per sensitivity level; snapshot before each session for clean-state recovery
- **VPN and Tor**: Route investigation traffic through VPNs or Tor to prevent IP-based attribution; use VPN providers with no-log policies and payment methods that do not identify the organization
- **Browser Isolation**: Use hardened browsers (Firefox with uBlock Origin, NoScript) in investigation VMs; disable WebRTC, JavaScript where possible; use Tor Browser for high-sensitivity collection
- **Whonix and Tails**: Whonix provides Tor-routed VM networking for persistent investigation environments; Tails provides amnesic OS for high-sensitivity one-off investigations
- **Operational Compartmentalization**: Never mix investigation personas, accounts, or identities; maintain strict separation between investigation infrastructure and organizational systems

---

## OSINT Categories

| Category | Description | Key Sources |
|---|---|---|
| **Passive Recon** | Collection with no direct target contact; purely observational | Shodan, DNS records, WHOIS, certificate transparency, cached pages |
| **Active Recon** | Collection involving interaction with target systems | Port scanning, web crawling, API enumeration — use only with authorization |
| **SOCMINT** | Social media intelligence; collection from social platforms | Twitter/X, LinkedIn, Facebook, Instagram, Reddit, Telegram |
| **GEOINT/IMINT** | Geospatial and imagery intelligence | Satellite imagery, photograph geolocation, mapping services |
| **Domain/IP Intelligence** | Technical infrastructure investigation | Shodan, Censys, SecurityTrails, DNS history, BGP data |
| **Dark Web Monitoring** | Collection from Tor and I2P hidden services | Ahmia, specialized crawlers, forum monitoring |
| **Corporate Intelligence** | Business structure, ownership, and financial investigation | Companies House, SEC EDGAR, OpenCorporates, LinkedIn |

---

## NIST 800-53 Control Alignment

| Control | ID | OSINT Relevance |
|---|---|---|
| Security Categorization | RA-2 | OSINT identifies what organizational information is publicly exposed; drives accurate classification of information requiring protection |
| Risk Assessment | RA-3 | External OSINT collection against an organization's own footprint is a direct input to threat-informed risk assessments |
| Penetration Testing | CA-8 | Passive and active OSINT recon is the mandatory first phase of any penetration test; unauthorized active recon violates this control boundary |
| Security Alerts, Advisories, and Directives | SI-5 | Threat intelligence OSINT feeds supply the early warning data that populates security alerts; OTX, URLhaus, and AbuseIPDB directly support this control |

---

## ATT&CK Coverage

OSINT maps directly to the MITRE ATT&CK Reconnaissance tactic. Defenders who understand what adversaries can collect via OSINT are better positioned to reduce their attack surface and detect early-stage reconnaissance.

| Technique | ID | Description |
|---|---|---|
| Gather Victim Identity Information | T1589 | Employee names, email addresses, credentials in breaches, social media profiles |
| Gather Victim Network Information | T1590 | IP ranges, ASN data, domain registrations, DNS records, network topology |
| Gather Victim Org Information | T1591 | Business relationships, org charts, physical locations, key personnel |
| Gather Victim Host Information | T1592 | Exposed services, OS fingerprints, software versions, configurations |
| Search Open Websites/Domains | T1593 | Social media mining, code repository search, paste site monitoring |
| Search Victim-Owned Websites | T1594 | Web crawling, sitemap analysis, hidden path discovery, metadata extraction |
| Search Open Technical Databases | T1596 | Shodan, Censys, certificate transparency logs, BGP routing data |
| Search Closed Sources | T1597 | Dark web forums, paid intelligence services, breach databases |
| Phishing for Information | T1598 | Pretexting via social engineering to elicit target information |

Understanding which of these techniques expose your organization's data drives prioritization of attack surface reduction, information classification review, and early detection of adversary reconnaissance activity.

---

## Books & Learning

| Book | Author | Why Read It |
|---|---|---|
| OSINT Techniques: Resources for Uncovering Online Information | Michael Bazzell | The definitive practitioner reference; updated annually with current tools, techniques, and workflows; covers every major OSINT category with hands-on guidance; the book every OSINT analyst should own |
| Open Source Intelligence Techniques (earlier editions) | Michael Bazzell | The predecessor to OSINT Techniques; earlier editions remain valuable references for methodology and foundational tool understanding |
| Hunting Cyber Criminals | Vinny Troia | Dark web investigation and threat actor attribution methodology from an experienced cybercriminal investigator; practical techniques for tracking threat actors across platforms and services |

---

## Certifications

- **BTL1** (Blue Team Labs Level 1 — Security Blue Team) — Hands-on analyst certification with OSINT modules covering threat intelligence collection and investigation; the most accessible entry-level validation for OSINT skills in a defensive context
- **SANS FOR578** (Cyber Threat Intelligence) — The most rigorous professional training for threat intelligence OSINT; covers structured analytic techniques, threat actor attribution, and intelligence production; leads to the GCTI certification
- **GCTI** (GIAC Cyber Threat Intelligence) — The certification paired with FOR578; validates professional-level threat intelligence and OSINT tradecraft; widely respected in corporate threat intelligence programs
- **OSCP** (Offensive Security Certified Professional) — Provides the offensive recon context that makes OSINT practitioners more effective; hands-on exploitation experience deeply informs what adversaries can do with collected intelligence
- **TCM Security OSINT Course** — Practical online course from TCM Security covering core OSINT tools and methodology; affordable and highly practical entry point before investing in SANS-level training

---

## Channels

- [Michael Bazzell (IntelTechniques)](https://www.youtube.com/@IntelTechniques) — The most authoritative OSINT practitioner content creator; tool tutorials, methodology walkthroughs, and the definitive annual OSINT resource guide
- [Bellingcat](https://www.youtube.com/@bellingcat) — Open source investigation methodology from the world's leading OSINT outlet; geolocation walkthroughs, verification techniques, and investigation case studies
- [OSINT Curious](https://www.youtube.com/@OSINTCuriousProject) — Community OSINT education including 10 Minute Tip series, webcast archives, and practitioner interviews covering current tools and techniques
- [Black Hills Information Security](https://www.youtube.com/@BlackHillsInformationSecurity) — Includes OSINT content for red team reconnaissance, passive recon methodology, and threat intelligence collection alongside broader security content
- [TCM Security](https://www.youtube.com/@TCMSecurityAcademy) — Practical OSINT and recon content alongside offensive security training; accessible and hands-on

---

## Who to Follow

- [@MichaelBazzell](https://x.com/IntelTechniques) — Michael Bazzell; author of the definitive OSINT Techniques book and podcast host; the most consistent practitioner voice in OSINT education
- [@bellingcat](https://x.com/bellingcat) — The leading open source investigation publication; methodology, tools, and real-world investigation case studies
- [@OSINTCurious](https://x.com/OSINTCurious) — OSINT Curious community; tool tips, technique sharing, and practitioner community news
- [@jakecreps](https://x.com/jakecreps) — Jake Creps; OSINT practitioner with strong social media intelligence and identity investigation content
- [@sector035](https://x.com/sector035) — Week in OSINT newsletter author; curates the best OSINT tool and technique content weekly; excellent for staying current
- [@dutch_osintguy](https://x.com/dutch_osintguy) — Authentic8 OSINT practitioner with strong browser isolation and analyst OpSec content

---

## Key Resources

- [OSINT Framework](https://osintframework.com) — The definitive taxonomy of OSINT tools organized by intelligence type; the first resource to consult when planning collection against any target type
- [Michael Bazzell's IntelTechniques](https://inteltechniques.com) — The most comprehensive OSINT practitioner resource; custom search tools, annual resource guide, and the best OSINT podcast available
- [Bellingcat Online Investigation Toolkit](https://docs.google.com/spreadsheets/d/18rtqh8EG2q1xBo2cLNyhIDuK9jrPGwYr9DI2UncoqJQ) — Community-maintained spreadsheet of OSINT tools organized by category; regularly updated by Bellingcat community contributors
- [MITRE ATT&CK Reconnaissance Tactic](https://attack.mitre.org/tactics/TA0043/) — The authoritative mapping of adversary reconnaissance techniques; use it to understand what attackers collect and how to reduce your organization's OSINT exposure
- [ATTACK-Navi](https://teamstarwolf.github.io/ATTACK-Navi/) — Visualize ATT&CK Reconnaissance technique coverage and detection gaps; map OSINT-informed threat models to detection priorities

---

## Related Disciplines

- [Threat Intelligence](/disciplines/threat-intelligence) — OSINT is the primary collection method for threat intelligence; threat intel analysts use OSINT to track threat actors, identify infrastructure, and produce finished intelligence products
- [Offensive Security](/disciplines/offensive-security) — OSINT recon is the mandatory first phase of any penetration test or red team engagement; offensive practitioners use OSINT to map attack surfaces before exploitation
- [Digital Forensics](/disciplines/digital-forensics) — OSINT complements forensic investigation by providing external context about actors, infrastructure, and timelines that internal artifacts alone cannot supply
- [Incident Response](/disciplines/incident-response) — OSINT enriches incident response by enabling rapid external context on attacker infrastructure, malware families, and threat actor groups during active incidents
- [Bug Bounty](/disciplines/bug-bounty) — External attack surface mapping via OSINT is the recon foundation for bug bounty hunting; finding exposed assets, subdomains, and technology stack details drives scope definition
