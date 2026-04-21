# Physical Security

Physical security is the discipline of protecting physical assets, facilities, people, and hardware from unauthorized access, theft, sabotage, and environmental threats. It bridges the gap between the digital and physical worlds — an attacker who can walk into a data center, clone a badge, or plug in a rogue device has bypassed virtually every logical control in place. Physical security professionals must think offensively (how would an adversary defeat our controls?) and defensively (what layers of protection make that defeat expensive and detectable?).

Physical security underpins every other security domain. Strong network segmentation means nothing if an attacker can unplug a server, and encryption is irrelevant if a drive can be physically removed. Understanding physical security is essential for penetration testers, red teamers, facility managers, and enterprise security architects alike.

## Where to Start

| Level | Description | Free Resource |
|-------|-------------|---------------|
| Beginner | Learn the fundamentals: access control categories (something you have, are, know), lock types, CCTV basics, visitor management, and why physical security matters in a layered security program | [CISA Physical Security Overview](https://www.cisa.gov/topics/physical-security) |
| Intermediate | Dive into RFID/NFC technology (how HID cards work, ISO 14443/15693 standards), lock bypass techniques, alarm system architecture, and physical penetration testing methodology | [Deviant Ollam's Physical Security Talks (YouTube)](https://www.youtube.com/@DeviantOllam) |
| Advanced | Master badge cloning with Proxmark3, OSDP protocol security, under-door tool techniques, multi-layer physical pen testing with full kill chain documentation, and integrating physical findings into enterprise risk reports | [DEF CON Physical Security Village Talks Archive](https://www.youtube.com/@DEFCONConference) |

## Free Training

| Platform | URL | What You Learn |
|----------|-----|----------------|
| CISA Physical Security Resources | https://www.cisa.gov/topics/physical-security | Facility hardening, active shooter response, perimeter security principles |
| DEF CON Physical Security Village | https://physec.village.defcon.org | Badge cloning, lock bypass, physical pen testing methodology |
| DEF CON Lockpick Village | https://toool.us/deviant/ | Lock picking mechanics, practice locks, bypass tools |
| Deviant Ollam YouTube | https://www.youtube.com/@DeviantOllam | Elevator hacking, door hardware attacks, physical pen test walkthroughs |
| SANS Reading Room (Physical) | https://www.sans.org/reading-room/ | Research papers on physical security controls and threat scenarios |
| Proxmark3 Community Wiki | https://github.com/Proxmark/proxmark3/wiki | RFID protocol analysis, card cloning, firmware usage |
| TOOOL (The Open Organisation Of Lockpickers) | https://toool.us | Lock picking fundamentals, bypass techniques, hardware analysis |

## Tools & Repositories

| Tool | Description | Link |
|------|-------------|-------|
| Proxmark3 | Premier RFID research tool supporting HID, EM4100, MIFARE, iCLASS, and dozens of other card standards — used for reading, cloning, and analyzing RF cards | https://github.com/Proxmark/proxmark3 |
| Flipper Zero | Portable multi-tool for RF, NFC, IR, iButton, GPIO, and BadUSB attacks; widely used in physical pen tests | https://github.com/flipperdevices/flipperzero-firmware |
| RFIDler | Open-source HF/LF RFID and NFC research platform | https://github.com/ApertureLabsLtd/RFIDler |
| Crapto1 | Implementation of the broken Crypto1 cipher used in MIFARE Classic cards; enables offline cracking of intercepted authentication sessions | https://github.com/RfidResearchGroup/proxmark3 |
| ChameleonMini | RFID emulator and sniffer for NFC and ISO 14443/15693 cards, useful for relay attacks and emulation | https://github.com/emsec/ChameleonMini |
| Lock Pick Training Boards (Sparrows) | Open-source cutaway lock designs for learning single pin picking | https://www.sparrowslockpicks.com |
| UDT (Under-Door Tool) Designs | Community documentation of under-door lever manipulation tools | https://github.com/deviantollam/decoding |
| Wiegand Attack Tools | Tools for intercepting and replaying Wiegand protocol signals from card readers | https://github.com/linklayer/wiegotcha |
| GrayKey / Cellebrite (research refs) | Commercial forensic tools referenced in physical security research for device seizure scenarios | — |

## Commercial Platforms

| Platform | Description |
|----------|-------------|
| HID Global (Lenel / OnGuard) | Industry-leading access control hardware (cards, readers, controllers) and PACS software; most common enterprise badge system |
| Software House / CCURE 9000 | Enterprise access control and video management platform widely deployed in large facilities |
| Lenel S2 | Cloud-connected PACS with mobile credential support and deep integration with HR and IT systems |
| Genetec Security Center | Unified physical security platform combining access control, video surveillance, and ALPR |
| Bosch Building Technologies | Enterprise-grade intrusion detection, video, and access control systems |
| Verkada | Cloud-managed enterprise cameras, access control, and environmental sensors with centralized management |
| Envoy / Proxyclick | Visitor management systems that register and badge guests, integrate with PACS, and log access |
| Allegion (Schlage) | Commercial-grade electronic locks, including wireless locks and mobile credential readers |
| Identiv / Hirsch | PACS and credential systems with strong government and defense market presence |
| Stanley Security | Comprehensive physical security integrator offering cameras, alarms, and access control |

## NIST 800-53 Control Alignment

| Control | Family | Relevance |
|---------|--------|-----------|
| PE-1 | Physical and Environmental Protection | Policy and procedures governing physical access to facilities |
| PE-2 | Physical and Environmental Protection | Physical access authorizations — who is permitted where |
| PE-3 | Physical and Environmental Protection | Physical access control enforcement at entry points — locks, card readers, guards |
| PE-4 | Physical and Environmental Protection | Access control for transmission medium — physical protection of cable runs and patch panels |
| PE-5 | Physical and Environmental Protection | Access control for output devices — printers, fax, displays with sensitive data |
| PE-6 | Physical and Environmental Protection | Monitoring physical access — CCTV, guard logs, access logs reviewed regularly |
| PE-8 | Physical and Environmental Protection | Visitor access records — maintaining and reviewing visitor logs |
| PE-9 | Physical and Environmental Protection | Power equipment and cabling — protecting utility infrastructure from tampering |
| PE-11 | Physical and Environmental Protection | Emergency power — UPS and generator controls |
| PE-13 | Physical and Environmental Protection | Fire protection systems — suppression and detection |
| PE-17 | Physical and Environmental Protection | Alternate work site physical protection requirements |
| PE-20 | Physical and Environmental Protection | Asset monitoring and tracking — asset tags, RF-based inventory systems |

## ATT&CK Coverage

| Technique ID | Name | Tactic | Relevance |
|-------------|------|--------|-----------|
| T1200 | Hardware Additions | Initial Access | Rogue devices (keyloggers, implants, network taps) plugged in during physical access |
| T1091 | Replication Through Removable Media | Initial Access / Lateral Movement | Dropping infected USB drives; payload delivery via physical media |
| T1052 | Exfiltration Over Physical Medium | Exfiltration | Removing data via USB drives, hard drives, or optical media physically carried out |
| T1078 | Valid Accounts | Defense Evasion / Persistence | Using cloned/stolen badges or credentials obtained through physical access |
| T1056.002 | Input Capture: Port Monitors | Collection | Hardware keyloggers installed during brief physical access |
| T1025 | Data from Removable Media | Collection | Accessing sensitive data from drives removed from systems |
| T1074.001 | Data Staged: Local Data Staging | Collection | Aggregating data to removable media before physical exfil |
| T1601 | Modify System Image | Defense Evasion | Firmware or hardware implants installed with direct physical access |
| T1495 | Firmware Corruption | Impact | Destructive firmware attacks possible only with physical device access |
| T1485 | Data Destruction | Impact | Physical destruction of drives, systems, or backup media |

## Certifications

| Certification | Issuer | Level | Notes |
|--------------|--------|-------|-------|
| CPP — Certified Protection Professional | ASIS International | Advanced | Gold standard for physical security management; covers risk, threat assessment, and program management |
| PSP — Physical Security Professional | ASIS International | Intermediate | Focused on physical security surveys, design, and implementation |
| APP — Associate Protection Professional | ASIS International | Entry | Entry-level ASIS credential for those new to physical security |
| CPOI — Certified Protection Officer Instructor | IFPO | Intermediate | Instructor-level credential for security officer programs |
| CPO — Certified Protection Officer | IFPO | Entry | Foundational credential for security officers |
| CPTED Certification | CPTED Security | Intermediate | Crime Prevention Through Environmental Design — architectural security |
| CompTIA Security+ (Physical Domain) | CompTIA | Entry | Covers physical controls as part of broader security+ objectives |

## Learning Resources

| Resource | Type | Notes |
|----------|------|-------|
| *Practical Lock Picking* — Deviant Ollam | Book | The definitive guide to lock picking; covers theory, tools, and technique |
| *The Art of Intrusion* — Kevin Mitnick | Book | Real-world case studies of physical intrusions, social engineering, and access bypass |
| *The Art of Deception* — Kevin Mitnick | Book | Social engineering and physical pretexting methodology |
| *Low Tech Hacking* — Jack Wiles | Book | Physical security threats in enterprise environments |
| *ASIS Physical Security Handbook* | Reference | Comprehensive reference aligned to CPP/PSP exam content |
| DEF CON Physical Security Village Talks | Video | Annual conference talks on badge cloning, lock bypass, and facility pentesting |
| Deviant Ollam — "It's the Little Things" Series | Video | Deep dives into door hardware vulnerabilities |
| NIST SP 800-116 | Standard | PIV card and reader deployment guidance for federal facilities |
| OSDP (SIA Open Supervised Device Protocol) | Standard | Modern access control wiring protocol; review for replay and manipulation vulnerabilities |
| Proxmark3 RDV4 Documentation | Documentation | Official docs for the most capable open-source RFID research tool |

## Physical Penetration Testing Methodology

A physical penetration test follows a structured kill chain:

1. **Reconnaissance** — Open-source intelligence: Google Maps satellite/Street View, Shodan for exposed cameras (search `has_screenshot:true`), LinkedIn for employee names and badge photos, company website for office locations and photos that reveal badge designs, access reader models, and security posture.
2. **Pretext Development** — Building a believable cover story (IT contractor, vendor, delivery, fire marshal inspection) with supporting props (uniforms, ID holders, lanyards, clipboards, fake work orders).
3. **Badge Cloning** — Using Proxmark3 or Flipper Zero at close range (e.g., in a crowded elevator) to read a victim's HID Prox, HID iCLASS, or EM4100 card and write a clone. iCLASS SE and SEOS cards require additional credential attacks.
4. **Lock Bypass** — Single pin picking (SPP), raking, bump keys, shims on padlocks, under-door tools (UDT) to manipulate lever handles, door gap tools (latch shims), loiding (credit card shimming), and REX (Request to Exit) sensor manipulation by sliding tools under doors to trigger motion-based door releases.
5. **Entry and Objective** — Tailgating/piggybacking through mantrap or turnstile, accessing server rooms, network closets, or executive offices, installing hardware implants or retrieving sensitive material.
6. **Evidence Collection and Exfiltration** — Photographing evidence, copying data to USB, and physically removing items per scope.
7. **Reporting** — Documenting each bypass method with photos, timestamps, and video; mapping findings to NIST PE controls and business risk; recommending specific remediations.

## RFID/NFC Attack Detail

- **HID Prox (125 kHz LF)**: No authentication; trivially cloned with Proxmark3 or Flipper Zero at 5–10 cm range. Extremely common in older deployments.
- **HID iCLASS (13.56 MHz HF)**: Early versions cracked using the iCLASS master key (publicly known since 2012). iCLASS SE and iCLASS Seos offer genuine cryptographic protection but are more expensive.
- **MIFARE Classic**: Uses the broken Crypto1 stream cipher. Vulnerable to nested authentication attacks and offline cracking with Crapto1. Widely deployed in parking, transit, and some enterprise PACS.
- **NFC Relay Attacks**: Using two devices (one near victim, one near reader) to relay an authentication session in real time — bypasses distance-based security assumptions.
- **OSDP Protocol**: Open Supervised Device Protocol (RS-485) is the modern standard for reader-to-controller communication. Unlike Wiegand (no encryption, no authentication), OSDP v2 supports AES-128 encryption, but many deployments leave it unconfigured.


## Physical Penetration Testing Methodology -- Extended

### Legal and Authorization

- **Scope document**: Explicit authorization letter from authorized decision-maker (not just IT director; facilities and legal leadership may also need to authorize)
- **Emergency contact list**: 24/7 numbers to call if caught by security or law enforcement
- **Get out of jail letter**: Physical letter on company letterhead authorizing the test; includes tester description, vehicle, equipment
- **Rules of engagement**: What constitutes success? Building access only? Executive floor? Server room? Data center? Safe combinations?

### Reconnaissance

- **OSINT**: Google Street View, Google Earth, building permit records, LinkedIn for security team names and schedules
- **Physical observation**: Note guard patrol patterns, shift changes, smoking areas (tailgate opportunities), delivery schedules
- **Social media**: Employees posting badge photos reveal badge design, color, and format

### Entry Techniques

- **Tailgating**: Following authorized personnel through door; asking them to hold it
- **Piggybacking**: Social engineering the holder to actively hold door
- **Shoulder surfing**: Observing PINs and access codes
- **Badge cloning**: Proxmark3 or ACR122U for 125kHz (HID Prox, EM4100) cloning; Flipper Zero for low-frequency RFID
- **Shimming**: Thin plastic card to slip door latch on improperly fitted door frames
- **Under-door tool**: Hook to pull down lever handles from underside of door
- **Rex sensor defeat**: Motion sensor above door triggers release from inside; use lever/thin rod under door

### Lock Picking

- **Single Pin Picking (SPP)**: Most controlled technique; feedback-driven; tension wrench + pick
- **Raking**: Fast, less controlled; serrated rakes; effective against low-security locks
- **Bumping**: Modified key + mallet; resonance defeats spring-loaded pins
- **Bypass tools**: Credit card shimming, loiding, jiggler keys for wafer locks
- **High-security locks**: Medeco, Abloy, Mul-T-Lock -- require specialist bypass or alternative attack path
- **Resources**: Deviant Ollam (Practical Lock Picking), LockPickingLawyer YouTube

### Wireless Security Testing

- **RFID/NFC attacks**: Flipper Zero, Proxmark3 -- read, save, replay, emulate badges
- **125kHz (HID, EM4100)**: No encryption; fully clonable; most common in older buildings
- **13.56 MHz (MIFARE Classic)**: Weakly encrypted; Crypto-1 cipher broken; clonable with mfoc/mfcuk
- **13.56 MHz (MIFARE DESFire, ICODE)**: AES/3DES encryption; much harder to clone
- **WiFi survey**: Detect rogue APs, probe for WPA2-Enterprise networks

### Social Engineering -- Physical Component

- **Pretext scenarios**: IT support, vendor/contractor, facilities maintenance, auditor, delivery person
- **Vishing before visit**: Call ahead to name-drop, set up pretext with receptionist
- **Physical props**: Hard hat, safety vest, clipboard, ID badge holder
- **Visual impersonation**: Dress like the target's typical contractors or visitors

---

## Physical Security Controls and Bypass Methods

| Control | Bypass Method | Detection/Prevention |
|---------|---------------|----------------------|
| Deadbolt | Lock picking, shimming, bump key | High-security locks (Medeco, Abloy), security pins |
| Electromagnetic lock (mag-lock) | REX sensor defeat, power outage | Fail-secure wiring, REX override, UPS |
| PIN pad | Shoulder surfing, thermal camera attack | Privacy shields, anti-tailgate sensors |
| RFID/Prox badge | Clone with Proxmark3/Flipper Zero | Encrypted badges (DESFire EV2), anti-cloning readers |
| Mantrap/airlock | Social engineering entry staff | Anti-tailgate + mantrap + trained guard |
| CCTV | Blind spots, covering cameras, misdirection | Overlapping coverage, motion alerts, FOV audits |
| Security guard | Social engineering pretext | Training, challenge culture, visitor escort policy |
| Dumpster | Physical access (public trash) | Shredding policy, locked dumpster enclosures |

---

## Reporting Physical Pen Test Findings

### Finding Format

- **Finding title**: e.g., Badge cloning enables unauthorized facility access
- **Risk rating**: Critical/High/Medium/Low
- **Evidence**: Photos (redacted if containing sensitive info), description of entry method used
- **Remediation**: Specific technical and procedural recommendations
- **Detection**: Were guards/security systems triggered? If not, detection gap noted

### Common Physical Security Findings

- 125kHz RFID badges (fully clonable without encryption)
- Tailgating not challenged by staff (culture/training gap)
- Server rooms accessible with same badge as main building
- Laptop/equipment left unattended in public/semi-public spaces
- Sensitive documents visible on desks or in unlocked filing cabinets
- Dumpster containing unshredded employee data

---
## Related Disciplines

- [Social Engineering](social-engineering.md)
- [Red Teaming](red-teaming.md)
- [Penetration Testing](penetration-testing.md)
- [Hardware Security](hardware-security.md)
- [Identity Access Management](identity-access-management.md)
- [Security Awareness](security-awareness.md)
- [OSINT](osint.md)
