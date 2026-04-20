# Physical Security

> Protecting physical assets, facilities, personnel, and systems from unauthorized physical access, theft, sabotage, and environmental threats. Physical access defeats all logical controls — a locked-down server is compromised the moment an attacker can touch it.

Physical security is frequently underestimated in security programs that focus heavily on cyber controls. It covers the full range from perimeter fencing and access badges to environmental controls in data centers, and extends into physical penetration testing as a discipline. For security professionals, understanding physical security is essential both for designing layered defenses and for assessing physical attack surface during engagements.

---

## Key Domains

| Domain | Description |
|---|---|
| Access Control | Badge systems, biometrics, PIN pads, mantraps, and turnstiles controlling entry to facilities and zones |
| Surveillance | CCTV, motion detection, video analytics, and security operations center (SOC) monitoring |
| Perimeter Security | Fences, bollards, security guards, vehicle barriers, and lighting |
| Environmental Controls | Fire suppression (halon, FM-200), UPS, HVAC, temperature/humidity monitoring |
| Data Center Physical Security | Cage locks, server rack locks, tamper-evident seals, strict visitor escorting |
| Lock Picking / Bypass | Techniques used by pen testers to defeat locks without keys — lock picking, bump keys, bypass tools |
| RFID / Credential Systems | Badge technologies (HID, MIFARE) and their vulnerabilities to cloning attacks |

---

## Physical Penetration Testing Techniques

Physical pen testers assess whether unauthorized individuals can gain access to restricted areas or sensitive systems:

| Technique | Description |
|---|---|
| Lock Picking | Manipulating lock pins with picks and tension wrenches to open locks without keys |
| Bump Keys | Using a specially cut key with impact to set pins and open pin tumbler locks |
| RFID Cloning | Capturing and replaying badge RF signals using tools like Proxmark3 or Flipper Zero |
| Tailgating / Piggybacking | Following authorized personnel through access-controlled doors |
| Badge Cloning | Duplicating proximity cards or smart cards to gain unauthorized access |
| Dumpster Diving | Recovering sensitive documents, credentials, or hardware from trash |
| Shoulder Surfing | Observing screens, keyboards, or combination entries in proximity |
| Device Implant Placement | Deploying rogue hardware (network implants, keyloggers, rogue APs) on-site |
| Social Engineering (Physical) | Impersonating vendors, IT staff, or delivery personnel to gain entry |

---

## Defensive Controls

Physical defense follows the same defense-in-depth principle as cyber security — multiple layers that an attacker must defeat sequentially:

**Layered Physical Defense Model**:
`Perimeter → Building → Floor → Room → Rack / Device`

| Control | Description |
|---|---|
| Mantraps / Airlocks | Double-door entry systems that prevent tailgating — only one person enters per authentication |
| Visitor Management | Sign-in, photo ID verification, escort requirements, and visitor logs |
| Clean Desk Policy | Requiring employees to clear desks of sensitive material when not in use |
| Screen Lock Enforcement | Auto-lock policies and physical privacy screens on displays |
| Cable Locks | Physical tethering of laptops and workstations to desks or fixtures |
| Tamper-Evident Seals | Seals on server chassis, cables, and enclosures that reveal interference |
| CCTV with Retention | Video surveillance with adequate retention for forensic investigation |
| Security Guards | Human patrol and response capability — first responders to physical incidents |
| Environmental Monitoring | Sensors for temperature, humidity, smoke, water intrusion, and power |

---

## NIST 800-53 Controls

| Control | Name | Relevance |
|---|---|---|
| PE-2 | Physical Access Authorizations | Maintains a current list of individuals authorized physical access to facilities |
| PE-3 | Physical Access Control | Controls entry and exit points using authentication mechanisms |
| PE-6 | Monitoring Physical Access | Reviews physical access logs and investigates anomalies |
| PE-9 | Power Equipment and Cabling | Protects power equipment and distribution cabling from damage and unauthorized access |
| PE-11 | Emergency Power | Provides short-term UPS and long-term alternate power for critical systems |
| PE-17 | Alternate Work Site | Establishes security controls for personnel working at alternate locations |
| MA-5 | Maintenance Personnel | Controls physical access for maintenance personnel and escorts as required |

---

## MITRE ATT&CK Coverage

| Technique ID | Name | Notes |
|---|---|---|
| T1200 | Hardware Additions | Placing rogue devices — USB implants, network taps, keyloggers — requiring physical access |
| T1091 | Replication Through Removable Media | Spreading malware via USB or other removable media introduced physically |
| T1052 | Exfiltration over Physical Medium | Removing data via physical media or devices rather than network channels |

**ICS ATT&CK**: Physical security failures in industrial environments can lead to direct manipulation of physical processes — ICS ATT&CK covers physical process manipulation as a final-stage impact.

Physical intrusions also enable **Initial Access** (ATT&CK TA0001) — once inside, attackers may connect implants to internal networks, access unattended workstations, or steal hardware.

---

## Tooling

### RFID and Badge Tools

| Tool | Purpose |
|---|---|
| Proxmark3 | Professional RFID research and cloning tool — reads, emulates, and clones HID and MIFARE cards |
| ChameleonMini | Open-source RFID emulator for NFC/RFID credential testing |
| Flipper Zero | Multi-tool device — RFID, NFC, infrared, sub-GHz, iButton, and GPIO in one portable unit |

### Lock Picking Resources

| Resource | Notes |
|---|---|
| Sparrows | Quality practice lock sets and picks used by security professionals |
| TOOOL (The Open Organisation Of Lockpickers) | Community organization promoting lock sport and physical security research |
| Practice Locks | Transparent and progressive practice locks for developing picking technique |

### Surveillance Platforms

| Tool | Type | Notes |
|---|---|
| Shinobi | Open source | Self-hosted video management system (VMS) |
| ZoneMinder | Open source | Linux-based video surveillance and monitoring platform |
| Verkada | Commercial | Cloud-managed physical security platform — cameras, access control, sensors |
| Axis | Commercial | Enterprise IP camera and video analytics platform |

### Physical Access Control Systems (PACS)

| System | Notes |
|---|---|
| Lenel OnGuard | Enterprise PACS widely deployed in large facilities |
| Software House C-CURE | Competitor PACS platform — common in corporate and government environments |
| Genetec Security Center | Unified security platform combining PACS, VMS, and analytics |
| HID Global | Leading manufacturer of credential and reader technology |

---

## Standards and Frameworks

| Standard / Framework | Scope |
|---|---|
| ASIS International | Leading professional association for physical security — publishes standards and the PSP/CPP certifications |
| NIST SP 800-116 | Guidelines for using PIV (Personal Identity Verification) credentials for physical access |
| IEC 62443 | Industrial cybersecurity standard — includes physical security requirements for ICS/OT environments |
| PCI DSS | Payment Card Industry standard — includes physical requirements for cardholder data environments (Requirement 9) |
| ISO 27001 Annex A.11 | Physical and environmental security controls within the ISO 27001 ISMS framework |

---

## Certifications

| Certification | Issuer | Relevance |
|---|---|---|
| PSP (Physical Security Professional) | ASIS International | Dedicated physical security credential — assessment, implementation, and management |
| CPP (Certified Protection Professional) | ASIS International | Broad security management credential covering physical, personnel, and information security |
| Security+ | CompTIA | Covers physical security controls as part of general security foundations |
| CEH (Certified Ethical Hacker) | EC-Council | Includes physical attack techniques in its pen testing curriculum |
| CPTE | Mile2 | Physical security as part of broader penetration testing curriculum |

---

## Learning Resources

- **Organization**: ASIS International (asisonline.org) — standards, certification, and professional community for physical security
- **Practitioner**: Deviant Ollam — leading physical pen tester; presentations at DEF CON and Black Hat on lock bypass, access control failures, and physical assessments
- **YouTube**: LockPickingLawyer (LPL) — the most accessible resource for understanding lock vulnerabilities and picking technique
- **Community**: TOOOL (toool.us) — The Open Organisation Of Lockpickers; chapters, resources, and lock sport events
- **Conference**: DEF CON Physical Security Village — hands-on lockpicking, talks, and physical pen testing competitions
- **Conference**: DEF CON — Gringo Warrior physical pen test competition
- **Book**: Deviant Ollam — *Practical Lock Picking* — the standard technical reference for physical pen testers

---

## Related Disciplines

- [Hardware Security](hardware-security.md) — Physical access is the primary enabler of hardware attacks — implants, JTAG, and side-channel attacks require physical proximity
- [ICS / OT Security](ics-ot-security.md) — Physical security of industrial facilities is critical — physical access to OT systems can cause real-world process disruption
- [Social Engineering](social-engineering.md) — Tailgating, impersonation, and pretexting are social engineering techniques with direct physical access objectives
- [Offensive Security](offensive-security.md) — Physical pen testing is a component of comprehensive red team and penetration testing engagements
- [Governance, Risk & Compliance](governance-risk-compliance.md) — Physical security controls are required by PCI DSS, HIPAA, ISO 27001, and NIST frameworks
