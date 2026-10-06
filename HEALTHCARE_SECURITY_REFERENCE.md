# Healthcare & Medical-Device Security

> In one minute: Healthcare is the highest-stakes, most-breached regulated sector; a compromise can stop cancer treatment, corrupt a lab result, or leak 190 million records at once. This is the defender's reference for the parts of the estate that are unlike anything in a normal enterprise: the clinical data protocols (HL7 v2 / FHIR / DICOM), the fleet of unpatchable, FDA-regulated connected devices (IoMT), and the standards and regulators (FDA Section 524B, IEC 62304/81001-5-1, AAMI SW96, the HIPAA Security Rule) that govern them. It leads with the sector threat profile, then works protocol-by-protocol and device-lifecycle stage-by-stage with concrete hardening. For the HIPAA breach-notification *clock* and the wider regulatory map see [REGULATORY_LANDSCAPE_REFERENCE.md](REGULATORY_LANDSCAPE_REFERENCE.md); for administrative HIPAA safeguards and audit prep see the GRC references.

| | |
|---|---|
| Read this when | segmenting a hospital network and its biomedical devices; scoping an IoMT/HTM security program; assessing a medical-device vendor or an FDA premarket submission; hardening an HL7 interface engine, a FHIR API, or a PACS; briefing clinical/biomed leadership on ransomware and patient-safety risk |
| Start at | [Sector Threat Profile](#sector-threat-profile), [Clinical Data Protocols](#clinical-data-protocols--their-security), [IoMT: Segmentation & Lifecycle](#iomt-medical-device-segmentation--lifecycle), [FDA Cybersecurity Requirements](#fda-medical-device-cybersecurity-requirements) |
| Pairs with | [REGULATORY_LANDSCAPE_REFERENCE.md](REGULATORY_LANDSCAPE_REFERENCE.md), [GRC_REFERENCE.md](GRC_REFERENCE.md), [GRC_COMPLIANCE_REFERENCE.md](GRC_COMPLIANCE_REFERENCE.md), [ICS_OT_SECURITY_REFERENCE.md](ICS_OT_SECURITY_REFERENCE.md), [FIRMWARE_IOT_SECURITY_REFERENCE.md](FIRMWARE_IOT_SECURITY_REFERENCE.md), [EMB3D_REFERENCE.md](EMB3D_REFERENCE.md), [ZERO_TRUST_REFERENCE.md](ZERO_TRUST_REFERENCE.md), [RANSOMWARE_DEFENSE_REFERENCE.md](RANSOMWARE_DEFENSE_REFERENCE.md) |

> Not legal advice. This is a defender's operational reference, not legal or regulatory counsel. HIPAA obligations, FDA requirements, and standards conformance turn on facts and definitions that change; confirm current text and your specific obligations with qualified counsel and your regulatory-affairs team. Time-sensitive facts are marked with a source and were verified 2026-09-29.

---

## Table of Contents

1. [Why Healthcare Is Different](#why-healthcare-is-different)
2. [Sector Threat Profile](#sector-threat-profile)
3. [Clinical Data Protocols & Their Security](#clinical-data-protocols--their-security)
4. [IoMT: Medical-Device Segmentation & Lifecycle](#iomt-medical-device-segmentation--lifecycle)
5. [FDA Medical-Device Cybersecurity Requirements](#fda-medical-device-cybersecurity-requirements)
6. [Standards & Frameworks](#standards--frameworks)
7. [The HIPAA Security Rule (and its 2025 overhaul)](#the-hipaa-security-rule-and-its-2025-overhaul)
8. [Defender Checklist](#defender-checklist)
9. [Tooling](#tooling)
10. [Related Resources](#related-resources)

---

## Why Healthcare Is Different

A hospital network is simultaneously an enterprise IT estate, an OT/ICS environment (building management, pneumatic tube systems, nurse call), and a fleet of safety-critical, human-attached computers. Four structural facts drive every control decision:

- Patient safety is the impact, not just confidentiality. The CIA triad inverts: *availability and integrity* of a drug-library, an infusion rate, or a lab result can be life-or-death. A ransomware-driven ED diversion or a corrupted result set is a clinical event, not only a data event.
- Devices you cannot patch, own, or reimage. Medical devices run vendor-locked, often end-of-life OSes (legacy Windows, embedded Linux/RTOS). Changing them can require FDA re-validation, so IT cannot freely patch, install EDR, or rebuild them. Average device lifespans (10-20 years for imaging) far exceed OS support windows.
- Flat networks and third-party dependence. Historically flat clinical VLANs let a single foothold reach everything, and the sector runs on shared clearinghouses, pathology labs, and imaging providers; one vendor outage cascades across hundreds of hospitals (see [Change Healthcare](#sector-threat-profile)).
- Highest-value data. A full medical record (PHI + insurance + SSN + payment) sells for far more than a card number and cannot be re-issued. Healthcare has recorded the highest average breach cost of any industry in IBM's *Cost of a Data Breach* report for well over a decade.

Key acronyms: PHI/ePHI (protected health information), HDO (healthcare delivery organization), IoMT (Internet of Medical Things), HTM/biomed (Healthcare Technology Management, the clinical-engineering team that owns devices), EHR/EMR, PACS (imaging archive), RIS/LIS (radiology/lab information systems), MDM (medical device manufacturer), SaMD (Software as a Medical Device).

---

## Sector Threat Profile

Two motives dominate: ransomware/extortion (availability + double extortion) and bulk PHI theft (identity/insurance fraud). Nation-state interest exists (IP theft from pharma/biotech, pre-positioning in critical infrastructure), but financially-motivated crews cause most day-to-day harm.

| Incident | When | Actor / vector | Impact | Lesson |
|---|---|---|---|---|
| Change Healthcare (UnitedHealth) | Feb 2024 | ALPHV/BlackCat: Citrix remote access without MFA | ~190M individuals notified (largest US healthcare breach on record); nationwide claims/pharmacy outage; ~$22M ransom paid, data still leaked | A single un-MFA'd remote-access box in a clearinghouse is systemic risk; concentration/third-party risk is a sector-level control gap. [HHS/CRS](https://www.congress.gov/crs_external_products/IN/HTML/IN12330.web.html) |
| Ascension | May 2024 | Black Basta: malicious file opened on a workstation | ~5.6M individuals; EHR down across a 140+ hospital system; weeks of pen-and-paper, ambulance diversion | Downtime procedures and network segmentation are clinical-continuity controls, not IT niceties. (per HHS OCR breach portal) |
| Synnovis (NHS pathology) | Jun 2024 | Qilin ransomware | Blood testing halted at London trusts; >10,000 appointments/1,700 operations cancelled; officially a contributing factor in patient harm including a death | Attacks on shared diagnostic labs convert directly into patient-safety incidents. [HIPAA Journal](https://www.hipaajournal.com/care-disrupted-at-london-hospitals-due-to-ransomware-attack-on-pathology-vendor/) |
| Contec CMS8000 patient monitor | Jan 2025 | Embedded backdoor in firmware (supply chain) | CVE-2025-0626 (hard-coded IP backdoor, CWE-912) + CVE-2025-0683 (plaintext PHI exfil, CWE-359); CISA advised removing devices from networks | Device *supply-chain* trust is not assumed: demand SBOMs and monitor egress. [CISA ICSMA-25-030-01](https://www.cisa.gov/news-events/ics-medical-advisories/icsma-25-030-01) |

Recurring TTPs to prioritize (map to [DETECTION_RULES_REFERENCE.md](DETECTION_RULES_REFERENCE.md) / [THREAT_HUNTING_REFERENCE.md](THREAT_HUNTING_REFERENCE.md)): valid-account access to external remote services without MFA (T1078/T1133); phishing -> loader (Black Basta, Qilin affiliates); rapid lateral movement across flat clinical VLANs; targeting of backup and EHR/imaging servers; abuse of legacy protocol stacks. Ransomware crews frequently seen against HDOs include BlackCat/ALPHV successors, Black Basta, Qilin (Agenda), RansomHub, LockBit successors, and INC/Interlock; verify current activity against live intel before citing in a report.

Legacy device/stack vulnerabilities worth knowing (still resident in fielded equipment): URGENT/11 (VxWorks IPnet TCP/IP, 2019), Ripple20 (Treck TCP/IP, 2020), Access:7 (Axeda remote-management agent, 2022), SweynTooth (BLE SoCs, 2020), and PwnedPiper (Swisslog TransLogic pneumatic tube systems, 2021). These illustrate why a single third-party network stack can expose an entire product class, and why *asset inventory to the component level* matters.

---

## Clinical Data Protocols & Their Security

The three protocols that carry clinical data were designed for trusted, closed networks and ship with little or no built-in security. Assume plaintext and no authentication unless you have explicitly added TLS + authN.

| Protocol | Carries | Transport / typical port | Built-in security | Primary defender action |
|---|---|---|---|---|
| HL7 v2.x | Admissions, orders, results (ADT/ORM/ORU) | MLLP over TCP (IANA `hl7` = 2575; often site-specific) | None: plaintext, no authN/integrity | Terminate on an interface engine; MLLP-over-TLS or mutual-TLS/VPN; segment; validate/whitelist message sources |
| FHIR (R4) | Modern REST API to EHR data | HTTPS (443) | TLS + OAuth2 *recommended, not mandatory* | Enforce TLS 1.2+, SMART on FHIR OAuth2 with least-privilege scopes, lock down `$export` bulk data |
| DICOM | Medical images + embedded PHI | TCP 104 (`dicom`); TLS 2762 (`dicom-tls`); 11112 common | Optional (PS3.15 profiles); usually off | Enable TLS + node authentication (ATNA); real AE-title allow-listing is not authentication; add TLS |

### HL7 v2 and the interface engine

HL7 v2 is the workhorse of intra-hospital messaging: pipe-and-hat delimited segments (`MSH|^~\&|...`) streamed over MLLP (Minimal Lower Layer Protocol) with no session security. Anyone with network reach to the listener can read messages, inject forged ADT/ORU messages (wrong patient, altered result), or replay. Defenses:

- Concentrate flows through an interface engine (Mirth/NextGen Connect, Rhapsody, Cloverleaf); it becomes the choke point where you add TLS, source allow-listing, schema validation, transformation, and audit.
- Wrap MLLP in TLS (MLLP/S) or run it only over segmented, IPSec/VPN-protected links; never route raw MLLP across trust boundaries or the internet.
- Validate and rate-limit inbound messages; alert on unexpected sending facilities/applications (`MSH-3`/`MSH-4`) and on malformed segments.
- Treat interface-engine credentials and channel configs as crown-jewel secrets ([SECRETS_MANAGEMENT_REFERENCE.md](SECRETS_MANAGEMENT_REFERENCE.md)).

### FHIR and SMART on FHIR

FHIR (Fast Healthcare Interoperability Resources) is a RESTful API exposing data as resources (`Patient`, `Observation`, `MedicationRequest`) in JSON/XML. FHIR R4 (4.0.1) is the version required by US regulation (ASTP/ONC certification, USCDI) even though R5 (5.0.0, 2023) exists and R6 is in ballot; build to R4 for US interoperability unless told otherwise. FHIR is deliberately "security-agnostic," so the security is in *how you deploy it*:

- Authorization = SMART on FHIR (SMART App Launch) over OAuth 2.0 / OpenID Connect. Scope apps tightly: prefer `patient/Observation.rs` over `patient/*.read`, and `user/*.*`/`system/*.*` only for vetted backends (SMART Backend Services, `client_credentials` with signed JWT).
- Bulk Data (`$export`) is the highest-risk endpoint: it dumps whole populations. Require strong authN, restrict to allow-listed backend clients, log every job, and monitor for unusual export volume.
- Enforce TLS 1.2+, short-lived tokens, audience-restricted JWTs, and server-side scope enforcement (never trust the client). Rate-limit and alert on broad reads. See [API_SECURITY_REFERENCE.md](API_SECURITY_REFERENCE.md) and [IDENTITY_ACCESS_MANAGEMENT_REFERENCE.md](IDENTITY_ACCESS_MANAGEMENT_REFERENCE.md).

```text
# SMART on FHIR scope hygiene
patient/Observation.rs        # good: one resource, read+search, single patient context
patient/*.read                # broad: entire record for the launch patient — justify it
system/Patient.read           # backend service — gate behind client-credentials + allow-list
$export (Bulk Data)           # population-scale export — treat as a data-exfil primitive
```

### DICOM and PACS

DICOM (Digital Imaging and Communications in Medicine) moves images and their embedded PHI between modalities, PACS, and viewers. Classic DICOM negotiates an "association" using Application Entity (AE) Titles (an identifier, *not* authentication) and defaults to cleartext. Consequences and controls:

- Internet-exposed PACS/DICOM nodes have repeatedly leaked millions of studies. Never expose 104/11112 to untrusted networks; put PACS behind segmentation and VPN, and periodically scan your own space (`nmap --script dicom-ping,dicom-brute`).
- Turn on DICOM security profiles (PS3.15): the Basic TLS Secure Transport Connection Profile (TLS + AES), node authentication, and the ATNA (Audit Trail and Node Authentication, IHE) profile for mutual-TLS + centralized audit. Use PS3.15 confidentiality profiles for de-identification when sharing.
- File-format risk: the DICOM Part-10 128-byte *preamble* can be crafted so a `.dcm` file is simultaneously a valid executable (polyglot), letting a malicious study double as malware while retaining PHI. Scan and content-inspect ingested DICOM; don't blindly trust extensions.
- Reference build: NIST NCCoE SP 1800-24, *Securing PACS*, is a practitioner blueprint for a hardened imaging environment.

---

## IoMT: Medical-Device Segmentation & Lifecycle

You will not patch your way to safety with medical devices; the strategy is know every device, isolate it to only what it needs, and watch it. Treat IoMT as a lifecycle program owned jointly by Security, IT, and HTM/biomed.

### 1. Discover and inventory (you cannot protect what you cannot see)

- Deploy passive, agentless device discovery (medical devices break under active scanning) to build a live inventory: make/model, OS/firmware, FDA class, clinical function, network behavior, and criticality.
- Enrich each model with its MDS2 (Manufacturer Disclosure Statement for Medical Device Security, current published edition ANSI/NEMA HN 1-2019, ~240 questions across ~23 security-capability categories; a revision expanding control documentation is in progress; *confirm current edition with the manufacturer*) and its SBOM to expose vulnerable components (Treck/VxWorks stacks, embedded OpenSSL, etc.).
- Reconcile against the CMMS/biomed asset register so security inventory and clinical-engineering records agree.

### 2. Segment and least-privilege the network

Micro/segmentation is the single highest-leverage control for unpatchable devices; it shrinks blast radius and enforces least privilege at the network layer ([ZERO_TRUST_REFERENCE.md](ZERO_TRUST_REFERENCE.md), [NETWORK_SECURITY_ARCHITECTURE.md](NETWORK_SECURITY_ARCHITECTURE.md)):

- Group devices into purpose-built segments/VLANs (e.g., imaging, infusion, patient monitoring, lab) and write default-deny allow-lists from device -> only its required server (PACS, drug library, EHR interface) and management host.
- Deny device->internet and device->user-VLAN by default; allow-list vendor remote-support/telemetry to specific destinations, brokered and logged (vendor remote access is a top breach vector; see Change Healthcare).
- Prefer identity/attribute-based microsegmentation (policy keyed to device identity, sourced from the discovery platform) where flat-network or NAC constraints make VLAN surgery impractical.
- Baseline normal device communication and alert on deviation (a monitor beaconing to a hard-coded external IP is the Contec pattern).

### 3. Compensating controls for what can't be fixed

Where patching, EDR, or hardening is blocked by FDA validation or EOL firmware: virtual-patch at the network layer (IPS signatures, segmentation), disable unused services/ports, change default credentials where permitted, restrict physical/USB access, and require the vendor's remediation timeline in writing.

### 4. Lifecycle: procurement to decommission

| Stage | Security action |
|---|---|
| Procurement | Require MDS2 + SBOM + patch-commitment SLA; make security a scored contract criterion; verify FDA cybersecurity documentation for cyber devices |
| Onboarding | Change defaults, place in correct segment, register in inventory + CMMS, capture baseline traffic |
| Operations | Monitor behavior, track vendor advisories/[CISA ICS-medical advisories](https://www.cisa.gov/news-events/cybersecurity-advisories), apply vendor-approved updates, re-assess on config change |
| End-of-life | Track EOL/EOS dates; migrate or add compensating controls before support ends |
| Decommission | Sanitize media/wipe PHI per NIST SP 800-88; document destruction for HIPAA |

---

## FDA Medical-Device Cybersecurity Requirements

Since Section 524B of the FD&C Act (added by the Consolidated Appropriations Act, 2023) took effect, cybersecurity is a legal precondition to marketing a connected device in the US; defenders should treat a vendor's FDA posture as a due-diligence signal.

- "Cyber device" scope (§524B(c)): software as/in a device, ability to connect to the internet, and technological characteristics that could be vulnerable to cyber threats.
- Premarket obligations (§524B(b)): submit a plan to monitor, identify, and address postmarket vulnerabilities and exploits (incl. coordinated disclosure); design/develop/maintain processes providing reasonable assurance the device is cybersecure and make updates and patches available (routine and out-of-cycle); and provide a Software Bill of Materials (SBOM) covering commercial, open-source, and off-the-shelf components.
- FDA "Refuse to Accept" authority: since Oct 1, 2023, FDA can decline premarket submissions for cyber devices that lack the required cybersecurity information.
- Current premarket guidance: *Cybersecurity in Medical Devices: Quality Management System Considerations and Content of Premarket Submissions*; the current version is dated February 2026, retitled and revised to align with the new QMSR (Quality Management System Regulation, 21 CFR 820 harmonized to ISO 13485, effective Feb 2, 2026). It supersedes the June 2025 and original Sept 27, 2023 versions. [FDA guidance page](https://www.fda.gov/regulatory-information/search-fda-guidance-documents/cybersecurity-medical-devices-quality-management-system-considerations-and-content-premarket)
- Postmarket: the primary guidance, *Postmarket Management of Cybersecurity in Medical Devices*, remains the 2016 final guidance (coordinated vulnerability disclosure, risk assessment of exploitability + patient-safety impact, and the "controlled/uncontrolled risk" model). (No formal replacement had been finalized as of 2026-09-29; *confirm before citing as current*.)
- FDA partners with CISA on medical-device advisories (ICSMA series) and recognizes consensus standards (below) for demonstrating conformance.

> Defender takeaway: for any new connected device, ask the vendor for its 524B premarket documentation, SBOM, MDS2, coordinated-disclosure policy, and patch cadence, and make them contractual.

---

## Standards & Frameworks

| Standard / program | Scope | Use it for |
|---|---|---|
| IEC 62304 (Ed. 1.1 = 2006/AMD1:2015) | Medical-device software life-cycle processes | Baseline SDLC for device software (safety classification A/B/C, maintenance, problem resolution) |
| IEC 81001-5-1:2021 | Cybersecurity activities across the health-software life cycle | Secure-development companion to 62304; FDA-recognized; the "how" of secure SDLC for devices |
| AAMI SW96:2023 (ANSI/AAMI) | Security risk management for device manufacturers | FDA-recognized normative standard; extends ISO 14971 to security threats; supersedes reliance on TIR57 |
| AAMI TIR57:2016 | Principles of security risk management | Informative predecessor/companion to SW96 |
| IEC 80001-1 (2021 revision) | Risk management for IT-networks that incorporate medical devices | HDO-side: roles/responsibilities between manufacturer, integrator, and hospital; folds security in with safety + effectiveness |
| ISO 14971 / ISO 27799 | Device risk management / health-sector ISMS (ISO 27002 for health) | Underpinning risk and infosec-management frameworks |
| HHS 405(d) HICP | *Health Industry Cybersecurity Practices* (2018, updated 2023) | Voluntary, right-sized practices vs. the top 5 healthcare threats; small/medium/large tech volumes |
| HHS HPH CPGs (Jan 2024) | Healthcare & Public Health Cybersecurity Performance Goals (Essential + Enhanced) | Voluntary baseline mapped to HICP + NIST CSF/800-53; signals likely future rulemaking |
| HSCC JSP | *Joint Security Plan* (Medical Device & Health IT), HSCC Cybersecurity WG | Shared manufacturer/HDO baseline; product-security lifecycle expectations |
| NIST NCCoE 1800-8 / 1800-24 / 1800-30 | Wireless infusion pumps / PACS / telehealth RPM | Reference architectures for named healthcare use cases |
| MITRE/FDA Playbook | Medical-Device Cybersecurity Regional Incident Preparedness & Response Playbook (2022) | IR planning specific to device-affecting incidents |

Cross-framework note: for threat-modeling embedded/medical firmware use MITRE EMB3D ([EMB3D_REFERENCE.md](EMB3D_REFERENCE.md)); for the OT side of the hospital (BMS, pneumatic tubes, nurse call) use [ICS_OT_SECURITY_REFERENCE.md](ICS_OT_SECURITY_REFERENCE.md).

---

## The HIPAA Security Rule (and its 2025 overhaul)

The HIPAA Security Rule (45 CFR Part 164, Subpart C) requires covered entities and business associates to protect ePHI with administrative, physical, and technical safeguards, driven by a mandatory risk analysis (§164.308(a)(1)). Today many specifications are "addressable" (implement, or document why an equivalent/none is reasonable) rather than "required," a flexibility often misread as optional. Core technical safeguards: access control, unique user IDs, audit controls, integrity, person/entity authentication, and transmission security (encryption).

The proposed overhaul: status matters. On January 6, 2025, HHS OCR published an NPRM to strengthen the Security Rule ([Federal Register 2024-30983](https://www.federalregister.gov/documents/2025/01/06/2024-30983/hipaa-security-rule-to-strengthen-the-cybersecurity-of-electronic-protected-health-information)). Headline proposals:

- Remove the "addressable" vs. "required" distinction: make nearly all specifications required.
- Mandate MFA, encryption of ePHI at rest and in transit, network segmentation, and a maintained asset inventory + network map.
- Require vulnerability scanning (≈ every 6 months) and penetration testing (≈ annually), plus more rigorous, regularly updated risk analysis and annual compliance audits.

Current status (verified 2026-09-29): the comment period closed March 7, 2025; no final rule has issued, and OMB's regulatory agenda has pushed the projected timeline to around 2027 (it may be revised again or shelved). The existing Security Rule remains in force; build to it now, and track the NPRM as the strategic direction (its proposals mirror the HPH CPGs above and current best practice, so most are worth adopting regardless).

For the breach-notification clock (≤60 days to individuals/HHS; media notice at ≥500) and how HIPAA sits among NIS2/GDPR/SEC/state laws, see [REGULATORY_LANDSCAPE_REFERENCE.md](REGULATORY_LANDSCAPE_REFERENCE.md). For administrative safeguards, BAAs, the 18 identifiers, and audit prep, see [GRC_REFERENCE.md](GRC_REFERENCE.md#hipaa) and [GRC_COMPLIANCE_REFERENCE.md](GRC_COMPLIANCE_REFERENCE.md).

> Legislation to watch: a *Health Infrastructure Security and Accountability Act* was introduced in Congress in 2024 to add mandatory, enforceable healthcare cybersecurity minimums; treat it as proposed (status to confirm before relying on it).

---

## Defender Checklist

Program & governance
- [ ] Joint IoMT/HTM security program with named owners in Security, IT, and Biomed/Clinical Engineering
- [ ] Live device inventory reconciled to the CMMS; MDS2 + SBOM on file per model
- [ ] Adopt HPH CPGs (Essential first) and 405(d) HICP practices; map to NIST CSF 2.0
- [ ] Third-party/vendor risk program covering clearinghouses, labs, imaging, and remote-support access

Network & access
- [ ] Default-deny microsegmentation for device classes; no device->internet or device->user-VLAN by default
- [ ] Brokered, logged, time-boxed vendor remote access; MFA on every external remote-access path (the Change Healthcare gap)
- [ ] Passive monitoring with per-device behavioral baselines and egress alerting

Protocols & data
- [ ] HL7 v2 terminated on an interface engine; MLLP-over-TLS or VPN; source allow-listing + schema validation
- [ ] FHIR on TLS 1.2+ with SMART/OAuth2 least-privilege scopes; `$export` locked to allow-listed backends
- [ ] DICOM TLS + ATNA node auth enabled; no internet-exposed PACS; DICOM content-inspected on ingest
- [ ] ePHI encrypted at rest and in transit (also the NPRM direction)

Resilience & IR
- [ ] Tested clinical downtime procedures and offline/immutable backups ([RANSOMWARE_DEFENSE_REFERENCE.md](RANSOMWARE_DEFENSE_REFERENCE.md), [CYBER_RESILIENCE_BCDR_REFERENCE.md](CYBER_RESILIENCE_BCDR_REFERENCE.md))
- [ ] IR playbook covering device-affecting and patient-safety scenarios (MITRE/FDA playbook)
- [ ] Pre-mapped HIPAA breach-notification runbook ([REGULATORY_LANDSCAPE_REFERENCE.md](REGULATORY_LANDSCAPE_REFERENCE.md))

```bash
# Discover clinical protocol listeners on a scoped, authorized range (passive-first for real devices)
nmap -Pn -p 104,2575,2761,2762,11112 --script dicom-ping,dicom-brute <scope>
#   104/11112 = DICOM   2762 = DICOM-TLS   2575 = HL7/MLLP
# Prefer your IoMT discovery platform's passive inventory over active scans against live patient devices.
```

---

## Tooling

IoMT / connected-device visibility & segmentation (named, current 2026): Claroty (Medigate / xDome for Healthcare), Armis (Centrix), Asimily, Ordr, Forescout (Medical Device Security), Cynerio, Palo Alto Networks Medical IoT Security, and identity-based microsegmentation (e.g., Elisity). These act as the "source of device truth"; feed their classifications into NAC/microsegmentation and the SIEM.

Clinical-protocol / interoperability: interface engines Mirth/NextGen Connect, Rhapsody, Cloverleaf; HAPI FHIR (open-source FHIR server/lib); ONC/ASTP Inferno (FHIR conformance + SMART test suite); DICOM toolkits dcm4che and Orthanc (support TLS) and DVTk for DICOM validation.

Standards & intel sources: Health-ISAC (sector threat sharing), CISA ICS-medical advisories (ICSMA), HHS 405(d) and hphcyber.hhs.gov, HSCC publications, FDA guidance portal, and the HHS OCR breach portal for sector breach trends.

Cross-reference general defensive tooling in [ENDPOINT_SECURITY_REFERENCE.md](ENDPOINT_SECURITY_REFERENCE.md), [SIEM_REFERENCE.md](SIEM_REFERENCE.md), [NETWORK_MONITORING_REFERENCE.md](NETWORK_MONITORING_REFERENCE.md), and [VULNERABILITY_MANAGEMENT_REFERENCE.md](VULNERABILITY_MANAGEMENT_REFERENCE.md).

---

## Related Resources

- [REGULATORY_LANDSCAPE_REFERENCE.md](REGULATORY_LANDSCAPE_REFERENCE.md): HIPAA breach-notification clock and the cross-jurisdiction reporting map
- [GRC_REFERENCE.md](GRC_REFERENCE.md), [GRC_COMPLIANCE_REFERENCE.md](GRC_COMPLIANCE_REFERENCE.md): HIPAA administrative safeguards, BAAs, 18 identifiers, audit prep
- [ICS_OT_SECURITY_REFERENCE.md](ICS_OT_SECURITY_REFERENCE.md): hospital OT (BMS, pneumatic tubes, nurse call) and Purdue-model segmentation
- [FIRMWARE_IOT_SECURITY_REFERENCE.md](FIRMWARE_IOT_SECURITY_REFERENCE.md), [EMB3D_REFERENCE.md](EMB3D_REFERENCE.md): device firmware analysis and embedded-device threat modeling
- [ZERO_TRUST_REFERENCE.md](ZERO_TRUST_REFERENCE.md), [NETWORK_SECURITY_ARCHITECTURE.md](NETWORK_SECURITY_ARCHITECTURE.md): segmentation and least-privilege patterns
- [RANSOMWARE_DEFENSE_REFERENCE.md](RANSOMWARE_DEFENSE_REFERENCE.md), [CYBER_RESILIENCE_BCDR_REFERENCE.md](CYBER_RESILIENCE_BCDR_REFERENCE.md): resilience, downtime, and recovery
- [API_SECURITY_REFERENCE.md](API_SECURITY_REFERENCE.md), [IDENTITY_ACCESS_MANAGEMENT_REFERENCE.md](IDENTITY_ACCESS_MANAGEMENT_REFERENCE.md): securing FHIR/SMART and OAuth
- [PRIVACY_ENGINEERING_REFERENCE.md](PRIVACY_ENGINEERING_REFERENCE.md): ePHI minimization, de-identification, and privacy-by-design

---

*Last updated: 2026-09-29 | TeamStarWolf Cybersecurity Reference Library*
