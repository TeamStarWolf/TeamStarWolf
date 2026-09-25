# MITRE EMB3D Reference (Embedded Devices)

> **[MITRE EMB3D™](https://emb3d.mitre.org/)** is a knowledge base of cyber threats and associated mitigations for **embedded devices** — the PLCs, controllers, medical devices, vehicle ECUs, and IoT endpoints that enterprise threat models routinely skip. Its core move: describe a device by its **properties** (has a bootloader, exposes a debug port, runs a web management interface), and the model returns the **threats** that property set attracts and the **technical mitigations** — tiered *Foundational / Intermediate / Leading* — that the **vendor must build into the device** to address them.

EMB3D is owned and maintained by [The MITRE Corporation](https://www.mitre.org/), developed with embedded-security partners including Niyo "Little Thunder" Pearson, Red Balloon Security, and Narf Industries. It first shipped publicly in May 2024 (threats and properties), added the mitigations catalog in October 2024, and reached v2.0 in April 2025 with a machine-readable STIX dataset. It targets embedded devices across critical infrastructure, IoT, automotive, healthcare, and manufacturing.

The defining design decision — and the thing to internalize before using it — is that **EMB3D mitigations are device-internal engineering mechanisms, not deployment advice**. "Isolate it on the network" and "monitor it externally" are explicitly *not* EMB3D mitigations. That makes EMB3D the demand-side language for asset owners ("which of these should the product already do?") and the requirements language for vendors ("which of these do we build next?").

| | |
|---|---|
| **Owner** | The MITRE Corporation (EMB3D™ is a MITRE trademark) |
| **Current version** | v2.0.2 (June 1, 2026 — site/tooling update; model content unchanged since v2.0.1, April 29, 2025) |
| **Structure** | Device Properties (PID-xx) → Threats (TID-xxx) → Mitigations (MID-xxx) |
| **Scale** (STIX v2.0.1 dataset) | 81 threats · 89 mitigations · 59 device properties · 343 relationships |
| **Mitigation tiers** | Foundational (48) · Intermediate (31) · Leading (10) |
| **Official mappings** | CWE (per threat), CVE examples (per threat, largely from CISA ICS Advisories), ISA/IEC 62443-4-2 (per mitigation) |
| **Data & tooling** | [STIX 2.1 JSON](https://emb3d.mitre.org/subtabs/data.html) · [Properties Mapper](https://emb3d.mitre.org/properties-mapper/) · [GitHub](https://github.com/mitre/emb3d) |

**Related:** [Firmware & IoT Security](FIRMWARE_IOT_SECURITY_REFERENCE.md) · [ICS/OT Security](ICS_OT_SECURITY_REFERENCE.md) · [Hardware Security](HARDWARE_SECURITY_REFERENCE.md) · [Threat Modeling](THREAT_MODELING_REFERENCE.md) · [CWE Reference](CWE_REFERENCE.md) · [CTEM](CTEM_REFERENCE.md)

---

## What EMB3D is (and is not)

Enterprise threat models assume an OS you can instrument, an EDR agent you can install, and an owner who can patch on demand. Embedded devices break all three assumptions: firmware is opaque, compute is constrained, update windows are rare, and the device's security posture was fixed the day the vendor shipped it. EMB3D exists to make that shipped-in posture *describable, comparable, and demandable*.

| EMB3D **is** | EMB3D **is not** |
|---|---|
| A structured threat model **specific to embedded devices** — threats keyed to the hardware/software/networking properties a device actually has | A general enterprise threat model (use [ATT&CK](ATTACK_TECHNIQUE_ATLAS.md) and [Threat Modeling](THREAT_MODELING_REFERENCE.md) methods for that) |
| A catalog of **vendor-implemented, built-into-the-device** technical mitigations | A deployment/hardening guide — network isolation and external monitoring are explicitly out of scope as mitigations |
| A **shared vocabulary** between device makers, asset owners, and testers ("does the device implement MID-030?") | A compliance standard or certification scheme |
| Evidence-driven: each threat carries maturity, public research/advisory references, CWE mappings, and example CVEs | A vulnerability database — TIDs are threat classes, not CVE entries |
| A living, public, community-updated model with machine-readable data | A finished document — content revs roughly quarterly-to-yearly; pin the version you assessed against |

Per MITRE's own framing on the [Background page](https://emb3d.mitre.org/background/), EMB3D aligns with and expands on CWE, ATT&CK, and CVE with a specific focus on embedded devices — it complements those models rather than replacing them.

---

## Who it serves

MITRE names four audiences in the [EMB3D paper](https://emb3d.mitre.org/assets/EMB3D_Paper_09-23-24.pdf) (§4.2 — vendors, asset owners, security researchers, and testing organizations); each uses the same model from a different side. (The [Getting Started page](https://emb3d.mitre.org/subtabs/getting-started.html) walks through the first three.)

| Audience | Primary use | What "done" looks like |
|---|---|---|
| **Device vendors / OEMs** | Prioritize security engineering; pick concrete technical mechanisms per threat | A property profile per product line, threats dispositioned, mitigation tier targets on the roadmap |
| **Asset owners / operators** | Inform acquisition and risk decisions; plan environment-level defenses around known device gaps | EMB3D questions in procurement; per-device gap register feeding compensating-control design |
| **Security researchers** | Organize and triage device investigation | Findings expressed as TIDs with evidence, not one-off write-ups |
| **Testing organizations** | Scope and structure device assessments | Test plans keyed to the device's property-derived threat list |

The vendor/owner split matters because of the mitigation philosophy: since every EMB3D mitigation is something only the **vendor** can implement, an asset owner's output from an EMB3D review is not "apply these mitigations" — it is (a) a list of demands for the vendor and the next procurement cycle, and (b) a precise map of what the environment must compensate for in the meantime (that compensation work lives in [ICS/OT Security](ICS_OT_SECURITY_REFERENCE.md) and [Network Defense](NETWORK_DEFENSE_REFERENCE.md) territory, outside EMB3D itself).

---

## Model structure: properties, threats, mitigations

Three pillars, two relationship types. Enumerate what the device *is*, and the model tells you what it *attracts* and what should have been *built in*.

```
   DEVICE PROPERTIES              THREATS                        MITIGATIONS
   (PID-xx)                       (TID-xxx)                      (MID-xxx)
   what the device is             what that exposes it to        what the vendor builds in

   PID-11 Includes a       ──►    TID-101 Power Consumption
          microprocessor   ──►    TID-102 Electromagnetic  ──►   side-channel-resistant
                                          Analysis Side          crypto implementations
                                          Channels

   PID-21 Includes a       ──►    TID-201 Inadequate       ──►   verified/secure boot,
          bootloader                      Bootloader             MID-030 Firmware Rollback
                                          Protection and         Protections, ...
                                          Verification
        properties ──map to──► threats ──addressed by──► tiered mitigations
```

| Pillar | ID scheme | Count (STIX v2.0.1) | What it captures |
|---|---|---|---|
| **Device Properties** | PID-xx | 59 (19 top-level + 40 sub-properties) | Hardware, system-software, application-software, and networking characteristics a device may have |
| **Threats** | TID-1xx–4xx | 81 | Threat classes an adversary can execute against devices with the mapped properties |
| **Mitigations** | MID-001–089 | 89 | Vendor-implemented technical mechanisms, each tiered Foundational / Intermediate / Leading |

The STIX v2.0.1 dataset encodes 343 relationships: 90 property→threat mappings, 213 mitigation→threat mappings, and 40 sub-property→parent links. Both properties and threats share the same four category spines:

| Category | Properties | Threats (ID range) |
|---|--:|---|
| **Hardware** | 10 | 16 (TID-1xx) |
| **System Software** | 25 | 26 (TID-2xx) |
| **Application Software** | 18 | 30 (TID-3xx) |
| **Networking** | 6 | 9 (TID-4xx) |

---

## The properties-to-threats mapping

This is EMB3D's tailoring mechanism and the reason a review doesn't start from all 81 threats. A device is profiled by walking the [properties list](https://emb3d.mitre.org/properties-list/) — does it include a microprocessor? a bootloader? an RTOS or full OS? a web management interface? wireless interfaces? remote update capability? — and each asserted property pulls in its mapped threats.

Worked examples from the official catalog:

| Property | Maps to | Why |
|---|---|---|
| **PID-11** Device includes a microprocessor | TID-101 Power Consumption Analysis Side Channel, TID-102 (electromagnetic side channel), among others — the dataset maps PID-11 to four threats | Physical side channels only matter if there's silicon executing secrets |
| **PID-21** Device includes a bootloader | TID-201 Inadequate Bootloader Protection and Verification | No bootloader, no boot-chain threat; a bootloader without verification is a persistence gift |

Practical consequences of this design:

- **The profile is the deliverable.** A property profile is reusable across every assessment, procurement, and pen test of that device family — build it once from vendor documentation, interface inspection, and testing, then maintain it.
- **Honesty beats optimism.** Properties are about what the device *has*, not what is *enabled by default*. A debug interface that "ships disabled" is still a property; whether the disablement is robust is exactly what the mapped threats interrogate.
- **Absence of a property prunes threats defensibly.** "Not applicable — device has no wireless interface (property not present)" is an auditable statement in a way that "we judged Wi-Fi attacks unlikely" never is.
- **The [Properties Mapper](https://emb3d.mitre.org/properties-mapper/)** automates the walk: tick the device's properties, get the candidate threat list. Since v2.0.2 the tool generates shareable URLs, so a device profile can be passed between vendor, tester, and owner as a link.

---

## Threat catalog: categories, evidence, and maturity

Threats are the TID-xxx entries, numbered by category. Representative entries (names verbatim from the official catalog):

| Category | Range | Count | Example |
|---|---|--:|---|
| **Hardware** | TID-1xx | 16 | TID-101 Power Consumption Analysis Side Channel |
| **System Software** | TID-2xx | 26 | TID-201 Inadequate Bootloader Protection and Verification |
| **Application Software** | TID-3xx | 30 | TID-311 Default Credentials |
| **Networking** | TID-4xx | 9 | TID-408 Unencrypted Sensitive Data Communication |

Every threat entry carries, per the [EMB3D paper](https://emb3d.mitre.org/assets/EMB3D_Paper_09-23-24.pdf):

| Field | Content | Use it for |
|---|---|---|
| **Description** | The threat mechanism at advisory level | Shared understanding across vendor/owner/tester |
| **Threat Maturity** | How real-world the threat is (see below) | Risk-ranking candidate threats |
| **Threat Evidence** | Links to public research, advisories, and ATT&CK where adversary use is documented | Justifying priority to engineering and leadership |
| **CWE mappings** | All 81 threats map to CWE, at the lowest abstraction available (falling back to Class/Pillar CWEs) | Connecting to SDLC weakness tracking — see [CWE Reference](CWE_REFERENCE.md) |
| **Example CVEs** | Concrete instances — per the paper, largely from CISA ICS Advisories (48 of 81 threats list at least one) | Proving "this happens to devices like ours" |

**Threat Maturity** is EMB3D's evidence-grading scale. Distribution in the STIX v2.0.1 dataset:

| Maturity | Count | Meaning for prioritization |
|---|--:|---|
| **Observed adversarial technique** | 32 | Documented in-the-wild use — treat as front of queue |
| **Proof of concept** | 25 | Public research demonstrates it works — viability is not in question, only targeting |
| **Known exploitable weakness** | 22 | Weakness class is established even without a public device-specific demo |
| **Observed adversarial behavior** | 2 | Adversary interest/behavior observed at the broader level |

> **Read maturity with your deployment context, not instead of it.** A proof-of-concept hardware side channel may be irrelevant for a device in a locked substation and decisive for a smart lock sold at retail. Maturity ranks the evidence; the review (below) ranks the risk.

---

## Mitigations: Foundational, Intermediate, and Leading tiers

The mitigations catalog (MID-001 through MID-089) is what turned EMB3D from a taxonomy into an engineering roadmap when it landed in the October 1, 2024 full release. Two rules define it (paper, §3.3.1–3.3.2):

1. **Vendor-implemented only.** A mitigation is a technical mechanism built into the device. Environment-level guidance — network isolation, external monitoring — is explicitly *not* an adequate EMB3D mitigation. (Contrast with ATT&CK mitigations, which freely include environmental controls.)
2. **Every mitigation is tiered** to signal engineering effort and maturity of practice. The paper labels the tiers Tier 0/1/2; the site uses the names:

| Tier | Count (STIX v2.0.1) | Official definition (paraphrased from paper Table 1) | Engineering signal |
|---|--:|---|---|
| **Foundational** | 48 | The minimal capability providing mitigation; already deployed across comparable embedded devices; well-defined implementation guidance; requires no additional/dedicated hardware and no proprietary or commercial technology dependencies | Table stakes. Absence on a current product is a finding, full stop |
| **Intermediate** | 31 | Commercially adopted in other domains (IT, mobile) but not yet prevalent in comparable embedded devices; may require hardware or design changes, longer-term planning, or proprietary technology integration | Roadmap items; differentiators in procurement |
| **Leading** | 10 | The most robust mitigation for the threat, reflecting the state of novel research — viable PoC, test-device implementation, or limited deployment; robust implementation guidance may not exist yet | Signals of a serious device-security program (e.g., MID-087 Utilization of Formally Verified OS (Micro-)Kernels) |

How to use the tiers without misusing them:

- **For vendors:** the tier ladder is a per-threat maturity roadmap — ship Foundational everywhere, plan Intermediate into next hardware revisions (they often need silicon or board changes), and treat Leading as R&D positioning. SecurityWeek's coverage of the full release framed the tiers exactly this way: helping vendors and OEMs identify deployment challenges and prioritize security strategies.
- **For asset owners:** tier language turns vague procurement asks into gradable ones. "Device implements all Foundational mitigations mapped to its property-derived threats" is a testable contract clause; "device is secure by design" is not.
- **Don't average tiers into a score.** A device with 40 Foundational mitigations and an unverified bootloader is not "mostly fine" — mitigations only count against the threats they map to, and threat criticality is set by your deployment.

---

## Alignment with ISA/IEC 62443-4-2

This is EMB3D's one official standards mapping, introduced with the full release: **all 89 mitigations** in the STIX v2.0.1 dataset carry an `x_mitre_emb3d_mitigation_IEC_62443_mappings` field referencing controls from **ISA/IEC 62443-4-2** (*Security for Industrial Automation and Control Systems: Technical Security Requirements for IACS Components*). Roughly 45 distinct control lines are referenced — an exact count is method-dependent because the dataset carries minor spelling variants of some control names — using the standard's component-requirement prefixes:

| Prefix | Requirement family |
|---|---|
| **CR** | Component Requirements (apply across component types) |
| **SAR** | Software Application Requirements |
| **EDR** | Embedded Device Requirements |
| **HDR** | Host Device Requirements |
| **NDR** | Network Device Requirements |

Example from the live catalog: [MID-030 Firmware Rollback Protections](https://emb3d.mitre.org/mitigations/MID-030.html) maps to *EDR / HDR / NDR 3.10 – Support for updates* and *SAR / EDR / HDR / NDR 3.2 – Protection for malicious code* (control names as the catalog prints them).

**What the mapping means — and what it does not** (paper §3.3.3):

- The stated intent is to help organizations already using 62443-4-2 identify **which EMB3D mitigations are necessary to fulfill the intent of a control**, assuming the underlying threat is relevant to the device.
- It is **many-to-one**: a single 4-2 control commonly expands into several EMB3D mitigations. The paper's worked example: control 3.2 (*Protection from malicious code*) maps to MID-004, MID-005, MID-006, MID-007, MID-015, MID-020, and MID-021.
- The paper explicitly warns the mappings are **not** lists of "potentially relevant" controls and the mapping is **not a compliance or certification crosswalk**. Implementing the mapped MIDs does not certify a component against 62443-4-2, and a 62443 certificate does not prove the MIDs are present. Treat the mapping as a translation layer between an engineering catalog and a requirements standard — in both directions it generates questions, not attestations.

For the surrounding 62443 series (zones and conduits, security levels, the Purdue model context), see [ICS/OT Security](ICS_OT_SECURITY_REFERENCE.md).

---

## How EMB3D complements ATT&CK, CWE, and CVE

Each model answers a different question; EMB3D's official position (Background page) is that it aligns with and expands on them for embedded devices. The linkages that actually exist:

| Model | Question it answers | Official EMB3D linkage |
|---|---|---|
| **[ATT&CK](ATTACK_TECHNIQUE_ATLAS.md)** | What do adversaries do post-compromise, at the campaign level? | **Evidence references only.** 30 of 81 threats cite attack.mitre.org pages in their Threat Evidence where adversary use is documented. There is **no official EMB3D↔ATT&CK technique crosswalk table** — do not build or trust one presented as official |
| **[CWE](CWE_REFERENCE.md)** | What class of weakness enables this? | **Full official mapping.** All 81 threats map to CWEs at the lowest available abstraction level (falling back to Class/Pillar CWEs) |
| **[CVE](CVE_REFERENCE.md)** | Which specific product instance is vulnerable? | **Per-threat examples.** 48 of 81 threats list concrete CVEs — per the paper, largely from CISA ICS Advisories |
| **[ATT&CK for ICS](ICS_ATTACK_ATLAS.md)** | How do adversaries operate across an OT environment? | No official mapping; complementary altitude — EMB3D covers the device build, ICS ATT&CK covers the operational campaign around it |

The altitude picture: **CWE** names the weakness class, **EMB3D** says which devices attract it and what the vendor should build against it, **CVE** records where it actually surfaced, and **ATT&CK** describes the adversary operation it enables. A useful practitioner loop: a CISA ICS advisory lands (CVE) → identify the EMB3D threat class it instantiates (the TID's example-CVE field often does this for you) → check whether your device profile carries the enabling property → ask whether the mapped mitigations exist in your firmware version → express the campaign risk in ATT&CK terms for the SOC. That loop is ours, not MITRE's — but every hop in it uses an official field.

No official EMB3D mappings exist to NIST SP 800-53, NIST CSF, or D3FEND as of v2.0.2. If you need those bridges, derive them internally via CWE or 62443-4-2 and label them as internal.

---

## EMB3D and CISA Secure by Design

**The relationship is thematic, not a formal mapping — no MITRE/CISA crosswalk document exists.** State it that way in any deliverable.

The thematic fit is real, though. [CISA Secure by Design](https://www.cisa.gov/securebydesign) urges manufacturers to build security in during design and manufacture; its core guidance is the joint whitepaper *Shifting the Balance of Cybersecurity Risk: Principles and Approaches for Security-by-Design and -Default* (first published April 13, 2023; updated October 2023 with 17 U.S. and international partners under the revised title *Shifting the Balance of Cybersecurity Risk: Principles and Approaches for Secure by Design Software*), built on three principles: **take ownership of customer security outcomes, embrace radical transparency and accountability, and lead from the top.** The companion [Secure by Design Pledge](https://www.cisa.gov/securebydesign/pledge) (announced May 8, 2024 with 68 initial software-manufacturer signers; CISA's page now cites 200+) commits signers to good-faith progress on seven goals.

EMB3D operationalizes the first principle for embedded devices: because its mitigations are by definition vendor-implemented and built in, working through the catalog *is* taking ownership of customer security outcomes at the device level. Press coverage of the May 2024 release made the connection explicit — The Hacker News described EMB3D as embracing secure-by-design so vendors ship "products that have a reduced number of exploitable flaws out of the box" (The Hacker News, May 13, 2024).

| Secure by Design principle | What EMB3D contributes |
|---|---|
| **Take ownership of customer security outcomes** | A concrete, threat-derived backlog of built-in mechanisms (the MID catalog), instead of shipping hardening guides that transfer the work to customers |
| **Radical transparency and accountability** | A public vocabulary for stating exactly which mitigations a product implements, at which tier, against which threats |
| **Lead from the top** | Tier progression (Foundational → Intermediate → Leading) as a board-legible security-engineering roadmap |

This table is our practitioner framing of a thematic alignment — cite the principles to CISA and the mitigation philosophy to MITRE, never as a joint mapping.

---

## Running a device threat-exposure review with EMB3D

MITRE's [Getting Started](https://emb3d.mitre.org/subtabs/getting-started.html) guidance defines a three-step workflow. Expanded into a runnable review:

```
 1. PROFILE                2. TRIAGE                    3. DISPOSITION
 enumerate properties  ──► review candidate threats ──► select / demand / compensate
 (docs + testing +         (maturity, evidence,          (mitigations by tier;
  Properties Mapper)        CWE, example CVEs,            vendor asks; environment
                            deployment context)           compensations; gap register)
```

**Step 1 — Enumerate the device's properties.** Work from vendor documentation, datasheets, interface inspection, and hands-on testing; record each property as present/absent/unknown with the evidence. Use the [Properties Mapper](https://emb3d.mitre.org/properties-mapper/) to turn the profile into a candidate threat list, and share the profile URL with every party in the review. Treat "unknown" as work, not as absent.

**Step 2 — Review each candidate threat for applicability and risk.** For each TID: read the description against the device's actual configuration; weigh Threat Maturity and Threat Evidence; check the example CVEs (are devices like this one already in CISA ICS advisories for this threat?); and layer on deployment context — physical accessibility, network exposure, safety/process impact. Disposition every threat explicitly: *applicable*, *not applicable (property absent or configuration removes it)*, or *needs testing*.

**Step 3 — Select and implement mitigations across the tiers.** For each viable threat, walk its mapped MIDs. Vendors implement; owners verify presence, demand absences via the vendor, and design environment compensations for gaps that won't close this hardware generation (the compensation design itself lives outside EMB3D — see [ICS/OT Security](ICS_OT_SECURITY_REFERENCE.md)).

**Do**

- Pin the EMB3D version (and STIX dataset version) the review used; re-diff the profile against new model releases.
- Record property evidence ("UART header populated, verified on board rev C") — the profile outlives the review.
- Profile per hardware revision, not per product name — board revisions add and remove properties, and the threat list moves with them.
- Make the vendor confirm or deny properties you cannot test; a refusal is itself risk data.
- Feed the output into your exposure program: an unmitigated, applicable TID on a deployed device is an exposure and belongs in the [CTEM](CTEM_REFERENCE.md) prioritization and validation stages like any other.
- Reuse the threat list to scope device pen tests — testers validating a property-derived TID list produce findings the vendor can act on.

**Don't**

- Don't start from all 81 threats — the property mapping exists to prune defensibly.
- Don't accept "the deployment network is segmented" as closing an EMB3D threat; by the model's own definition that is compensation, not mitigation. Track it as compensation.
- Don't score the device by counting mitigations across unrelated threats.
- Don't present internally derived mappings (to ATT&CK techniques, 800-53, CSF) as EMB3D content.
- Don't bulk-copy threat/mitigation text into your deliverables — EMB3D content is © The MITRE Corporation under MITRE's Terms of Use (not Creative Commons/MIT); summarize, cite IDs, and link.

### Worked example (hypothetical device, verified IDs)

A networked industrial gateway is under review. The property walk confirms, among others, **PID-11** (includes a microprocessor) and **PID-21** (includes a bootloader), plus a web management interface and non-removable support for a legacy plaintext protocol. Four rows from the resulting review illustrate the disposition patterns:

| Candidate threat | Property trigger | Disposition | Outcome |
|---|---|---|---|
| **TID-101** Power Consumption Analysis Side Channel | PID-11 | Applicable in principle; device lives in a locked, monitored cabinet, and the threat evidence is research-grade | Deprioritized **with the physical-access assumption written down** — the disposition is invalid for the same SKU deployed in a field enclosure |
| **TID-201** Inadequate Bootloader Protection and Verification | PID-21 | Vendor documentation claims signed boot; testing confirms it, but firmware rollback protection (MID-030) is absent | Applicable, partially mitigated — gap-register row, vendor ask with roadmap date |
| **TID-311** Default Credentials | Web management interface | First-boot forced credential change confirmed by hands-on testing | Mitigated — evidence recorded, row closed |
| **TID-408** Unencrypted Sensitive Data Communication | Legacy protocol support | Protocol cannot be disabled in this hardware generation | Applicable, unmitigated in-device — environment compensation (encrypting front-end, segment restrictions) tracked as compensation, plus a next-generation procurement requirement |

Four rows, four different endings — deprioritized-with-assumptions, partial-with-vendor-ask, verified-closed, and compensated-plus-procurement. A finished review is a register of such dispositions, not a score.

---

## Limitations and honest edges

Knowing where the model stops prevents the two classic failure modes: treating EMB3D as a certification scheme, and dismissing it because it isn't one.

| Limit | Consequence for your program |
|---|---|
| **No built-in risk scoring** | Threat Maturity grades evidence, not impact. Severity ranking is your job, using deployment context (physical access, network exposure, process/safety impact) |
| **Mitigation presence is hard to verify externally** | Firmware is opaque; many MIDs can only be confirmed by vendor attestation or destructive/instrumented testing. Weight vendor claims accordingly and prefer testable formulations in contracts |
| **Vendor-only mitigations mean owner reviews end in asks, not fixes** | Budget for the compensation engineering the model deliberately excludes; EMB3D tells you *where* to compensate, not *how* |
| **Living model** | New releases can add threats to a profile you considered settled (v2.0 did exactly this with logging). Version-pin assessments and diff on release |
| **Official mappings stop at CWE, CVE examples, and 62443-4-2** | Bridges to NIST CSF, SP 800-53, D3FEND, or ATT&CK technique level are internal work products if you build them — label them as such |
| **Coverage is threat-class altitude** | A TID disposition never substitutes for product-specific vulnerability response; keep the CVE/advisory pipeline ([CVE Reference](CVE_REFERENCE.md)) running independently |

---

## Program guidance: procurement, vendor questionnaires, and gap tracking

EMB3D's leverage for an asset owner peaks **before purchase** — it is the difference between asking "is it secure?" and asking gradable questions. (The framing below is practitioner guidance from this library, built on official EMB3D fields.)

**Procurement language that works:**

| Ask | Why it's answerable |
|---|---|
| "Provide the device's EMB3D property profile (Properties Mapper link acceptable)" | Forces the vendor to state what the device *is*; disagreements surface immediately |
| "For each applicable threat, state implemented mitigations by MID and tier" | Converts marketing into a checkable matrix |
| "Identify applicable threats with **no** implemented Foundational mitigation, with roadmap dates" | The gaps clause — Foundational absences are the red flags by MITRE's own tier definition |
| "State which ISA/IEC 62443-4-2 controls your EMB3D mitigations were mapped against" | Ties the answer into existing 62443-based procurement without pretending it's certification |
| "Commit to notifying us when EMB3D releases change the threat set applicable to this device's properties" | Makes the living-model problem contractual |

**Vendor questionnaire seeds, by threat category** — phrase questions against threat classes, not exploits:

| Category | Sample question |
|---|---|
| Hardware (TID-1xx) | "Which debug/test interfaces exist on production boards, and what mechanism disables or authenticates them?" |
| System Software (TID-2xx) | "Describe boot-chain verification end to end, including rollback protection (cf. MID-030) and what happens on verification failure" |
| Application Software (TID-3xx) | "How are default credentials (cf. TID-311) eliminated — forced first-boot change, per-device uniqueness, or neither?" |
| Networking (TID-4xx) | "Which services transmit sensitive data without encryption (cf. TID-408), and is legacy plaintext protocol support removable?" |

**Gap register.** Track one row per (device family × applicable TID): columns for property evidence, threat maturity, mitigations present (MIDs + tier), vendor commitment + date, environment compensation + owner, and residual-risk sign-off. Roll it up two ways — per device family for procurement leverage, per threat category for architecture decisions. Report movement (gaps closed by vendor fix vs. by compensation vs. accepted) with your [security metrics](SECURITY_METRICS_REFERENCE.md), and treat the open-gap rows as exposure inputs to [CTEM](CTEM_REFERENCE.md).

**Watching the open gaps.** While a gap row stays open, the asset owner's remaining moves are telemetry and exposure control. EMB3D itself treats device logging capability as model content — v2.0 added logging-related properties (PID-28, PID-34) and two log-related threats (TID-225, TID-226) — so "what can this device even tell us?" is a property-profile question, not an afterthought. Practical telemetry per threat category (our guidance, not MITRE's):

| Open-gap category | Collect while you wait |
|---|---|
| Hardware (TID-1xx) | Physical-access records for enclosures/cabinets; tamper-evidence checks folded into maintenance rounds; chassis-intrusion signals where the device exposes them |
| System Software (TID-2xx) | Firmware version inventory reconciled against vendor releases; boot-failure and watchdog-reset counts; device syslog/event output shipped off-device wherever the properties allow |
| Application Software (TID-3xx) | Authentication successes/failures on management interfaces; configuration-change events; account inventory reviews against commissioning records |
| Networking (TID-4xx) | Flow records for the device's segment; alerting on plaintext management protocols and on peers outside the engineered communication set |

**Vendor-side: EMB3D in the device SDLC.** For device makers, the same catalog runs forward through the lifecycle:

- **Design gate:** draft the property profile from the architecture and review candidate threats *before* BOM and silicon lock — Intermediate-tier mitigations are the ones that routinely need hardware or board changes, and they cannot be retrofitted after that gate.
- **Backlog:** carry mitigations as engineering backlog items under their MID and tier; the tier label is the effort/maturity signal product management needs for sequencing.
- **Verification:** key the security test plan (internal and third-party) to the applicable TID list, so testing demonstrates threat coverage rather than tool output.
- **Release:** publish the property profile and implemented-MID matrix as customer-facing security documentation — this is the transparency half of [Secure by Design](https://www.cisa.gov/securebydesign) made concrete, and it pre-answers the procurement questionnaires above.
- **Maintenance:** diff each EMB3D release against shipped profiles, and contribute observed-but-uncataloged threats back through [the community process](https://github.com/mitre/emb3d) rather than forking privately.

---

## Machine-readable data and tooling

| Resource | What it is |
|---|---|
| **[STIX JSON dataset](https://emb3d.mitre.org/subtabs/data.html)** | The full model in STIX 2.1, generated with the OASIS python-stix2 library: threats as `vulnerability` objects, mitigations as `course-of-action`, properties as custom `x-mitre-emb3d-property` objects, plus the relationship graph. Datasets published for v2.0 and v2.0.1; there is no v2.0.2 dataset because 2.0.2 changed no model content — cite v2.0.1 as current content |
| **[Properties Mapper](https://emb3d.mitre.org/properties-mapper/)** | Interactive property → candidate-threat-list tool; shareable profile URLs since v2.0.2 |
| **[GitHub — mitre/emb3d](https://github.com/mitre/emb3d)** | Public repository; community updates are accepted. Contact: emb3d@mitre.org |
| **[EMB3D paper](https://emb3d.mitre.org/assets/EMB3D_Paper_09-23-24.pdf)** | *The EMB3D Threat Model for Embedded Devices* (Sept 23, 2024, 21 pp., MITRE case 24-00165-2) — the canonical technical description: tier definitions, mitigation philosophy, 62443 mapping methodology |

The STIX dataset is the right substrate for automation: diffing model versions, joining TIDs to your CWE/CVE pipelines, generating per-device threat lists from stored property profiles, or building an internal register without screen-scraping the site. All counts in this reference were taken from the v2.0.1 STIX dataset; if you republish numbers, attribute them to a dataset version the same way.

---

## Version history and maintenance

| Date | Release | What changed |
|---|---|---|
| **Dec 13, 2023** | Draft pre-release | Announced by MITRE with Niyo "Little Thunder" Pearson, Red Balloon Security, and Narf Industries |
| **May 13, 2024** | First public release | Threats + device properties; mitigations not yet included |
| **Oct 1, 2024** | Full release | Mitigations catalog with Foundational/Intermediate/Leading tiers; ISA/IEC 62443-4-2 mappings |
| **Apr 22, 2025** | v2.0 | STIX 2.1 dataset; new logging properties (PID-28, PID-34); two log-related threats (TID-225, TID-226); six new mitigations (MID-084–089, incl. MID-087 formally verified microkernels) |
| **Apr 29, 2025** | v2.0.1 | Content revision (official log: "TID-213 reverted to its correct name") — current model content |
| **Jun 1, 2026** | v2.0.2 | Site/usability update (shareable Properties Mapper URLs); no model-content change |

Full log: [version history](https://emb3d.mitre.org/subtabs/version-history.html). Operational consequences: pin the version each assessment used; diff the STIX data on new releases and re-run affected device profiles (the v2.0 logging additions are the template — new properties can add threats to a profile you considered settled); and route observed-but-uncataloged embedded threats to the community process rather than a private fork.

---

## Using EMB3D with the rest of this library

| Goal | How |
|---|---|
| **Analyze the firmware itself** | EMB3D says *what to worry about*; [Firmware & IoT Security](FIRMWARE_IOT_SECURITY_REFERENCE.md) covers extraction, analysis, UEFI/BIOS, and the hardware interfaces behind the TID-1xx/2xx threats |
| **Go deep on hardware roots of trust** | [Hardware Security](HARDWARE_SECURITY_REFERENCE.md) — TPM, secure boot, side channels, JTAG — the mechanisms many MIDs are built from |
| **Place devices in an OT program** | [ICS/OT Security](ICS_OT_SECURITY_REFERENCE.md) for the 62443 series, Purdue model, and the environment-level compensations EMB3D deliberately excludes |
| **Model the adversary campaign around the device** | [ICS ATT&CK Atlas](ICS_ATTACK_ATLAS.md) and the [Technique Atlas](ATTACK_TECHNIQUE_ATLAS.md) — remembering there is no official EMB3D↔ATT&CK crosswalk |
| **Connect to weakness/vulnerability plumbing** | [CWE Reference](CWE_REFERENCE.md) (official per-threat mappings) and [CVE Reference](CVE_REFERENCE.md) (per-threat examples, largely from CISA ICS Advisories) |
| **Threat-model the wider system** | [Threat Modeling](THREAT_MODELING_REFERENCE.md) — STRIDE/PASTA for the system; EMB3D for the device nodes inside it |
| **Feed exposures into the loop** | Open gap-register rows are exposures for [CTEM](CTEM_REFERENCE.md) prioritization and validation |
| **Buy better devices** | Pair the procurement asks above with [Supply Chain Security](SUPPLY_CHAIN_SECURITY_REFERENCE.md) |

---

## Sources

- EMB3D home — https://emb3d.mitre.org/
- Background — https://emb3d.mitre.org/background/
- Getting Started — https://emb3d.mitre.org/subtabs/getting-started.html
- Threats index — https://emb3d.mitre.org/threats/
- Mitigations index — https://emb3d.mitre.org/mitigations/
- Device properties — https://emb3d.mitre.org/properties-list/
- Properties Mapper — https://emb3d.mitre.org/properties-mapper/
- Version history — https://emb3d.mitre.org/subtabs/version-history.html
- Data downloads (STIX) — https://emb3d.mitre.org/subtabs/data.html
- EMB3D paper (Sept 23, 2024) — https://emb3d.mitre.org/assets/EMB3D_Paper_09-23-24.pdf
- STIX v2.0.1 dataset (source of all counts herein) — https://emb3d.mitre.org/assets/emb3d-stix-2.0.1.json
- GitHub — https://github.com/mitre/emb3d
- Full-release announcement (BusinessWire, Oct 1, 2024) — https://www.businesswire.com/news/home/20241001622675/en/MITRE-Unveils-Full-Release-of-EMB3D-Threat-Model-that-Introduces-Mitigations
- First-release coverage (The Hacker News, May 13, 2024) — https://thehackernews.com/2024/05/mitre-unveils-emb3d-threat-modeling.html
- Full-release coverage (SecurityWeek) — https://www.securityweek.com/mitre-adds-mitigations-to-emb3d-threat-model/
- CISA Secure by Design — https://www.cisa.gov/securebydesign
- CISA Secure by Design Pledge — https://www.cisa.gov/securebydesign/pledge

---

*EMB3D™ and ATT&CK® are trademarks of The MITRE Corporation; EMB3D content is © The MITRE Corporation and provided under MITRE's Terms of Use (see the footer at [emb3d.mitre.org](https://emb3d.mitre.org/)). This is an independent practitioner reference summary, not affiliated with or endorsed by MITRE or CISA; consult the upstream model for authoritative and current content.*
