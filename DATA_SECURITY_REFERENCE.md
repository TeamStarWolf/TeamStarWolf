# Data Security Reference

> **Data security is a program, not a perimeter — and its public spine already exists.** [NIST CSF 2.0](https://csrc.nist.gov/pubs/cswp/29/the-nist-cybersecurity-framework-csf-20/final) (final, February 26, 2024) gives the discipline its skeleton in the Protect function's **Data Security category (PR.DS)**, whose four subcategories are the states every control in this document serves: data **at rest** (PR.DS-01), data **in transit** (PR.DS-02), data **in use** (PR.DS-10), and **backups** created, protected, maintained, and tested (PR.DS-11). Around that skeleton, NIST SP 800-171 Rev. 3 defines what protecting regulated data actually requires, SP 800-188 governs how to keep less of it, and a fast-moving commercial tool landscape (DSPM, DLP, DDR) supplies the machinery.

Most security programs protect *systems* and hope the data inside benefits. A data security program inverts that: it starts from **what data exists, where it lives, and what its loss costs**, then aims classification, discovery, loss prevention, encryption, egress control, and minimization at the answer. The payoff shows up everywhere else — ransomware double extortion, insider theft, cloud bucket exposure, and regulatory scope are all, at bottom, data problems.

This reference is the program layer for the data-security discipline path: taxonomy and threat behavior at a conceptual level, defender architecture and controls in concrete detail.

**Related:** [Insider Threat Program](INSIDER_THREAT_REFERENCE.md) · [Privacy Engineering](PRIVACY_ENGINEERING_REFERENCE.md) · [Cryptography](CRYPTOGRAPHY_REFERENCE.md) · [GRC Compliance](GRC_COMPLIANCE_REFERENCE.md) · [Zero Trust](ZERO_TRUST_REFERENCE.md) · [Security Metrics](SECURITY_METRICS_REFERENCE.md)

---

## Scope & how to use this reference

| You need | Go to |
|---|---|
| **Cipher mechanics, algorithm selection, PKI** | [Cryptography Reference](CRYPTOGRAPHY_REFERENCE.md) |
| **Key vaults, secret detection, machine credentials** | [Secrets Management](SECRETS_MANAGEMENT_REFERENCE.md) |
| **Backup architecture and restore testing** (PR.DS-11 in depth) | [Ransomware Defense & Resilience](RANSOMWARE_DEFENSE_REFERENCE.md) |
| **Privacy law detail, DPIAs, consent, anonymization engineering** | [Privacy Engineering](PRIVACY_ENGINEERING_REFERENCE.md) · [GRC Compliance](GRC_COMPLIANCE_REFERENCE.md) |
| **The insider-threat program around exfiltration telemetry** (HR, legal, UAM) | [Insider Threat Program](INSIDER_THREAT_REFERENCE.md) |
| **Cloud storage misconfiguration and IAM attack paths** | [Cloud Security](CLOUD_SECURITY_REFERENCE.md) · [Cloud Attack Reference](CLOUD_ATTACK_REFERENCE.md) |
| **SaaS sharing, OAuth abuse, tenant hardening** | [SaaS Security](SAAS_SECURITY_REFERENCE.md) |
| **The data protection program itself** — classification, discovery, DLP, encryption pointers, egress, retention, metrics | **This document** |

Everything here is defensive and policy-level. Attacker behavior is described in the language public advisories and MITRE ATT&CK use; defender actions are described concretely.

---

## The data security program model

Five capabilities, run as a loop. Tool categories change names; these do not.

| Capability | Question it answers | Primary machinery |
|---|---|---|
| **Govern** | What data matters, who owns it, what may we keep and for how long? | Classification policy, retention schedule, data ownership, risk appetite — [GRC Compliance](GRC_COMPLIANCE_REFERENCE.md) |
| **Know** | Where is the data, what is it, who can touch it? | Discovery scanning, DSPM, classification & labeling |
| **Protect** | Is it encrypted, minimized, and reachable only by need? | Encryption at rest/in transit/in use, access control, DLP policy, minimization |
| **Detect** | Is it moving somewhere it shouldn't? | DLP events, egress telemetry, [ATT&CK Exfiltration (TA0010)](https://attack.mitre.org/tactics/TA0010/) analytics, UEBA |
| **Respond** | Contain, revoke, notify, learn | [IR Playbooks](IR_PLAYBOOKS.md) (data exfiltration playbook), breach-notification readiness |

Two structural truths drive the whole document:

- **You cannot protect what you have not found, and you cannot prioritize what you have not classified.** Discovery and classification are not paperwork preceding the "real" controls — they are the targeting system every downstream control depends on. Untargeted DLP is noise; untargeted encryption is theater on the wrong data.
- **Every copy is attack surface.** The cheapest data-security control is *having less data* — fewer copies, shorter retention, de-identified analytics. Minimization competes with every tool purchase on this page and frequently wins.

---

## Data classification & labeling

### Sensitivity tiers

Classification converts "all data is important" into an enforceable gradient. Three to five tiers is the working range — Microsoft's own guidance for Purview deployments is that effectiveness drops beyond roughly **5 main labels** (with up to 5 sublabels each), and that experience generalizes: every tier you add must buy a *different handling rule*, or it is taxonomy for its own sake.

| Tier (typical) | Typical contents | Handling expectation the tier must trigger |
|---|---|---|
| **Public** | Published material, marketing | No restriction; integrity still matters |
| **Internal** | Routine business content | No external sharing by default; baseline access control |
| **Confidential** | Customer data, financials, most PII | Encryption, need-to-know access, DLP monitoring, external sharing by exception |
| **Restricted** | Regulated data (PHI, CUI, payment data), trade secrets, credentials | Encryption with managed keys, explicit access grants, DLP blocking, logging, egress restrictions |

**Regulated schemes ride on top of the tiers, not instead of them.** The clearest example is **Controlled Unclassified Information (CUI)**: [NIST SP 800-171 Rev. 3](https://csrc.nist.gov/pubs/sp/800/171/r3/final) (final, May 2024) defines the 97 security requirements a nonfederal system handling CUI must meet — see [Regulatory & framework drivers](#regulatory-amp-framework-drivers) below. Internally, CUI is simply a population of items your classification scheme must be able to identify and route to the controls the requirement set demands.

**Do**

- Derive tiers from **business and legal impact of loss**, with the data owners in the room — classification is a governance output, not a security-team artifact.
- Write the **handling rule table first** (who may access, where it may live, how it may move, when it dies) and only then name the tiers.
- Make labels **machine-readable metadata** so DLP, encryption, retention, and sharing controls can key off them automatically.
- Set a **default label** for new content and auto-label the patterns you can match reliably (identifiers, document fingerprints); humans handle the ambiguous middle.
- Label at **creation time** — retrofitting a petabyte estate is where classification projects go to die; start the flywheel on new data while discovery works the backlog.

**Don't**

- Ship a taxonomy a busy employee cannot apply in a few seconds.
- Classify everything Restricted "to be safe" — over-classification trains the workforce to ignore labels and drowns DLP in false positives.
- Let labels exist with no enforcement wired to them; a label that changes nothing is a sticker.
- Treat classification as a one-time project. Data is created continuously; classification is an operation.

### Microsoft Purview sensitivity labels — the enterprise example

The most widely deployed enterprise labeling system, and a useful concrete model of what "labels as machinery" means. Facts below per [Microsoft Learn](https://learn.microsoft.com/en-us/purview/sensitivity-labels):

| Property | How Purview implements it |
|---|---|
| **Persistence** | The label is stored as **clear-text, persistent metadata** on the file or email — it travels with the item and third-party tools/DLP systems can read it even when they cannot read encrypted content |
| **Cardinality** | Exactly **one sensitivity label per item**; a sensitivity label can **coexist with a retention label** on documents and emails (protection and lifecycle are separate axes) |
| **Hierarchy** | Two-tier taxonomies use **sublabels** under a main label; **label groups** are replacing parent labels as the grouping construct |
| **Priority** | Ordinal list — **least restrictive at the top, most restrictive at the bottom**; label **downgrades can require user justification**, recorded in Activity Explorer |
| **Scopes** | **Files & other data assets** (now absorbing the former "schematized data assets" scope — SQL, Azure SQL, Synapse, Cosmos DB, AWS RDS via the Data Map), **Emails**, **Meetings**, and **Groups & sites** (Teams, Microsoft 365 Groups, SharePoint sites, Viva Engage, Loop workspaces) |
| **Enforcement a label can carry** | Encryption (rights management), content markings (watermark limited to 255 characters; headers/footers 1,024 characters, except 255 in Excel), container privacy and external-sharing settings, the default SharePoint sharing-link type, and auto-labeling conditions |
| **Tenant limits** | 1,000+ labels supported per tenant, but a **maximum of 500** if labels apply encryption that specifies users and permissions; practical guidance remains ~5 main labels / 5 sublabels |

The design lesson generalizes beyond Microsoft: a label is only useful when it is (a) persistent metadata, (b) singular and unambiguous per item, (c) ordered so "upgrade" and "downgrade" mean something, and (d) attached to enforcement. Evaluate any labeling tool — open-source or commercial — against those four properties.

---

## Data discovery & DSPM

### The category

**Data Security Posture Management (DSPM)** is Gartner-coined vocabulary — the term first appeared in the **Gartner Hype Cycle for Data Security, 2022** (the report itself is paywalled; vendor acknowledgments are the public evidence). Gartner's public definition says DSPM provides "visibility as to where sensitive data is, who has access" to it — plus how it has been used and what the security posture of the store or application holding it is ([Gartner Peer Insights](https://www.gartner.com/reviews/market/data-security-posture-management)).

Strip the acronym and DSPM is the **Know** capability productized for cloud-era sprawl:

| DSPM answers | Why it was hard before |
|---|---|
| **Where is the data?** — including *shadow data*: copies, snapshots, abandoned buckets, dev/test clones, orphaned warehouses | Cloud makes copying a data store a one-line operation; inventories built for servers never saw the copies |
| **What is it?** — classification of contents, not just store names | A bucket named `temp-2` can hold PHI |
| **Who can access it?** — effective permissions after role chains, sharing links, cross-account trust | IAM answers "what does this role allow"; DSPM asks "who, in total, can read this table" |
| **What is its posture?** — encryption state, public exposure, versioning, residency | Config posture per store, evaluated *because of* what the store contains |
| **How is it used?** — access patterns, dormancy | Dormant-but-sensitive data is a minimization target, not a monitoring target |

Adjacent vocabulary you will meet in the same vendor conversations: **DDR** (data detection and response — the real-time detection layer some DSPM vendors bolt on) and **insider risk management** (the people-centric analytic layer; program side in [Insider Threat Program](INSIDER_THREAT_REFERENCE.md)). All three are analyst-firm categories, not standards.

> **No official mapping exists** from commercial categories (DSPM, DLP, DDR) to NIST CSF subcategories or SP 800-53 controls. As editorial orientation only: DSPM chiefly serves *knowing* (Identify-flavored work that makes PR.DS enforceable), DLP serves *protecting* data in motion and use, and DDR serves *detecting*. Do not present any such crosswalk as NIST's.

### Running discovery as a program

**Do**

- Inventory **stores first, contents second** — a complete map of databases, buckets, file shares, and SaaS tenants with unknown contents beats deep classification of the three stores you already knew about.
- Point discovery at the **ugly places**: object storage, snapshots and backups, dev/test environments, analytics pipelines, collaboration tools, and file shares with decades of sediment.
- Feed findings **into the label system and the minimization queue**, not into a standalone DSPM dashboard nobody actions.
- Track **exposure findings** (public buckets, anyone-with-link shares, cross-tenant grants) as vulnerabilities with SLAs — same mobilization discipline as [CTEM](CTEM_REFERENCE.md).
- Re-scan continuously. Discovery, like classification, is an operation, not a project.

**Don't**

- Buy DSPM to learn what your CMDB already knows — the value is in the stores *not* in the CMDB.
- Let "who has access" findings die as reports; wire them to the access-review process in [Identity & Access Management](IDENTITY_ACCESS_MANAGEMENT_REFERENCE.md).
- Confuse DSPM with CSPM: config posture (public bucket) without data context (bucket contains card data) cannot prioritize; see [Cloud Security](CLOUD_SECURITY_REFERENCE.md) for the CSPM side.

---

## DLP architecture

### The four channels

DLP is not one control; it is a policy engine replicated across the channels data moves through. Coverage claims should be evaluated channel by channel:

```
   WHERE DATA LIVES               CONTROL POINT                WHERE IT LEAKS TO

  ┌───────────────────┐   ENDPOINT DLP ─ USB, print,        ┌────────────────────┐
  │ File shares       │        clipboard, local save   ───► │ Removable media,   │
  │ Databases         │                                     │ personal devices   │
  │ SharePoint / M365 │   EMAIL DLP ─ outbound mail,        │ External inboxes,  │
  │ SaaS app stores   │        attachments, forwards   ───► │ auto-forward drains│
  │ Cloud buckets &   │                                     │                    │
  │ warehouses        │   NETWORK/WEB DLP ─ uploads,        │ Personal cloud,    │
  │                   │        webmail, GenAI prompts  ───► │ webmail, AI apps   │
  │ (mapped by DSPM,  │                                     │                    │
  │  aimed by labels) │   CLOUD/SaaS DLP ─ sharing          │ Anyone-with-link,  │
  └───────────────────┘        links, guests, OAuth    ───► │ guests, 3rd-party  │
                                                            │ apps               │
                                                            └────────────────────┘
```

| Channel | What it sees | Typical actions | Blind spots to plan for |
|---|---|---|---|
| **Endpoint** | File operations, USB writes, print, clipboard, uploads from the device | Warn, block, block-with-override, quarantine | Unmanaged/BYOD devices; heavy tuning load |
| **Email** | Outbound messages and attachments at the gateway/tenant | Block, encrypt, redirect for approval, strip attachment | Personal webmail used from a browser (that's the web channel's job) |
| **Network / web** | Uploads and posts in web traffic — proxy/SWG, browser, or SASE enforced | Block destination category, block upload, coach | Off-network devices unless the agent/browser enforces; encrypted traffic without inspection |
| **Cloud / SaaS** | Data at rest in tenants, sharing links, external grants, app connections | Remove public links, quarantine files, revoke grants | The SaaS apps you haven't connected — shadow SaaS ([SaaS Security](SAAS_SECURITY_REFERENCE.md)) |

### Detection methods — precision is bought, not tuned

The single biggest lever on DLP economics is *how* content is matched, decided before any policy is written:

| Method | Mechanism | Precision profile |
|---|---|---|
| **Patterns / keywords** | Regex for identifier formats plus checksum validation, keyword proximity | Cheap, broad, noisiest — fine for coaching, weak for blocking |
| **Exact data match (EDM)** | Hashes of your *actual* records (customer table, employee roster) matched in content | Very high precision — "a real customer's SSN," not "something SSN-shaped" |
| **Document fingerprinting** | Hash of known sensitive documents/templates and derivatives | High precision for crown-jewel documents and form-based content |
| **Trainable / ML classifiers** | Models classifying content types (source code, contracts, resumes, financials) | Covers what regex can't describe; validate before enforcement |
| **Label-based predicates** | Policy keys off the sensitivity label | As good as labeling coverage — the payoff of the classification program |

### Microsoft Purview DLP — the enterprise example

Facts per [Microsoft Learn](https://learn.microsoft.com/en-us/purview/dlp-learn-about-dlp). Purview DLP organizes coverage into two policy surfaces:

| Surface | Covers |
|---|---|
| **Enterprise applications & devices** | Exchange Online, SharePoint, OneDrive, Teams chat/channel messages; Windows 10/11 and the three latest macOS versions as endpoints; on-premises file shares and on-prem SharePoint via the Information Protection scanner; non-Microsoft cloud apps via Defender for Cloud Apps; Fabric/Power BI workspaces; Microsoft 365 Copilot (in preview) |
| **Inline web traffic** | Edge for Business browser DLP and network data security via SASE integrations — covering uploads to GenAI apps such as ChatGPT, Gemini, and DeepSeek |

Protective actions span the escalation ladder this section recommends: **policy tips** (coach), **block-with-override plus a captured user justification**, **hard block**, **quarantine** of at-rest items, and **message hiding** in Teams. All monitored activity lands in the M365 audit log and Activity Explorer, and **simulation mode** exists specifically to tune a policy against real traffic before it enforces anything.

### False-positive economics

DLP programs die of false positives, not of missed leaks. The arithmetic is unforgiving: a policy that fires 500 times a day at 2% precision generates 490 daily interruptions of legitimate work — each one training users to click through, teaching the SOC to ignore the queue, and spending the program's political capital. Design for the economics explicitly:

| Cost | Borne by | Contained by |
|---|---|---|
| **Triage cost** — every alert a human reviews | SOC / insider team | Precision-first matching (EDM, fingerprints, labels); per-policy alert budgets |
| **Friction cost** — every legitimate action blocked | The business | Block-with-override as the default enforcement for the ambiguous middle; hard block reserved for high-confidence, high-impact matches |
| **Desensitization cost** — every ignored warning | The program itself | Fewer, truer policy tips; retire policies nobody actions |

**The staged rollout that respects the economics:**

1. **Simulation / audit-only** — run the policy silently against real traffic; measure match volume and sample for precision. A policy that can't demonstrate acceptable precision here does not advance.
2. **Policy tips** — warn users, block nothing. Watch whether behavior shifts.
3. **Block-with-override** — the workhorse tier: the user can proceed, but must give a justification that is logged and reviewed. Overrides are *telemetry*, not failure — a spike in overrides with reasonable justifications means the policy is wrong, not the workforce.
4. **Hard block** — only where a match is near-certain (EDM against Restricted data) and the destination is indefensible.

**Do**

- Scope policies to **labeled/classified data first**; "match all SSN-shaped strings everywhere" is how programs earn their bad reputation.
- Track **precision per policy per channel** (true positives / total alerts, from sampled review) and set a floor below which a policy returns to simulation.
- Review **override justifications weekly** — they are the cheapest source of policy-improvement signal you will ever get.
- Route DLP events into the [SIEM](SIEM_REFERENCE.md) and the insider-risk analytic, not just the DLP console ([Insider exfiltration telemetry](#insider-exfiltration-telemetry) below).

**Don't**

- Turn on blocking on day one. Every mature deployment guide, including Microsoft's, assumes a simulate → coach → enforce progression.
- Measure the program by alert or block counts — that rewards noise. Measure covered channels, precision, and time-to-disposition.
- Let exceptions accumulate silently: an unbounded allowlist is a shadow policy nobody approved.

### Market note

Gartner retired the **Magic Quadrant for Enterprise DLP** around 2018 (last published 2017) and now covers the space with the **Market Guide for Data Loss Prevention** (2025 edition current), alongside adjacent categories such as insider risk management and data detection and response. Read the category shift as a design instruction: standalone monolithic DLP lost; DLP as a *capability embedded in* endpoint, email, SaaS, and SASE platforms won. (Gartner research is paywalled; attribution here is to Gartner via licensed reprints and public acknowledgments.)

---

## Encryption pointers — at rest, in transit, in use

Deep mechanics live in the [Cryptography Reference](CRYPTOGRAPHY_REFERENCE.md); this section fixes the program-level anchors per data state.

| State | CSF 2.0 anchor | Primary mechanisms | Authoritative anchors |
|---|---|---|---|
| **At rest** | PR.DS-01 | Full-disk/volume encryption, file-level encryption, application-layer encryption, database TDE, object-storage SSE | **AES** — [FIPS 197](https://csrc.nist.gov/pubs/fips/197/final), updated as FIPS 197-upd1 (May 9, 2023 — editorial only, no technical change); three variants (AES-128/192/256), all on 128-bit blocks |
| **In transit** | PR.DS-02 | TLS 1.3 for external and internal traffic, mTLS for service-to-service, encrypted transports for legacy protocols | **TLS 1.3** — [RFC 8446](https://datatracker.ietf.org/doc/html/rfc8446) |
| **In use** | PR.DS-10 | Confidential computing: computation inside a hardware-based, **attested** Trusted Execution Environment (TEE) | [Confidential Computing Consortium terminology](https://confidentialcomputing.io/wp-content/uploads/sites/10/2023/03/Common-Terminology-for-Confidential-Computing.pdf): a TEE assures **data confidentiality, data integrity, and code integrity** — use the CCC's definition, not vendor marketing, when writing requirements |
| **Backups** | PR.DS-11 | Encrypted, immutable, offline-capable copies with tested restores | [Ransomware Defense & Resilience](RANSOMWARE_DEFENSE_REFERENCE.md) — the full architecture |

Three program-level truths that outrank algorithm choice:

- **Encryption is only as good as its key management.** The current general anchor is [NIST SP 800-57 Part 1 Rev. 5](https://csrc.nist.gov/news/2020/nist-publishes-sp-800-57-pt-1-revision-5) (May 2020): inventory keys and certificates, protect key metadata, control access to keys, plan rotation and compromise recovery. Keys live apart from the data they protect — an attacker who reads both the ciphertext and the key from the same store got plaintext with extra steps. HSM-backed storage: [Hardware Security](HARDWARE_SECURITY_REFERENCE.md).
- **Encryption at rest is not access control.** TDE and volume encryption defeat stolen disks and snapshots; they do nothing against a valid credential or an injected query, because the platform decrypts for every authorized request. Threats through the front door are answered by the access-control and detection layers, not by more encryption.
- **Today's ciphertext is tomorrow's harvest.** Long-retention sensitive data is in scope for harvest-now-decrypt-later planning — see [Post-Quantum Migration](POST_QUANTUM_MIGRATION_REFERENCE.md) for inventory and migration sequencing.

---

## Database & file-share security

The two oldest data stores in the enterprise, and still where most of the crown jewels sit.

### Databases

| Control | Concrete form |
|---|---|
| **Least-privilege access** | Per-application accounts with minimal grants; no shared logins; humans through brokered/JIT access, not standing DBA rights ([IAM Reference](IDENTITY_ACCESS_MANAGEMENT_REFERENCE.md)) |
| **Transparent data encryption (TDE)** | Protects data files, logs, and backups against media theft — pair with the access controls it does not replace |
| **Column/field-level protection** | Application-layer encryption or platform features (column encryption, dynamic data masking, row-level security) for the highest-sensitivity fields |
| **Native audit** | Database audit facilities (e.g., SQL Server Audit, and equivalents in other engines) capturing privileged actions, schema changes, and bulk reads — forwarded to the SIEM, not rotting locally |
| **Bulk-read detection** | Baseline rows-returned and export volume per account; a service account suddenly running `SELECT *` across the customer table is the database-side view of collection |
| **Exposure hygiene** | No database listeners reachable from the internet; no production data in dev/test without masking or synthesis; snapshots and backups inherit the classification of their source |

### File shares

Windows file-share telemetry is free and mostly off by default — the same events the insider program depends on:

| Control | Concrete form |
|---|---|
| **Permission hygiene** | Remove broad grants (`Everyone`, `Authenticated Users`, `Domain Users`) from sensitive shares; review broken ACL inheritance; scan for open shares from an unprivileged account and treat hits as findings |
| **Access-based enumeration** | Users don't see folders they can't open — shrinks casual discovery |
| **Auditing** | SACLs on sensitive trees with **Event 4663** (object access) and **Event 5145** (detailed file share) collection scoped to the shares that matter — auditing everything collapses the SIEM |
| **SMB hardening** | SMB signing and SMB 3 encryption on sensitive shares; kill SMBv1; block outbound SMB at the edge |
| **Lifecycle** | Stale-share review — the 2009 project share full of exports is pure liability; feed it to the [minimization queue](#retention-minimization-amp-de-identification) |

Both stores share a failure mode worth naming: **exports walk**. The database and the share can be perfectly hardened while a scheduled job exports the contents to a CSV in an unlabeled folder every night. Discovery and labeling have to chase the *derivatives*, not just the systems of record.

---

## Data egress controls

Egress control is the recognition that data leaves through a small, enumerable set of doors. Instrument every door: block where confidence is high, add friction where it is medium, and log everything.

| Egress path | Control | Telemetry |
|---|---|---|
| **Web uploads / personal cloud / webmail** | SWG/CASB destination controls; block or step-up corporate→personal transfers; browser-based DLP for managed browsers | Proxy/SASE upload logs with byte counts per user per destination |
| **GenAI applications** | Treat prompts as uploads: inline web-traffic DLP (the Purview "inline web traffic" surface exists for exactly this — ChatGPT/Gemini/DeepSeek-class apps); sanctioned-AI alternatives so the block has a legitimate outlet | Browser/SASE DLP events per AI destination |
| **Email out** | Outbound DLP, transport rules; **disable external auto-forwarding tenant-wide** and alert on exceptions | Gateway verdicts; new inbox-rule and mailbox-forwarding audit events |
| **Removable media** | Deny-write by default via GPO/device control; where business requires USB, require encrypted media (BitLocker To Go pattern); hardware-ID allowlists for exceptions | Device-connect and removable-storage write events ([details](INSIDER_THREAT_REFERENCE.md#the-exfiltration-chain-instrumented)) |
| **Sharing links & guests** | Default SharePoint/collaboration link type set by sensitivity label; expiration on external links; periodic external-grant recertification | Sharing and guest-access audit events; DSPM exposure findings |
| **Cross-tenant / third-party apps** | Tenant restrictions, OAuth app governance and consent policies ([SaaS Security](SAAS_SECURITY_REFERENCE.md)) | OAuth grant and app-consent logs |
| **Print** | Enable the print operational log (off by default); page-count outliers on sensitive-system users | PrintService operational channel, Event 307 |

**Do**

- Rank doors by your data's realistic paths and instrument in that order — for most orgs today: web uploads and GenAI, email, sharing links, USB.
- Pair every block with a sanctioned path (approved transfer tool, sanctioned AI, guest-sharing workflow); egress control without an outlet becomes shadow IT generation.
- Decide the TLS-inspection question deliberately: uninspected encrypted egress limits network DLP to destination-level control, which pushes the work to endpoint and browser layers. Either answer is defensible; not answering is not.

**Don't**

- Assume "we block USB" ends the conversation — the modern default path is a browser upload.
- Forget unmanaged devices: every egress control above assumes a management plane. BYOD access to sensitive stores is an egress policy decision, not an IT convenience decision.

---

## Retention, minimization & de-identification

Minimization is the control that works *before* the incident: data that was deleted, never collected, or de-identified is data no attacker can steal, no insider can leak, and no regulator can fine you for losing. Your breach scope in five years is your retention policy today.

### Retention

- **Retention schedules are governance artifacts** — owned by records management and legal, informed by regulation and business need, enforced by technology. Security's job is to make enforcement real (retention labels, lifecycle policies, deletion that actually deletes — including the copies discovery found).
- **Sensitivity and retention are separate axes** and coexist per item (Purview models this explicitly: one sensitivity label plus one retention label). "How sensitive" and "how long" have different owners and different logic.
- **Deletion has to chase derivatives**: backups, snapshots, exports, analytics copies, and the shares from the file-share section. This is where DSPM findings and the retention program meet.

### De-identification — NIST SP 800-188

[NIST SP 800-188, *De-Identifying Government Datasets: Techniques and Governance*](https://csrc.nist.gov/pubs/sp/800/188/final) (final, September 2023) is the reference for reducing what retained data reveals:

| SP 800-188 theme | Program takeaway |
|---|---|
| **Data-sharing models** | Choose release model first (public, controlled access, enclave) — technique follows model |
| **Techniques** | Removal of direct identifiers; transformation of **quasi-identifiers** (generalization, suppression); **synthetic data** as an alternative to releasing transformed records |
| **Re-identification risk** | De-identification is risk *reduction*, not a binary; quasi-identifier combinations (ZIP + birthdate + sex-class attributes) re-identify — risk must be assessed, not assumed away |
| **Governance** | **Disclosure Review Boards** — a standing body that owns release decisions, rather than per-team improvisation |

Anonymization/pseudonymization engineering detail and the privacy-law framing (GDPR's anonymous-vs-pseudonymous line, HIPAA de-identification) live in [Privacy Engineering](PRIVACY_ENGINEERING_REFERENCE.md).

### When minimization becomes law

Under **EO 14117** (February 28, 2024, restricting bulk sensitive-data transactions with countries of concern), CISA's finalized [Security Requirements for Restricted Transactions](https://www.cisa.gov/resources-tools/resources/EO-14117-security-requirements) make encryption and **data minimization** compliance obligations — covered data must be processed so it is not "linkable, identifiable, unencrypted, or decryptable" by covered parties. The requirements are incorporated into the DOJ **Data Security Program** at 28 CFR Part 202 (final rule January 8, 2025; largely effective April 8, 2025; affirmative due-diligence and audit obligations effective October 6, 2025). The direction of travel is clear: minimization is migrating from best practice to legal requirement.

---

## Insider exfiltration telemetry

Data security and insider-threat programs converge on the same sensors: the DLP events, egress logs, and file-share auditing this document builds are exactly the telemetry the insider program's analytics consume. Build once, feed both. The program wrapper — HR partnership, legal and privacy guardrails, UAM governance, case handling — lives in the [Insider Threat Program Reference](INSIDER_THREAT_REFERENCE.md); the instrumented chain with event IDs is in its [exfiltration chain section](INSIDER_THREAT_REFERENCE.md#the-exfiltration-chain-instrumented).

The shared taxonomy is MITRE ATT&CK's **Exfiltration tactic ([TA0010](https://attack.mitre.org/tactics/TA0010/))** and the Collection tactic that precedes it (ATT&CK is at **v19.2** as of this writing — pin the version when you import mappings). Techniques below are current ATT&CK Enterprise techniques; the grouping into a "data theft chain" is practitioner framing, not an official MITRE sequence:

| Chain stage | Techniques | The data-security sensor that sees it |
|---|---|---|
| **Collect** | [T1213](https://attack.mitre.org/techniques/T1213/) Data from Information Repositories · [T1005](https://attack.mitre.org/techniques/T1005/) Data from Local System · [T1039](https://attack.mitre.org/techniques/T1039/) Data from Network Shared Drive · [T1530](https://attack.mitre.org/techniques/T1530/) Data from Cloud Storage · [T1114](https://attack.mitre.org/techniques/T1114/) Email Collection · [T1025](https://attack.mitre.org/techniques/T1025/) Data from Removable Media | Repository/SaaS download audit events, database bulk-read baselines, file-share SACL auditing (4663/5145), cloud-storage access logs |
| **Stage & package** | [T1560](https://attack.mitre.org/techniques/T1560/) Archive Collected Data · [T1119](https://attack.mitre.org/techniques/T1119/) Automated Collection | Process-creation telemetry for archive utilities; endpoint DLP file events; unusual archive volume per user |
| **Exfiltrate** | [T1567](https://attack.mitre.org/techniques/T1567/) Exfiltration Over Web Service · [T1048](https://attack.mitre.org/techniques/T1048/) Exfiltration Over Alternative Protocol · [T1052](https://attack.mitre.org/techniques/T1052/) Exfiltration Over Physical Medium · [T1041](https://attack.mitre.org/techniques/T1041/) Exfiltration Over C2 Channel · [T1020](https://attack.mitre.org/techniques/T1020/) Automated Exfiltration | Every [egress control](#data-egress-controls) above: SWG/CASB upload logs, email DLP, device control, netflow egress baselines |

What differs between the external and insider case is the *analytic*, not the sensor:

- **External actor** (ransomware double extortion, APT collection): exfiltration follows compromise, so correlate with intrusion telemetry — C2 beaconing, credential abuse, the [ransomware exfiltration rows](RANSOMWARE_DEFENSE_REFERENCE.md). Volume is often large and fast.
- **Insider**: activity is authorized, so the signal is *deviation* — per-user and peer-group baselines, sequence detection (repository read → archive → egress within days), and HR-state-aware sensitivity. That analytic discipline, and the guardrails it requires, are the insider doc's [detection approaches](INSIDER_THREAT_REFERENCE.md#detection-approaches).

Detection engineering per technique: [Technique Detection Library](detections/TECHNIQUE_DETECTION_LIBRARY.md) · [ATT&CK Data Components](ATTACK_DATA_COMPONENTS.md).

---

## Regulatory & framework drivers

Summary level only — program depth in [GRC Compliance](GRC_COMPLIANCE_REFERENCE.md) and [GRC Reference](GRC_REFERENCE.md); privacy-law depth in [Privacy Engineering](PRIVACY_ENGINEERING_REFERENCE.md).

| Driver | Status (verified) | What it pulls into the data program |
|---|---|---|
| **NIST CSF 2.0** ([CSWP 29](https://csrc.nist.gov/pubs/cswp/29/the-nist-cybersecurity-framework-csf-20/final)) | Final, Feb 26, 2024 | PR.DS-01/-02/-10/-11 as the data-state spine this document is organized around |
| **NIST SP 800-171 Rev. 3** ([final](https://csrc.nist.gov/pubs/sp/800/171/r3/final)) | Final, May 2024; **Rev. 2 withdrawn May 14, 2024** | **97 security requirements in 17 families** for protecting CUI in nonfederal systems (down from 110 in 14 families in Rev. 2; Rev. 3 added Planning, System & Services Acquisition, and Supply Chain Risk Management families). Companion assessment guide: [SP 800-171A Rev. 3](https://csrc.nist.gov/pubs/sp/800/171/a/r3/final) (May 2024) |
| **CMMC** | 48 CFR acquisition rule published Sept 10, 2025; effective **Nov 10, 2025** | DFARS clause 252.204-7021 makes CMMC certification a condition of DoD contract award, phased in over a ~3-year, 4-phase rollout beginning with Level 1/Level 2 self-assessments. Note the version question: NIST's current publication is Rev. 3, while CMMC assessment requirements pin the revision specified in 32 CFR Part 170 — verify the currently pinned SP 800-171 revision there before scoping an assessment |
| **NIST Privacy Framework** | **1.0 (Jan 2020) is the current final version**; [v1.1 exists only as an Initial Public Draft](https://csrc.nist.gov/pubs/cswp/40/nist-privacy-framework-11/ipd) (CSWP 40 ipd, Apr 14, 2025) | Privacy risk-management structure that shares the govern/know/protect shape of this document; the 1.1 draft realigns with CSF 2.0 and adds AI privacy content — cite 1.0 until a final 1.1 ships |
| **HIPAA Security Rule NPRM** | **Proposed rule only** — published in the [Federal Register Jan 6, 2025](https://www.federalregister.gov/documents/2025/01/06/2024-30983/hipaa-security-rule-to-strengthen-the-cybersecurity-of-electronic-protected-health-information); HHS has moved it to long-term actions with final action anticipated around July 2027 | Signals direction for ePHI protection (encryption, asset inventory, stronger required safeguards) — describe it as proposed, plan against the current Security Rule |
| **EO 14117 / DOJ Data Security Program** | Final rule Jan 8, 2025 (28 CFR Part 202); largely effective Apr 8, 2025; due-diligence/audit obligations Oct 6, 2025 | Encryption + minimization as legal requirements for covered bulk sensitive-data transactions ([above](#retention-minimization-amp-de-identification)) |
| **CISA/NSA/FBI joint AI data security guidance** | Released [May 22, 2025](https://www.cisa.gov/news-events/alerts/2025/05/22/new-best-practices-guide-securing-ai-data-released) | Best practices for securing the data used to train and operate AI systems — the data program's scope now includes training corpora, model inputs, and AI pipelines |
| **CISA Cross-Sector CPG 2.0** | Released [Dec 11, 2025](https://www.cisa.gov/news-events/alerts/2025/12/11/cybersecurity-performance-goals-20-critical-infrastructure) | Baseline goal set restructured to align with CSF 2.0 (including Govern), with cost/impact/ease ratings — a floor-check for the data-relevant goals (pull specific goal IDs from the CPG 2.0 document itself) |

---

## Metrics for a data protection program

Report movement, not activity — formulas and reporting patterns in [Security Metrics](SECURITY_METRICS_REFERENCE.md).

| Metric | Why it matters |
|---|---|
| **% of data stores inventoried and scanned** (by environment: cloud, SaaS, on-prem) | The Know capability, measured; everything else is bounded by this number |
| **% of sensitive data labeled** (auto + manual, by repository) | Classification coverage — the targeting system's field of view |
| **Shadow-data findings open vs. closed** (unknown stores, snapshots, dev copies) | Whether discovery output is being actioned or admired |
| **Exposure findings MTTR** (public buckets, anyone-with-link, external grants) | The data-security equivalent of patch SLA |
| **DLP precision per policy per channel** (sampled TP rate) + **override rate with justification quality** | The false-positive economics, tracked — a falling precision trend is a policy recall notice |
| **Egress channel coverage** (% of the doors table instrumented: web, GenAI, email, USB, sharing, print) | Blind doors, counted honestly |
| **% of crown-jewel data encrypted at rest / in transit** (and % of keys under managed lifecycle) | PR.DS-01/-02 as numbers, including the key-management half |
| **Stale/dormant sensitive data volume** (past retention, unaccessed N months) | The minimization backlog — the only metric where *down* means safer |
| **Separation-review completion rate** for departures from sensitive roles | The insider-overlap control that most often exists on paper only ([Insider Threat](INSIDER_THREAT_REFERENCE.md)) |
| **Restore-test pass rate for critical data** | PR.DS-11, borrowed from the [ransomware metrics](RANSOMWARE_DEFENSE_REFERENCE.md) — data you can't restore is data you don't have |

---

## A 90-day program bootstrap

For an organization starting from "we have an AV, a firewall, and a vague sense of where the data is" — same logic as the [CTEM](CTEM_REFERENCE.md) and [ransomware](RANSOMWARE_DEFENSE_REFERENCE.md) plans: narrow scope, measure reality, fix the cheapest link first.

| Phase | Weeks | Do this |
|---|---|---|
| **Scope & govern** | 1–2 | Pick one or two crown-jewel data classes (customer PII, CUI, source code). Name data owners. Draft a 4-tier classification with the handling-rule table written first. |
| **Find it** | 3–5 | Inventory the stores that hold the chosen classes — including exports, shares, snapshots, dev copies. Run discovery/DSPM scanning where you have it; scripted store enumeration where you don't. Log every public/anyone-with-link exposure as a finding with an SLA. |
| **Label it** | 5–8 | Deploy the labels; auto-label the reliably matchable patterns; default-label new content. Wire one enforcement per tier (sharing-link default, encryption on Restricted) so labels change behavior from day one. |
| **Watch the doors** | 7–10 | Stand up DLP in simulation on the two busiest channels (web/GenAI uploads and email) scoped to labeled data. Disable external auto-forwarding tenant-wide. Enable file-share auditing (4663/5145) on the crown-jewel shares. Measure precision before any enforcement. |
| **Cut the hoard** | 9–12 | First minimization pass: delete or archive stale sensitive shares found in discovery; kill production data in dev/test; set retention labels on the chosen classes. |
| **Enforce & report** | 11–13 | Promote proven DLP policies to policy-tips → block-with-override. Publish the first metrics pack (coverage, precision, exposure MTTR, stale-data volume) and the roadmap for the next data class. |

> **Failure modes to avoid:** buying DSPM before naming data owners; classifying the whole estate before enforcing anything; turning on DLP blocking without a simulation phase; encrypting everything while keys sit next to the data; minimization deferred indefinitely because "storage is cheap" (the breach isn't); and building egress telemetry the insider program never receives.

---

## Sources

- NIST — CSF 2.0, CSWP 29 (final, Feb 26, 2024): <https://csrc.nist.gov/pubs/cswp/29/the-nist-cybersecurity-framework-csf-20/final>
- NIST — SP 800-171 Rev. 3, Protecting CUI in Nonfederal Systems (final, May 2024): <https://csrc.nist.gov/pubs/sp/800/171/r3/final> · Rev. 2 withdrawal (May 14, 2024): <https://csrc.nist.gov/pubs/sp/800/171/r2/upd1/final> · transition FAQ: <https://csrc.nist.gov/files/projects/protecting-controlled-unclassified-information/documents/FAQ/FAQ-SP800-171R3-171AR3.pdf>
- NIST — SP 800-171A Rev. 3, Assessing Security Requirements for CUI (May 2024): <https://csrc.nist.gov/pubs/sp/800/171/a/r3/final>
- NIST — SP 800-188, De-Identifying Government Datasets (final, Sept 2023): <https://csrc.nist.gov/pubs/sp/800/188/final>
- NIST — Privacy Framework 1.1 Initial Public Draft, CSWP 40 ipd (Apr 14, 2025; v1.0 of Jan 2020 remains current final): <https://csrc.nist.gov/pubs/cswp/40/nist-privacy-framework-11/ipd>
- NIST — FIPS 197, Advanced Encryption Standard (FIPS 197-upd1, May 9, 2023): <https://csrc.nist.gov/pubs/fips/197/final>
- NIST — SP 800-57 Part 1 Rev. 5, Recommendation for Key Management (May 2020): <https://csrc.nist.gov/news/2020/nist-publishes-sp-800-57-pt-1-revision-5>
- IETF — RFC 8446, TLS 1.3: <https://datatracker.ietf.org/doc/html/rfc8446>
- Confidential Computing Consortium — Common Terminology for Confidential Computing: <https://confidentialcomputing.io/wp-content/uploads/sites/10/2023/03/Common-Terminology-for-Confidential-Computing.pdf>
- Microsoft Learn — Purview sensitivity labels: <https://learn.microsoft.com/en-us/purview/sensitivity-labels>
- Microsoft Learn — Purview Data Loss Prevention: <https://learn.microsoft.com/en-us/purview/dlp-learn-about-dlp>
- Gartner — DSPM market definition (Peer Insights, public page): <https://www.gartner.com/reviews/market/data-security-posture-management> · DSPM's first appearance in the Hype Cycle for Data Security 2022, via vendor acknowledgment: <https://www.soterosoft.com/blog/dspm-mentioned-in-the-2022-gartner-hype-cycle-for-data-security-report/> · Enterprise DLP Magic Quadrant retirement analysis: <https://www.zscaler.com/blogs/product-insights/what-happened-gartner-dlp-magic-quadrant>
- CISA — EO 14117 Security Requirements for Restricted Transactions: <https://www.cisa.gov/resources-tools/resources/EO-14117-security-requirements>
- CISA/NSA/FBI — AI Data Security best-practices guide announcement (May 22, 2025): <https://www.cisa.gov/news-events/alerts/2025/05/22/new-best-practices-guide-securing-ai-data-released>
- CISA — Cybersecurity Performance Goals 2.0 announcement (Dec 11, 2025): <https://www.cisa.gov/news-events/alerts/2025/12/11/cybersecurity-performance-goals-20-critical-infrastructure>
- HHS/OCR — HIPAA Security Rule NPRM, Federal Register (Jan 6, 2025; proposed, not final): <https://www.federalregister.gov/documents/2025/01/06/2024-30983/hipaa-security-rule-to-strengthen-the-cybersecurity-of-electronic-protected-health-information>
- PreVeil — CMMC 48 CFR final acquisition rule analysis (published Sept 10, 2025; effective Nov 10, 2025): <https://www.preveil.com/blog/cmmc-final-rule-published/>
- MITRE ATT&CK — version list (v19.2 current as of this writing): <https://attack.mitre.org/resources/versions/> · Exfiltration tactic TA0010: <https://attack.mitre.org/tactics/TA0010/>

---

*This reference summarizes third-party frameworks and publications — NIST CSF 2.0, SP 800-171/171A/188/800-57, FIPS 197, the NIST Privacy Framework, MITRE ATT&CK®, CISA guidance, DOJ/CISA rulemaking under EO 14117, Gartner market categories, the Confidential Computing Consortium's terminology, and Microsoft Purview documentation — as an independent practitioner summary; it is not affiliated with or endorsed by those organizations, and it is not legal advice. Product capabilities, tenant limits, and rulemaking status change; consult the linked originals before relying on a specific number or date.*
