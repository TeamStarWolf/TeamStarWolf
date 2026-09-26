# Respond to a Ransomware Incident

> **Work the first 24–72 hours of a ransomware incident in the order that preserves your evidence, your legal options, and your ability to restore — the same order as the joint CISA/FBI/NSA/MS-ISAC #StopRansomware Guide response checklist.** This guide is for the incident commander, SOC lead, or sysadmin who just confirmed active encryption and needs a sequence to execute, not a framework to read.

| **Time** | **Difficulty** | **You need** | **You'll produce** |
|---|---|---|---|
| First 24–72 hours of the incident (steps run in parallel after Step 3) | High — decisions under pressure, some irreversible | EDR/SIEM access, out-of-band comms, printed contact card, your IR plan | Contained systems, preserved evidence, filed law-enforcement and insurer reports, an OFAC-screened payment decision, restoration underway in tested order |

This guide operationalizes the response checklist in Part 2 of the [#StopRansomware Guide](https://www.cisa.gov/stopransomware/ransomware-guide) (CISA/MS-ISAC/NSA/FBI, October 2023). The full NIST-lifecycle procedure with investigation tables, negotiation guidance, and AD-rebuild detail is the library's [IR Playbooks — Ransomware](/IR_PLAYBOOKS.md); the program you should have built before today is the [Ransomware Defense Reference](/RANSOMWARE_DEFENSE_REFERENCE.md). This guide sequences those two documents for the first three days — it does not replace them.

## Before you start

Everything below is a peacetime artifact. If you are reading this mid-incident and one is missing, improvise and note the gap for the after-action report.

- [ ] **A written ransomware playbook**, printed — your tooling may be encrypted. Start from [IR Playbooks — Ransomware](/IR_PLAYBOOKS.md) and the checklist in the [#StopRansomware Guide](https://www.cisa.gov/stopransomware/ransomware-guide).
- [ ] **A payment-decision policy signed off with legal counsel**, including the OFAC screening step — see the payment policy section of the [Ransomware Defense Reference](/RANSOMWARE_DEFENSE_REFERENCE.md) and OFAC's [ransomware payment advisory](https://ofac.treasury.gov/system/files/126/ofac_ransomware_advisory.pdf).
- [ ] **A business-ranked restore order** (identity first, then critical services) — the restore-wave model in the [Ransomware Defense Reference](/RANSOMWARE_DEFENSE_REFERENCE.md).
- [ ] **Offline or immutable backups with a recent passed restore test** — backup architecture in the [Ransomware Defense Reference](/RANSOMWARE_DEFENSE_REFERENCE.md); if you cannot confirm a clean copy exists, say so out loud in the first hour, because it changes every later decision.
- [ ] **A printed contact card**: cyber insurer (policy number, notification deadline), external DFIR retainer, legal counsel, local [FBI field office](https://www.fbi.gov/contact-us/field-offices), and [CISA reporting](https://www.cisa.gov/report) details. Write both URLs on the card: cisa.gov/report currently forwards to the CISA Incident Reporting Form at myservices.cisa.gov/irf, and a printed card should survive either link changing.
- [ ] **EDR and SIEM access from an account that still works** — response actions per your EDR vendor's official docs, e.g. Microsoft's [Take response actions on a device](https://learn.microsoft.com/en-us/defender-endpoint/respond-machine-alerts).

## Step 1 — Isolate impacted systems, in checklist order

The guide is explicit: take the first three checklist steps **in sequence**. This step is checklist items 1 and 2; Step 2 below is item 3.

1. **Determine which systems were impacted, and immediately isolate them.** If several systems or subnets look affected, take the network offline at the switch level rather than chasing hosts one by one. If you can't act at the switch, unplug affected devices or drop them from Wi-Fi.
2. Where your EDR is still trusted, use its isolation action instead of pulling cables — it cuts the network while keeping the forensic channel open. In Microsoft Defender for Endpoint: open the device page in the Defender portal, select **Isolate device**, type a comment, select **Confirm**; the device stays connected to the Defender service for investigation. Other EDR platforms have equivalents (e.g., network containment) — use the vendor's documented action, not an improvised firewall rule.
3. **Only if you cannot disconnect a device from the network, power it down** — that is checklist item 2, and it is a last resort.
4. For cloud resources, snapshot affected volumes so you have a point-in-time copy to review later.
5. Move coordination to **out-of-band channels** (phone calls, a separate tenant, personal-device messaging approved by counsel) now. Assume email and chat are readable by the actor.

**Checkpoint:** Every system showing encryption behavior is off the network or EDR-isolated, no affected device has been rebooted or wiped, and responders are talking on a channel the attacker cannot read.

**Watch out:** Powering down destroys volatile memory — encryption keys, running processes, and network connections that forensics (and sometimes decryption) depend on. Disconnect, don't shut down, wherever you have the choice. And don't announce the response in email: threat actors monitor victim mailboxes and can accelerate to full encryption or data destruction when they see detection.

## Step 2 — Triage for restoration and preserve evidence

1. **Triage impacted systems for restoration and recovery** (checklist item 3): identify which encrypted systems sit on your critical-asset list — health-and-safety and revenue-critical services first — and which can wait. This ranking should already exist in writing; see the restore-order waves in the [Ransomware Defense Reference](/RANSOMWARE_DEFENSE_REFERENCE.md).
2. Collect a **system image and memory capture from a sample of affected devices**, per the guide — you do not need to image everything, you need a defensible sample plus patient zero when you find it. Tools and chain-of-custody practice: [Digital Forensics Reference](/DIGITAL_FORENSICS_REFERENCE.md).
3. Preserve the raw material of the investigation before anyone "cleans up": ransom notes, a few encrypted files, EDR telemetry, firewall/VPN/proxy logs, and — critically — **backup-console audit logs**, which show whether the actor reached your backups.
4. Check backup integrity now, not at restore time: are the offline/immutable copies intact, and were backup jobs, retention settings, or repository credentials touched? [ATT&CK T1490](https://attack.mitre.org/techniques/T1490/) (Inhibit System Recovery) is the behavior to look for.

**Checkpoint:** You have a written priority list of what restores first, memory/disk images from sample systems, preserved ransom notes and logs, and a yes/no answer on whether clean backups survived.

**Watch out:** Well-meaning admins deleting ransom notes, re-imaging machines, or running antivirus "cleanup" in the first hours destroy the evidence that identifies the variant, the entry point, and the scope of data theft. Freeze the environment; changes go through the incident commander.

## Step 3 — Scope the intrusion through the advisory stream

Encryption is the end of the intrusion, not the start. The actor has typically been inside for days to weeks, and the public advisory stream is your fastest map of what they likely did.

1. **Identify the family.** Upload a ransom note and an encrypted file sample to [ID Ransomware](https://id-ransomware.malwarehunterteam.com/) or No More Ransom's [Crypto Sheriff](https://www.nomoreransom.org/crypto-sheriff.php?lang=en). The family name unlocks everything else. Family profiles: [Malware Families](/MALWARE_FAMILIES.md).
2. **Pull the matching #StopRansomware advisory** from [stopransomware.gov](https://www.cisa.gov/stopransomware) — the AA-numbered joint advisories carry ATT&CK-mapped TTPs (pinned to a stated ATT&CK version), IOCs with STIX downloads, and mitigations. How to read one: the advisory-anatomy section of the [Ransomware Defense Reference](/RANSOMWARE_DEFENSE_REFERENCE.md).
3. **Form the initial-access hypothesis.** Review VPN/RDP and edge-appliance logs for the prior 30–60 days, and diff your internet-facing services against the [KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) entries flagged `knownRansomwareCampaignUse: Known` — exposed, unpatched KEV entries are the most common way affiliates buy or gain entry.
4. **Hunt the precursors and the spread.** Search for precursor malware the guide names (QakBot-class loaders), lateral-movement fan-out, new privileged accounts, and persistence. Detection logic per technique: [Technique Detection Library](/detections/TECHNIQUE_DETECTION_LIBRARY.md).
5. **Answer the exfiltration question early** — large outbound transfers, cloud-storage uploads, Rclone/MEGA-class tooling in the weeks before encryption. Double extortion changes your legal, notification, and payment calculus, so counsel needs this answer fast.

**Checkpoint:** You can state the family, the advisory you're working from, a supported initial-access hypothesis, the earliest known foothold date, and whether data left the network — in one written situation summary.

**Watch out:** Advisory TTP tables are pinned to a specific ATT&CK version; import them as published and record the pin. And don't declare "no exfiltration" from absence of an alert — check egress volumes and proxy logs before counsel repeats that claim to a regulator.

## Step 4 — Report and notify: law enforcement, insurer, counsel

This is the checklist's Reporting and Notification phase, and it runs in parallel with everything after Step 3. Early, self-initiated law-enforcement reporting is also a documented mitigating factor in OFAC sanctions enforcement — it protects your options in Step 5.

1. **Engage legal counsel first** and route the investigation through them (privilege matters for everything that follows).
2. **Notify your cyber insurer** against the policy clock — many policies require notice within 24–72 hours and require use of approved DFIR/negotiation panels.
3. **Report to CISA**: [cisa.gov/report](https://www.cisa.gov/report) (the incident reporting portal — it currently forwards to the CISA Incident Reporting Form at myservices.cisa.gov/irf), Central@cisa.dhs.gov (the reporting address the #StopRansomware Guide lists), or 1-844-SAY-CISA (1-844-729-2472). CISA can provide no-cost technical assistance.
4. **Report to the FBI** via your local [field office](https://www.fbi.gov/contact-us/field-offices) and file with [IC3](https://www.ic3.gov/). The FBI sometimes holds decryption keys for specific variants; reporting does not obligate any decision about payment. Financial-fraud angles can also go to the [U.S. Secret Service](https://www.secretservice.gov/contact/field-offices).
5. **SLTT organizations**: also engage MS-ISAC — soc@msisac.org or 866-787-4722.
6. **Brief leadership on a cadence** (the guide: keep management and senior leaders informed via regular updates) and hold all public statements until counsel approves. Full escalation and regulatory-deadline tables: [IR Playbooks](/IR_PLAYBOOKS.md).

**Checkpoint:** Counsel is engaged, the insurer notification is timestamped inside the policy window, CISA and FBI reports are filed with report numbers recorded, and a leadership update cadence exists.

**Watch out:** Skipping the insurer notification deadline can void coverage for the entire incident. And do not let anyone outside the approved channel talk to the threat actor — first contact sets the negotiation posture and can create legal exposure.

## Step 5 — Decide the payment question with the policy you already wrote

You wrote the payment policy in peacetime with counsel (see Before you start). Now you execute it — you do not draft it at 3 a.m.

1. **Check for a free decryptor before any payment discussion.** [No More Ransom](https://www.nomoreransom.org/) hosts free decryption tools and states plainly that not every family has a solution — check the live site for yours, and recheck later; law-enforcement takedowns add keys.
2. **Run the OFAC screening step.** Under OFAC's September 21, 2021 [advisory](https://ofac.treasury.gov/system/files/126/ofac_ransomware_advisory.pdf), a payment that reaches a sanctioned party is a strict-liability violation — intent doesn't matter — and the prohibition covers facilitators (insurers, negotiators, DFIR firms) as well as victims. Your earlier law-enforcement reports are on the advisory's own list of mitigating factors.
3. **If payment is on the table, work only through professionals**: your insurer's approved negotiator or DFIR firm, with counsel in the loop. Negotiation principles, test-decryption practice, and the payment decision framework are in [IR Playbooks — Ransomware](/IR_PLAYBOOKS.md); the policy considerations are in the [Ransomware Defense Reference](/RANSOMWARE_DEFENSE_REFERENCE.md).
4. **Whatever you decide, keep responding.** Payment does not end the incident: decryptors are slow and imperfect, stolen data stays stolen, and the intrusion path stays open until you eradicate it.

**Checkpoint:** A documented decision — restore, negotiate, or pay — made by the pre-designated decision-maker, with the OFAC screen and free-decryptor check recorded in the incident log.

**Watch out:** Letting a third party pay "on your behalf" outside your compliance review does not transfer the sanctions risk — strict liability follows the payment. And clean backups do not answer double extortion: the non-publication demand survives a perfect restore, so the decision framework still has to run.

## Step 6 — Contain and eradicate before you rebuild

This is the checklist's Containment and Eradication phase — the detailed procedure is [IR Playbooks — Ransomware](/IR_PLAYBOOKS.md), Phase 4. The sequence that matters:

1. Block the advisory's and your investigation's IOCs (C2 IPs/domains, hashes) at firewall, DNS, and email gateway.
2. Identify the systems and accounts involved in the initial breach, then remove every persistence mechanism found — scheduled tasks, services, registry run keys, WMI subscriptions, rogue GPOs.
3. **Reset credentials on the assumption AD is fully compromised**: all users, service accounts, local admins. If the KRBTGT hash was exposed, reset it twice with the documented interval — details in [IR Playbooks](/IR_PLAYBOOKS.md).
4. **Rebuild compromised systems from known-good images; do not remediate in place.**
5. Patch or close the initial access vector before anything returns to production, and verify backup infrastructure is clean before reconnecting it.

**Checkpoint:** IOCs blocked, persistence inventory closed out, credential resets executed, initial access vector remediated, and a written eradication statement the incident commander is willing to sign.

**Watch out:** Declaring eradication early is the classic failure: freshly restored systems get re-encrypted because a persistence mechanism or the original entry point survived. Extended persistence analysis comes before restoration, not after.

## Step 7 — Restore in the tested order

Recovery is hundreds of restores under pressure, in an order someone has to choose — you chose it in peacetime (see Before you start). Execute the waves as written in the [Ransomware Defense Reference](/RANSOMWARE_DEFENSE_REFERENCE.md):

1. **Wave 0 — trust foundation**: identity (AD/Entra rebuilt or verified clean — restoring a compromised DC restores the compromise), DNS, DHCP, time.
2. **Wave 1 — recovery enablers**: backup infrastructure, hypervisor management, out-of-band admin, the SIEM.
3. **Wave 2 — business-ranked critical services**, in the pre-agreed order from Step 2's triage.
4. **Wave 3 — everything else**, on a communicated schedule.

Restore from **offline, encrypted backups into a clean, segmented network** — not the still-suspect flat one — and validate each wave against your encryption/backup-tampering detections before opening it to users. Wider resilience and DR context: [Cyber Resilience & BCDR Reference](/CYBER_RESILIENCE_BCDR_REFERENCE.md).

**Checkpoint:** Identity and recovery infrastructure are up and verified clean, the first business-critical service is restored and monitored, and no re-encryption tripwire has fired in the restored segment.

**Watch out:** Backups made during the dwell window can contain the attacker's tooling. Scan and validate restore points against the earliest-foothold date from Step 3 before trusting them.

## Step 8 — Close out the first 72 hours

1. Work the **breach-notification question** with counsel against the deadlines that apply to you — several regimes are measured in hours or days (e.g., GDPR's 72-hour supervisory notification; the SEC's four-business-day Form 8-K for public companies). The regulatory deadline table is in [IR Playbooks](/IR_PLAYBOOKS.md).
2. Deliver the stakeholder communications your plan pre-drafted: employees, customers, partners — factual, counsel-approved, and consistent with what you told regulators.
3. Consider **sharing indicators of compromise with CISA** to help the next victim, as the guide's recovery phase suggests.
4. Schedule the after-action review while memories are fresh (the library standard: lessons-learned within 14 days, written AAR with owners and deadlines), and open tracked remediation work for every control gap the incident exposed.
5. Feed the incident back into the program: update detections, re-run the relevant advisory's mitigation list, and re-test restores — the program layer is the [Ransomware Defense Reference](/RANSOMWARE_DEFENSE_REFERENCE.md).

**Checkpoint:** Notification decisions are documented with counsel sign-off, IOCs are shared or a decision not to is recorded, the AAR is on calendars, and remediation items exist as tracked work — not intentions.

**Watch out:** The 72-hour mark is when adrenaline fades and shortcuts creep in. Restoration continues for days or weeks; keep the tripwire detections paged and the incident log running until the incident commander formally closes the incident.

## What good looks like

- The first three checklist actions happened **in sequence** — isolate, power down only where disconnection failed, triage — and nobody wiped or rebooted evidence.
- The variant was identified within hours and the response tracked a current #StopRansomware advisory rather than guesswork.
- Insurer, CISA, and FBI notifications all landed inside their windows, with report numbers in the incident log.
- The payment decision — whichever way it went — was made by the pre-designated owner, with the OFAC screen and free-decryptor check documented.
- Restoration followed the pre-agreed waves from clean backups into a segmented network, and nothing got re-encrypted.
- Within two weeks there is a written AAR whose remediation items map to specific control gaps, not generalities.

## Go deeper

Library references:

- [Ransomware Defense Reference](/RANSOMWARE_DEFENSE_REFERENCE.md) — the program layer: advisory stream, backup architecture, payment policy, exercising, metrics
- [IR Playbooks — Ransomware](/IR_PLAYBOOKS.md) — the full NIST-lifecycle playbook this guide sequences, including negotiation and AD-rebuild detail
- [Incident Response Reference](/INCIDENT_RESPONSE_REFERENCE.md) — IR program design: roles, severity models, communications plans
- [Malware Families](/MALWARE_FAMILIES.md) — family-by-family ransomware profiles and lineage
- [Digital Forensics Reference](/DIGITAL_FORENSICS_REFERENCE.md) — evidence handling, imaging, and memory analysis
- [Technique Detection Library](/detections/TECHNIQUE_DETECTION_LIBRARY.md) — detection logic for the techniques advisories map

Authoritative external resources:

- [#StopRansomware Guide](https://www.cisa.gov/stopransomware/ransomware-guide) — CISA/MS-ISAC/NSA/FBI; Part 2 is the checklist this guide follows
- [CISA Ransomware Response Checklist](https://www.cisa.gov/stopransomware/ive-been-hit-ransomware) — the checklist as a standalone page; print it for the IR binder
- [OFAC Updated Ransomware Payment Advisory](https://ofac.treasury.gov/system/files/126/ofac_ransomware_advisory.pdf) — the controlling U.S. sanctions guidance on payments
- [NIST IR 8374r1](https://csrc.nist.gov/pubs/ir/8374/r1/final) — Ransomware Risk Management, a CSF 2.0 Community Profile

*Guides are procedures: verify every command, contact, and menu path against current official documentation before relying on it in production — advisory streams, reporting portals, and decryptor availability change continuously.*
