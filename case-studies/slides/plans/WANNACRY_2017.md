# Slide plan: WannaCry 2017: How an Unclosed Patch Gap Became a Healthcare Service Crisis

- Study: case-studies/WANNACRY_2017.md
- Cover title: WannaCry 2017 / A Patch Gap / Became a Care Crisis
- Subtitle: A published patch did not equal verified protection, and that distance interrupted care.
- Published: 15 November 2026
- Notes: Evidence-bounded account of the 2017 outbreak and the NHS response in England.

## EXECUTIVE SUMMARY | The malware and the emergency operated at different scales

An attacker needed a vulnerable machine and a reachable service. A defender needed to know which machines existed, which were reachable, who could change them, and what those changes would interrupt.

- **Exposure is a condition, not a notice:** an advisory, a download and a protected endpoint differ.
- **Continuity is a web of dependencies:** a service can fail even when encryption is escaped.
- **Evidence keeps its limits:** sample behavior is not every victim's history.
Caption: The real distance is from a published remedy to verified protection.
Notes: MS17-010 published 14 March; outbreak 12 May [1][2]. The lesson is the gap, not whether a patch existed.

## KEY FACTS | Separate the records before reading the numbers

Stat: 14 Mar | MS17-010 bulletin published
Stat: 12 May | SMB-propagating outbreak
Stat: 2 mo | Bulletin-to-outbreak interval
Stat: 236 | NHS trusts in the denominator
- The study separates infection, precautionary shutdown, dependency failure and later cost.
- It distinguishes vendor analysis, NHS reporting, government attribution and criminal allegation.
- Detection time is not infection time, and a page date is not every sentence's date.
Caption: Evidence grade: Confirmed, from dated primary records.
Notes: Chronology and categories from NAO, NHS Digital and vendor reports [1][2][8][17].

## PART 1 | A warning reached mailboxes but did not close exposure

NHS Digital describes a 17 March advisory, a 25 April portal advisory and a 28 April bulletin, and later distinguished tracking patch downloads from confirming installation.

- A distribution list measures delivery; an acknowledgement measures receipt.
- Neither alone proves a machine stayed exploitable when a peer could reach it.
- A deployed-package dashboard can hide a server that could not restart.
Caption: Evidence grade: Confirmed, from NHS Digital written evidence.
Notes: The 17 March warning concerned the vulnerability, not a known campaign [17, 3.2 and 3.6].

## PART 1 | The maintenance dilemma is real but not self-resolving

The Public Accounts Committee stressed the difficulty of updating equipment in care settings, supplier-controlled systems and skills shortages.

- All 200 trusts assessed had failed the assessment, a preparedness finding, not an infection total.
- "Patch regardless" ignores operational hazard; "never interrupt" becomes an indefinite exemption.
- A useful exception names device, dependency, constraint, fallback and the next decision date.
Caption: Evidence grade: Reported, from a committee evidence session.
Notes: The demanding standard and continuing patch failures are noted [9]. Approval does not remove residual risk.

## PART 2 | Propagation changed the shape of the emergency

Microsoft described a dropper with separate propagation and ransomware parts, a connection check and an mssecsvc2.0 service, and did not establish the initial entry vector.

- Talos observed TCP 445 scanning with EternalBlue and DoublePulsar-related functionality.
- A worm turns one accessible host into another scanning source, unlike user-mediated delivery.
- One endpoint alert should prompt questions about reachable peers and trust boundaries.
Caption: A phishing email causing WannaCry is not adopted as a universal explanation.
Notes: Dropper structure and the unestablished initial vector [1]; Talos scanning observations [15].

## PART 2 | Storage damage is not identical to network spread

Secureworks found local, removable and mapped-drive targeting rather than unmapped-share hunting, with hybrid RSA and AES encryption and recovery-inhibition commands.

Left: Where code can travel
- The network map: which hosts a worm reaches over SMB.
- Reachability decides where the code runs next.
Right: What data a process can reach
- The access map: which files a writable mapping exposes.
- A file server can be damaged without the malware running on it.
Caption: Evidence grade: Demonstrated, from vendor sample analysis.
Notes: Mapped-drive targeting, hybrid encryption and recovery inhibition [13][14].

## PART 2 | Exceptional patches were a bridge, not an operating model

Microsoft made emergency updates available for Windows XP, 8 and Server 2003 described as in custom support, plus a later 22 May removal-tool update.

- Emergency support is a crisis measure, not a restoration of ordinary support.
- Depending on an exceptional fix means no dependable maintenance pathway exists.
- A migration plan should name what stays dependent on that exception.
Caption: Evidence grade: Confirmed, from Microsoft emergency guidance.
Notes: Neither statement reads as permanent support for obsolete platforms [4].

## PART 2 | The domain intervention bought time; it did not repair anything

Marcus Hutchins registered an unregistered domain during analysis; a successful connection was associated with non-execution, a failed connection with ransomware activity.

- "Kill switch" is memorable but hides conditions about the specific sample and host.
- The interruption did not decrypt a changed file, clean a machine or apply an update.
- Treat a research rescue as time gained, not a repeatable continuity capability.
Caption: Evidence grade: Reported; the anti-sandbox reading is a hypothesis, not adopted.
Notes: Altering the check could defeat it; the explanation stays a hypothesis [5][16].

## PART 2 | Count the right thing: affected is not infected

Stat: 80 | Affected trusts, of 236
Stat: 34 | Infected and locked out
Stat: 46 | Disrupted, not classified
Stat: 595 | Infected GP practices
- Identified cancellations were 6,912 against an estimated 19,494 total, not figures to add.
- A cancellation is not a person, and a delayed result can disrupt care without a cancellation.
- Supported Windows 7 with patching and firewall gaps, not an XP-only event.
Caption: Evidence grade: Confirmed and Reported; some figures are estimated.
Notes: 21 trusts contacted the domain without lockout; the 80-versus-81 difference is a reclassification [8][11][17].

## DEFENDER VIEW | Identify, authorize, implement and verify are different verbs

A completed task can become false evidence of another's assumed completion when nobody owns the handoff.

- The team that identifies exposure may lack authority to stop a clinical service.
- The executive who authorizes downtime may lack access to the equipment.
- An independent reviewer should check closure evidence, not the implementer's claim.
Caption: Evidence grade: Analytical, the study's proposed model.
Notes: The CIO review assigns distinct roles and recommends clearer accountability [11, sections 4-5].

## DEFENDER VIEW | Prove the service works, not only that the machine is patched

Communications are part of the control environment: email was lost and staff used personal phones and messaging apps.

- "No response" is not "not vulnerable": it may mean off, disconnected or unmanaged.
- A protected machine can still support a broken service; test a real transaction.
- Separate observed facts, estimates, actions, dependencies and decisions needed.
Caption: Evidence grade: Reported and Analytical, a committee finding plus the study model.
Notes: Do not elevate one messaging app into a standard; plan a survivable method [9].

## MITRE MAPPINGS | ATT&CK organizes questions; it does not prove protection

S0366 lists behaviors; this subset maps cited evidence, not a claim each technique hit every NHS organization.

| Behavior in record | Technique | Investigator needs |
|---|---|---|
| SMB remote exploitation | T1210 | Attempt-versus-success evidence |
| Service creation | T1543.003 | Service event and binary identity |
| File discovery | T1083 | File-access evidence, visibility limit |
| Data encrypted for impact | T1486 | Confirmed paths and time window |
| Inhibit system recovery | T1490 | Process and recovery-state evidence |
Caption: Evidence grade: a Confirmed taxonomy over historical analysis.
Notes: Labels from the current taxonomy; coverage of T1210 is not proof a control stopped this incident [12].

## CROSS-CUTTING THEMES | The story is overstated and understated at once

Left: Overstated
- "A patch existed, so negligence."
- "An XP-only disaster."
- "The kill switch saved everyone."
Right: Understated
- Handoffs that nobody owned.
- Uninfected services that still failed.
- Unmeasured clinical consequence.
Caption: Evidence grade: Analytical, the study's synthesis.
Notes: Absence of a harm report is not proof of no harm; cost is not ransom revenue [3][8][10].

## CLOSE | Make each transition explicit, from warning to resolution

A remedy can exist without being deployed. A machine can be uninfected while its service is disrupted. A public record can be authoritative yet revised.

- Warning to owner, owner to action, action to verification.
- Verification to service acceptance, temporary exception to durable fix.
- Preserve the speaker, date, confidence and legal status of every claim.
Caption: The attribution ladder keeps assessment and allegation distinct; no conviction is claimed.
Notes: Closing synthesis of the study's transitions and evidence discipline [6][7].
