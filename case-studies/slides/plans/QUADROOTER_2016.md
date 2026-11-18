# Slide plan: QuadRooter 2016: Exposure Is Not Compromise

- Study: case-studies/QUADROOTER_2016.md
- Cover title: QuadRooter 2016 / 7 August 2016 / Local driver trust
- Subtitle: QuadRooter grouped four Qualcomm driver flaws reached by a malicious app, not remote code; the 900 million figure is exposure, not compromise.
- Published: 18 November 2026
- Notes: The cover sets the frame: four disclosed driver flaws and the last mile of patching, not an attributed incident.

## EXECUTIVE SUMMARY | Four flaws under one name, not an attributed incident

- QuadRooter grouped four Qualcomm-related vulnerabilities under one public name.
- It did not name a malware family or show every affected handset was compromised.
- Check Point's 900 million figure was potential exposure, not an observed victim count.
- The subject is driver trust and the last mile of mobile patching.
Caption: Evidence grade: Confirmed disclosure; no incident attributed.
Notes: Executive-assessment framing from [1]; issue-level and patch detail from [4][5][6][7].

## KEY FACTS | One name, four CVEs, three monthly bulletins

Stat: 900M | Devices with the component, not victims
Stat: 4 | Qualcomm CVEs grouped as QuadRooter
Stat: 3 | Android bulletins, July to September
Stat: 63% | Scan reports flagging one or more
- Check Point announced the findings on 7 August 2016 via a malicious-application route. [1]
- The CVEs are CVE-2016-2503, CVE-2016-2504, CVE-2016-2059 and CVE-2016-5340. [7]
- Nearly 500,000 voluntary scan reports came in from 7 through 10 August 2016. [2]
Caption: Evidence grade: Confirmed CVEs and dated advisories.
Notes: Exposure framing from [1]; CVE set from [7]; scanner sample from [2].

## PART 1 | Keep vulnerability, exploit and incident distinct

- A vulnerability is a potential failure; an exploit is a method that worked under stated conditions.
- An incident is actual use against a target; the three levels must stay separate.
- Keep affected, reachable, mitigated and compromised in separate fields.
- A device containing the component is not a victim, and a scanner flag is not a breach.
Caption: Evidence grade: Confirmed definitions; no exploitation-in-the-wild claim.
Notes: Evidence-level discipline from the executive assessment and [1]; scanner caveats from [2].

## PART 1 | One public label, four distinct Qualcomm issues

Google's annual account lists four CVEs and a malicious installed application as the prerequisite. [7]

| CVE | Component | Failure pattern |
|---|---|---|
| CVE-2016-2059 | IPC-router sockets | Inconsistent locking on role change |
| CVE-2016-5340 | Qualcomm ashmem | Weak file-type identity check |
| CVE-2016-2503 | Graphics driver | Sync-object destruction race |
| CVE-2016-2504 | Graphics memory | Object reachable before init |
Caption: Evidence grade: Confirmed component mapping, technical paper.
Notes: CVE set and app prerequisite from [7]; component detail from [8], pages 7-18.

## PART 1 | Local app route, not remote over-the-air code

- The flaws sit in software drivers shipped with Qualcomm chipsets. [1]
- Exploitation was described through an application without special requested permissions. [1]
- That differs from an unsolicited network packet compromising an untouched phone.
- An ordinary app should not be able to exceed the platform's authority boundaries.
Caption: Evidence grade: Confirmed reachability boundary.
Notes: Driver location and local application route from [1]; the authority framing is original analysis.

## PART 2 | Three supplier milestones, July to September

Each monthly bulletin names a different CVE and keeps patch-level granularity.

| Month | CVE | Supplier detail |
|---|---|---|
| July 6 | CVE-2016-2503 | Critical GPU EoP; Nexus 5X, 6P; binary driver |
| August 1 | CVE-2016-2504 | Critical GPU EoP; local application context |
| September 6 | CVE-2016-5340 | Critical kernel shared-memory EoP |
| September 6 | CVE-2016-2059 | High networking; needs compromised process |
Caption: Evidence grade: Confirmed, dated Android bulletins.
Notes: July from [4]; August from [5]; September levels and entries from [6].

## PART 2 | A patch level carries meaning a date erases

- The July bulletin distinguishes the 1 July and 5 July security patch levels. [4]
- September defines separate 1, 5 and 6 September levels. [6]
- "July update" or "September date" can hide a partial versus a complete level.
- A binary-driver correction is not the same as a publicly released source patch.
Caption: Evidence grade: Confirmed patch-level semantics.
Notes: July levels and binary-driver note from [4]; three September levels from [6].

## PART 2 | Conflicting chronology deserves a visible note

- The annual report places three fixes in July and CVE-2016-5340 in October. [7]
- The monthly bulletin lists CVE-2016-5340 under 6 September instead. [6]
- Record the disagreement and cite the issue-level bulletin for the milestone.
- Do not blend the sources into an invented universal rollout date.
Caption: Evidence grade: Reported conflict, preserved not resolved.
Notes: Annual-report wording from [7]; the 6 September entry from [6]; Check Point date shifts in [2][3].

## PART 2 | Scanner evidence shows exposure, not compromise

Stat: ~500K | Voluntary initial scan reports
Stat: 63% | Reports flagging one or more issues
Stat: 2 of 4 | Issues judged by update metadata
- The reports were voluntarily submitted from 7 through 10 August 2016. [2]
- For two issues the scanner relied on installed update metadata, not direct confirmation. [2]
- A sample of volunteers is not a random sample of every Android owner.
- A flag that a device contains the component is exposure, not evidence of compromise.
Caption: Evidence grade: Reported scanner sample; method-bound.
Notes: Collection window, 63 percent and the dual method from [2].

## PART 2 | A chipset brand is not a device inventory

- A chipset association is a lead, not proof a managed device is still exposed.
- Software build, variant, OS release, patch level and update channel change the outcome. [4]
- A carrier version should not inherit a directly purchased device's status.
- Record the evidence source and observation time; keep unavailable devices visible.
Caption: Evidence grade: Inferred fleet-analysis guidance.
Notes: Variant and channel factors from [4]; the inventory discipline is original analysis.

## DEFENDER VIEW | Closure requires active-state evidence

- Connect the exact applicable CVE to the device's active build, not just update availability.
- A downloaded package may be uninstalled, and an installed update may await a restart.
- Collect evidence through ordinary management channels with a recorded observation time.
- Where a device cannot update, record a bounded restriction, replacement or retirement.
Caption: Evidence grade: Inferred closure checklist.
Notes: Active-state closure and update-state distinctions are original analysis building on [4][6].

## CROSS-CUTTING THEMES | What the record overstates versus understates

Left: Overstated in the retelling
- "900 million devices infected": exposure is not infection.
- A scanner flag read as proof of compromise.
- One "QuadRooter fixed" checkbox for four separate issues.
Right: Understated and worth keeping
- Four distinct flaws across three different failure patterns.
- Patch availability is not deployed, active correction.
- Reputable primary sources carry conflicting chronology.
Caption: Evidence grade: editorial corrections the case requires.
Notes: Overstated and understated contrasts drawn across [1][2][7][8].

## CLOSE | Keep exposure scale and victim scale separate

- A large ecosystem estimate explains concern; it does not count reached devices.
- Track issue-level applicability, scanner method and evidence a correction is active.
- Keep affected, locally inventoried, assessed-vulnerable and confirmed-compromise distinct.
- A correction travels through accountable handoffs before it protects a device.
Caption: Evidence grade: case-specific conclusions, bounded.
Notes: Separation of exposure and victim scale from the conclusion; rests on [1] through [8].
