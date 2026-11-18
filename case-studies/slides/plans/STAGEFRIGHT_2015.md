# Slide plan: Stagefright 2015: When Patched Did Not Mean Deployed

- Study: case-studies/STAGEFRIGHT_2015.md
- Cover title: Stagefright 2015 / Patch Completeness / & Trust Boundaries
- Subtitle: Android media-parsing flaws where an initial fix proved incomplete and a source fix still had to reach each device through carriers and makers.
- Published: 18 November 2026
- Notes: The cover sets the frame: related but distinct developments and a contested update path, not one universal fix.

## EXECUTIVE SUMMARY | A family name hides four distinct developments

- Stagefright is shorthand for a set of Android media-processing flaws, not one identical defect with one universal update.
- Original disclosures, an incomplete correction, later library findings and 2016 hardening were related but separate developments.
- A source fix still had to become a product update that reached the actual device, so distribution is part of the case.
- The long-term lesson concerns authority: a parser handling untrusted content should hold no more access than its task needs.
Caption: Evidence grade: Confirmed disclosures; no mass-exploitation campaign attributed.
Notes: Executive-assessment framing from [1] and [8]; no malicious media was generated, sent or tested.

## KEY FACTS | Seven CVEs and an estimate, not a victim census

Stat: 7 | CVEs in the original Zimperium list
Stat: Jul 27 | 2015 public research announcement
Stat: Sep 9 | 2015 bulletin fixing CVE-2015-3864
- Zimperium publicly described Joshua Drake's research on 27 July 2015 with seven CVE identifiers. [1]
- The original set is CVE-2015-1538, -1539, -3824, -3826, -3827, -3828 and -3829. [1]
- The announcement estimated exposure across a very large Android population, a capability claim and not a count of compromised devices.
Caption: Evidence grade: Confirmed CVE list and dates; exposure figure is Reported.
Notes: CVE set and announcement from [1]; CERT catalog context VU#924951 from [2].

## PART 1 | Keep vulnerability, exploit and incident distinct

- A memorable name is an index, not a complete technical specification; "Stagefright fixed" leaves open which issue and which build.
- Where a family holds several issues, preserve the set rather than collapsing it into one checkbox. [1][2]
- A later variant is not proof every earlier correction failed, and an earlier fix is not coverage for every later issue of the same name.
- A better record connects each issue identifier to the supplier's applicability statement and the specific deployed build.
Caption: Evidence grade: Confirmed identifiers; the auditing rule is original analysis.
Notes: Vulnerability-identity discipline from [1] and [2]; several processing flaws can share one CVE.

## PART 1 | Media handling can precede the recognized action

- Remote-content paths included MMS and browser playback; Hangouts and Messenger were changed so media would not auto-pass to vulnerable processes. [3]
- Receiving, inspecting, extracting metadata, rendering a preview and consciously opening are separate stages a user may not distinguish.
- The relevant consequence is the media process's authority, not an assumed takeover of the entire phone. [3]
- A setting that changes one application's automatic behavior does not repair the parser or cover every app using the shared component.
Caption: Evidence grade: Confirmed bulletin statements; the staged model is analysis.
Notes: Media paths, application mitigations and privileged-service wording from [3].

## PART 2 | August and September were different milestones

Each bulletin is a supplier milestone with a defined build and scope, not an ecosystem-wide status.

| Milestone | Date | Build | Note |
|---|---|---|---|
| August Nexus bulletin | 13 Aug 2015 | LMY48I or later | Listed issues, media paths |
| September Nexus bulletin | 9 Sep 2015 | LMY48M or later | CVE-2015-3864, first fix insufficient |
Caption: Evidence grade: Confirmed, dated Nexus bulletins.
Notes: August scope and build from [3]; September scope and the incomplete-fix relationship from [4].

## PART 2 | Why the incomplete patch mattered

- Mark Brand's Project Zero article, 16 September 2015, analyzed CVE-2015-3864 and demonstrated a scoped research exploit on Android 5.0 and later on a Nexus 5. [5]
- An apparently adequate arithmetic check failed to account for different integer widths; "patched" needed qualification.
- A patch should be reviewed against the property it must guarantee, not just the one sample that exposed the defect.
- One passing regression test shows a single input no longer fails; it does not prove every related path keeps the boundary.
Caption: Evidence grade: Demonstrated under stated conditions; limits acknowledged in source.
Notes: Patch-completeness, platform scope and arithmetic-type discussion from [5]; exploit material not reproduced.

## PART 2 | Later findings need exact source reconciliation

Coordination summaries and supplier bulletins do not align cleanly, so use the exact supplier entry.

| Source | CVEs | Build or level | Caveat |
|---|---|---|---|
| CERT VU#924951 | -6602, -6610 | LMY48K, Nov guidance | Wording differs from supplier |
| October bulletin | -3876, -6602 | LMY48T, incl. LMY48W | Credits Drake |
| November bulletin | -6610 | LMY48X, Nov 1 level | -6610 local EoP, lower remote likelihood |
Caption: Evidence grade: Confirmed entries; the discrepancy is preserved, not merged.
Notes: Coordination summary from [2]; October scope from [6]; November assessment from [7].

## PART 2 | Fixed upstream is distinct from deployed to devices

- A source correction is not the same as a carrier-specific package, and a package announcement is not the state of an employee's phone.
- Reference-device builds such as the Nexus bulletins do not establish that every product received those exact builds on the bulletin date. [3][4]
- A remediation record should separate source availability, product release, delivery eligibility, installation and active-state verification.
- Each transition needs its own evidence; no single observation should be credited with proving more than it can show.
Caption: Evidence grade: Confirmed milestones; the evidence-chain model is original analysis.
Notes: Delivery-versus-activation separation from [3] and [4]; carriers and makers control the update path.

## PART 2 | Exposure estimates are not victim counts

- The large exposure estimate describes the population believed to contain vulnerable code, not the number attacked or compromised. [1]
- A vulnerable population, a reachable population, a tested device set and a confirmed incident population measure different things.
- Avoid adding precision through arithmetic the evidence cannot support; a percentage of an approximate population is deceptively exact.
- For organizational decisions, a local inventory is more useful than a global headline for naming which asset remains exposed.
Caption: Evidence grade: Reported estimate; the denominator discipline is analysis.
Notes: Exposure-versus-victims distinction from [1]; retain each estimate's date, method and uncertainty.

## PART 2 | Demonstrated capability versus observed incidents

- Google's Android Security 2015 Year in Review, April 2016, separated researcher demonstrations and toolkit inclusion from exploitation of actual user devices. [9]
- At the report's writing, Google said it had neither observed nor been made aware of successful Stagefright exploitation against actual users. [9]
- That is a dated observation with a visibility boundary, not proof exploitation was impossible, and it does not erase the research demonstrations.
- Detection of vulnerable software is not compromise; a laboratory result does not identify a real-world actor or victim.
Caption: Evidence grade: Confirmed dated observation; Demonstrated capability kept separate.
Notes: The capability-versus-incident distinction and the dated bounded statement from [9].

## PART 2 | Prevention and containment do different jobs

- Google's May 2016 media-hardening article paired integer-overflow checks across the Android N media stack with a redesign separating media responsibilities into more restricted processes. [8]
- Prevention tries to stop the dangerous state arising; containment assumes a component may still fail and limits its reach.
- Investing in one does not make the other unnecessary, and having both is not a promise no future parser flaw exists.
- A parser's resource needs should be explicit: start from the job, list what it requires, and justify any extra authority it holds.
Caption: Evidence grade: Confirmed hardening measures; the least-privilege framing is analysis.
Notes: Integer checks, privilege separation and the prevention-versus-containment goals from [8].

## DEFENDER VIEW | Measure correction with a local inventory

- Record device model, hardware variant, OS build, patch level when supported, management status and update owner, plus the media-handling apps in use.
- Distinguish assessed devices, confirmed-applicable devices, available updates, completed installations and verified active states.
- Keep unknown facts visible as tasks; do not count an unreported device as corrected, and do not automatically count it as compromised.
- Describe any temporary mitigation narrowly, with the path it reduces, the verified product version, the owner and an exit condition.
Caption: Evidence grade: Inferred defensive guidance drawn from the study.
Notes: Inventory, metrics and scoped-mitigation discipline synthesized from the study's response sections.

## CROSS-CUTTING THEMES | What the record overstates versus understates

Left: Easy to overstate
- "Patched" as one universal fix, when an original correction was found incomplete.
- A reference-device bulletin as proof the whole ecosystem was updated.
- The exposure estimate read as a count of attacked or compromised users.
Right: Easy to understate
- Fixed upstream and deployed to a device are distinct; carriers and makers control delivery.
- Demonstrated remote reachability via a crafted media message, bounded to stated conditions.
- Correction and containment reinforce each other, yet neither guarantees no future defect.
Caption: Evidence grade: Mixed; each claim bounded to its source's scope.
Notes: Overstated and understated contrasts drawn across [1], [4], [5], [8] and [9].

## CLOSE | A testable claim beats a reassuring label

- A security claim is not fully described by a family name, and a remediation is not fully described by a source patch. [1][5]
- Keep the original set, the incomplete correction and later findings distinct, each tied to the exact supplier entry and build.
- Separate exposure estimates from victim counts, and research demonstrations from dated observations of real-world activity.
- Map the actual processing path, verify the exact product correction, reopen tasks when evidence changes, and maintain devices across their service life.
Caption: Evidence grade: a conclusion synthesis bounded to the record.
Notes: Conclusion synthesis across the study; rests on [1] through [9].
