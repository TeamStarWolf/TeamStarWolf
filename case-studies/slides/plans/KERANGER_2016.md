# Slide plan: KeRanger 2016: A Signed Installer Crossed a Trusted Download Boundary

- Study: case-studies/KERANGER_2016.md
- Cover title: KeRanger 2016 / Signed Installer / Trusted Download
- Subtitle: A legitimate download with a valid signature was not safety; distribution, executed malware, and damaged data stayed distinct problems.
- Published: 18 November 2026
- Notes: The cover sets the frame: a trusted channel and a valid signature were not, together, a harmlessness guarantee.

## EXECUTIVE SUMMARY | A real download site and a valid signature were not safety

- KeRanger demonstrated that a legitimate distribution site plus a valid code signature were not a complete assurance of safety.
- This was not a user grabbing an obvious fake; it was trust in a familiar project, a release artifact, and signed code.
- Distinct work addressed distribution, already-executed malware, and damaged data, which later summaries often blur.
- The sources supply no verified worldwide infection count, total ransom figure, or definitive attacker identity.
Caption: Evidence grade: Demonstrated trust-failure case; no verified victim count.
Notes: Executive-assessment framing; sources are [1] through [6], with no sample run and no attacker service contacted.

## KEY FACTS | Dated contemporary analyses, with the limits kept visible

Stat: 3 | Day encryption delay in the analyzed sample
Stat: 2.90 | Transmission version carrying the payload
Stat: Mar 4 | Unit 42 detects modified installers, 2016
Stat: 4 | Primary research firms this study cites
- Unit 42 warned of a download window from March 4, 11 a.m. PST to March 5, 7 p.m. PST. [1]
- Unit 42 reported a valid signing certificate, different from the prior one, with later revocation and detection updates. [1]
- ESET confirmed the analyzed version delayed encryption for three days and warned a missing ransom note did not establish safety. [2]
- The sources supply no verified worldwide infection count or ransom total.
Caption: Evidence grade: Confirmed, dated 2016 analyses.
Notes: Window, certificate and delay facts from [1] and [2]; the four firms are Unit 42, ESET, Check Point, Bitdefender [1-4].

## PART 1 | What each contemporary report actually observed

- Unit 42 detected two modified Transmission 2.90 installers on March 4 and said it could not confirm how the infection occurred. [1]
- ESET analyzed the modified application, confirmed the three-day delay, and noted ransom text was retrieved remotely and could change. [2]
- Check Point described access to user and mounted-volume files and separated updated platform blocking from malware already executed. [3]
- Check Point's sample lacked persistence across reboot unless the app was reopened; that is sample-specific, not a remediation rule. [3]
Caption: Evidence grade: Confirmed contemporary analyses; method of compromise unconfirmed.
Notes: Per-firm observations from [1], [2] and [3]; keep observed behavior separate from the uncertain initial access.

## PART 1 | A chronology with distinct kinds of dates

Each row separates a supported event from what it does not prove.

| Date or record | Supported event | What it does not prove |
|---|---|---|
| March 4, 2016 | Unit 42 detects affected installers | The precise method of distribution compromise |
| March 4-5 | Reported exposure window for downloads | A count of infected or encrypted devices |
| March 5 | Malicious files reported removed from site | Every downloaded copy was recalled |
| March 8 | Bitdefender code-similarity findings | A verified identity or universal decryption |
| 2.92 release record | Project notes built-in KeRanger removal | Removal recovers encrypted files |
| August 2016 | Separate Keydnap distribution incident | The March and August malware are one family |
Caption: Evidence grade: Confirmed dates; non-claims kept explicit.
Notes: Dates and the "does not prove" column from [1-6]; the GitHub release page shows publication metadata, not the original incident timeline [5].

## PART 1 | A distribution compromise, with initial access unresolved

- The observed distribution of a modified installer through a legitimate channel establishes a supply-chain case on its own.
- It does not require inventing a stolen password, a server flaw, or a malicious maintainer to matter. [1]
- Shorthand like "the website was hacked" must not be expanded into an unsupported step-by-step intrusion account.
- Release distribution integrity failed while the exact upstream intrusion stays unresolved; that conclusion is precise, not weak.
Caption: Evidence grade: Confirmed distribution path; initial access unresolved.
Notes: Unit 42's stated uncertainty preserved [1]; the limit on preventive-control claims is original analysis.

## PART 1 | A valid signature is not a harmlessness guarantee

- Bitdefender discussed misuse of a legitimate certificate and noted signed Mac malware had existed before this case. [4]
- A signature answers a limited set of questions about an artifact and its signer; it is not a verdict on behavior.
- A changed signing identity can be legitimate, so the proportionate response is review before broad deployment, not automatic accusation.
- Accepting an artifact signed under an abused identity is different from forging a signature; this was not a cryptographic break.
Caption: Evidence grade: Confirmed certificate misuse; not a cryptographic break.
Notes: Certificate misuse and the Linux.Encoder comparison from [4]; the verification framing is original analysis.

## PART 1 | The three-day delay created a misleading quiet period

- ESET warned the ransomware could be present before a ransom note or visible encryption appeared. [2]
- An app that opens normally and leaves files readable for a time can create false confidence that installation simply succeeded.
- For an investigation, separate download, installation, first execution, payload activity, and observed file impact as distinct events.
- Do not turn the delay into a guaranteed rescue deadline; sample behavior is not a safe countdown for a real incident.
Caption: Evidence grade: Demonstrated in the analyzed sample; not a rescue countdown.
Notes: Delay and the "not yet visible" warning from [2]; the event-separation discipline is original analysis.

## PART 2 | Connected storage and the Time Machine distinction

- Check Point reported encryption affecting mounted storage as well as user files. [3]
- Unit 42 separately identified a Time Machine-related function that was implemented but unused in the samples it discussed. [1]
- General access to connected storage can create backup risk without proving a dedicated Time Machine routine executed.
- The case should not become "KeRanger destroyed all Time Machine backups," nor "backups were irrelevant"; examine reachability and tested restoration.
Caption: Evidence grade: Reported mounted-volume risk; the Time Machine routine was unused.
Notes: Mounted-volume access from [3]; the unused routine from [1]; the backup-reachability lesson is original analysis.

## PART 2 | Separate observed behavior from dormant capability

- Malware writing mixes observed behavior, code that appears present but unexecuted, and inference about a developer's intent.
- A function name does not show the code was reachable, triggered, or successful; failing to observe it once does not prove it never occurs.
- A useful report has separate fields for observed behavior, code-supported possibility, and analyst inference, each with confidence and limits.
- That structure lets responders decide which findings justify immediate action and avoids turning uncertainty into panic or complacency.
Caption: Evidence grade: Original analysis on evidence categories.
Notes: Rests on the Time Machine example [1]; the three-field reporting format is original defensive analysis.

## PART 2 | March KeRanger and August Keydnap were different incidents

- ESET's August 30 report described Keydnap distributed through a modified Transmission 2.92 application. [6]
- It characterized Keydnap as credential-stealing malware with a persistent backdoor, with only a similar delivery technique. [6]
- The same project and a similar path can appear in separate incidents; a version number is not proof every copy is malicious.
- Similar code or technique supports investigation but does not prove one person controlled both events; attribution stops short.
Caption: Evidence grade: Confirmed separate August incident; no shared-actor proof.
Notes: Keydnap distribution and payload from [6], used only as a boundary check; a full Keydnap case is a separate study.

## DEFENDER VIEW | Trace every conclusion to evidence and its boundary

This matrix shows how different evidence answers different questions; it is a planning tool, not a 2016 records claim.

| Question | Useful evidence | Boundary to preserve |
|---|---|---|
| Which artifact was obtained? | Package identity, acquisition record | Product name is not enough |
| Was it executed? | Endpoint records and user context | Download does not prove execution |
| Which signer was expected? | Approved release identity, change record | Valid signature is not the expected signer |
| What data was affected? | File evidence, business-owner validation | Reachable storage is not infected storage |
| What remediation occurred? | Verified endpoint and distribution actions | Removed download does not recall copies |
| Can operations resume? | Security review, representative restores | Readable files do not close the incident |
Caption: Evidence grade: an original planning tool.
Notes: Condensed from the study's evidence matrix; preserve original timestamps and document any PST conversion.

## DEFENDER VIEW | Release assurance spans producers and consumers

Left: Producers (the whole delivery path)
- Map the authority to create, sign, approve, upload and replace a release, and ask whether one identity can do every step.
- Keep an authoritative record of approved artifacts and expected signer, and compare what is distributed with what was approved.
- Prepare withdrawal and advisory capability that still works if the usual release channel is unavailable.
Right: Consumers (deliberate acceptance)
- A managed catalog names approved products, expected publishers, and review triggers, with a legitimate route for needed software.
- An unexpected signer or urgent upstream warning gets an owner, a review, and a recorded decision.
- Keep authenticity separate from suitability; acceptance is per artifact and use case, not a permanent exemption for a brand.
Caption: Evidence grade: Original defensive analysis.
Notes: Producer and consumer practices are original analysis prompted by the distribution failure; not Transmission's internal process.

## CROSS-CUTTING THEMES | What the retelling overstates versus understates

Left: Easy to overstate
- "The website was hacked" expanded into a step-by-step intrusion the record does not establish.
- "KeRanger destroyed all Time Machine backups," from an unused routine.
- A valid signature or a 2.92 removal release read as full remediation.
Right: Easy to understate
- Release distribution integrity failed even with initial access unresolved.
- The three-day delay created a misleading quiet period before visible impact.
- March KeRanger and August Keydnap were separate incidents, not one family.
Caption: Evidence grade: editorial corrections the case requires.
Notes: Overstated and understated contrasts drawn across [1-6]; keep distribution, execution and data impact as distinct problems.

## CLOSE | A traceable account beats an alarming headline

- Getting an app from its real site with a valid signature was not, by itself, assurance of safety.
- Distribution, already-executed malware, and damaged data were distinct problems with different scopes.
- A milestone like 2.92 removal is a response feature, not a promise that encrypted files return. [5]
- The record bounds the case: no verified victim count, no ransom total, no definitive actor; recovery rests on tested paths, not on paying an attacker.
Caption: Evidence grade: a conclusion synthesis.
Notes: Conclusion synthesis across the study; the removal feature is read from the release note [5], not an independent remediation test.
