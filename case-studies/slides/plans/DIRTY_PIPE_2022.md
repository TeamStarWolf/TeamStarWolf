# Slide plan: Dirty Pipe 2022: Read-Only Data That Lost Integrity

- Study: case-studies/DIRTY_PIPE_2022.md
- Cover title: Dirty Pipe 2022 / CVE-2022-0847 / Read-only data lost integrity
- Subtitle: A Linux kernel pipe-buffer flaw let a local process overwrite read-only data it could not modify, enabling local privilege escalation.
- Published: 18 November 2026
- Notes: Conceptual study; no proof-of-concept executed, no production file altered, exploit procedure not reproduced.

## EXECUTIVE SUMMARY | An integrity boundary broke, not every system equally

- Dirty Pipe let a local unprivileged process modify cached content of files it could only read.
- The significance was a violated integrity boundary, affecting content without ordinary write permission.
- Not every install was equally exploitable; Red Hat found RHEL 8 kept the flaw but the known path failed.
- The later record adds a supplier warning of indications of targeted exploitation, so respond on evidence.
Caption: Evidence grade: Confirmed; no universal victim census.
Notes: Executive framing from [1], [2] and [3]; no proof-of-concept run and no file altered.

## KEY FACTS | Dates, lineage and the two-line upstream correction

Stat: 4.9 | Upstream lineage, missing flag init
Stat: 5.8 | Lineage enabling the described attack
Stat: 2 lines | Upstream correction scope, one file
Stat: Mar 7 | 2022 public disclosure date
- CVE-2022-0847; stable fixes on 23 February 2022 were 5.10.102, 5.15.25 and 5.16.11.
- Max Kellermann's timeline: first support ticket 29 April 2021, kernel recognition 19 February 2022.
- The flaw let a local unprivileged process modify cached content of files it could only read.
- This is local privilege escalation, not a remote, unauthenticated network-entry mechanism.
Caption: Evidence grade: Confirmed, dated records.
Notes: CVE and dates from [1] and [4]; stable-release list and timeline from [4].

## PART 1 | Keep vulnerability, exploit and incident distinct

- A vulnerability is a potential failure; an exploit is a method shown to work under stated conditions.
- An incident is actual use against a target; keep the three levels in separate fields.
- Keep patch available, patch installed and active correction verified as distinct states.
- Exploitable in theory is not exploited in the wild; a serious local flaw is not a proven breach.
Caption: Evidence grade: Confirmed definitions; no universal exploitation claim.
Notes: Evidence discipline from [3] and [7]; state separation as the study requires.

## PART 1 | Discovery began with an integrity symptom

- Kellermann traced the investigation to repeated corruption in downloadable access logs.
- The first support ticket was 29 April 2021; kernel recognition came 19 February 2022.
- A reliability symptom can reveal a security boundary failure, not only malicious activity.
- Preserve representative failures so a later engineer sees a pattern the first responder could not.
Caption: Evidence grade: Confirmed discoverer timeline.
Notes: Corruption symptom and timeline from [4]; the support-process lesson is original analysis.

## PART 1 | Two changes, two different historical claims

Ubuntu separates an older missing initialization from the later merge behavior the attack needed.

| Milestone | What entered the tree | What it means |
|---|---|---|
| Upstream 4.9 | Missing flag initialization | Older defect, before the public attack path |
| Upstream 5.8 | Per-buffer merge flag behavior | Later change the described attack needs |
| 23 Feb 2022 | Fixes 5.10.102, 5.15.25, 5.16.11 | Corrected kernels to verify as active |
Caption: Evidence grade: Confirmed upstream and distribution records.
Notes: Lineage split and update guidance from [2]; stable-release list from [4].

## PART 1 | The two-line correction and what it proves

- Upstream commit 9d2231c initializes flags when constructing the relevant pipe buffers.
- The displayed change is two added lines in one file, addressing missing initialization.
- A small diff measures the fix's focus, not the incident's importance or the diagnosis effort.
- The restored invariant: a new file-backed buffer cannot inherit merge authority from a previous role.
Caption: Evidence grade: Confirmed upstream commit.
Notes: Commit scope and message from [5]; the ownership invariant from [4] and [5].

## PART 2 | Local privilege escalation is still consequential

- The flaw is local; it is not a stand-alone, unauthenticated network-entry mechanism.
- A response must account for where less-trusted code runs and what authority it already holds.
- Calling it local does not make every local actor trusted or the issue safe to ignore.
- A serious local flaw does not by itself prove an internet-facing service is compromised.
Caption: Evidence grade: Confirmed scope; prioritization is original analysis.
Notes: Local-scope framing consistent with the constraints in [4]; prioritization is original analysis.

## PART 2 | Red Hat: affected is not the same as exploitable

- Red Hat rated the issue Important and listed affected products including RHEL 8.
- Its advisory said the known merge-flag vector was unavailable there, while the defect remained.
- It recommended corrected packages and said SELinux and kpatch did not mitigate this flaw.
- Preserve both fields: defect applicability and documented exploitability conditions.
Caption: Evidence grade: Confirmed vendor advisory.
Notes: Product scope, vector limitation and mitigation statements from [3].

## PART 2 | An applicability and correction decision table

This is a historical guide; distribution records take precedence over a raw version comparison.

| Milestone | What evidence establishes | What closes the local question |
|---|---|---|
| Upstream 4.9 | Missing init predates the public path | Use the product assessment, not a blanket label |
| Upstream 5.8 | Merge behavior enables the attack | Check branch and vendor fixes, not the version |
| RHEL 8 | Defect present; known vector absent | Keep the qualifier; follow Red Hat package guidance |
| Android May 2022 | Listed at the 2022-05-05 patch level | Verify device and vendor update; do not generalize |
Caption: Evidence grade: Confirmed source records; table is original synthesis.
Notes: Rows condensed from the study's decision table, citing [1-4], [6] and [7].

## PART 2 | Installed is not active; the restart boundary

- Ubuntu USN-5317-1, dated 8 March 2022, instructs a reboot after the standard update.
- Package installation and active correction are separate milestones.
- A successful update job can leave the old kernel running until the supported activation step.
- The notice warns the kernel ABI change needs attention to third-party kernel modules.
Caption: Evidence grade: Confirmed Ubuntu notice.
Notes: Reboot instruction, ABI warning and package detail from [6].

## PART 2 | Android gives bounded evidence of exploitation

- Android's May 2022 bulletin places CVE-2022-0847 at the 2022-05-05 kernel patch level.
- It classifies the issue as high-severity elevation of privilege.
- It states there were indications the flaw might be under limited, targeted exploitation.
- That is stronger than no evidence, but narrower than a public, widespread campaign account.
Caption: Evidence grade: Reported targeted-exploitation indication.
Notes: Patch-level placement, severity and bounded wording from [7]; no victim census.

## DEFENDER VIEW | Correction is not recovery after compromise

- Installing a fixed kernel addresses future use of the known flaw.
- It does not establish that no file, process or credential was affected before activation.
- A page-cache change may not persist to disk, yet altered content can influence a process first.
- When credible compromise evidence exists, investigate under the incident procedure, not a patch ticket.
Caption: Evidence grade: Confirmed persistence limits; response model is original.
Notes: Writeback and persistence limits from [4]; the correction-versus-recovery split is original analysis.

## CROSS-CUTTING THEMES | What this case overstates versus understates

Left: Overstated in the usual retelling
- Every Linux system was equally exploitable by the published attack.
- Patch available means the fleet is protected and active.
- A serious local flaw proves a breach already happened.
Right: Understated and worth keeping
- Lineage, product applicability and active runtime state answer different questions.
- Installed is not active; a reboot can stand between them.
- A targeted-exploitation indication can raise priority without a victim count.
Caption: Evidence grade: editorial corrections the case requires.
Notes: Contrasts drawn across [1] to [7]; keep applicability and activation distinct.

## CLOSE | Precision over an invented scale

- A small initialization defect broke a large integrity assumption when later behavior gave it significance.
- Separate upstream lineage, product applicability, active state and incident evidence.
- Keep patch available, patch deployed and verified remediated distinct.
- Identify the kernel that matters, activate the correction safely, and investigate credible signs separately.
Caption: Evidence grade: case-specific conclusions.
Notes: Conclusion synthesis across [1] to [7]; precision directs effort to the real condition.
