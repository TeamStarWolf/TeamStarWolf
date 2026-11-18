# Slide plan: Drupalgeddon2 2018: Patched Site Is Not Recovered Service

- Study: case-studies/DRUPALGEDDON2_2018.md
- Cover title: Drupalgeddon2 2018 / Patched vs Recovered / CVE-2018-7600
- Subtitle: A patched Drupal site is not a verified clean one; once automated exploitation began, a late update could not remove an implant placed earlier.
- Published: 18 November 2026
- Notes: The cover sets the frame: a patched website and a recovered service are different claims, not one receipt.

## EXECUTIVE SUMMARY | A patched website is not a recovered service

- Drupalgeddon2 let untrusted requests influence internal processing, enabling unauthenticated remote code execution.
- Drupal issued SA-CORE-2018-002 for CVE-2018-7600 on 28 March 2018 and warned of automated attacks by mid-April.
- Once automated attacks were underway, an updated install could still hold unauthorized changes from an earlier compromise.
- The April follow-up CVE-2018-7602 is a separate issue with its own identifier and prerequisites, not a second label for the same fix.
Caption: Evidence grade: Confirmed advisory dates; no victim census claimed.
Notes: Executive-assessment framing; patch-versus-recovery and the two-CVE split rest on [1][3][5].

## KEY FACTS | One nickname covers two distinct CVEs

Stat: 2 | Distinct CVEs: 7600 and 7602
Stat: Mar 28 | 2018 SA-CORE-2018-002 disclosure
Stat: Apr 13 | PSA warned of automated attacks
Stat: Apr 25 | 2018 out-of-band follow-up release
- CVE-2018-7600 is SA-CORE-2018-002, commonly called Drupalgeddon2; CVE-2018-7602 is SA-CORE-2018-004.
- The 13 April notice set 11 April as the date evidence emerged, allowing for earlier targeted activity.
- A record that only says "Drupalgeddon fixed" cannot say which issue was addressed or whether the site was assessed.
Caption: Evidence grade: Confirmed, dated advisories.
Notes: Identifiers and dates from [1][3][5]; the follow-up release schedule from [6].

## PART 1 | Keep vulnerability, exploit and incident distinct

- A vulnerability is a potential failure; a demonstration is a method that worked under stated conditions.
- An incident is actual use against a target; these levels must not be collapsed into one claim.
- A request resembling a published exploit may have failed, reached a corrected site or hit a non-Drupal service.
- Keep patched, verified-not-compromised and exploited-in-the-wild as separate fields, not one green status.
Caption: Evidence grade: Confirmed definitions; no universal-compromise claim.
Notes: Evidence-level discipline from the study's method sections [1][3]; detection caveats echo the Section 18 analysis.

## PART 1 | Two CVEs share the Drupalgeddon nickname

The nickname is a search aid; the formal identifier is the stable key.

| CVE | Advisory and date | Vector |
|---|---|---|
| CVE-2018-7600 | SA-CORE-2018-002, 28 Mar | Unauthenticated remote code execution |
| CVE-2018-7602 | SA-CORE-2018-004, 25 Apr | Requires user authentication |
| 2014 event | Older, separate issue | Not a source of 2018 dates |
Caption: Evidence grade: Confirmed identifiers and vectors.
Notes: Mapping and the authentication difference from [1][5]; the 2014 caution is the study's own warning not to borrow dates.

## PART 1 | Untrusted data crossed an internal boundary

- Check Point's 12 April research describes insufficient input sanitization in Drupal's Form API and rendering structures.
- External data could influence behavior intended for trusted internal metadata; this study does not reproduce the demonstration.
- The engineering lesson is to find where data changes meaning as it passes through framework layers.
- The invariant: user-controlled data must not gain internal execution authority by resembling trusted metadata.
Caption: Evidence grade: Demonstrated mechanism; exploit not reproduced.
Notes: Trust-boundary discussion from [4]; the operational demonstration is reviewed but not executed.

## PART 1 | Remote execution is not automatic OS root

- Volexity described code execution with the privileges of the account running the web server and Drupal.
- That is already serious, but it is not proof that every attempt obtained unrestricted operating-system authority.
- Start the consequence model from the application's real permissions, files, credentials and trusted services.
- Least privilege can reduce impact, but it cannot repair the defect or prove confidential data stayed safe.
Caption: Evidence grade: Confirmed execution context; broader claims bounded.
Notes: Privilege scope and the consequence model from [7]; inflation to universal root is the error the study rejects.

## PART 2 | Advance notice bought preparation time

- On 21 March, Drupal announced a highly critical release scheduled for 28 March with a specified UTC window.
- It urged teams to reserve time, described exceptional updates for older branches and said no database update was required.
- Advance notice converts to readiness: identify owners, confirm deployment access and establish a rollback plan.
- Preparation is not pre-approving an unknown production change; it is deciding how review will happen quickly.
Caption: Evidence grade: Confirmed advance-notice record.
Notes: Release-window and preparation details from [2]; the readiness framing is the study's original analysis.

## PART 2 | The March correction was branch-specific

The old version numbers reconstruct the response; they are not current install targets.

| Branch | Corrected release | Note |
|---|---|---|
| Drupal 7 | 7.58 | Direct branch correction |
| Drupal 8.5 | 8.5.1 | Direct branch correction |
| Drupal 8.3 and 8.4 | 8.3.9 and 8.4.6 | Exceptional older-branch releases |
| Drupal 6 | None | Affected and end-of-life |
Caption: Evidence grade: Confirmed historical release targets.
Notes: Branch-specific corrections and the Drupal 6 end-of-life note from [1]; connect the correction to the actual deployment artifact.

## PART 2 | Automated attempts changed the response problem

- The 13 April notice said it was a follow-up about the same vulnerability, not a new one.
- It warned that sites unpatched by 11 April might be compromised and that patching would not remove backdoors.
- Separate urgent correction from retrospective investigation; both can run, but neither substitutes for the other.
- Document the exposure window you can establish and the gaps you cannot, without rewriting gaps as proof.
Caption: Evidence grade: Confirmed warning; compromise not asserted per site.
Notes: Follow-up status, the 11 April date and the backdoor warning from [3]; the parallel-task model is original analysis.

## PART 2 | Observed attempts are breadth, not a census

- In its 16 April report, Volexity described thousands of scan and exploitation attempts observed since early 13 April.
- Reported activity varied, including attempts to install backdoors and cryptocurrency miners.
- A monitoring provider sees its own traffic; attempt totals are not a global count of unique compromised sites.
- Scanning and attempts are not confirmed compromise of every scanned site; attempt totals must not become victim totals.
Caption: Evidence grade: Reported monitoring scope, not a victim count.
Notes: Attempt volume and payload categories from [7]; preserving the observer's scope is the study's reporting lesson.

## PART 2 | The April follow-up was a separate correction

- The 23 April notice scheduled an out-of-band release for 25 April; the advisory covered CVE-2018-7602.
- Corrected releases were 7.59, 8.5.3 and the exceptional 8.4.8, with a user-authentication requirement.
- Direct patches required the earlier SA-CORE-2018-002 fix to already be present.
- A patch that applies cleanly is not proof that all required earlier changes exist; record the baseline.
Caption: Evidence grade: Confirmed advisory and prerequisite.
Notes: Follow-up schedule, releases and the dependency on the earlier fix from [5][6]; keep the two advisories non-identical.

## PART 2 | Public version strings are imperfect evidence

- In a June 2018 response, Drupal disputed vulnerability counts based on public CHANGELOG.txt version text.
- A direct security patch can leave version text stale, and vendor mitigations can protect a site without changing that file.
- The reverse inference is also weak: a current-looking version cannot prove the absence of an earlier backdoor.
- Correctness and trust are separate dimensions; a strong report records both, not one combined status.
Caption: Evidence grade: Reported objection; direct page retrieval returned an error.
Notes: The CHANGELOG objection and the stale-version point from [8], read from the search-indexed excerpt only.

## DEFENDER VIEW | Separate correction status from trust status

- Build a site-by-issue matrix: which CVE, which deployed artifact, what changed and what was verified.
- Verify an unexplained patch by provenance: an approved actor, a known artifact and a deployment event.
- Inventory forgotten and indirect sites: old microsites, staging copies and alternate routes to an origin.
- Preserve a forensic copy before destructive cleanup; a recent backup may already sit inside the compromise window.
Caption: Evidence grade: Inferred defensive guidance drawn from the sources.
Notes: Provenance, inventory and preservation guidance from [3][9]; the matrix is the study's original response model.

## CROSS-CUTTING THEMES | What the record overstates versus understates

Left: Easy to overstate
- Reading mass-scanning totals as confirmed compromise of every scanned site.
- Treating an applied update as proof the service is clean.
- Collapsing CVE-2018-7600 and CVE-2018-7602 into one "Drupalgeddon fixed" line.
Right: Easy to understate
- A patched site could already hold an implant placed before the update.
- Remote execution still runs in a real, privileged application context.
- The April issue carried its own prerequisite and authentication vector.
Caption: Evidence grade: editorial corrections the case requires.
Notes: Overstated and understated contrasts tie to [3][5][7]; keep scanning, compromise and correction distinct.

## CLOSE | A traceable account beats a single green status

- A patched website and a recovered service are different outcomes, and the update does not remove an earlier implant.
- Keep patched, verified-not-compromised and exploited-in-the-wild separate, with exact identifiers and prerequisites.
- Keep attempt totals bounded to the observer's scope; do not invent a victim count or attribution.
- Deliver a traceable account: which issue, which site, what changed, what was verified and what remains uncertain.
Caption: Evidence grade: case-specific conclusions, outcome claims bounded.
Notes: Conclusion synthesis across the study; rests on [1][3][5][7][9] and the patched-versus-recovered distinction.
