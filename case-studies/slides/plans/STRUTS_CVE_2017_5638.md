# Slide plan: Struts CVE-2017-5638: Error Path to Execution

- Study: case-studies/STRUTS_CVE_2017_5638.md
- Cover title: Struts CVE-2017-5638 / March 2017 / Error path to execution
- Subtitle: A crafted Content-Type header hit the Jakarta multipart parser's error path, turning request data into pre-authentication code execution.
- Published: 18 November 2026
- Notes: The cover sets the frame: an error-handling path, not the upload feature, and a framework fix the deploying organization must apply.

## EXECUTIVE SUMMARY | An error path, not just the upload workflow

- In the affected framework, exception handling and error-message generation formed part of a remote code-execution path.
- The dangerous behavior was not limited to the intended successful upload workflow; a rejected request still reached complex processing.
- S2-045 and S2-046 describe different request-header vectors for the same CVE-2017-5638.
- This study analyzes framework behavior and patch verification; it does not retell the Equifax breach as a substitute.
Caption: Evidence grade: Confirmed advisories; no incident re-derived.
Notes: Executive-assessment framing from [1][2]; Equifax is referenced only as a consequence of unpatched exposure, not re-derived here.

## KEY FACTS | One CVE, two bulletins, a critical rating

Stat: 1 | CVE-2017-5638
Stat: 2 | Bulletins S2-045 and S2-046
Stat: Critical | Apache S2-045 severity
Stat: 8 Mar | Talos exploitation report
- S2-045 names the Jakarta Multipart parser and lists affected versions 2.3.5 to 2.3.31 and 2.5 to 2.5.10.
- Recommended historical upgrades were 2.3.32 or 2.5.10.1; Nike Zheng is the credited reporter.
- The trigger is a malicious Content-Type value whose handling produces an exception, then a user-facing error message.
Caption: Evidence grade: Confirmed, dated Apache bulletins.
Notes: Component, ranges and reporter from [1]; the exploitation date from [5]. Historical fixed releases are not a 2026 maintenance baseline.

## PART 1 | Keep vulnerability, exploit and incident distinct

- A vulnerability is a potential failure; an exploit demonstration is a method that worked under stated conditions.
- An incident is actual use against a target; the three levels must not be collapsed into one claim.
- Keep "patch available" separate from "patch deployed" and from "verified remediated".
- Exploitable-in-theory is not exploited-in-the-wild, and a common mechanism is not an attribution.
Caption: Evidence grade: Confirmed definitions; no exploitation inferred here.
Notes: Evidence-level discipline follows the study's method; the attribution caution echoes [5].

## PART 1 | The affected component and its version ranges

S2-045 rates the issue critical and bounds it to specific releases.

| Item | Detail |
|---|---|
| Component | Jakarta Multipart parser, Struts 2 |
| Affected | 2.3.5 to 2.3.31; 2.5 to 2.5.10 |
| Historical fix | 2.3.32 or 2.5.10.1 |
| Reporter | Nike Zheng (S2-045) |
Caption: Evidence grade: Confirmed, Apache S2-045.
Notes: Versions, rating and credit from [1]; the pre-authentication boundary is that untrusted request data reached framework machinery running with server-side authority.

## PART 1 | Error handling is a security boundary

- Invalid header content entered an exception path that both bulletins connect to remote execution.
- Untrusted request data influenced processing carrying more authority than ordinary display data should receive.
- Error construction deserves the same trust analysis as the main business operation.
- The invariant: rejected client content must stay inert when the application explains the rejection.
Caption: Evidence grade: Confirmed path; the review principle is original analysis.
Notes: Exception-path behavior from [1][2]; the trust-analysis principle is the study's original lesson, not a claim that every exception is unsafe.

## PART 2 | A second bulletin is not a second vulnerability

- S2-046 describes malicious Content-Disposition or improper Content-Length as vectors for the same CVE.
- It credits Chris Frohoff, Nike Zheng and Alvaro Munoz, and keeps the earlier affected ranges and fixes.
- A second advisory number should not create a second vulnerability count or re-open the corrected releases.
- Removing the File Upload Interceptor is limited to Struts 2.5.8 through 2.5.10, not a universal recipe.
Caption: Evidence grade: Confirmed, Apache S2-046.
Notes: Vectors, credits and constrained alternatives from [2]; advisory identifiers organize communication, while the CVE and technical scope describe the flaw.

## PART 2 | When a defensive conclusion changed

- JPCERT/CC first tested a sample Struts application on Tomcat and found execution in affected versions.
- Early results showed no execution for a JakartaStreamMultiPartRequest configuration.
- The 17 March update superseded that: the alternative was also affected, and it strongly favored updating.
- A record saying only "alternate parser tested safe" would lose the build, configuration and advisory revision.
Caption: Evidence grade: Demonstrated then corrected, per JPCERT/CC.
Notes: Initial test, the superseding update and the 21 March same-CVE note from [3]; corroborated by Hitachi's chronology in [4].

## PART 2 | A patch milestone is not a protected service

Separate a dated event from what it does not establish.

| Date | Supported event | Does not establish |
|---|---|---|
| 8 Mar 2017 | Talos reports exploitation | Proof of execution on a given host |
| 9 Mar 2017 | CERT-EU remediation warning | That every customer is protected |
| 15 Mar 2017 | SAS completes not-vulnerable finding | A rule for any similarly named product |
| 17 Mar 2017 | JPCERT corrects the workaround | That any local system has yet changed |
Caption: Evidence grade: Confirmed dates; non-claims kept explicit.
Notes: Dates and findings from [3][5][6][8]; the non-claims follow the study's evidence discipline.

## PART 2 | Observation limits around exploitation reports

- Talos described probing and attempts to deliver malware, with varied payloads and some attempted persistence.
- It cautioned that aspects of the early timeline were unclear; these are first-party observations, not a census.
- CERT-EU described execution with the privileges of the service account.
- A public vulnerability can attract unrelated actors; a shared mechanism is not a campaign narrative.
Caption: Evidence grade: Reported first-party observations.
Notes: Payload and timeline caveats from [5]; service-account execution context from [6]. No victim count or single operator is inferred.

## PART 2 | Supplier scope beats a generic library match

Left: Cisco
- The advisory lists affected products and routes readers to per-product fixed-release records.
- Its header states no workarounds are available for the advisory.
Right: SAS
- The assessment completed 15 March found its managed custom Struts version not vulnerable.
- A flagged library in a component did not mean the affected functionality was used.
Caption: Evidence grade: Confirmed vendor statements, defined product scope.
Notes: Product routing and the no-workaround note from [7]; the supplier not-vulnerable finding from [8]. Do not generalize either statement into a universal rule.

## DEFENDER VIEW | Six evidence states from advisory to runtime

- Distinguish six states: advisory understood, applications identified, remedy selected, artifact prepared, deployed, service verified.
- Selecting an approved framework version does not establish that a build includes it.
- A completed rollout does not establish that a stale standby node cannot rejoin with the old artifact.
- Use named application owners and a central coordinator; a broadcast message alone creates no accountability.
Caption: Evidence grade: Original defensive analysis.
Notes: The six-state model and coordination roles are the study's original response framework, developed from the documented parser issue.

## DEFENDER VIEW | Identify applications, not just hosts

A repository change, a package and a running service are different evidence.

| Question | Useful evidence | Invalid shortcut |
|---|---|---|
| Which app runs it? | Build manifests, deploy records | A host banner's version |
| Change in effect? | Post-rollout runtime evidence | A repository commit alone |
| Recovery safe? | Retired or gated old artifacts | Changing the primary node |
| Supplier scope? | Exact product and advisory | A generic library name |
Caption: Evidence grade: an original review tool.
Notes: Condensed from the study's application-identity and artifact sections; supplier rows draw on [7][8].

## CROSS-CUTTING THEMES | What the retelling gets wrong

Left: Easy to overstate
- Reading the Equifax breach as the vulnerability's own analysis.
- Treating a second bulletin as a re-opened, separate vulnerability.
- Reading "patched" as a verified, running remediation.
Right: Easy to understate
- An error path, not the upload feature, carried the execution.
- A workaround's justification can expire before any calendar deadline.
- Rejection paths need the same review as successful workflows.
Caption: Evidence grade: editorial corrections the case requires.
Notes: Contrasts drawn across the study; Equifax is kept to the study's bounded reference, with no incident re-derived.

## CLOSE | A chain of evidence, not a patch receipt

- CVE-2017-5638 was a failure at an input-to-interpretation boundary, reachable before authentication.
- The fix is a framework update the deploying organization must apply, then verify on the running service.
- A patch response needs a chain of evidence linking an advisory to the deployed application and its active runtime.
- Keep technical remediation separate from investigation of earlier activity.
Caption: Evidence grade: a conclusion synthesis.
Notes: Conclusion synthesis across the study; rests on [1] through [9].
