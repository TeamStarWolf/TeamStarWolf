# Slide plan: EternalBlue and MS17-010: What a Patch Response Must Prove

- Study: case-studies/ETERNALBLUE_MS17_010_2017.md
- Cover title: EternalBlue and MS17-010 / What a Patch Response / Must Prove
- Subtitle: A vendor releasing a correction is not the same as an organization proving the fix took effect and the exposure stayed closed.
- Published: 15 November 2026
- Notes: Cover only; a TeamStarWolf case study on the assurance gap between a published patch and a verified one.

## EXECUTIVE SUMMARY | A release is not a verified fix

MS17-010 separates a vendor issuing a correction from an organization establishing protection.

- A correction sitting in a catalog does not establish the state of any one machine.
- A message telling administrators to patch does not establish whether they acted.
- No single measure proves earlier compromise did not happen, and one fix does not close every route.
- The primary-source record holds traps: differing CVE labels and revised NHS totals that must be kept distinct.
Caption: Evidence grade: Confirmed [1][3].
Notes: The study reframes the case as an assurance problem, not a WannaCry or NotPetya retelling [1][3]. Source discrepancies are flagged for later slides [2][4][6][7].

## KEY FACTS | One bulletin, five flaws, two outbreaks

Stat: 5 | RCE CVEs grouped in MS17-010
Stat: 14 Apr | EternalBlue public via Shadow Brokers
Stat: 12 May | WannaCry campaign began, 2017
Stat: 97% | Endpoint coverage, still breached
MS17-010 shipped 14 March 2017; the exploit release and WannaCry made the gap consequential.
Caption: Evidence grade: Confirmed [1][3][8].
Notes: Bulletin date and five RCE identifiers CVE-2017-0143/-0144/-0145/-0146/-0148 from [1]; chronology from CERT-EU [3]; the 97 percent coverage case from the Petya retrospective [8].

## PART 1 | The bulletin fixed a reachable network service

MS17-010 addressed several SMBv1 server flaws; it changed how the server handled crafted requests.

- Five identifiers were grouped as remote-code-execution; CVE-2017-0147 was described separately as information disclosure.
- An unauthenticated attacker could, in most situations, reach the vulnerable processing over the network.
- The risk was not limited to a user opening a document; a reachable service could process hostile input.
- The fix belonged in OS maintenance and network exposure management, not endpoint protection alone.
Caption: Evidence grade: Confirmed [1].
Notes: The technical boundary is established without reproducing exploitation mechanics [1]. An inventory storing only a nickname cannot say which package applies per platform.

## PART 1 | Exploit availability, not the CVE, drove urgency

CERT-EU recorded EternalBlue becoming public on 14 April 2017, after the March correction, with WannaCry from 12 May.

- These dates set a sequence of changing public risk, not what each defender or attacker knew on a given day.
- The March bulletin's "No" exploitation columns are a dated statement, not a timeless denial.
- A scheduled correction can become an emergency without its vulnerability identifier changing.
- Separate time since vendor release from time since an organization found the affected asset.
Caption: Evidence grade: Reported [1][3].
Notes: The chronology and the "still needed to install the patch" warning are from CERT-EU [3]; the archived bulletin columns from [1]. The escalation criteria are original analysis.

## PART 1 | Sources label EternalBlue with different CVEs

Microsoft's WannaCrypt analysis and CERT-EU tie EternalBlue to CVE-2017-0145; the Petya description names CVE-2017-0144.

- The study keeps the discrepancy rather than silently correcting every record to one label.
- The stable response reference across the records is MS17-010.
- Record the exact relationship a source asserts; do not infer a bulletin covers only one issue.
- A reused phrase in several advisories may trace to one source, not several independent validations.
Caption: Evidence grade: Confirmed [3][4][9].
Notes: The naming split is documented across [3][4][9]. The research-register fields (terminology, revision date, bulletin, claim) are original guidance.

## PART 2 | Early analysis left the entry vector open

Microsoft's WannaCrypt analysis described worm-like spreading but said the initial entry vector was not established.

- Possible entry scenarios appeared as hypotheses, not a finding that phishing began every infection.
- Initial entry and later propagation are separate tasks with different urgency and evidence needs.
- A sample's platform constraints do not prove a whole OS family has no exposure.
- Keep separate records of vulnerability applicability, observed behavior, and confirmed local compromise.
Caption: Evidence grade: Reported [4].
Notes: The explicit entry-vector uncertainty is from early WannaCrypt analysis [4]. Patch decisions should follow vendor affected-product data, not one sample description.

## PART 2 | Emergency updates bought time, not maintenance

Microsoft made updates broadly available for XP, Windows 8 and Server 2003; Canada's 13 May alert urged test and deploy.

- Guidance distinguished custom-support-only platforms from those that got the March release normally.
- An exceptional correction reduces immediate risk; it is not a promise of future maintenance.
- "Uncorrected" has distinct causes: out of support, unmanaged, incompatible, awaiting downtime, or missed.
- A single label of legacy hides the different decisions each cause requires.
Caption: Evidence grade: Confirmed [5][10].
Notes: Exceptional availability and the supported-platform distinction are from [5]; the deployment urging from [10]. The exception-record fields are original analysis.

## PART 2 | Supported Windows 7, not just XP, was hit

The NAO found no formal mechanism before the attack to assess compliance with national guidance.

| Figure | Website summary | Revised PDF |
|---|---|---|
| Affected trusts | at least 81 | at least 80 |
| Infected trusts | 37 | 34 |
| Disrupted, no infection | not stated | 46 |
Most infected NHS devices were unpatched but running supported Windows 7, per NHS Digital.
Caption: Evidence grade: Reported [6][7].
Notes: The study uses the revised PDF figures [7]; the website summary differs [6]. Three trusts were reclassified from infected. Disruption is not the same as infection.

## DEFENDER VIEW | A newer update is not a proven correction

Microsoft's verification article warns its historical tables do not replace supersedence data from update channels.

- "A newer update exists" and "this correction is included" are different claims.
- Failing to find the first March KB does not by itself prove a machine is still vulnerable.
- Start from platform and servicing branch, then use current vendor evidence of inclusion.
- A "not applicable" message is not an assurance result; investigate why the package did not apply.
Caption: Evidence grade: Confirmed [2].
Notes: The supersedence caveat, the rollup-versus-security-only distinction, and the applicability message are from [2]. The verification model is original defensive guidance.

## DEFENDER VIEW | Reachability is a control of its own

CERT-EU recommended restricting SMB reachability and disabling SMBv1 alongside applying the update.

- Observing no ransom screen did not establish safety; do not rely on one variant's properties.
- State a restriction's scope precisely; a boundary rule differs from a per-host or segmentation rule.
- Validate with authorized configuration review and controlled checks, not live malicious traffic.
- Retiring SMBv1 can expose unrecorded dependencies; plan discovery, change, validation, retirement.
Caption: Evidence grade: Reported [3].
Notes: The reachability and anti-SMBv1 advice and the variant warning are from CERT-EU [3]. The scope, validation, and migration-plan stages are original analysis.

## DEFENDER VIEW | Patching one method leaves others open

Microsoft's February 2018 Petya retrospective saw more propagation through impersonation than through MS17-010.

- One organization had 97 percent endpoint patch coverage yet saw enterprise-wide infection.
- These are scoped observations, not a universal method split or a claim patching failed.
- Keep protecting credentials, limiting authority, and preparing recovery after a fix is verified.
- Report "this component is corrected," not "protected from malware," when that is the real evidence.
Caption: Evidence grade: Reported [8].
Notes: The impersonation-over-SMB observation and the 97 percent case are scoped to that report [8]. If a corrected system is hit, ask which boundary failed.

## MITRE MAPPINGS | The study maps no ATT&CK techniques

The case study does not provide a formal MITRE ATT&CK technique mapping, and none is inferred here.

- It is an assurance and evidence study, not a reverse engineering of EternalBlue.
- It states that no exploit payload, attack sequence, scanning command or live-target test is provided.
- Assigning technique IDs would add claims the primary sources do not support.
- The stable technical anchor remains the bulletin reference MS17-010 and its named CVEs.
Caption: Evidence grade: Not mapped.
Notes: The boundary is preserved deliberately; the study scopes itself away from exploitation mechanics and offers no ATT&CK mapping to carry forward.

## CROSS-CUTTING THEMES | Overstated names, understated assurance

The record tends to overstate what a famous name settles and understate what proof of state requires.

Left: Overstated
- A nickname fixes the asset.
- XP alone caused the NHS disruption.
- A patch job means protection.
Right: Understated
- Which CVE and package apply.
- Supported Windows 7 exposure.
- A verified, active, corrected state.
Caption: Evidence grade: Inferred [2][6][7][8].
Notes: The theme synthesizes the naming split [4][9], the NHS figures [6][7], the supersedence caveat [2], and the Petya scope [8]. The analysis is the study's own.

## CLOSE | Prove what was fixed, name what remains

A vendor release creates the possibility of correction; organizational work must establish it took effect.

- Identify the affected population, choose the supported remedy, and verify the active state.
- Keep the unresolved population visible; do not improve a percentage by shrinking the denominator.
- Reachability, authority, recovery, and incident investigation outlast any single update.
- Say exactly which condition was removed, where confidence comes from, and what stays unknown.
Caption: Evidence grade: Inferred [2][6][8].
Notes: The conclusion draws the assurance thesis together [2][6][8]; the metrics and closure guidance are original analysis. Notification or deployment is not evidence of an active state.
