# Slide plan: ShadowHammer 2019: Broad Reach, Narrow Selection

- Study: case-studies/ASUS_SHADOWHAMMER_2019.md
- Cover title: ASUS ShadowHammer / 2018-2019 / Broad reach, narrow aim
- Subtitle: A signed, supplier-distributed update reached many systems while selecting a few; receipt, execution and follow-on stay separate.
- Published: 18 November 2026
- Notes: The cover sets the frame: a release-trust failure where distribution breadth and targeting breadth are measured apart.

## EXECUTIVE SUMMARY | A widely distributed update was a selective entry mechanism

- A widely distributed, apparently legitimate update served as a selective entry mechanism for a much smaller set of systems.
- Distribution breadth and targeting breadth describe different parts of one operation, not a contradiction.
- Three questions stay separate: did a system receive the modified software, did it execute, and did it go further.
- The record supports maliciously modified, legitimately signed installers, not a confirmed second-stage victim roster.
Caption: Evidence grade: Confirmed signed malicious installers; victims unresolved.
Notes: Executive framing from the study's summary; telemetry limits and selector findings from [1], unresolved victims from [2].

## KEY FACTS | Broad telemetry, narrow selectors, unresolved worldwide count

Stat: 57,000+ | Affected users in Kaspersky telemetry
Stat: 600+ | Distinct MAC addresses as selectors
Stat: 200+ | Samples the selectors came from
Stat: Mar 2019 | Kaspersky public disclosure
- Kaspersky placed the observed campaign between June and November 2018 and said a worldwide count could not be calculated.
- Modified installers came from official ASUS update infrastructure and were signed with legitimate ASUS certificates.
- Those figures are targeting selectors, not a verified count of successful second-stage infections.
Caption: Evidence grade: Reported telemetry; selectors, not confirmed infections.
Notes: Counts, dates and telemetry caveat from the March 25, 2019 disclosure [1]; selector logic detailed later in [2].

## SCOPE AND EVIDENCE | State what the record establishes and what it does not

The study fixes its boundaries before analysis, with labeled evidence categories.

| Field | Scope |
|---|---|
| Incident | ASUS Live Update supply-chain compromise, ShadowHammer |
| Primary question | Handling signed, supplier-distributed software with selective behavior |
| Distinct from | Firmware infection, every ASUS product, or complete victim attribution |
| Testing | No malware obtained or executed; no third-party endpoint scanned |
Caption: Evidence grade: Scope statement; evidence labels defined.
Notes: Scope and testing boundaries from section 1; researcher observation, interpretation, advisory and vendor guidance kept distinct per section 1.1 [1][2].

## PART 1 | The word infected needs qualification

- "Infected" can mean a file was downloaded, a first-stage component ran, a later payload arrived, or access persisted.
- The study uses exposure, malicious-artifact receipt, execution, selector match and follow-on activity as separate categories.
- A signature check, a version check, or a target-list lookup cannot independently answer all three questions.
- These are analytical categories, not a claim that every affected organization preserved enough evidence to fill them.
Caption: Evidence grade: Confirmed definitions; no in-the-wild victim claim.
Notes: Terminology discipline from section 1.2; the three questions restate the study's central distinction [2].

## PART 1 | Signed bytes were still malicious bytes

- Published research reported valid signatures on modified installers, not a forged filename or an imitation website.
- A consumer could see the expected supplier, the expected update channel, and a matching signature together.
- Signature validation establishes identity assurance; it does not establish release authorization.
- An approved process intending those bytes, a reviewed source, and harmless code each need separate evidence.
Caption: Evidence grade: Confirmed valid signatures on modified installers.
Notes: Valid-signature finding and the identity-versus-authorization split from sections 2.2 [1][2].

## PART 1 | Selectors narrowed behavior, not responsibility for investigation

- Samples compared hashes of local network-adapter MAC addresses against embedded tables; some conditions used paired entries.
- More than 600 distinct MAC addresses came from over 200 samples, and the embedded tables differed across samples.
- A selector is a condition used by code, not a one-to-one map to a unique computer, person or organization.
- Researchers stated that the ultimate victims and the origin of the target identifiers remained unknown.
Caption: Evidence grade: Reported selector logic; victims and origin unknown.
Notes: Selector mechanics and the stated unknowns from the April 23, 2019 technical report, sections 2.3 and 7 [2].

## PART 2 | A five-link release trust model

The study proposes an original model; each link is a place release trust can break.

| Link | What it governs |
|---|---|
| Source approval | The decision that a change belongs in the product |
| Build identity | Inputs transformed into an artifact |
| Signing authorization | Permission to apply a trusted signing identity |
| Publication integrity | Approved signed artifact versus distributed bytes |
| Endpoint execution | What happens after delivery |
Caption: Evidence grade: Original defensive analysis, not disclosed ASUS failures.
Notes: Model from section 3; stated as proposed reasoning, not a finding that ASUS lacked every control described.

## PART 2 | Measure scale and selectivity separately

- A supplier channel reaches many endpoints without the adversary contacting each target individually.
- A local selection condition then limits follow-on activity, so scale and selectivity must be measured separately.
- A test system can execute a modified package without the behavior a selected system shows; quiet is a bounded observation.
- Even a nonselected endpoint can hold evidence about delivery, execution, or the campaign's distribution.
Caption: Evidence grade: Original analysis of the distribution-selection split.
Notes: Distribution breadth versus targeting breadth and the false-reassurance caveat from sections 4.1 and 4.2.

## DEFENDER VIEW | An evidence ledger that separates the stages

Each stage proves only its own step; counts need a stated denominator.

| Stage | Useful evidence | Does not prove alone |
|---|---|---|
| Product present | Software inventory | Receipt of a malicious release |
| Artifact received | Cache, download record, digest | Execution |
| Artifact executed | Process and installation records | Selector match or follow-on |
| Selector met | Sample logic, historical configuration | Successful payload retrieval |
| Follow-on request | Network and process correlation | Full extent of access |
Caption: Evidence grade: Original evidence ledger; counts need denominators.
Notes: Ledger from section 5; overlapping counts should not be added as if they were separate devices.

## RESPONSE | Repair the supplier path and the endpoint separately

- Contain the suspect release path by product, package and interval; avoid blocking all updates indefinitely.
- If code executed, assess reachable authority: local data, credentials, sessions, network resources, software-management privileges.
- A clean rebuild does not revoke already-copied credentials; change credentials from a trusted environment.
- Treat CERT-EU, Huntress and the 3.6.8 tool as dated resources; the ASUS FAQ now ends LiveUpdate support on December 4, 2025.
Caption: Evidence grade: Original response analysis plus dated vendor and advisory guidance.
Notes: Response reasoning from section 6; contemporary advisory and the 3.6.8 fix from [3][5], lifecycle change and 3.6.15 final version from section 2.5 [6].

## SIGNING LESSONS | Do not infer key theft from the signature alone

- A valid signature on malicious content is strong evidence of a release-trust failure, not a full account of its cause.
- Possible paths include misuse of signing services, a compromised release workflow, or exposed signing material.
- Researchers did not definitively explain how the signing capability was compromised; keep the hypotheses separate.
- Measure signing decisions, not only key storage: bind each signing request to an approved artifact and accountable process.
Caption: Evidence grade: Confirmed uncertainty; mechanism unresolved in the record.
Notes: Unresolved signing mechanism from [2]; the authorization-versus-custody point from sections 7.1 and 7.2.

## CROSS-CUTTING THEMES | Where the retelling overstates and understates

Left: Easy to overstate
- Every recipient as a confirmed second-stage victim of the worst payload.
- A single MAC selector read as a named person or organization.
- A newer installer taken as proof that earlier execution was reversed.
Right: Easy to understate
- The first-stage release-trust failure, which holds even on nonselected endpoints.
- Broad distribution breadth kept distinct from narrow targeting breadth.
- An unknown signing mechanism and an unknown target origin that stay unresolved.
Caption: Evidence grade: Editorial corrections the case requires.
Notes: Contrasts drawn from sections 4, 7 and 10; each claim bounded to the study's stated evidence.

## CLOSE | A defensible release relationship beats a recognizable publisher

- A release needs more than a recognizable publisher identity to be trusted.
- It needs a defensible relationship among approved source, produced artifact, signing decision, published bytes and observed behavior.
- The answer to a compromised update channel is not permanent distrust of all maintenance.
- Repair distribution and endpoints separately, and state what remediation complete actually means.
Caption: Evidence grade: Case conclusions, bounded to the record.
Notes: Conclusion synthesis from section 10; rests on the disclosure and technical report [1][2].
