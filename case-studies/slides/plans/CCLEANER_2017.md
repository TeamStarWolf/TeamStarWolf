# Slide plan: CCleaner 2017: Signed, Distributed and Still Compromised

- Study: case-studies/CCLEANER_2017.md
- Cover title: CCleaner 2017 / Signed and Distributed / Still Compromised
- Subtitle: A signed build from the official source still carried a payload; distribution breadth and second-stage targeting are separate measurements.
- Published: 18 November 2026
- Notes: The cover sets the frame: a signature and an official source are trust claims about bytes, not proof the build process was trustworthy.

## EXECUTIVE SUMMARY | A valid signature could not prove a trustworthy build

- Downloading from the official source and checking the signature cannot establish that the producer's build and release process was trustworthy.
- When malicious content enters before an authorized artifact is signed and distributed, the package can satisfy the checks users were taught to perform.
- A widely installed consumer utility created a large opportunity, while a later stage selected a much smaller population.
- Downloads, affected installations, callbacks, selected targets and confirmed second-stage delivery are different measurements.
Caption: Evidence grade: Confirmed vendor and researcher record; no malware run.
Notes: Trust-boundary framing and the five-measurement distinction from [1] and [2]; no installer, payload or infrastructure was downloaded or contacted.

## KEY FACTS | One signed build, two products, a record that kept changing

Stat: 2.27M | Early affected-user estimate, Avast 19 Sep
Stat: 32-bit | Architecture of the affected 5.33 build
Stat: 40 | Computers served a second stage, 25 Sep
Stat: Mar 11 | 2017 initial remote access to workstation
- Talos reported the payload in the 32-bit CCleaner 5.33 binary; CCleaner Cloud 1.07.3191 was also identified as affected. [1]
- Talos records discovery on 13 September 2017, and acknowledges separate reporting by Morphisec. [1]
- Avast later placed initial access on 11 March 2017 through TeamViewer on a developer workstation, credential origin unknown. [6]
Caption: Evidence grade: Confirmed, dated advisories; counts carry their denominators.
Notes: Artifact facts from [1]; the 2.27 million figure from [2]; the 40-recipient figure from [5]; supplier-side access from [6].

## PART 1 | Five numbers that answer different questions

A supply-chain incident needs a population ledger, not one headline count.

| State | Reported in the record | Different from |
|---|---|---|
| Affected install estimate | 2.27 million [2] | Repeatable downloads |
| Callback observations | 1,646,536 MAC-based [5] | A census of people or devices |
| Second-stage targets | A selection list of firms [4] | Confirmed delivery to them |
| Second-stage recipients | 20, later 40 [3][4][5] | Full execution or data theft |
Caption: Evidence grade: Reported, each figure bounded to its source's denominator.
Notes: Ledger logic from [2] and [5]; target-versus-recipient distinction from [3] and [4]; a MAC-based count is an operational measurement, not unique people.

## PART 1 | The record changed as visibility improved

| Date | Reported milestone | Scope note |
|---|---|---|
| Mar 11, 2017 | Remote access to a developer workstation [6] | Credential origin unknown |
| Aug 15, 2017 | Compromised release distributed [2] | Not the intrusion date |
| Sep 2017 | Signed malicious software detected [1][2] | Milestones differ by source |
| Sep 20-21 | Targeted second stage from partial records [3][4] | Target list is not recipient list |
| Sep 25 | Expanded records, larger recipient count [5] | A 40-hour gap remains |
| Apr 2018 | Supplier-side access findings [6] | Reconstruction, not a new event |
Caption: Evidence grade: Confirmed dates; superseded conclusions kept visible.
Notes: Chronology from [1] through [6]; the early no-second-stage belief in [2] was corrected by [4]; absence in an incomplete dataset is not proof of absence.

## PART 1 | Signed and trusted is not the same as safe

- A valid signature faithfully authenticated an artifact whose creation process had been compromised.
- The vendor account describes build-process modification, not malicious bytes inserted after signing.
- Keep "signed and trusted" distinct from "safe"; keep distribution breadth distinct from targeting breadth.
- "Affected" is not "compromised", and a target-list entry is not a confirmed compromised organization.
Caption: Evidence grade: Confirmed distinctions required by the editorial checks.
Notes: Signature-versus-content point from [1]; build-process modification from [2]; the affected-versus-compromised and target-versus-recipient discipline from [3] and [4].

## TRUST BOUNDARY 1 | Remote access can reach development authority

- A developer workstation can bridge ordinary office activity and extensive production capability: source, signing requests, deployment credentials or build access.
- A remote-access session should be attributable to a verified identity, a managed device and an approved purpose, with authority constrained, not inherited.
- Access reviews should examine effective permissions, not job titles, to reveal indirect paths into release inputs.
- Evidence should survive outside the workstation; a log kept only on a compromised endpoint may be insufficient later.
Caption: Evidence grade: Inferred defensive analysis grounded in the vendor account.
Notes: Initial access via TeamViewer on a developer workstation is the anchoring fact [6]; the authority and evidence-retention framing is original analysis, not a claim about Piriform's 2017 controls.

## TRUST BOUNDARY 2 AND 3 | From reviewed source to signed release bytes

Left: Source becomes an artifact
- Compilers, build scripts, dependencies, configuration and packaging all shape the result.
- An attacker who alters a trusted build input need not change the code reviewers examine.
- A clean source diff does not rule out a compromised build environment.
Right: Signing authorizes release bytes
- Controlled authorization to sign matters more than inability to export the key.
- An auditable signing log ties the requester, approved digest, policy decision and release together.
- Customer-side verification should inform analysis, not end it; a publisher name is not a behavior exemption.
Caption: Evidence grade: Inferred recommendations, original to the study.
Notes: Build-input and signing-authorization analysis is the study's own design proposal, not a description of what Piriform used; consistent with the artifact facts in [1] and [2].

## TRUST BOUNDARY 4 AND 5 | Distribution scales the mistake; the endpoint inherits authority

Left: Distribution
- Official channels, mirrors, enterprise tools and cached installers replicate one upstream change.
- A stale installer in a deployment image can reintroduce the package after endpoint cleanup.
- Containment must address every distribution path, not only the current download page.
Right: Installed software
- Risk depends on where the software runs and what authority it receives.
- Least privilege reduces consequences without guaranteeing prevention.
- Identifying an affected package does not by itself prove every connected credential was stolen.
Caption: Evidence grade: Inferred defensive analysis drawn from the sources.
Notes: Distribution and endpoint reasoning synthesizes the study's trust-boundary sections; Talos advised restoration or reimaging rather than assuming an update removed every later payload [3].

## DEFENDER VIEW | Watch the trusted thing act unexpectedly

- Hypothesis A: a signed maintenance utility communicates outside its expected role; combine publisher identity, process lineage, deployment timing and destination history.
- Hypothesis B: a release artifact cannot be explained by its declared inputs; compare build records, approved source, packaging and digests.
- Hypothesis C: a developer identity acquires unexpected release influence; correlate new privilege with remote sessions and test that it expires.
- Hypothesis D: remediation leaves a historical exposure unresolved; a package update is not an endpoint-confidence or credential review.
Caption: Evidence grade: Demonstrated as original hypotheses for authorized testing only.
Notes: Hypotheses A through D are the study's own proposals for benign, isolated testing; they are not production rules and do not reproduce the original malware.

## DEFENDER VIEW | Scope before declaring completion

Left: Consumer response
- Identify affected artifacts and stop further distribution through internal management systems.
- Preserve installation and execution evidence; a negative search is meaningful only within its coverage.
- Treat hosts with secondary-stage evidence as a broader intrusion, not a maintenance task.
Right: Producer response
- Protect customers from continued distribution and establish a defensible path for the replacement.
- Publishing a clean-looking version from the same unexplained builder may not resolve the risk.
- A server takedown is not proof that every delivered component has been removed.
Caption: Evidence grade: Inferred response guidance, original to the study.
Notes: Consumer and producer sections are original recommendations; the takedown-versus-removal distinction echoes the correction sequence in [2] through [5].

## CROSS-CUTTING THEMES | Where the record is overstated versus understated

Left: Easy to overstate
- Using all-time download totals as the incident population.
- Treating 40 observed recipients as a guaranteed complete census.
- Turning code similarity or server settings into definitive national attribution.
Right: Easy to understate
- A later stage selected a much smaller, specific population than the broad first stage.
- Missing logs reflect a database failure and gap, not confirmed absence of activity.
- The replacement's provenance, not just its version number, is what restores trust.
Caption: Evidence grade: Mixed; each claim bounded to its source's scope.
Notes: Overstatement cautions from the editorial checks and [5]; the database failure and 40-hour gap are from [5] and [7]; attribution stays bounded per [7].

## COMMUNICATION | Precision when the evidence changes

- "No second-stage activity has been observed" is different from "no second-stage activity occurred"; removing the qualifier changes the meaning.
- Maintain a claim ledger with four fields: claim, evidence, limitation and revision trigger.
- A claim about package replacement should not silently expand into a claim about endpoint recovery.
- Uncertainty does not require vague messaging: state affected versions, recommended action, what is unknown and when the next update comes.
Caption: Evidence grade: Inferred communication model built on the public revisions.
Notes: The claim-ledger model is original; the public corrections it trains on are the 19 Sep belief [2] revised on 21 Sep [4] and expanded on 25 Sep [5].

## CLOSE | Software trust is a chain of claims, not one certificate

- The producer must establish how reviewed source and inputs became an approved, signed artifact.
- The consumer must establish what ran, what it did and what remains uncertain after remediation.
- Both need evidence that survives the compromise of the system being evaluated.
- A valid signature remains useful; it becomes dangerous only when asked to prove more than it can.
Caption: Evidence grade: Conclusion synthesis across the study.
Notes: Conclusion synthesis rests on [1] through [7]; the account should explain a release from developer access to endpoint execution and revise when new evidence appears.
