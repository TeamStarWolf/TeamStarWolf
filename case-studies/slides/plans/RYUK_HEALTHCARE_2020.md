# Slide plan: Ryuk and Healthcare 2020: A Sector Warning, Not One Attack

- Study: case-studies/RYUK_HEALTHCARE_2020.md
- Cover title: Ryuk and Healthcare 2020 / A sector warning / A continuity problem
- Subtitle: A sector advisory identifies recurring behavior; it does not establish the access method, malware family or outcome at each hospital.
- Published: 18 November 2026
- Notes: The cover sets the frame: a campaign-level warning and a continuity problem, not one attributed hospital attack.

## EXECUTIVE SUMMARY | A sector warning is not a victim investigation

- On 28 October 2020, CISA, FBI and HHS issued a joint warning of an imminent ransomware threat to US healthcare.
- The advisory highlighted Ryuk and TrickBot in a sector already responding to COVID-19.
- This study treats it as a campaign-level case, not a claim that every hospital experienced the same intrusion.
- A warning identifies recurring behavior; it does not establish the access method, malware family, patient outcome or ransom at each organization.
Caption: Evidence grade: Confirmed warning; per-victim chain Inferred.
Notes: Executive framing from the summary; the joint warning is Confirmed [1], and the boundary from advisory to victim investigation is this study's Inferred reading.

## KEY FACTS | One warning date, several records that measure different things

Stat: Oct 28 | 2020 CISA, FBI, HHS joint warning
Stat: US$67M | UHS 2020 pre-tax impact estimate
Stat: ~5 hr | DFIR case: Bazar to domain ransomware
Stat: 10 | Red Canary detection opportunities
- The UHS IT security incident began 27 September 2020; the US$67 million figure is a pre-tax operational impact, not a ransom payment.
- The DFIR Report case reported exploitation of Zerologon, CVE-2020-1472, in one investigation, not a sector-wide cause.
- Ryuk, TrickBot and BazarLoader are named distinctly across sources; the study keeps each source's own terms.
Caption: Evidence grade: Confirmed dates and disclosures; figures bounded to their source.
Notes: Warning date [1]; UHS incident date and impact estimate [6]; the five-hour case and Zerologon [10]; detection count [11]; no number is combined across sources.

## PART 1 | The warning was not the beginning of the campaign

- An HHS HC3 alert dated 2 October 2020 described a BazarLoader, Cobalt Strike and Ryuk sequence reported in recent intrusions.
- It noted roughly three days between phishing and encryption and distinguished the downloader from the later ransomware.
- Publication on a government website is not evidence that any provider received, understood or could deploy the recommendations.
- A missing perfect prediction is not an excuse to leave an unowned warning queue; these are review questions, not findings against a provider.
Caption: Evidence grade: Confirmed as the alert's account [7]; review questions are Analysis.
Notes: Earlier-alert chronology and the downloader-versus-ransomware distinction from [7]; the postmortem questions are this study's analysis.

## PART 1 | A label tracks activity; disruption is not eviction

- Mandiant's March 2020 account describes a January investigation: TrickBot recon, then Cobalt Strike and attempted lateral movement, roughly 46 minutes from infection to attempted movement.
- UNC1878 began as an activity cluster whose objective was not yet understood; a label is a tracking instrument, not a person or an org chart.
- Microsoft announced action against TrickBot infrastructure on 12 October 2020; that changes whether new commands can issue, not whether hosts or identities remain usable.
- Separate three questions: command infrastructure, host access mechanisms, and stolen identities elsewhere.
Caption: Evidence grade: Confirmed responder and vendor accounts [8][9]; the response model is Analysis.
Notes: The 46-minute figure and the actor-label discipline from [8]; the infrastructure-disruption account from [9]; the three-question separation is this study's analysis.

## PART 2 | A ransomware-family name is not a complete incident model

- HHS's November 2020 briefing describes Ryuk attempting to remove backups and stop security services, alongside a BazarLoader to Cobalt Strike to Ryuk pattern.
- NHS Digital separates an October 2020 BazarLoader delivery change from a March 2021 self-propagating variant; CERT-FR likewise describes multiple chains.
- Calling all 2020 Ryuk a self-spreading worm would erase that chronology.
- Investigate foothold, credential exposure, remote execution and recovery impairment separately; removing the encryptor does not evict the earlier access.
Caption: Evidence grade: Confirmed as the briefing and advisory accounts [3][4][5]; the operational inference is Inferred.
Notes: Payload behaviors and the chains from [3]; the dated delivery-versus-worm distinction from [4][5]; a 2021 feature must not be backdated to all 2020 samples.

## PART 3 | Two responder records, deliberately kept separate

Left: DFIR Report, 18 October 2020 [10]
- A Bazar-delivered intrusion reached domain-wide ransomware in about five hours.
- Zerologon, then SMB/WMI and RDP movement, with deployment first to a backup server.
- The report says no GPO was changed or added; it is a case, not a sector average.
Right: Red Canary and Kroll medical center [11]
- A phishing PDF, Bazar activity, discovery and Cobalt Strike-associated movement in mid-October.
- The authors state ransomware was not deployed; a Ryuk follow-on was an assessment, not an outcome.
- An interrupted precursor must not become a claimed Ryuk-encryption victim.
Caption: Evidence grade: Confirmed as responder accounts [10][11]; neither is a named hospital attribution.
Notes: The five-hour chain and backup-server pivot from [10]; the interrupted, non-encrypted case from [11]; the two records are reported separately and never merged.

## PART 3 | Comparison without constructing a fictional composite

A transparent comparison is more informative than a uniform but unsupported story.

| Record | What can be learned | What must not be borrowed |
|---|---|---|
| Mandiant Jan, pub. Mar [8] | A commodity label can hide fast operator activity | Its timing or identities are not a hospital timeline |
| DFIR Report Oct [10] | A privilege-escalation chain can compress response time | Zerologon is not the cause of all healthcare incidents |
| Red Canary / Kroll [11] | Containment may interrupt a precursor chain | Prevented encryption is not a claimed Ryuk victim |
| UHS disclosure [6] | A corporate record documents sustained disruption | Financial reporting does not reconstruct the chain |
Caption: Evidence grade: Confirmed source accounts; the exclusions are Analysis.
Notes: Rows condensed from the study's comparison table; one cannot join a phishing attachment, a vulnerability and a loss estimate into what happened to "the hospital."

## PART 4 | A victim comparison without false attribution

An IT incident with documented consequences is not, by itself, proof of one uniform Ryuk chain.

| Evidence layer | Supported conclusion | Unsupported shortcut |
|---|---|---|
| Sector warning [1] | Authorities warned of an acute threat | Every later outage came from one campaign |
| HHS briefing [3] | Multiple related delivery patterns discussed | Every listed tool ran at every victim |
| UHS disclosure [6] | An IT incident disrupted services and finances | The full financial impact was a ransom payment |
| Later variant reports [4][5] | Ryuk behavior evolved over time | A 2021 feature existed in all 2020 samples |
Caption: Evidence grade: Confirmed as the source accounts; the chronology is Analysis.
Notes: UHS dates the incident to 27 September 2020 and estimates about US$67 million pre-tax impact [6]; that release does not independently establish Ryuk attribution, and no proven ransomware-caused patient death is claimed.

## PART 5 | Read financial, harm and recovery language carefully

- A corporate loss estimate, a restitution amount, an insurance receipt and a ransom payment measure different things; keep period, basis and source.
- Serious disruption and clinical risk are not a finding that a particular injury or death occurred; harm needs case-specific clinical review.
- "No evidence of theft" carries a date and scope; it is not a universal negative, and a generic advisory is not proof a provider's records were stolen.
- "Online," "substantially restored" and "backlog cleared" are not synonyms; record the specific milestone, not one universal recovery date.
Caption: Evidence grade: Inferred from [6]; recovery and theft language bounded to source scope.
Notes: The UHS estimate is a 2020 pre-tax impact disclosed February 2021 [6]; qualified source statements stay qualified, and milestone language follows the study's recovery table.

## MITRE MAPPINGS | Analyst mappings, not proof of execution

These are retrospective mappings of behavior in the cited sources, not a victim-specific reconstruction.

| Behavior | Candidate ATT&CK technique | Evidentiary limit |
|---|---|---|
| Encryption of business files | T1486, Data Encrypted for Impact | Inferred mapping from the Ryuk behavior in [3][4] |
| Removal of recovery mechanisms | T1490, Inhibit System Recovery | Inferred mapping from the HHS description [3] |
| Interference with security services | T1685, Disable or Modify Tools | Analyst mapping from [3]; MITRE definition checked [14] |
Caption: Evidence grade: Inferred analyst mappings; not an incident-specific attribution.
Notes: T1685 was checked against MITRE technique version 1.0, modified 11 September 2026 [14]; any machine-readable export should pin the full ATT&CK release and preserve evidence scope.

## DEFENDER VIEW | Investigate the intrusion, with explicit decision points

- Establish the entry event, not just the first alert; distinguish earliest retained evidence, earliest observed action and inferred compromise, and disclose retention gaps.
- Separate identity compromise from local malware cleanup; a password change does not prove the attacker cannot act through another valid session or token.
- Treat a connection as not yet execution, and a successful backup job as not yet a restorable copy after the management environment is compromised.
- Define scope by a stated unit; keep confirmed, suspected, examined-without-evidence and unassessed assets distinct, and update as evidence changes.
Caption: Evidence grade: an original analytical framework (Recommendation).
Notes: Condensed from the study's investigation model; "no persistence observed" is more precise than "no persistence" when collection is incomplete.

## DEFENDER VIEW | Clinical continuity is a separate workstream

Controls are useful only when there is evidence they work under the conditions being planned for.

| Proposed control | Evidence of implementation | Exercise question |
|---|---|---|
| Separate recovery administration | Independent credential path, reviewed | Can a compromised production admin delete every copy? |
| Tested restoration | Dated record with service-owner acceptance | Can the service run with dependencies unavailable? |
| Independent incident comms | Offline roster and tested channel | Can staff get instructions if email and identity fail? |
| Detection validation | Benign test results and known gaps | Can the sensor observe the behavior, not only infer it? |
Caption: Evidence grade: Recommendations; none establishes regulatory compliance.
Notes: Controls and exercise questions from the study's acceptance-criteria and continuity sections; a clinical owner, not an application owner, accepts that information is safe to use.

## CROSS-CUTTING THEMES | What the record overstates versus understates

Left: Easy to overstate
- A sector warning as a confirmed attack on any one named hospital.
- A company loss estimate as a ransom payment or a sector total.
- An interrupted precursor case as a Ryuk-encryption victim.
Right: Easy to understate
- A documented continuity and financial consequence at UHS.
- That Ryuk's behavior and delivery evolved across dated sources.
- That recovery, containment and closure measure different things.
Caption: Evidence grade: editorial corrections the case requires.
Notes: Overstatements and understatements drawn across [1][3][4][5][6][10][11]; keep "claimed by operators" separate from "confirmed," and affected separate from compromised.

## CLOSE | Investigate as an intrusion, manage as a continuity emergency

- A sector advisory identifies recurring behavior; it does not establish the chain at each organization.
- The ransomware family matters, but so do the preceding access, the authority gained, the recovery environment and the service acceptance decision.
- Treat those as separate workstreams rather than reducing the event to one executable or one ransom figure.
- Open gaps remain: no verified victim census, no single operator identity, no combinable total loss, and no patient-level causal finding.
Caption: Evidence grade: Analysis; outcome and attribution claims bounded.
Notes: Conclusion synthesis from Part 12; rests on [1] through [14], with no attack or detection example executed.
