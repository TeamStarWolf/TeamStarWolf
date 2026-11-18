# Slide plan: Colonial Pipeline and DarkSide in 2021: An IT Incident with Operational Consequences

- Study: case-studies/COLONIAL_DARKSIDE_2021.md
- Cover title: Colonial Pipeline and DarkSide / An IT Incident with / Operational Consequences
- Subtitle: A fuel-delivery outage, a legacy VPN profile, and the line between IT ransomware and the pipeline
- Published: 15 November 2026
- Notes: Slide plan for the deck of case-studies/COLONIAL_DARKSIDE_2021.md. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | An IT ransomware shutdown, not attacker control of the pipeline

- On 7 May 2021 Colonial Pipeline shut its own system down in response to ransomware; the FBI attributed the compromise to DarkSide on 10 May.
- DOE records a whole-system restart and deliveries to all markets on 13 May. That establishes a fuel-delivery interruption, not an attacker's control of pipeline equipment.
- The case is three different problems: unauthorized access, lost trust in enterprise systems, and an operational decision under uncertainty.
- Treating all three as "the pipeline was hacked" hides what defenders can actually change, since each needs a different owner and a different test.
Caption: Evidence grade: Confirmed for the shutdown, attribution and restart; Inferred for the IT-versus-OT distinction.
Notes: Shutdown and restart [1][2]. FBI attribution of DarkSide [2]. The three-problem framing and the IT-versus-OT distinction are the study's analysis.

## KEY FACTS | The dates and figures the record actually supports

Stat: 29 Apr | Earliest identified VPN login, a legacy profile
Stat: 7 May | Ransom note found; Colonial shuts the pipeline down
Stat: 75 BTC | Ransom reported paid; about 63.7 later seized
Stat: 13 May | DOE records a systemwide restart to all markets
- Earliest entry was an employee credential login through a legacy VPN profile, per Mandiant testimony; the profile was later removed.
- The narrow attribution is to DarkSide ransomware, not a named operator or a proven state sponsor.
Notes: Entry date and legacy profile [3]. Shutdown [5]. Ransom paid and seizure amount [4]. Restart [1]. Attribution boundary [2].

## PART 1 | A legacy VPN profile without MFA was the earliest entry

- Mandiant's Charles Carmakal testified the earliest identified compromise was an employee-credential login on 29 April through a legacy VPN profile without MFA.
- He described a complex password found among credentials stolen elsewhere, but said the exact originating website was unknown.
- The record supports credential abuse of the observed entry. It does not justify naming a VPN exploit, a vendor, a phishing message or a former employee's account.
- An appliance can be patched and still expose an unwanted authentication route, so an access review needs reachability evidence, not only a scan result.
Caption: "Legacy profile" is not "a former employee's account"; those are different claims the sources do not merge.
Notes: Carmakal testimony on the VPN profile, missing one-time passcode and unknown password origin [3]. The distinctions and the access-review point are the study's analysis.

## PART 1 | The shutdown was a precaution, not proof of a crossed boundary

- Colonial's Joseph Blount testified the decision to stop operations was meant to contain uncertainty about spread into operational technology.
- Do not convert "we could not safely assume the boundary was intact" into "the attacker crossed the boundary." The reverse inference fails too.
- An absence of published proof of controller compromise is not proof that an organization can run indefinitely without trustworthy IT.
- A useful architecture review asks whether enterprise identity or traffic can reach process-control zones, and whether operators can verify process state without their normal tools.
Caption: A protective operator shutdown is not an adversary command; the study maps no ICS manipulation.
Notes: Blount company testimony on containment and staged return [5]. The boundary questions and both failed inferences are the study's analysis.

## PART 2 | A tight incident clock, from first login to the seizure

| Date | Event |
|---|---|
| 29 Apr 2021 | Earliest identified VPN login, legacy profile without MFA (investigator testimony) |
| 7 May 2021 | Ransom note found in IT; employees shut the pipeline down; FBI notified |
| 8 May 2021 | Ransom paid, about 75 bitcoin, per DOJ and company testimony |
| 10 May 2021 | FBI publicly attributes the compromise to DarkSide ransomware |
| 11 May 2021 | CISA and FBI issue advisory AA21-131A |
| 12-13 May 2021 | Return to service begins; DOE records a systemwide restart |
| 7 Jun 2021 | DOJ announces seizure of 63.7 bitcoin tied to the payment |
Caption: The study keeps the clocks separate: notification, payment and restart are different events.
Notes: Dated events from the study's timeline and data/case_studies.yaml [1][3][4][5]. Advisory AA21-131A on 11 May. Restart [1].

## PART 3 | The ransom, the imperfect decryptor and the seizure

- DOJ's 7 June announcement says Colonial reported paying about 75 bitcoin; the seized 63.7 bitcoin was then valued at roughly $2.3 million.
- DOJ traced transfers on the public ledger to an address for which the FBI held the private key, and did not explain how that key was obtained.
- Blount told the Senate the decryption tool was used and helped but was imperfect, and that Mandiant considered the backups good but needing days to work through.
- Those statements support neither "the decryptor did nothing" nor "paying restored the pipeline."
Caption: The study reports the tool's usefulness as a witness claim, not a measured return on the payment.
Notes: Seizure amount, valuation and the unexplained private key [4]. Decryptor and backups, expanded Senate record [8].

## PART 3 | Recovered coin is not recovered business

Left: Three inferences to resist
- A recovered coin count is not a recovered share of the original dollar outlay; price and valuation dates matter.
- Holding a private key is not proof that Bitcoin's cryptography was broken.
- A seizure of proceeds is not a promise of recovery for another victim, or proof that paying restores safely.
Right: What a seizure cannot answer
- How the FBI obtained the private key.
- Which individual affiliate ran this case.
- Whether 75 minus 63.7 reveals a revenue split; that subtraction is not an attribution technique.
Caption: Law enforcement and enterprise recovery can assist each other without being the same workstream.
Notes: The three resisted conclusions [4]. The seizure's open questions and the subtraction caution [4][12].

## PART 3A | The outage spread beyond the compromised company

Stat: $3.03 | National regular-gasoline average per gallon on 17 May (EIA)
Stat: $2.88 | Lower Atlantic average, up 10 cents on the week
Stat: 2 levels | Technical remediation and consequence management ran in parallel
- EIA's 18 May report connected the disruption with station outages and increased buying in the Lower Atlantic.
- These are published regional and national measures, not prices at every station or a total-damages figure; the study assigns no economic-loss total.
- A recently published statistic is not necessarily a recent measurement: EIA separated inventory observation dates from publication dates.
Caption: A widely repeated loss number without a defined boundary can obscure rather than clarify the impact.
Notes: EIA prices, the Lower Atlantic rise and the observation-versus-publication point [10]. No total-loss figure is assigned, per the study.

## PART 3A | The public response ran on a different track from remediation

- DOE describes coordinating industry, state and federal partners, supporting safe restoration and helping move fuel, with transport measures and fuel waivers.
- Those were responses to the consequences of supply interruption, not technical remediation of the VPN profile or removal of malware.
- A shipping waiver cannot establish that an identity system is clean; a clean identity system cannot eliminate fuel transit time.
- Essential-service operators should agree in advance which measurements each partner needs, what can be shared, and who can approve changes to operations or messages.
Caption: Success on one track need not immediately solve the other.
Notes: DOE consequence-management chronology [1]. The two-track distinction and the pre-crisis coordination point are the study's analysis and recommendation.

## MITRE MAPPINGS | A small, defensible map that guides evidence, not a full chain

| Technique | Case support | Boundary |
|---|---|---|
| T1133 External Remote Services | VPN entry described by investigator [3] | No claim of every remote-access technique |
| T1078 Valid Accounts | Employee credentials used [3] | Account subtype and privilege not assigned |
| T1486 Data Encrypted for Impact | IT encryption described by company [5] | Not evidence of encrypted controllers |
| ICS manipulation or destruction | No controller-level evidence reviewed | Not mapped; a shutdown is not an adversary command |
Caption: Filling every stage with a familiar technique makes a complete-looking chart but a weaker case study.
Notes: Mapping is the study's interpretation of MITRE definitions checked 14 November 2026, not a MITRE mapping of this incident [3][5]. Phishing, exploitation and password guessing are not mapped as observed.

## DEFENDER VIEW | Five tests the record actually earns

Left: Prove and detect
- Prove obsolete access is gone: reconcile every reachable profile against a named owner, ending in evidence the path no longer works.
- Detect successful misuse, not just failed passwords, on approved and alternate remote-access routes.
Right: Exercise and sequence
- Exercise loss of business IT while operations decide whether the physical process can safely continue, including that it cannot.
- Restore trust before restoring connectivity, and communicate recovery in service milestones, not a single restart moment.
Caption: These are proposed practices, not a claim that Colonial lacked each control.
Notes: The five practices condense Part 5, owners named in the study (identity and remote-access engineering, detection, continuity, restoration, communications).

## CROSS-CUTTING THEMES | What the record does not prove

- No attacker control of pipeline equipment is established; the evidence supports a fuel-delivery interruption and a precautionary shutdown.
- The ransom payment's exact contribution to restoration is unestablished; usefulness is a witness claim, not a measured result.
- The earliest evidence found is not a guarantee of the first activity that ever occurred, and a committee member's question is not a witness's answer.
- The study fills none of these gaps with a generic ransomware playbook, an assumed CVE, a guessed affiliate or an invented controller attack.
Caption: Historical criticism, operational weakness and legal noncompliance each need different evidence.
Notes: The editorial boundaries are stated across the executive summary, scope section and Part 7 of the study.

## CLOSE | One line to carry out of the room

- A successful shutdown can still cause a serious outage: safety containment and business availability are separate outcomes, and both deserve assessment.
- The useful questions are about access paths, dependencies and decisions under uncertainty, not a single headline about a hacked pipeline.
Caption: Full study and sources: teamstarwolf.github.io, the Colonial Pipeline and DarkSide case study.
Notes: Closing restatement of the study's key findings; no new claims introduced.
