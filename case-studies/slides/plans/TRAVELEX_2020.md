# Slide plan: Travelex 2019-2020: Layered Recovery After Ransomware

- Study: case-studies/TRAVELEX_2020.md
- Cover title: Travelex 2019-2020 / Layered Recovery / Ransomware and Beyond
- Subtitle: A ransomware crisis, a pandemic and a restructuring overlapped; keep encryption, data theft, cost and causation in separate fields.
- Published: 18 November 2026
- Notes: The cover sets the frame: a layered recovery, not a single-cause ransomware story.

## EXECUTIVE SUMMARY | Not ransomware alone: distinct outcomes

- The incident began at the end of 2019 and became a major operational crisis in early 2020.
- Keep encryption and availability distinct from data theft; the record bounds each separately.
- Keep ransom demanded, ransom paid and total recovery cost as separate, mostly unestablished fields.
- Administration of particular legal entities is not the disappearance of the whole brand.
Caption: Evidence grade: Confirmed statements; causation kept multi-factor.
Notes: Executive-assessment framing; separates company statements, a forecast, administrators and audit, drawing on [1][2][3][4].

## KEY FACTS | One detection date, several later milestones

Stat: Dec 31 | 2019 detection; systems taken offline
Stat: Jan 8 | 2020 Finablr regulatory disclosure
Stat: Mar 2 | 2020 customer-facing systems restored
Stat: Aug 6 | 2020 restructuring completed
- Sodinokibi, also called REvil, was identified after detection on December 31, 2019. [1]
- The six other Finablr brands were reported operating normally in early January. [1]
- Restructuring completed on August 6, 2020; the brand continued under changed ownership. [3]
- The study does not establish a ransom amount, an entry path or a full exfiltration scope.
Caption: Evidence grade: Confirmed, dated company and administrator records.
Notes: Dates and ransomware name from [1]; restructuring date from [3]; open questions stated as such.

## PART 1 | What the January disclosure established and bounded

- Finablr's January 8, 2020 announcement reproduced Travelex's January 7 update. [1]
- It identified the ransomware as Sodinokibi, also called REvil, after December 31 detection. [1]
- It reported no evidence at that time of exfiltration or encryption of structured personal data. [1]
- That dated, scoped statement is not an undated conclusion that no data was ever exposed.
Caption: Evidence grade: Confirmed company statement, bounded to its date.
Notes: Statement content and its qualifications from [1]; the early no-material-impact expectation belongs to its date.

## PART 1 | Keep encryption distinct from data theft

- Encryption drove the availability outage and the manual operating mode; that is one question.
- Data exfiltration is a separate question the January record did not confirm either way. [1]
- "Affected" is not "compromised"; "claimed" is not "confirmed"; keep the pairs apart.
- Naming a ransomware family does not establish actor identity, entry path or exposure scope.
Caption: Evidence grade: Confirmed distinctions; exfiltration unestablished.
Notes: The encryption-versus-exfiltration discipline follows the study's reading of [1]; technical certainty kept bounded.

## PART 2 | March restoration and a bounded cost estimate

- On March 2, 2020, Travelex Financing announced restoration of all customer-facing systems. [2]
- It estimated a roughly GBP 25 million like-for-like Q1 underlying EBITDA reduction versus 2019. [2]
- It expected insurance to offset a material proportion, with timing left undetermined. [2]
- The estimate is a dated earnings measure, not a ransom figure or audited lifetime cost.
Caption: Evidence grade: Reported management estimate, dated and bounded.
Notes: Restoration, the EBITDA estimate, mostly attributed to malware with COVID-19 also in the outlook, and the insurance expectation from [2].

## PART 2 | Restructuring combined several pressures

Stat: 1,802 | UK jobs safeguarded in the sale
Stat: 3,635 | jobs safeguarded elsewhere
Stat: 1,309 | UK employees made redundant
- PwC records a December cyberattack followed by a severe COVID-19 travel decline. [3]
- A sale process ended in June; restructuring completed on August 6, 2020. [3]
- These figures describe the restructuring outcome, not losses from ransomware alone. [3]
- Continuation of the brand is not the same as unchanged ownership or every retail site.
Caption: Evidence grade: Reported, PwC administrators' account.
Notes: Job figures, the June sale-process termination and the August restructuring from [3]; later page updates noted but not relied on.

## PART 2 | Audit evidence recovered on its own schedule

- Travelex Topco's statements cover July 15 to December 31, 2020, not the old full-year group. [4]
- KPMG's report dated November 29, 2021 disclaims an opinion for lack of sufficient evidence. [4]
- Its basis includes restructuring, late appointment and an ineffective general IT control environment. [4]
- A disclaimer is not proof every balance was false, nor a quantified cyber-loss finding.
Caption: Evidence grade: Confirmed audit disclaimer; not a loss total.
Notes: Reporting period, the November 29, 2021 disclaimer and its stated basis from [4]; operational restoration and auditable evidence recover on different schedules.

## PART 2 | Each milestone measures a different thing

Each row pairs a documented development with what it does not establish.

| Date | Documented development | Does not establish |
|---|---|---|
| Dec 31, 2019 | Detection; systems taken offline | Earliest attacker access time |
| Jan 7-8, 2020 | Ransomware named; manual service | Complete exposure or final loss |
| Mar 2, 2020 | Customer systems restored; Q1 estimate | Every internal recovery task done |
| Jun-Aug 2020 | Sale process ends; restructuring | Ransomware as the sole cause |
| Nov 29, 2021 | Audit records evidence limits | Every balance proven incorrect |
| Apr 2022 | Tribunal weighs agreed background | A technical or criminal attribution |
Caption: Evidence grade: Confirmed dates; non-claims kept explicit.
Notes: Timeline and the "does not establish" column condensed from the study, across [1][2][3][4][5].

## PART 2 | A known weakness is not a proven entry path

- The NCSC's October 2019 advisory warned of VPN exploitation, including Pulse Secure products. [6]
- It separated patching from investigating and revoking credentials that might already be stolen. [6]
- The advisory does not name Travelex or establish that any one vulnerability caused this attack.
- A plausible route existing is not evidence the attacker used it; the study keeps the bridge missing.
Caption: Evidence grade: Confirmed advisory; no incident-specific entry path.
Notes: The October 8, 2019 version 2 advisory from [6], used as remote-access control context only, never converted into a forensic conclusion.

## DEFENDER VIEW | Resilience has more than one finish line

- Minimum viable service asks whether customers can do the key function safely at reduced capacity.
- Sustainable operation asks whether staff can meet demand without a growing exception backlog.
- Trustworthy reconciliation asks whether records can be matched to supporting evidence.
- A separate investigation track resolves unauthorized-access and exposure questions.
Caption: Evidence grade: Original defensive analysis.
Notes: Original analysis; each finish line needs explicit acceptance tests, and a loading website is weaker evidence than a reconciled transaction.

## DEFENDER VIEW | Manual trading is a controlled operating mode

- Manual operation preserves a service but transfers work and risk; it does not erase the incident.
- A manual record needs a unique reference, time, operator and context to reconcile later.
- Capacity limits and escalation paths should be explicit; pausing can beat an unmanageable backlog.
- Decide the exit plan before staff accumulate temporary records that must re-enter the system.
Caption: Evidence grade: Original defensive analysis.
Notes: Original analysis; approvals, custody and separation of duties must survive the change of medium to paper or spreadsheets.

## DEFENDER VIEW | The audit trail is a recovery asset

- An audit trail connects a business statement to the evidence that supports it.
- A restored record can be usable for daily work yet lack the history needed for verification.
- Protect original artifacts from overwriting during restoration; label any reconstruction.
- Preserved evidence stays access-controlled; urgency does not remove permission requirements.
Caption: Evidence grade: Original defensive analysis.
Notes: Original analysis; it shows why operational restoration is not the same as evidentiary recovery.

## CROSS-CUTTING THEMES | Overstated versus understated

Left: Overstated in the usual retelling
- Ransomware alone destroyed the company.
- A confirmed ransom payment and a full list of stolen data.
- Restoration of customer systems as full incident recovery.
Right: Understated and worth keeping
- COVID-19 and a prior retail decline were concurrent pressures. [3][5]
- Auditable evidence recovered later than customer service. [4]
- Early "no evidence found" statements were dated and scoped, not permanent. [1]
Caption: Evidence grade: editorial corrections the case requires.
Notes: Overstated and understated contrasts drawn from [1][3][4][5]; keep concurrent causes and distinct recovery schedules visible.

## CLOSE | Layered recovery beats a single-cause story

- Customer service, internal processing, financial evidence and viability need not recover together.
- Keep encryption, data theft, ransom demanded, ransom paid and total cost in separate fields.
- Keep "services restored" distinct from "incident eradicated" and "business recovered".
- Prepare for the work after systems restart: provenance, dated estimates and verifiable records.
Caption: Evidence grade: case-specific conclusions, bounded to the record.
Notes: Conclusion synthesis across [1][2][3][4][5][6]; resilience restores the ability to explain and verify what the business has done.
