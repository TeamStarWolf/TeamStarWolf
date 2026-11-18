# Slide plan: Norsk Hydro and LockerGoga, 2019: Recovery Reached the Floor

- Study: case-studies/NORSK_HYDRO_LOCKERGOGA_2019.md
- Cover title: Norsk Hydro and LockerGoga / 2019 / Recovery to the factory floor
- Subtitle: A manufacturing-centered reading of the 2019 ransomware incident that keeps encryption, non-payment and evolving cost estimates in separate lanes.
- Published: 18 November 2026
- Notes: Conceptual study; no victim systems, stolen data or malware binaries accessed.

## EXECUTIVE SUMMARY | Ask what a plant can safely deliver

- A line can stay mechanically capable while its information system prevents dependable work.
- An organization can preserve output through manual procedures while carrying a burden normal figures hide.
- The record holds separate parts: intrusion, visible disruption, production recovery, IT recovery and finance.
- Counting rebuilt computers manages the rebuild; it does not decide that the business has recovered.
Caption: Evidence grade: Confirmed reporting; the recovery model is original analysis.
Notes: Executive framing from the study; historical points rest on [1] and [3], while the gates are proposed analysis.

## KEY FACTS | Several clocks, estimates that changed with dates

Stat: Dec 2018 | Attachment per responder account [4]
Stat: Mar 19 | 2019 first public operating picture [1]
Stat: Apr 5 | Output normal, admin still lagging [3]
Stat: NOK 800M | Rounded retrospective total cost [8]
- LockerGoga is the named ransomware family; keep the attribution bounded. [5]
- Hydro reported no safety-related incidents at the March 19 point. [1]
- The company decided not to pay and relied on trusted backups. [4]
Caption: Evidence grade: Confirmed dated records; one rounded retrospective figure.
Notes: Dates from [1] and [3], the initial attachment from [4], and the rounded total from [8].

## PART 1 | Keep affected, compromised, claimed and confirmed apart

- Encryption and availability loss are distinct from any data-theft claim; the record centers on availability.
- Ransom demanded, ransom paid and total recovery cost are separate figures; Hydro did not pay. [4]
- "Systems restored" and "manual operations" are not the same as "incident eradicated."
- A company statement reports what was publicly said; a responder interview is not a full forensic record. [4]
Caption: Evidence grade: Confirmed reporting with explicit source limits.
Notes: Evidence-label discipline from the study's provenance section; attributions to [1] and [4].

## PART 1 | March 19: isolation and uneven operational effects

- Hydro isolated plants and operations and moved to manual operation where possible. [1]
- Energy and Bauxite & Alumina operated normally; Extruded Solutions and Rolled Products saw stops. [1]
- The company reported no safety-related incidents at that point. [1]
- That dated statement must not become a permanent claim of no safety implications. [1]
Caption: Evidence grade: Confirmed, dated company statement [1].
Notes: Operating picture and the no-safety-incident caveat from [1]; March 21 was an intermediate checkpoint [2].

## PART 1 | The responder account adds an earlier intrusion phase

- Microsoft's December 2019 feature describes a malicious attachment in a legitimate conversation in December 2018. [4]
- Antivirus detected the Trojan days later, after a foothold had been established. [4]
- The account reports captured admin credentials and a manual ransomware push from domain controllers. [4]
- These are attributed victim and responder accounts, not independently reproduced forensics. [4]
Caption: Evidence grade: Reported; attributed account, not an independent audit [4].
Notes: Earlier intrusion phase, non-payment and transparent communication from [4]; do not convert into an exact dwell time.

## PART 1 | A chronology with explicit limits

Each checkpoint carries what it does not establish.

| Checkpoint | Record establishes | Does not establish |
|---|---|---|
| Dec 2018 | Initial attachment and foothold described later [4] | A complete, validated intrusion log |
| Mar 19, 2019 | Widespread IT impact and isolation [1] | That every controller was encrypted |
| Apr 5, 2019 | Output normal while administration lags [3] | That billing and all IT are complete |
| 2020 reporting | Revised estimate and total compensation [7] | A simple cash profit or loss figure |
Caption: Evidence grade: Confirmed dates; non-claims kept explicit.
Notes: Checkpoints and the "does not establish" column from [1], [3], [4] and [7].

## PART 1 | Malware capability is not the incident timeline

- Unit 42 examined multiple LockerGoga samples and described changes between variants. [5]
- The analysis found no worm-like self-propagation; SMB movement was actor-driven copying. [5]
- This resists the shorthand that ransomware automatically spreads everywhere by itself. [5]
- Sample-specific behavior should stay sample-specific, not become a Hydro event log. [5]
Caption: Evidence grade: Confirmed malware-family analysis [5].
Notes: Variant analysis and the propagation caveat from [5]; keep it separate from the responder account [4].

## PART 2 | Keep financial estimates beside their dates and sources

Impact, recognized compensation and cash received are different categories.

| Reporting | Impact estimate | Insurance |
|---|---|---|
| 2019 statements | NOK 650-750 million | NOK 216 million recognized [6] |
| 2020 statements | NOK 800 million to 1 billion | NOK 769 million received total [7] |
| Later retrospective | Around NOK 800 million | Not an accounting reconciliation [8] |
Caption: Evidence grade: Confirmed financial reporting [6][7][8].
Notes: 2019 figures from Note 1.3 page 40 [6]; 2020 from Note 1.3 page 46 [7]; the rounded total from [8].

## RECOVERY MODEL | The factory's information dependency chain

- An order passes through sales, engineering, planning, operators, quality, logistics and finance.
- Each stage can depend on IT without the attacker ever touching a controller.
- Missing order, quality or identity records can stop a valid job the equipment could still run.
- The model is proposed analysis; it does not prove which dependency failed at Hydro.
Caption: Evidence grade: Inferred; original analytical model, not a Hydro finding.
Notes: The dependency-chain model is proposed analysis; physical equipment and the business service are distinct objects.

## CONTINUITY | Safe continuity needs a stopping rule

- Manual operation is a contingency with an approved scope, a staffing model and a review interval.
- Qualified operations and safety staff decide whether the process can run, not whoever controls the network.
- Stop conditions may include lost traceability, unavailable supervision or a growing reconciliation backlog.
- The threshold comes from the organization's own procedures; this study prescribes no universal hours.
Caption: Evidence grade: Inferred; proposed continuity practice.
Notes: Stopping-rule and authority points are proposed analysis; no universal safe-duration number is claimed.

## RECOVERY GATES | Trusted recovery: five acceptance gates

Each gate is an explicit, inspectable acceptance decision.

| Gate | What it accepts |
|---|---|
| 1 Command and safety | A decision structure and out-of-band contacts |
| 2 Trusted administration | Identity, privileged access and credentials |
| 3 Recoverable data | A restored business object, not a checksum |
| 4 Operational acceptance | A business-owner scenario on the critical path |
| 5 Reconciliation | A monitored return and resolved downtime records |
Caption: Evidence grade: Inferred; proposed recovery framework.
Notes: The five gates are summarized from the recovery section; the framework is original analysis, not a Hydro audit.

## DEFENDER VIEW | A defender's evidence worksheet

A good answer can be "unknown, owner assigned, next review set."

| Question | Evidence to request | Owner |
|---|---|---|
| Which orders can the site accept? | Approved service scope and a test | Operations and service |
| Who can administer the service? | Privileged-access map and validation | Identity and platform |
| What changed after the backup? | Gap ledger and reconciliation plan | Application and data owners |
| What prevents unsafe reconnection? | Dependency review and approval gate | Security and plant engineering |
Caption: Evidence grade: Inferred; proposed defender artifact.
Notes: Worksheet rows condensed from the study; an unsupported green status is discouraged.

## CROSS-CUTTING THEMES | What this case overstates versus understates

Left: Easy to overstate
- That every industrial controller was compromised.
- That LockerGoga was a self-propagating worm.
- That insurance erased the incident's consequences.
Right: Easy to understate
- Serious industrial consequences from IT disruption alone.
- An earlier intrusion phase before the visible event.
- Several recovery clocks that moved at different speeds.
Caption: Evidence grade: editorial corrections the case requires.
Notes: Overstated and understated contrasts from the pitfalls section; they tie to [1], [4] and [5].

## CLOSE | Prove one service end to end, with evidence

- Follow the work beyond encryption: safe operation, trusted administration and transaction integrity.
- Production, information systems and finance can recover at different speeds.
- Select one essential service and prove its recovery end to end, then keep the evidence.
- A traceable account beats a green status that assumes restored machines equal a restored business.
Caption: Evidence grade: a conclusion synthesis.
Notes: Conclusion synthesis across the study; rests on [1] through [8].
