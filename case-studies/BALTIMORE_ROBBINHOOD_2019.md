# Baltimore and RobbinHood, 2019: When a Network Outage Becomes a Transaction Crisis

*A TeamStarWolf case study. Published 15 November 2026.*

[All case studies](/case-studies/README.md) · Related: [Ransomware Defense Reference](/RANSOMWARE_DEFENSE_REFERENCE.md), [Incident Response Reference](/INCIDENT_RESPONSE_REFERENCE.md), [Cyber Resilience BCDR Reference](/CYBER_RESILIENCE_BCDR_REFERENCE.md), [Atlanta and SamSam, 2018](/case-studies/ATLANTA_SAMSAM_2018.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Public-sector security and IT leaders, municipal incident responders, finance and legal owners, and communications leaders

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 23 min (5,227 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You want an evidence-bounded account of the 2019 Baltimore RobbinHood incident, you need to keep a disputed EternalBlue claim out or separate three cost numbers or a plea from an indictment, or you are reviewing transaction continuity and provisional-data integrity

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Executive summary](#executive-summary), [Original framework: transaction continuity has four layers](#original-framework-transaction-continuity-has-four-layers), [Cost reconciliation: three numbers, three meanings](#cost-reconciliation-three-numbers-three-meanings)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Ransomware Defense Reference](/RANSOMWARE_DEFENSE_REFERENCE.md), [Incident Response Reference](/INCIDENT_RESPONSE_REFERENCE.md), [Cyber Resilience BCDR Reference](/CYBER_RESILIENCE_BCDR_REFERENCE.md), [Atlanta and SamSam, 2018](/case-studies/ATLANTA_SAMSAM_2018.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

Key takeaways (reviewed 2026-11-17):

- Baltimore's 2019 ransomware shows how municipal technology connects to transactions outside city hall, not just employees. ([Executive summary](#executive-summary))
- Early recovery estimates, spending authority and later loss statements measure different things. ([Executive summary](#executive-summary))
- Malware research can explain what a sample can do without revealing the exact path used to compromise a particular city. ([Executive summary](#executive-summary))
- The sources reviewed do not justify repeating EternalBlue as Baltimore's established entry mechanism. ([Executive summary](#executive-summary))

<!-- meta:end -->

## Executive summary

Baltimore's 2019 ransomware incident is especially useful for understanding how municipal technology connects to transactions outside city hall. A payment portal, a permit workflow and a property-record service do not merely support employees. They connect residents, lenders, businesses, professional intermediaries and public agencies. When those connections fail, the city must preserve both the continuity of service and the integrity of obligations that will outlast the outage.

The record should not be reduced to a dramatic exploit name or a single unexplained dollar figure. Early recovery estimates, spending authority and later loss statements measure different things. A financial projection that includes delayed revenue cannot honestly be described as money already spent. An appropriation is not automatically an invoice. The fact that a later source reports a different number does not make either number interchangeable with the other.

The technical story also needs boundaries. Malware research can explain what a sample is capable of doing without revealing the exact path used to compromise a particular city. A family-level observation is not a host-level forensic conclusion. Claims about EternalBlue became part of the public discussion, but the sources reviewed here do not justify repeating that exploit as Baltimore's established entry mechanism.

This study presents a bounded historical account and an original recovery framework focused on transaction integrity. Its core proposition is that a safe workaround needs an authority model, an audit trail and an exit plan. A temporary process can reopen economic activity while creating new obligations and reconciliation work. Those consequences must be designed deliberately, not discovered after systems return.

## Scope and method

The main incident is Baltimore's May 2019 RobbinHood attack. Contemporary city communications supply dated service conditions. A Maryland legislative fiscal note records an early cost estimate, a city legislative record documents spending authority, and a later Justice Department announcement adds a verified guilty-plea milestone. Technical research provides limited malware context. These are different evidence types and should retain their labels.

Sources were reviewed on 15 November 2026. No ransomware was obtained or executed, no victim records were inspected, and no attacker-controlled site was visited. This article does not reproduce leaked personal information, payment instructions, malicious commands or exploit procedures. Its exercises are intended for authorized environments using synthetic data and harmless simulations.

The legal update is deliberately bounded to the Justice Department's verified May 2025 plea announcement. Later search results suggested additional proceedings, but an authoritative judgment and complete subsequent docket were not established for this package. This document therefore does not report a current sentence, appeal outcome or final restitution award. It also does not repeat the plea announcement's future sentencing schedule as if that schedule remained current.

The implementation sections are original proposals rather than claims about Baltimore's actual internal controls. They are not a current city security audit, legal advice for property transfers, accounting guidance for a specific jurisdiction or authority to modify production systems. Historical workarounds are described to understand the incident, not offered as instructions people should follow today.

## Evidence account: what the sources establish

### 1. The city described containment and differentiated service conditions

Baltimore's 17 May 2019 update said the incident was discovered on 7 May, that systems had been taken offline for containment, and that manual alternatives were being used. It distinguished operating life-safety functions from unavailable email and online-payment services. The same update described a temporary process intended to allow property transactions to proceed, involving an affidavit and a changed way of issuing lien information while the underlying system was inaccessible. This was a dated city policy response, not evidence that property debts had ceased to exist. [1]

### 2. Partial technical access did not mean all workflows were restored

The city's 10 June 2019 update reported that 65 percent of employees could again use computers and email while data and application recovery continued. It separately described water-billing limitations, online permit-payment restrictions and a manual property-transaction workaround. The city said the property-transaction backlog had been cleared. These statements concern different populations and services; the employee-access percentage is not a percentage of all city functions restored, and one cleared backlog does not establish the absence of all other backlogs. [2]

### 3. The early estimate included potential lost or delayed revenue

A January 2020 Maryland fiscal note summarized a May 2019 estimate of approximately USD18 million: roughly USD10 million for restoring and repairing networks and USD8 million in potential lost or delayed revenue. The wording matters. Delayed collections can affect cash flow without becoming permanent losses, and a projected restoration amount is not necessarily an already-paid total. The note is a legislative background source, not a final forensic accounting of the incident. [3]

### 4. A separate legislative record documents funding authority

Baltimore's legislative record for file 19-0404 identifies an enacted USD10 million supplementary appropriation for ransomware response and recovery. That record establishes the existence and purpose of an appropriation. It does not, by itself, establish the exact total of invoices paid, the ultimate loss or how much of another published estimate overlaps with that amount. Adding the appropriation to the early estimate would risk counting the same recovery activity twice. [4]

### 5. The public legal record advanced beyond the 2019 uncertainty

On 27 May 2025, the Justice Department announced that Sina Gholinejad pleaded guilty to computer fraud and abuse and conspiracy to commit wire fraud in the Robbinhood scheme. Its statement described Baltimore losses exceeding USD19 million and prolonged interruption of revenue-related services. It also discussed information copying in the broader campaign. That campaign description does not provide a complete Baltimore-specific inventory of stolen records. The plea is a verified later milestone; this study makes no claim about a subsequent sentence or appeal. [5]

### 6. The indictment is broader than one municipal incident

The indictment posted by DOJ describes an alleged conspiracy extending from 2019 into 2024 and includes Baltimore among multiple victims. It alleges that data theft sometimes accompanied encryption and places the Baltimore deployment on or about 7 May 2019. Its detailed account dates copying to conspirator-controlled virtual servers from at least around 2022. That wording must not be silently backdated to establish a specific 2019 exfiltration path. A charging document's full narrative should not automatically be treated as every fact admitted in a later plea, particularly for unnamed participants or individual victim details. The article distinguishes that allegation record from the separately announced plea. [6]

## Timeline: separate operational, financial and legal events

| Period | Bounded event | What it does not establish |
|---|---|---|
| May 2019 | Discovery, containment and temporary service arrangements | A complete intrusion chronology |
| June 2019 | Partial employee access and service-specific restoration update | Universal operational recovery |
| 2019 legislative action | Supplementary response-and-recovery appropriation | Final expenditure or loss total |
| January 2020 fiscal note | Retrospective account of an early cost projection | Audited final accounting |
| May 2025 | DOJ announces guilty plea and later loss statement | A present sentence or final appellate outcome |

This timeline prevents two common mistakes. The first is treating discovery as the first moment of unauthorized activity. The second is treating a later legal announcement as proof that every operational detail was already known in 2019. A historical study should show how knowledge changed rather than flattening the record into a single omniscient account.

A separate recovery chronology would need evidence for each service: when a fallback began, when staff could use the normal application, when historical records were accessible, when accumulated transactions were reconciled, and when temporary rules ended. The public sources reviewed do not establish all those dates. Leaving gaps visible is more useful than filling them with a citywide recovery date that the evidence cannot support.

## Technical context without a fictional exploit chain

SentinelLabs' sample analysis describes a Go-based ransomware implementation, hybrid encryption, interference with backup and other services, and an absence of autonomous network spreading in the analyzed sample. Its discussion of likely deployment mechanisms was an inference, not a complete Baltimore forensic reconstruction. A later note on the page rejects the EternalBlue and BlueKeep propagation claims and refers to a city statement. The precise initial infection vector remained unresolved in the analysis. [7]

The NHS Digital advisory, originally published before the Baltimore incident, described RobbinHood as targeted ransomware and discussed possible delivery through remote desktop services or another payload. It also described service termination and encryption behavior. Because that advisory predates the incident and discusses a malware family, it cannot establish how Baltimore was entered. Its historical mitigation text should not be copied wholesale into a present production runbook without review. [8]

These sources support a defensive distinction between access, deployment and impact. Access is the capability to reach an environment without authorization. Deployment is the action that places or starts a payload on a host. Impact is what happens to data and services. A malware sample may reveal impact behavior while providing little evidence about the access step that preceded its execution.

The absence of a self-spreading exploit inside an encryption executable is not, by itself, proof that no exploit was used anywhere else in an intrusion. Conversely, the existence of a famous exploit does not establish its use in an incident. Network evidence, host telemetry and investigative findings are needed to connect those claims. This case study does not invent that connection.

It also does not transpose later RobbinHood techniques into 2019 without evidence. Malware families evolve, and reports can describe different operators, versions and campaigns under similar names. A technical mapping should identify its source date and sample scope. A visually impressive attack-chain diagram is worse than a modest one if it makes uncertain steps appear established.

## Cost reconciliation: three numbers, three meanings

The early projection, the supplementary appropriation and the later DOJ loss statement should appear in separate rows of any presentation. They differ in date, purpose and evidentiary basis. The appropriate editorial response is not to choose whichever produces the largest headline. It is to explain why each number was published and what it can legitimately support.

A useful internal ledger distinguishes projected cost, authorized budget, committed spend, invoiced amount, cash paid, delayed revenue, permanently uncollectible revenue and reimbursement. A municipality can have a cash-flow problem because receipts arrive late even if those receipts are eventually collected. That is a real operational concern, but it is not identical to a permanent loss.

Double counting becomes especially easy when emergency appropriations finance work already included in an estimate. A public article should not add all amounts found in search results. The finance owner should identify overlap and reconcile categories before presenting an aggregate. If the source does not permit a reliable reconciliation, say that the totals are not directly additive.

The same caution applies to modernization. Rebuilding a compromised environment may involve replacing obsolete equipment or changing architecture. Some work restores prior capability; some improves future capability; some serves both purposes. Honest reporting can disclose that distinction without implying the improvements were unnecessary or that all long-term investment was direct incident damage.

A prosecution loss statement may use a legal or investigative methodology that differs from a municipal accounting report. Without the underlying calculation, an author should not claim to have reconciled them. This article attributes the later figure to DOJ and preserves the earlier projection as a historical estimate. It does not assert a new final total of its own.

## Original framework: transaction continuity has four layers

The following model is an original analytic framework, not a claim about Baltimore's response plan. A municipal transaction requires availability, authority, integrity and finality. Each layer can fail separately, so reopening a webpage is not sufficient proof that the transaction is safe to complete.

Availability means the person can reach a usable channel and receive a response. The channel may be digital, telephone-based or physical, but it must work for the intended population. A process available only during limited office hours may technically exist while remaining impractical for residents who cannot leave work or travel easily.

Authority means the staff member or system is permitted to make the relevant decision. During an outage, a helpful employee may be able to collect a request but not waive a charge, change a deadline or issue a legally significant certificate. The process must state the difference. Authority cannot be improvised simply because normal software is unavailable.

Integrity means the information and its history remain trustworthy. A temporary record needs an identifier, a creation time, an accountable source and a controlled method of correction. If a value is provisional, that status should travel with the record. A recipient should not mistake an unavailable balance for a verified zero balance.

Finality means the parties know what has actually been completed and what remains conditional. A submitted request, an accepted payment and a final permit are different states. The city needs a way to communicate the state and later reconcile it without silently changing the person's obligations. This model turns a vague promise of continuity into testable requirements.

## Property-related workflows expose cross-organizational dependence

Property transactions can depend on public records while being managed by many separate organizations. A municipality may supply one piece of information, while buyers, sellers, lenders, title professionals and recording offices each have their own responsibilities. An outage in one component can interrupt the entire chain even when most participants' systems remain available.

A continuity plan should map the information being requested and the consequence of supplying an incomplete or provisional answer. The city must know who is entitled to rely on the answer and who can approve any temporary alternative. The technical team can explain that a database is inaccessible, but cannot independently redefine property obligations or transfer legal risk.

A workaround therefore needs explicit policy ownership. The responsible authorities should document its scope, effective period, required disclosures, review process and exit conditions. Participants should be told which information was verified, which was unavailable and what later reconciliation may occur. Historical city procedures in the source record illustrate the importance of such questions, not a template that another jurisdiction can automatically adopt.

Testing should use a fictional transaction with several edge cases. What happens if the parties disagree about an outstanding amount? What if an earlier temporary certificate is corrected? What if the normal system returns before the transaction finishes? The objective is to identify handoff failures before they affect an actual person's property or financial interests.

## Revenue systems are a chain, not a single portal

A payment process usually contains more than the collection interface. It can involve account identification, balance calculation, payment authorization, settlement, posting, receipt generation and reconciliation. A portal may accept a transaction while a downstream posting function remains unavailable. An alternative collection channel can keep money moving but leave uncertainty about which obligation was satisfied.

Define the state of each step rather than publishing a binary available or unavailable label. If the account balance cannot be verified, say so. If payments can be accepted but posting is delayed, provide a controlled receipt and explain the limitation. If the safe alternative is to defer collection, that decision must come from the responsible authority and be communicated consistently.

Temporary processes should prevent duplicate obligations and duplicate collections. A resident may try several channels after receiving no confirmation. The city needs a reference that allows staff to recognize the same underlying transaction without exposing unnecessary personal information. Matching only on a person's name is insufficient when accounts, addresses or obligations may differ.

Financial reconciliation needs both technical and business owners. The payment platform can report a completed transfer while the relevant department cannot find the corresponding account entry. Neither team should close the case alone. A shared exception queue should identify the evidence, the owner of the next decision and the deadline for follow-up.

## Provisional data should never masquerade as verified data

One of the most important design choices is how a system represents missing information. A blank field, a zero value and a confirmed absence are not the same thing. During a recovery, default values can create false certainty if the application does not clearly distinguish unavailable data from validated data.

Use explicit status fields for provisional records. A status should explain why the record is provisional, who can resolve it and what actions are permitted meanwhile. Do not rely solely on a free-text note that disappears when a record is exported. The uncertainty needs to survive the handoff to another department or external party.

Every correction should retain a history suitable for the business purpose. A silently overwritten amount can make later reconciliation impossible. Record the earlier value, the corrected value, the reason and the authority for the change within approved retention and privacy rules. Auditability does not mean keeping unnecessary sensitive information forever; it means preserving the evidence required for accountable decisions.

When restoring data from multiple sources, avoid assuming that the newest timestamp is authoritative. Clocks can differ, delayed entry can be legitimate, and manual records may reflect work completed before the restored system's latest snapshot. Reconciliation should use transaction context and approved rules, not a universal last-write-wins shortcut.

## Identity restoration is only one progress indicator

Employee reauthentication can be an important recovery milestone, but it measures access rather than complete service capability. A person may regain email while the application needed for their primary work remains unavailable. A login may succeed even though a necessary shared record is incomplete or an external integration is disabled.

Report access restoration separately from application availability, validated data coverage, business throughput and unresolved exceptions. This gives leaders a clearer view of why an apparently large technical improvement may not immediately eliminate public delays. It also protects technical staff from being blamed for business dependencies outside the narrow metric they reported.

Identity recovery should examine administrative and service authority as well as ordinary user access. Recovery tools, deployment platforms and vendor connections can have broad influence. A clean workstation is not a sufficient trust boundary if it reconnects to an administrative path that has not been assessed. Prioritize authority by potential impact rather than account count alone.

Temporary access needs a controlled lifecycle. Record the reason, approver, scope and expiry conditions, and verify removal when the emergency need ends. Otherwise, recovery can leave behind a collection of exceptional privileges that are difficult to explain months later. The evidence of cleanup is part of closure, not merely an administrative preference.

## Protect evidence while rebuilding capability

Restoration and investigation create understandable tension. Rebuilding a system may reduce disruption but also remove information that would help explain the intrusion. The answer is not to postpone every recovery action indefinitely. It is to establish a documented preservation decision that reflects urgency, evidentiary value, technical feasibility and the relevant authority.

Keep records of what was preserved, what was not and why. A partial evidence collection can still be valuable if its scope is clear. An unexplained claim that all evidence was retained is less useful than a precise account of selected systems and known gaps. The investigation should be able to distinguish absence of an artifact from absence of collection.

Use trusted recovery sources and a controlled environment for validation. Verify configuration, identity dependencies, logging and representative business functions before reconnecting a rebuilt service. The acceptance package should explain the basis for trust and the residual limitations. A successful installation or clean antivirus result alone does not prove that every relevant risk has been addressed.

Preserve a separation between internal investigation details and public guidance. Residents need accurate service instructions, not sensitive technical evidence or speculative blame. The organization can communicate uncertainty honestly without publishing information that would impair an investigation or expose personal records. The disclosure decision belongs with authorized legal and communications owners.

## Security monitoring should follow operational consequences

The following detection ideas are original hypotheses for authorized testing, not a list of confirmed Baltimore indicators. Tests should use disposable resources, synthetic records and benign actions. No live ransomware or destructive commands are needed to evaluate whether people can recognize and respond to a meaningful event.

One hypothesis concerns administrative reach. An approved test identity performs a limited, logged action across an unusual set of test systems. The objective is to determine whether the event is noticed and whether the alert identifies the account's business owner and the affected services. A raw technical alert without context can be difficult to prioritize during a noisy incident.

A second hypothesis concerns attempts to change recovery protection. In a test environment, simulate an authorized configuration event affecting backup retention or recovery access. Determine whether independent monitoring captures it and whether the team can identify the approval. The test should not weaken production backups or exercise destructive malware behavior.

A third hypothesis concerns data movement before an availability event. Use a synthetic export in an approved environment to test whether monitoring can connect unusual volume with identity, destination and data classification. This does not assume that every ransomware incident includes the same form of theft. It tests whether the organization can investigate confidentiality separately from availability.

A fourth hypothesis concerns the quality of escalation. Deliver a simulated alert outside a routine meeting and observe whether it reaches someone with authority to act. Measure access to the service map, ability to contact the business owner and clarity of the next decision. A technically correct detection is incomplete if it cannot produce a timely and proportionate response.

## Public communication needs a state model

A useful public update describes the service, the current limitation, the safe alternative and the next expected update. It should avoid implying that a workaround offers exactly the same functionality as the normal process. If a temporary route accepts requests but cannot finalize them, the distinction belongs in the opening explanation.

Separate verified progress from a target. A forecast for restoring most users is not a statement that the target has already been reached. Keep the date and denominator visible, and explain what the measure excludes. This prevents later readers from treating a planning estimate as a confirmed historical milestone.

Historical instructions should be clearly marked when reused in a case study. Phone numbers, office hours, fee arrangements and temporary forms from an incident are not current service guidance. This article therefore analyzes the historical process without reproducing it as an actionable checklist for residents today.

Public updates also need accessible alternatives. Online-only announcements may fail people who depended on an affected service or lack reliable connectivity. Coordinate information across telephone support, in-person staff and official digital channels. A consistent message reduces repeated contacts and helps staff avoid improvising answers that conflict with policy.

## Procurement and vendor handoffs

Emergency work should have a clear deliverable even when its full scope cannot be known at the start. A statement of work can define an initial assessment, a decision point and conditions for expanding the engagement. This is more accountable than an open-ended instruction to fix everything without a record of who approves the next phase.

Require documentation that the municipality can actually use after the vendor leaves. Relevant outputs may include configuration changes, evidence inventories, remaining risks, restoration procedures and training for internal owners. A vendor's private notes are not a sustainable operational dependency. Access and ownership expectations should be settled through the authorized contractual process.

Vendor remote access should be proportionate, monitored and temporary where possible. The urgency of recovery does not justify giving every participant permanent broad administration. Identify the systems needed for each task and verify that access ends when the engagement or phase ends. Record exceptions with a clear reason and accountable owner.

Tie payment acceptance to defined outcomes rather than the passage of time alone. Some tasks may appropriately be billed for expert effort, while others produce verifiable milestones. Finance and technical owners should understand the distinction. The goal is not to pretend all incident work is predictable, but to make uncertainty visible and governable.

## Ninety-day transaction-resilience programme

### First month: identify consequential dependencies

Select a small group of services that represent different transaction types, such as revenue collection, application processing and interorganizational record exchange. Map the critical data, identity systems, external parties and authority decisions for each. Record which dependencies have actually been tested and which remain assumptions.

Build a short service-state template that separates access, information quality, processing capacity and reconciliation. Identify the owner of each measure. Establish how the template can be used when the main collaboration platform is unavailable. A resilience plan that cannot be opened during the incident is itself a hidden single point of failure.

### Second month: test safe alternatives

Exercise one approved temporary workflow for each selected service with synthetic records. Include an ambiguous balance, a duplicate submission, a changed deadline and an external participant who cannot use the normal channel. Record what staff can decide, what requires escalation and what must wait for authoritative information.

Test restoration in an isolated environment and verify representative end-to-end work. Include the transition from temporary records back to the restored system. A successful rebuild without this transition leaves the most consequential integrity question unanswered: whether the organization can resume normal service without losing, duplicating or misrepresenting obligations.

### Third month: prove closure and improve governance

Run a cross-functional tabletop involving technology, departmental owners, finance, legal advisers, communications and appropriate external partners. Ask each group to supply the evidence another group needs. The exercise should reveal missing authority, inaccessible documentation and incompatible definitions of restored.

Create a limited improvement backlog with owners, resources and retest dates. Prioritize changes that remove a high-impact uncertainty or fragile handoff. Report the scope honestly: testing a few services provides evidence about those services, not a guarantee for every city function. Expand coverage deliberately rather than declaring universal readiness.

## Metrics that make the hidden work visible

| Metric | Definition that helps | Misleading shortcut |
|---|---|---|
| Service availability | Specific function usable through an approved channel | Website responds |
| Data confidence | Records validated for the intended transaction | Database mounted |
| Financial exposure | Dated categories with overlap reconciled | Every published amount added together |
| Workaround integrity | Provisional status and authority preserved | Paper form exists |
| Reconciliation | Exceptions resolved or explicitly owned | Backlog entry count falls |
| Recovery closure | Temporary access and rules retired with evidence | Incident bridge ends |

Metrics should describe their denominator and confidence. If only a subset of records has been checked, say which subset. If an estimate includes uncertain future collections, show that uncertainty. A dashboard should make uncomfortable questions easier to ask, not turn incomplete knowledge into a decorative green status.

Measure staff capacity as well as technology. A workaround that requires repeated overtime or one irreplaceable specialist may not remain viable through a long recovery. Record training needs, coverage gaps and the volume of unresolved cases. Sustainable service is an outcome that depends on people and process, not just storage and compute.

## Tabletop: the provisional balance problem

This fictional exercise uses a simulated city and synthetic records. It does not reproduce an actual Baltimore transaction or authorize legal, financial or production-system actions.

Inject one: the revenue portal is unavailable, but a department can accept payments through an approved alternative. Ask the team how it verifies the account, issues a receipt and prevents duplicate posting. Success is a traceable transaction state rather than a promise that someone will sort it out later.

Inject two: an external professional needs a record whose authoritative balance is inaccessible. Ask who can approve an alternative, what uncertainty must be disclosed and what the recipient can rely on. Success is an authorized, bounded process, not a technical employee replacing the missing balance with zero.

Inject three: the restored database contains a record older than a temporary paper receipt. Ask which evidence governs and how a correction will be documented. Success preserves the history and resolves the conflict through approved rules rather than choosing the newest visible timestamp automatically.

Inject four: a public update says most users are back online, but several revenue workflows still cannot finalize transactions. Ask communications staff to explain the difference. Success is a clear statement of available functions, limitations and safe alternatives without discrediting genuine technical progress.

Inject five: a briefing combines a recovery estimate, a supplementary appropriation and a later loss figure into one total. Ask finance and editorial owners to identify overlap and separate the categories. Success is a smaller but defensible explanation rather than an impressive unsupported number.

Inject six: an investigation lead wants to preserve a server while a department needs its function urgently. Ask the incident authority to record the evidence and service tradeoff, obtain appropriate approval and select a bounded recovery route. Success is a justified decision with documented limitations, not the assumption that either investigation or operations always wins.

The exercise ends only when each unresolved issue has an owner and a retest condition. A collection of observations is not an improvement plan. The organization should be able to explain which changes will make the next transaction safer and how it will know those changes worked.

## Editorial conclusions

Baltimore's case should be taught as a disruption to trusted transactions, not merely an example of encrypted machines. The city communications reveal why access restoration, application recovery and temporary public processes must be tracked separately. The financial record illustrates why estimates, spending authority and later loss statements need their own labels. The later plea announcement demonstrates the need to update historical articles without pretending that the entire subsequent legal record has been reviewed.

Do not repeat a disputed exploit as established fact, treat malware capability as proof of host-level behavior, or convert a campaign-level data-theft statement into a precise local breach inventory. Keep source dates, scope and limitations visible in every format. A condensed deck should simplify the prose without erasing the distinctions that make it trustworthy.

The strongest operational lesson is to design for the uncertain interval. A municipality needs a way to continue necessary work while clearly separating verified information from provisional information, authorized decisions from helpful improvisation, and restored access from completed obligations. Recovery is successful when the public can rely on the transaction again.

## Sources and reading notes

[1] City of Baltimore. City Provides Update on Baltimore Ransomware Attack. 17 May 2019. Dated containment and service update; historical workaround, not current legal or service instructions. https://content.govdelivery.com/accounts/MDBALT/bulletins/2459686

[2] City of Baltimore. City Provides Update on Baltimore Ransomware Attack. 10 June 2019. Employee-access percentage and service-specific conditions are different measures. https://content.govdelivery.com/accounts/MDBALT/bulletins/249f7d3

[3] Maryland Department of Legislative Services. HB215 Fiscal and Policy Note, First Reader, 24 January 2020. Page 4 summarizes the early estimate and potential lost or delayed revenue; not final accounting. https://mgaleg.maryland.gov/2020RS/fnotes/bil_0005/hb0215.pdf

[4] Baltimore City Council. File 19-0404, supplementary USD10 million appropriation for ransomware response and recovery. Legislative authority, not proof of cash paid or final losses. https://baltimore.legistar.com/LegislationDetail.aspx?GUID=94CE9547-A8FF-4E3B-BAEB-47E4317B12CF&ID=4068851&Options=&Search=

[5] U.S. Department of Justice. Iranian Man Pleaded Guilty to Role in Robbinhood Ransomware. 27 May 2025. Verified plea milestone and dated loss statement; later sentencing and appeals not established in this package. https://www.justice.gov/opa/pr/iranian-man-pleaded-guilty-role-robbinhood-ransomware

[6] United States v. Sina Gholinejad. Indictment filed 4 April 2024, publicly posted by DOJ in 2025. Allegation record broader than a single victim or the plea announcement. https://www.justice.gov/d9/2025-05/gholinejad_indictment.pdf

[7] Vitali Kremez, SentinelLabs. RobinHood Ransomware CoolMaker Functions Not So Cool. Sample analysis with later update; technical inference must remain distinct from a Baltimore-specific forensic report. https://www.sentinelone.com/labs/robinhood-ransomware-coolmaker-functions-not-so-cool/

[8] NHS Digital. RobbinHood Ransomware, CC-3026. Published 1 May 2019, last edited 14 February 2020. Historical family advisory, not proof of Baltimore initial access or a current production runbook. https://digital.nhs.uk/cyber-alerts/2019/cc-3026
