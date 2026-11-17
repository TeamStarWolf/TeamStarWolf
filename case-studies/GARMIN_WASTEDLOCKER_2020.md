# Garmin's 2020 Outage: Connected-Service Recovery and the WastedLocker Evidence Boundary

*A TeamStarWolf case study. Published 15 November 2026.*

[All case studies](/case-studies/README.md) · Related: [Ransomware Defense Reference](/RANSOMWARE_DEFENSE_REFERENCE.md), [Cyber Resilience BCDR Reference](/CYBER_RESILIENCE_BCDR_REFERENCE.md), [Incident Response Reference](/INCIDENT_RESPONSE_REFERENCE.md), [SaaS Security Reference](/SAAS_SECURITY_REFERENCE.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Connected-product and service-reliability engineers, incident commanders, customer-support leaders and security researchers

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 16 min (3,768 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You want an evidence-bounded account of the 2020 Garmin outage, you need to separate an outage from confirmed data theft or a malware-family label from a company-confirmed attribution, or you are reviewing connected-service recovery, backlog replay and availability, integrity and confidentiality evidence

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Executive summary](#executive-summary), [Connected products: identify the actual failure boundary](#connected-products-identify-the-actual-failure-boundary), [Recovery is a dependency problem, not a server count](#recovery-is-a-dependency-problem-not-a-server-count)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Ransomware Defense Reference](/RANSOMWARE_DEFENSE_REFERENCE.md), [Cyber Resilience BCDR Reference](/CYBER_RESILIENCE_BCDR_REFERENCE.md), [Incident Response Reference](/INCIDENT_RESPONSE_REFERENCE.md), [SaaS Security Reference](/SAAS_SECURITY_REFERENCE.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## Executive summary

A connected product has more than one definition of working. Its local functions may continue while synchronization, account services, customer support and organizational communications are unavailable. An outage can therefore produce widespread uncertainty without establishing that every product has failed or that customer information has been stolen. The defender's job is to identify the actual dependency that failed and explain the consequence in terms the customer can use.

Garmin's July 2020 incident is a useful case for studying those distinctions. The company publicly confirmed encryption of systems and disruption of online services. WastedLocker research published around the same period provides relevant ransomware context, but a general campaign description is not a substitute for a victim-specific forensic report. This study deliberately does not present a reconstructed Garmin intrusion chain that the reviewed primary records cannot establish.

The main recommendation is to design recovery around trustworthy customer outcomes. Restoring a server is an intermediate step. A service is ready when its identities, data, queued work and monitoring can support a defined customer operation without silently duplicating, losing or corrupting work. That requires security and reliability teams to share acceptance criteria before pressure to reopen becomes overwhelming.

The article also treats communication as an operational control. Customers need to know what remains usable, what is delayed and which actions they should avoid. They should not have to interpret a ransomware family name to decide whether to keep a local record or wait for synchronization. Accurate boundaries are more useful than either blanket reassurance or an unsupported worst-case narrative.

## Scope, method and limits

This case covers the July 2020 outage and the relevant historical WastedLocker reporting. Five primary records support its factual foundation: Garmin's July 27 statement filed with the SEC, the company's 2020 annual report, and research from Symantec, Palo Alto Networks Unit 42 and Microsoft. The financial report was checked at its incident-specific risk-factor passage, not treated as a complete forensic disclosure. Vendor reports were read for their stated scope and qualifications.

No Garmin systems, customer records, malware samples or leaked internal materials were accessed.

The title pairs a confirmed company outage with its surrounding threat context. It does not convert the malware label into a company-confirmed attribution. The reviewed Garmin records do not establish the initial entry method, the responsible individuals, a ransom demand, a payment amount, the mechanics of decryption or the complete sequence of internal recovery. Those gaps remain gaps throughout the article and deck.

Historical summaries are intentionally bounded. Most of the remainder is original defensive analysis, proposed test criteria and a fictional exercise. Recommendations do not imply that Garmin lacked the listed controls. Nor does a successful outcome at one company prove that a particular recovery technique will work at another organization with different data, dependencies and constraints.

## The historical record: five bounded accounts

### 1. Garmin's contemporaneous statement

On July 27, Garmin said an attack had encrypted some systems on July 23 and interrupted online services, including website functions, customer support, applications and communications. It reported no indication that customer data had been accessed, lost or stolen. Product functionality was described as unaffected except for online-service access. Restoration was underway, with processing delays expected as accumulated information was handled. Its expectation of no material operational or financial impact was forward-looking at that date. The statement did not identify a ransomware family, actor or payment. [1]

### 2. The later annual-report disclosure

In the incident passage of its 2020 Form 10-K, Garmin said its due diligence and independent forensic analysis had found no indication of customer-data access, loss or theft. It stated that the outage's impact on operations and financial results was not material, while acknowledging possible adverse consequences beyond expectations. That later assessment is different from the July forecast. Neither wording proves that costs were zero or supplies a public, host-by-host forensic record. The relevant passage is on printed page 16. [2]

### 3. Symantec's separate WastedLocker campaign observations

Symantec's June 25 report, updated June 30, described attacks against at least 31 customer organizations and efforts to interrupt ransomware deployment. Its campaign account included deceptive software updates, SocGholish, credential theft and movement through enterprise networks. It discussed attribution of WastedLocker to Evil Corp and explicitly noted limits to its visibility. These observations predate the Garmin disclosure. They are not a declaration that Garmin was one of those customers or that all observed organizations experienced completed encryption. [3]

### 4. Unit 42's general threat assessment

Unit 42 described WastedLocker as targeted, post-intrusion ransomware rather than indiscriminate mass infection. Its overview discussed reconnaissance, legitimate administrative utilities, interference with defenses and recovery mechanisms, and organization-specific payloads. It also relied on other researchers for portions of the campaign account. Its scope was a general threat assessment, not a disclosed Garmin incident investigation. That distinction matters when turning a plausible campaign pattern into a claim about one victim. [4]

### 5. Microsoft's sample-specific description

Microsoft's July 29 entry described WastedLocker as human-operated ransomware, including a campaign using fake browser updates. It noted that variants can behave differently and identified the sample underlying its technical description. Its stated recovery guidance did not guarantee successful recovery after payment. The sample's filename conventions and behaviors should not be universalized across every deployment or imported into Garmin's incident without matching evidence. [5]

## A chronology that does not invent missing events

| Date or period | Public record | What it does not establish |
| --- | --- | --- |
| June 2020 | Vendor campaign observations preceded the outage. [3] | Garmin's initial compromise date or membership in that observed set. |
| July 23, 2020 | Date of encryption specified by Garmin. [1] | The first unauthorized access or full attacker dwell time. |
| July 27, 2020 | Company statement and restoration expectations. [1] | An exact completion time for every service. |
| July 29, 2020 | Microsoft's WastedLocker entry. [5] | A company-confirmed malware attribution. |
| 2020 annual report | Retrospective materiality and investigation statement. [2] | Zero cost, a public ransom figure or complete forensic disclosure. |

The dates describe different things: an observed threat campaign, a disruptive event, public communication and later assessment. Combining them into a continuous story would conceal the evidence gaps. A timeline should remain useful even when it contains unknown intervals. Its purpose is to improve judgment, not make the narrative look complete.

For an internal investigation, retain separate clocks for first suspicious activity, first confirmed unauthorized access, encryption, customer impact, containment and service acceptance. A later discovery can move the first-access date without changing the customer-outage date. That distinction affects evidence retention and scoping while leaving the public chronology intact.

## Attribution and payment: explicit claim controls

A malware-family label, an operator attribution and a payment claim answer different questions. A sample can resemble a known family without identifying the person who ran it. A vendor can associate a family with a group without having investigated every incident carrying that label. A recovery event can occur without a public explanation of how the recovery material was obtained.

This study does not establish whether a payment occurred, what amount might have been demanded or transferred, or whether a particular intermediary was involved. Repetition of an unsourced amount would make the article sound precise while reducing its reliability. Likewise, the existence of a suspected actor does not establish the legality of an unknown transaction. Any live payment decision requires current legal and sanctions advice specific to the parties and facts; this historical study provides none.

A useful research register records the narrowest supported claim, the source's role and what would change the conclusion. For example, a company statement can establish what the company publicly disclosed. A laboratory analysis can establish observed behavior in an identified sample. Neither alone proves a complete chain from entry to payment in a separate organization.

The editorial rule is straightforward: preserve uncertainty where it changes the reader's decision. An unqualified family name can cause a defender to search only for one indicator set. An unqualified assurance can cause a data owner to stop investigating too early. An unqualified loss estimate can distort investment priorities. Accurate qualifications are therefore part of the technical value, not an obstacle to readable writing.

## Connected products: identify the actual failure boundary

The following model is original analysis, not a representation of Garmin's internal architecture. Divide a connected service into local product functions, account and identity services, ingestion, processing, user-visible presentation, support and administrative control. Each component can fail independently, and several can share dependencies that are not obvious from the product interface.

A customer may successfully create a local record while being unable to upload it. An upload may succeed while the presentation layer is delayed. A support agent may be unable to look up the record even though the data exists. These are different failure modes with different instructions. Telling everyone to retry can worsen a processing backlog or produce duplicate submissions.

Build the service inventory around a concrete operation, such as storing a customer-created record and displaying it in the account history. Identify where the record exists at each step, which identity authorizes the transition, what acknowledgment means and what happens if that acknowledgment is lost. This exposes ambiguity that a list of servers does not capture.

Define degraded modes explicitly. Can the product retain work locally? For how long? What happens when storage fills? Is a stale display clearly marked? Which operation should a customer avoid because retrying is not safe? Product teams should answer these questions in normal testing rather than asking incident responders to discover them during a widespread outage.

## Availability, integrity and confidentiality require separate evidence

Unavailable information is not necessarily deleted. Readable information is not necessarily trustworthy. An absence of evidence of theft is not the same as proof that no access occurred. These distinctions should be recorded as separate findings with their own scope, time window and supporting evidence.

For availability, measure whether a defined customer operation completes. For integrity, test whether the result is correct, associated with the right account and free from unexpected changes. For confidentiality, examine access and transfer evidence with attention to the visibility gaps. A single green status indicator cannot answer all three questions.

This separation also improves customer communication. A service update can accurately state that synchronization is delayed while an investigation continues into a different security question. It need not imply that the two findings share the same confidence. Conversely, an encouraging investigation result does not make a service available before its dependencies are ready.

Internally, maintain a confidence ledger. Each finding should name the responsible investigator, the reviewed evidence, missing coverage and the next review trigger. When a claim becomes stronger, preserve the earlier wording and why it changed. This helps later reviewers understand the progression without mistaking an early provisional statement for a false final assertion.

## Recovery is a dependency problem, not a server count

A recovery plan that counts restored machines can hide the absence of a critical identity service or a broken queue. Start with a minimum useful customer operation and work backward through its dependencies. Restore the components required for that operation in a trusted environment, then validate the result before expanding the audience.

Identity deserves special attention. Restoring application data while keeping suspect administrative authority can reintroduce risk. However, indiscriminately changing every credential at once can disable the recovery tools and services needed to proceed. The response plan should identify which credentials and sessions support each dependency, who can change them and how the replacement will be verified.

The same principle applies to configuration. A backup may contain the data needed to resume work while also carrying an unwanted scheduled action or outdated access grant. Recovery therefore needs a configuration baseline, not merely successful file restoration. Record which configurations are trusted, which are reconstructed and which are accepted temporarily under monitoring.

Define a stop condition before a service is reopened. Unexpected account association, repeated processing failures, new privileged activity or unexplained data discrepancies should trigger a controlled pause. The precise thresholds depend on the service, but the authority to pause should not require improvisation after customers have already returned.

## Backlog replay: the second incident to prevent

A long outage can leave work waiting on devices, in upload buffers, in message queues and in downstream processing systems. Once access returns, that work may arrive at a rate far above normal demand. A recovery that ignores backlog behavior can create another outage or leave customers with inconsistent results.

Reconciliation begins with ownership. For each work item, determine the authoritative identifier and the system responsible for deciding whether it has already been processed. If a request is repeated after an acknowledgment was lost, the service should recognize the same operation rather than create an unintended second record. Where that property does not exist, the recovery team needs a deliberate duplicate-handling process.

Preserve the distinction between the time an activity occurred, the time it was received and the time it was processed. A delayed item may legitimately arrive after newer activity. Sorting only by arrival time can create misleading histories or incorrect downstream decisions. Tests should include out-of-order items, repeated submissions and partially completed operations.

Do not release the entire backlog merely because capacity appears available. Use controlled batches, compare counts and integrity checks, and watch customer-visible outcomes. A queue shrinking is encouraging but not sufficient: rejected records, account mismatches and silent drops may also shrink it. Completion means the work is accounted for, including exceptions.

Publish service-specific guidance about delayed records only after product owners verify it. Advising customers to reset, delete or reinstall something can remove useful local data in some systems. This study does not recommend such actions for Garmin products. The general lesson is to test the advice against the product's actual retention behavior before sending it widely.

## Detection priorities before visible encryption

The campaign reports illustrate why ransomware should be investigated as an intrusion problem rather than only a malicious-file problem. [3-5] The following detection design is a proposed framework, not an assertion that a particular event occurred inside Garmin.

Monitor changes in administrative behavior alongside endpoint alerts. A new remote-management pattern, unusual privilege use or a change to protection settings can matter even when the utility involved is legitimate. Interpretation requires context: the same action may be normal maintenance or an unexplained departure from the approved work schedule.

Tie detections to a response owner and a feasible next step. An alert about backup changes should reach someone who can verify the change and protect the relevant recovery material. An alert without an accountable decision path may be recorded perfectly while the opportunity to contain the incident passes.

Retain evidence outside the authority most likely to be affected. If the same administrative identity can alter production systems and erase the only audit records, later investigators may be unable to distinguish absence of activity from missing visibility. Separation must include access permissions, retention controls and a tested method of retrieval during an outage.

Avoid treating an old hash or filename as the entire detection strategy. Historical indicators are useful for retrospective checks, but an operator can change the visible artifact. Behavioral relationships, trusted baselines and evidence of unauthorized administrative reach remain important when the artifact differs from the published sample.

## Customer communication during partial restoration

Customers need operational instructions, not a stream of malware terminology. A useful update identifies the affected function, the consequence, the available alternative, the next update time and any action that could make recovery harder. It also distinguishes a known limitation from a question still being investigated.

Prepare communications channels that do not depend entirely on the affected environment. That does not mean a public status page should reveal sensitive internal details. It means authorized responders must still be able to publish a concise, accurate update when ordinary corporate messaging or support tools are unavailable.

Keep service status granular enough to help. A general statement that systems are returning can coexist with a particular operation remaining delayed. Each visible service should have an owner who verifies its status, and updates should preserve their timestamp so that a customer can tell whether the information is current.

Support teams need a consistent internal explanation of what they may promise. A script should not turn a tentative restoration estimate into a guarantee or convert an investigation finding into an absolute statement. Provide an escalation path for conflicting reports and record which customer questions reveal gaps in the public guidance.

After restoration, close the communication loop. Explain whether backlogged work is still processing, what a customer should do if an expected item remains missing and where the organization will post further findings. Silence after a broad recovery announcement can leave people unable to distinguish a personal account problem from an unresolved service issue.

## A proposed recovery acceptance record

| Acceptance question | Evidence to retain | Accountable role |
| --- | --- | --- |
| Can the intended customer operation complete? | A documented end-to-end test and observed result. | Service owner. |
| Is administrative access trustworthy? | Reviewed identities, session decisions and approved exceptions. | Identity and security leads. |
| Is restored information correct? | Reconciliation results, integrity checks and unresolved discrepancies. | Data owner. |
| Is accumulated work handled safely? | Replay batch results, duplicates and rejected-item accounting. | Processing owner. |
| Can new suspicious activity be observed? | Tested alert delivery and accessible audit records. | Detection lead. |
| Does the public status match the service? | Timestamped approval and support instructions. | Incident communications lead. |

This is a proposed working record, not a regulatory checklist or a claim about Garmin's process. A small organization may combine roles, but should not combine the questions into a single unsupported declaration. Each exception needs an owner, a reason for acceptance and a review deadline.

Acceptance is conditional on the tested scope. A service that works for a pilot population may still fail at normal scale. An operation that succeeds for new data may mishandle older delayed items. Record those distinctions so that expansion is a conscious decision rather than an assumption hidden inside a green status report.

## Ninety-minute tabletop: reopening without losing trust

This fictional exercise concerns a connected-product company, not Garmin. No live systems are changed. Participants include security, identity, product engineering, reliability, customer support, communications and an executive incident owner. The facilitator provides evidence in stages rather than announcing a complete answer at the beginning.

During the first thirty minutes, participants learn that some internal systems are encrypted and online synchronization is unavailable. Local product behavior differs by model. Ask the team to identify what it knows, which customer instructions are safe and how it will communicate if its usual tools are unavailable. Require a written uncertainty list.

During the next thirty minutes, a recovery team proposes reopening authentication and ingestion. A small test has succeeded, but an older queue contains records with ambiguous processing status. Ask who can approve reopening, which test population is appropriate and what evidence is required to distinguish retries from new work. The exercise should expose disagreements about ownership.

During the final thirty minutes, service demand rises and support reports missing records. A separate investigation update is cautiously reassuring about customer-data exposure. Participants must avoid using that security finding as proof that processing is correct. Ask them to decide whether to pause expansion, how to preserve evidence and what to tell customers.

Score the exercise on the clarity of decisions rather than the speed of declaring success. Did the team keep known facts separate from assumptions? Did every exception have an owner? Could it explain the customer consequence without unsupported promises? Did it know which observations would justify reversing the reopening decision?

## Thirty-, sixty- and ninety-day improvement plan

In the first thirty days, document a small set of important customer operations and their dependencies. Identify shared administrative authority, evidence-retention gaps and the channels available during an internal outage. Choose one degraded-mode test and one restoration test that can be conducted safely. The deliverable is a verified dependency record, not a large untested diagram.

By sixty days, test the recovery of a representative operation in an isolated environment. Include identity restoration, configuration review and replay of delayed synthetic work. Check the behavior of duplicates and partial failures. Have support and communications staff evaluate the resulting customer instructions rather than leaving them until the technical exercise is over.

By ninety days, rehearse a staged reopening with a deliberately ambiguous evidence set. Require explicit acceptance from the service and data owners. Test whether monitoring survives the assumed administrative compromise and whether staff can retrieve the relevant records. Assign deadlines to failed tests and repeat them after corrective work.

Measure outcomes that reflect readiness: time to establish trusted administration, time to complete an end-to-end restore, percentage of delayed work accounted for and time to issue an accurate service-specific update. Counting backups or alerts without testing their use can create an appearance of preparedness while leaving the important failure unresolved.

## Research conclusions and publication cautions

The strongest lesson here is not a claimed reconstruction of Garmin's attacker. It is the need to separate the observed outage, the available forensic statements and the surrounding ransomware research. That separation makes the defensive recommendations more credible because they do not depend on pretending that undisclosed details are known.

For connected services, recovery must include data reconciliation and customer comprehension. A product that retains local capability can still leave users confused about online dependencies. A restored service can still be unsafe to expand if queued work is not accounted for. A reassuring investigation statement can still coexist with operational work that remains unfinished.

Before public publication, preserve the evidence labels in the title, summary, timeline and slides. Do not insert an unverified ransom amount to make the story more dramatic. Do not convert the annual report's materiality assessment into a claim of no harm. If a reliable new victim-specific record becomes available, update the claim register and document precisely which uncertainty it resolves.

The practical objective is a service that can recover without asking customers to guess what happened to their work. That objective is testable. It brings security, reliability, product design and communication into the same recovery decision while keeping each team's evidence visible.

## Sources and reading record

[1] Garmin, July 27, 2020 statement, SEC Exhibit 99.1. Full short statement reviewed. https://www.sec.gov/Archives/edgar/data/1121788/000121390020018705/ea124587ex99-1_garmin.htm

[2] Garmin, 2020 Form 10-K. Incident passage and surrounding risk discussion, printed page 16, reviewed; not a full financial-statement audit. https://www8.garmin.com/aboutGarmin/invRelations/reports/2020_10K.pdf

[3] Symantec, WastedLocker campaign report, June 25, 2020, updated June 30. Campaign scope and observations reviewed. https://www.security.com/threat-intelligence/wastedlocker-ransomware-us

[4] Unit 42, Threat Assessment: WastedLocker Ransomware. General threat overview reviewed; portions cite other researchers. https://unit42.paloaltonetworks.com/wastedlocker/

[5] Microsoft Security Intelligence, Ransom:Win32/WastedLocker, July 29, 2020. Description and sample-scope qualifications reviewed. https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=Ransom:Win32/WastedLocker
