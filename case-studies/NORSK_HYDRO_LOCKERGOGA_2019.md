# Norsk Hydro and LockerGoga, 2019: Recovery Had to Reach the Factory Floor

*A TeamStarWolf case study. Published 15 November 2026.*

[All case studies](/case-studies/README.md) · Related: [Ransomware Defense Reference](/RANSOMWARE_DEFENSE_REFERENCE.md), [ICS and OT Security Reference](/ICS_OT_SECURITY_REFERENCE.md), [Cyber Resilience BCDR Reference](/CYBER_RESILIENCE_BCDR_REFERENCE.md), [Incident Response Reference](/INCIDENT_RESPONSE_REFERENCE.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Industrial and OT security teams, incident commanders, manufacturing and business-continuity leaders, and identity engineers

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 18 min (4,231 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You want an evidence-bounded account of the 2019 Norsk Hydro LockerGoga incident, you need to separate production recovery from IT recovery or malware capability from the incident timeline, or you are reviewing manufacturing continuity and trusted administrative recovery

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Executive summary](#executive-summary), [Safe continuity requires a stopping rule](#safe-continuity-requires-a-stopping-rule), [Trusted recovery: five acceptance gates](#trusted-recovery-five-acceptance-gates)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Ransomware Defense Reference](/RANSOMWARE_DEFENSE_REFERENCE.md), [ICS and OT Security Reference](/ICS_OT_SECURITY_REFERENCE.md), [Cyber Resilience BCDR Reference](/CYBER_RESILIENCE_BCDR_REFERENCE.md), [Incident Response Reference](/INCIDENT_RESPONSE_REFERENCE.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## Executive summary

The useful question in an industrial ransomware incident is not simply whether the machines still run. It is whether the organization can accept the right order, produce the right material, preserve traceability, approve shipment and reconcile the transaction afterward. A production line can remain mechanically capable while its surrounding information system prevents dependable work. Conversely, an organization may preserve output through manual procedures while carrying a substantial burden that normal production figures fail to show.

Norsk Hydro's 2019 incident provides a particularly clear setting for examining these distinctions. The historical record describes different effects across business areas, a lengthy return to normal information technology, and financial estimates that changed with the reporting period. It also contains a responder account of an intrusion that preceded the visible ransomware event. These are separate parts of the story, and each needs its own evidence label.

This study develops a manufacturing-centered recovery framework. It treats safe operation, trusted administration, usable production information, customer delivery and transaction reconciliation as separate acceptance gates. The proposed framework is original analysis. It does not claim that every suggested practice existed at Hydro or that an omitted control caused the incident.

The central lesson is practical: a recovery dashboard needs to describe the service that a plant can safely deliver. Counting rebuilt computers is necessary for managing the rebuild, but insufficient for deciding whether the business has recovered. The same discipline improves exposure management before an incident. A reachable administrative path matters because of the production decisions and records behind it, not only because of the machines on its network diagram.

## Scope, provenance and reading guidance

The incident occurred in 2019. The source register includes contemporary Hydro disclosures, Hydro financial reporting for 2019 and 2020, a later corporate retrospective, a Microsoft responder feature and original malware research from Unit 42. These sources answer different questions. A company statement establishes what the company publicly reported. A responder interview offers useful technical context but does not expose the complete forensic record. Malware-family research describes examined samples and should not silently become a victim-specific event log.

No victim systems, stolen information or malware binaries were accessed. Historical findings below are paraphrased and bounded. The recovery model, sample evidence artifacts, tabletop scenario, metrics and prioritization rubric are proposed analytical work, not new discoveries about Hydro. Readers should consult the linked originals before using the historical findings in another publication.

## Historical record: what the sources support

### 1. The first public operating picture

Hydro's March 19 update said it had isolated plants and operations and was moving to manual operation where possible. Energy and Bauxite & Alumina were operating normally. Norwegian primary-metal plants continued with more manual work. Production-system connectivity problems affected Extruded Solutions and Rolled Products, with temporary stops at several plants. The company reported no safety-related incidents at that point and said the full scope, financial effect and recovery timing remained uncertain. That dated statement must not be converted into a permanent assertion that the event had no safety implications. [1]

### 2. Early recovery remained uneven

The March 21 update continued to describe manual procedures and differing operating conditions across business areas. It is useful as an intermediate reporting checkpoint rather than proof that a whole-company recovery had finished. A dated update can document progress while leaving substantial uncertainty about underlying system restoration. [2]

### 3. Production and administration recovered on different clocks

On April 5, Hydro said most production output was normal or near normal. Reporting, billing and invoicing still faced delays. The company explicitly described safe recovery as complex and time-consuming and said full normal IT operations would take longer. This is direct evidence for distinguishing operational throughput from completion of the information-system recovery. [3]

### 4. The responder account adds an earlier intrusion phase

Microsoft's December 2019 feature, quoting Hydro personnel and its DART responders, describes a malicious attachment introduced into a legitimate customer conversation in December 2018. It says antivirus detected the Trojan days later, after the intruder had established a foothold. The account describes captured administrative credentials and a manual ransomware push from Hydro's domain controllers. It also reports Hydro's decision not to pay and its reliance on trusted backups, alongside a transparent communication strategy. These are attributed responder and victim accounts, not independently reproduced forensic findings. [4]

### 5. Malware capability does not equal the incident timeline

Unit 42's LockerGoga research examined multiple related samples and described changes between variants. Its analysis said the malware lacked worm-like self-propagation and described observed movement through SMB as actor-driven copying. The report is useful for resisting a misleading shorthand in which ransomware automatically spreads everywhere by itself. It does not establish every deployment path inside Hydro, and its sample-specific behaviors should remain sample-specific. [5]

### 6. Financial reporting changed the estimate

Hydro's 2019 financial statements estimated the financial impact at NOK 650-750 million and recorded NOK 216 million in insurance compensation for that year. The report identified lost sales associated with production and order-processing disruption in March and April, plus remediation of systems and data. The relevant passage is in Note 1.3, PDF page 40. [6]

The 2020 statements revised the estimated impact to NOK 800 million-1 billion. They reported total insurance compensation received of NOK 769 million, with NOK 216 million recognized in 2019 and NOK 553 million recognized in 2020. This is Note 1.3, PDF page 46. The later report should not be flattened into the earlier estimate, and insurance receipts should not be represented as the entire cost or as proof of complete economic recovery. [7]

Hydro's later public retrospective gives a rounded total of around NOK 800 million. It describes Extruded Solutions as the most affected area, rebuilding encrypted machines from backups and reorganizing security work. The rounded retrospective and the 2020 financial range should both retain their provenance instead of being silently reconciled into a falsely exact number. [8]

## A chronology with explicit limits

| Checkpoint | What the record establishes | What it does not establish |
|---|---|---|
| December 2018 | The later Microsoft feature describes an initial malicious attachment and foothold [4] | A publicly complete, independently validated minute-by-minute intrusion log |
| March 19, 2019 | Hydro publicly describes widespread IT impact, isolation and differing operational effects [1] | That every machine or industrial controller was encrypted |
| March 21, 2019 | Hydro supplies another operating-status update [2] | A universal date of business recovery |
| April 5, 2019 | Most output is normal or near normal while administrative processes still lag [3] | That billing, reporting, trusted IT and all reconciliation are complete |
| 2019 financial reporting | NOK 650-750 million estimate and NOK 216 million compensation recognized [6] | A final lifetime cost |
| 2020 financial reporting | NOK 800 million-1 billion estimate and NOK 769 million total compensation received [7] | A simple cash profit or loss from subtracting incompatible figures |
| Later retrospective | Around NOK 800 million in a rounded public account [8] | An explanation for every difference between earlier accounting estimates |

The defensible narrative has several clocks: intrusion, visible disruption, production recovery, IT recovery and financial recognition. A timeline graphic should show these as separate lanes. Forcing them into one red-to-green progress bar creates an appearance of precision while obscuring the questions operational leaders actually need answered.

## Analytical model: the factory's information dependency chain

The rest of this study presents proposed analysis unless a source number explicitly attributes a historical statement.

Consider a hypothetical extrusion order. A customer requests a specific profile, alloy, finish and delivery date. Sales captures the request. Engineering resolves the specification. Planning assigns capacity and tooling. Operators receive approved instructions. Quality staff associate inspection results with the produced material. Logistics releases the shipment. Finance invoices the correct customer. Each stage can depend on IT without requiring the attacker to manipulate a controller.

This model explains why an IT incident can constrain industrial output. Missing order information can prevent a valid job from reaching the line. Missing quality records can prevent release of material already produced. Missing identity services can prevent authorized staff from using otherwise functional applications. The physical equipment and the business service are different objects with different recovery criteria.

The model does not prove which of these exact dependencies failed at Hydro. It provides a disciplined way to investigate a similar organization. Interview the people who authorize each transition, ask what record they require, and identify the system that supplies it. Then test the process with a sample order during a controlled exercise. A dependency that nobody has tested should remain an assumption in the continuity plan.

A useful map includes people and physical artifacts as well as applications. If a manual workaround depends on a single experienced supervisor, that person is a capacity constraint. If it depends on printed specifications, version control matters. If an outsourced carrier requires an electronic manifest, the workaround must include that external interface. A diagram containing only servers can miss the point where a shipment actually stops.

## Safe continuity requires a stopping rule

Manual operation is a contingency with limits. It should have an approved scope, a staffing model and a review interval. A plant might be able to complete a restricted set of familiar orders while being unable to accept a complex new product. The continuity plan should distinguish those conditions rather than labeling the entire plant operational.

The first question is who has authority to approve the temporary mode. Security engineers can explain the confidence they have in connected systems. Qualified operations and safety personnel decide whether the physical process can run within its approved constraints. Customer-service staff cannot resolve a technical safety uncertainty by promising delivery, and IT personnel should not make a process-safety judgment merely because they control the network.

The second question is what ends the temporary mode. Examples of hypothetical stop conditions include inability to verify the applicable production instruction, loss of required traceability, unavailable qualified supervision or a growing reconciliation backlog beyond an agreed threshold. The threshold must come from the organization's own procedures and risk assessment. This study does not prescribe a universal number of hours that manual production is safe.

The third question is sustainability. Extra effort can preserve an initial shift but fail over several days. A continuity exercise should include handover between shifts, rest periods, absent specialists, a changed customer order and a supplier delay. These complications expose whether the workaround is a repeatable operating method or an improvised success dependent on exceptional people being present.

## Trusted recovery: five acceptance gates

### Gate 1: incident command and safety authority

Before reconnection, the team needs an agreed decision structure. Record who can isolate a business service, who can approve a temporary operating mode, who owns forensic preservation and who can accept a constrained restoration. These roles may differ by facility. Publish an out-of-band contact tree that remains accessible when the primary directory, email or collaboration platform is unavailable.

A practical artifact is a one-page service decision record. It names the affected service, the permitted operating mode, the current limitations, the next review time and the approving roles. It should also record who receives updates. This prevents a technical ticket closure from becoming an accidental business authorization.

### Gate 2: administration that the defender can trust

An organization recovering from privileged access abuse needs confidence in the systems that administer other systems. A restored endpoint can become exposed again if it reconnects to an administrative plane that remains under attacker control. Recovery planning should therefore include identity infrastructure, privileged workstations, management servers, service accounts and the credentials held by backup or deployment tools.

The team should document its basis for trusting each administrative dependency. This may include investigation results, approved rebuilding, credential replacement, validated configuration and restricted access paths. No single action proves cleanliness in every incident. The point is to make the trust decision explicit and inspectable rather than assuming that an absence of fresh alerts is sufficient evidence.

### Gate 3: recoverable data and applications

A successful backup job does not by itself establish that an application can support work. An isolated restoration test should demonstrate that the data opens, the application interprets it correctly and its dependencies function. For manufacturing, the test should include a representative business object such as an order, specification or quality record, rather than only a filesystem checksum.

Record the restoration point and the gap between that point and the interruption. Staff need a plan for legitimate transactions inside the gap. Some may exist on paper or in a partner's system. Others may need verification before re-entry. Recovery personnel should avoid inventing missing records merely to make the database look complete.

### Gate 4: operational acceptance

The business owner should execute an agreed acceptance scenario. In a hypothetical plant this might involve receiving a test order, verifying its approved specification, completing required checks and producing the shipping documentation. The scenario should cover the service's critical path without unnecessarily affecting live equipment or customer commitments.

Pass criteria need to describe function, not confidence alone. The system should return the intended information to the intended role, preserve the required audit trail and reject unauthorized changes. Exceptions should have a named owner and a due date. An exception that prevents safe or compliant work blocks acceptance, even if most ordinary desktop functions are already available.

### Gate 5: reconciliation and monitored return

Reconnection starts a monitored phase. During that period, the team checks for security recurrence and for business inconsistencies introduced by downtime. Duplicate orders, mismatched shipment records and unresolved quality paperwork are recovery work even when no malware remains. The dashboard should keep them visible until their owners resolve them.

Reconciliation needs a controlled method. Give temporary records unique identifiers, retain their original timestamps and record how they map to restored-system entries. Require a second review for consequential discrepancies. Keep evidence of corrections instead of silently overwriting the temporary record. These practices support customer confidence and later explanation of decisions made under pressure.

## Exposure management tied to manufacturing outcomes

A proposed exposure-management review begins with a question: what administrative or information path could disable this essential workflow? The answer may involve a vulnerability, but it may also involve excessive privilege, an untested dependency, stale credentials or a restoration process that nobody can execute without the compromised directory.

Prioritize paths using business consequence, breadth of reachable services, ease of containment and strength of recovery evidence. Avoid a false numerical precision that reduces uncertain assumptions to a single score. A short explanation of the consequential path is often more useful than a heat-map color. For example, an administrative account that can deploy software to several facilities deserves a documented investigation of scope and safeguards even if its software is fully patched.

For each path, identify a preventive measure, a detection opportunity and a recovery fallback. The preventive measure reduces the ability to reach or misuse the service. Detection provides evidence soon enough for an owner to act. Recovery restores the service after the first two layers fail. These are complementary responsibilities and should have distinct tests.

Useful tests include whether a suspicious management action reaches a monitored destination, whether analysts can identify the responsible identity, whether the affected segment can be isolated without uncontrolled process interruption and whether a clean restoration can operate under constrained connectivity. These tests should occur in a safe test environment or an explicitly approved exercise, with process owners involved. An unsolicited production experiment would introduce the very risk the program is intended to reduce.

## A defender's evidence worksheet

| Question | Evidence to request | Owner who should explain it |
|---|---|---|
| Which orders can the site currently accept? | Approved temporary service scope and representative test | Plant operations and customer service |
| Who can administer the restored service? | Current privileged-access map and validation record | Identity and platform owners |
| What changed after the backup point? | Gap ledger and reconciliation plan | Application and business-data owners |
| Can quality release the product? | Required inspection and traceability records | Quality lead |
| What prevents unsafe reconnection? | Network dependency review and approval gate | Security with plant engineering |
| Which claims are suitable for customers? | Timestamped status statement and accountable approver | Incident communications lead |

This worksheet is a proposed artifact, not a forensic finding. A good response can be "unknown, owner assigned, next review at a specified time." That answer preserves uncertainty honestly and gives incident command a way to resolve it. An unsupported green status does neither.

## Communication as an operational control

Hydro's public reporting supplies useful examples of dated operational updates, but no organization's communication style should become a script that another company copies without context. The proposed goal is consistent decision support. Staff need to know what they may connect, customers need a realistic service commitment and leadership needs a status that distinguishes evidence from expectation.

A useful update has four fields: what changed, what remains constrained, what action the audience should take and when the next update is expected. It should avoid declaring complete recovery because a single application or a majority of endpoints has returned. The public message and the internal dashboard can differ in detail while sharing the same underlying status definitions.

Communication channels also have dependencies. A crisis plan stored only in the unavailable collaboration platform is difficult to use. Staff should know how to authenticate an emergency instruction received through an alternate channel, especially when the instruction concerns network access or credentials. The exercise should test this authentication step without collecting or exposing real secrets.

Financial communication deserves the same discipline. Record the currency, reporting period, estimate range and whether a figure represents impact, expense, recognized compensation or cash received. Do not mix those categories to create a sensational total. An evolving estimate is not automatically a contradiction or concealment. The editor should first ask whether the measurement basis or maturity of the claim changed.

## Ninety-minute tabletop: one facility, two recovery clocks

This is a fictional exercise inspired by the operational questions in the case, not a reconstruction of Hydro's actions. Participants should include security, identity, plant operations, engineering, quality, logistics, finance and communications. The facilitator should agree in advance that no live industrial changes will occur.

### Minutes 0-15: uncertain scope

Several business workstations show ransomware messages. The production line still operates, but the order-management application is unavailable. A plant manager asks whether the line should continue with printed instructions from the previous shift. The exercise tests authority, version verification and the ability to state uncertainty. A successful discussion produces an approved decision path, not an improvised technical verdict from whoever speaks first.

### Minutes 15-35: constrained continuity

A familiar customer requests a change to an order already in progress. The temporary workflow can record the request but cannot confirm the latest specification. Quality staff warn that the manual traceability log is incomplete. Ask who can promise delivery, who can reject the change and what evidence permits work to proceed. The facilitator should resist solving the issue by magically restoring the unavailable application.

### Minutes 35-55: an attractive shortcut

The platform team restores an order database in isolation. A management server needed for normal deployment remains under investigation. Someone proposes reconnecting immediately because the customer backlog is growing. Ask which acceptance gate is missing, what restricted service might be possible and which role can accept the residual risk. The aim is to make the decision visible, not to reward blanket refusal or reckless optimism.

### Minutes 55-75: output returns before records do

The line reaches a near-normal rate for the restricted product set. Shipping can dispatch some orders, but finance identifies duplicate temporary order numbers. Leadership asks for a green recovery status. Participants should separate production capacity, information integrity and unresolved transactions. The exercise should produce a bounded status statement and a reconciliation owner rather than an argument about whether the company is technically back online.

### Minutes 75-90: learning without invented certainty

Each function names one missing artifact and one measurable improvement. Capture decisions that lacked a clear owner, dependencies nobody could verify and assumptions that changed during the exercise. Assign remediation to a role and require evidence of completion. A follow-up exercise should retest the failed transition rather than merely confirm that someone updated the plan.

## Thirty-, sixty- and ninety-day improvement plan

The following plan is a proposed starting point. Timing must fit the organization's resources, safety procedures and existing obligations.

In the first thirty days, choose a small set of essential manufacturing services and document their end-to-end dependencies. Establish authority for temporary operation and reconnection. Confirm that emergency contact information and core response instructions remain available without the ordinary directory. Inventory privileged paths into the chosen services. The deliverable is an accountable service map, not a complete inventory project that never reaches a usable conclusion.

By sixty days, conduct isolated restoration tests for representative applications and data. Include the business owner in acceptance. Exercise one manual workflow across a shift handover and a changed order. Test whether a suspicious administrative event generates evidence that a named analyst can interpret. Resolve the highest-consequence gaps found during those tests before expanding the exercise to more facilities.

By ninety days, run a cross-functional scenario that combines constrained production, trusted administration and reconciliation. Review what the earlier tests failed to predict. Approve continuing exceptions explicitly and establish their review dates. Extend the approach to additional services using the artifacts that proved useful, rather than imposing every document on every site regardless of relevance.

## Metrics that reveal useful progress

Measure time to a safe containment decision separately from time to restore an endpoint. Measure the percentage of essential services with a witnessed business acceptance test, rather than counting backup jobs alone. Track unresolved downtime records by age and consequence. Record how long the organization can sustain the approved temporary mode under realistic staffing assumptions.

For detection, measure whether analysts can connect an administrative action to an identity, destination and business owner within the exercise's decision window. For recovery, record which dependencies blocked acceptance and how often the same blocker reappears. For communication, check whether different audiences received consistent definitions of restricted, restored and fully reconciled service.

Metrics should expose uncertainty instead of encouraging optimistic classification. If a service has never undergone a restoration test, label its recovery capability untested. If an exercise used a simplified dependency, retain that limitation. Trend improvement against the same test conditions or explain why the conditions changed. A better-looking chart is not evidence of resilience if the later test was easier.

## Editorial pitfalls and limits

Do not describe the incident as proof that every industrial controller was compromised. The reviewed record supports serious industrial consequences from the IT disruption, not that blanket technical claim. Do not call LockerGoga a self-propagating worm merely because many systems were affected. Keep Unit 42's malware-family analysis separate from the incident-specific responder account.

Do not convert the December attachment account into an exact unqualified dwell-time calculation. The source describes a period, and the available public record is incomplete. Do not add a named perpetrator, exfiltration claim, ransom amount or recovery percentage without a source that supports that specific statement. An absence of a fact in this study is not proof that the underlying event did not occur.

Keep the financial estimates side by side with dates and source types. The 2020 financial range is an important addition to an account that would otherwise repeat only the widely cited rounded NOK 800 million figure. Avoid claiming that insurance erased the incident's consequences. This study does not offer an accounting reconciliation, a legal opinion or an estimate of unreported indirect losses.

Finally, the proposed recovery gates and tabletop are not a diagnosis of Hydro's current security program. They are educational tools derived from the questions the public record raises. Their value lies in making decisions testable at another organization without pretending to possess private knowledge of the victim.

## Conclusion

The strongest industrial ransomware case study follows the work beyond encryption. It asks how a plant can continue within approved limits, how administration becomes trustworthy again and how customer transactions regain integrity. It recognizes that production, information systems and finance can recover at different speeds.

For defenders, the immediate practical task is to select one essential service and prove its recovery end to end. Include the people who authorize the work, the records that make it valid and the dependencies that permit it to happen. Preserve the evidence from that test. That produces a more useful improvement plan than assuming a collection of restored machines equals a restored business.

## Source register

[1] Hydro, "Update: Hydro subject to cyber attack," March 19, 2019. Contemporary operating status. https://www.hydro.com/en/global/media/news/2019/update-hydro-subject-to-cyber-attack/

[2] Hydro, "Update on cyber attacks March 21," March 21, 2019. Intermediate status. https://www.hydro.com/en/global/media/news/2019/update-on-cyber-attacks-march-21/

[3] Hydro, "Update on cyber attack April 5," April 5, 2019. Production versus administration. https://www.hydro.com/en/global/media/news/2019/update-on-cyber-attack-april-5/

[4] Microsoft Source, "Hackers hit Norsk Hydro with ransomware. The company responded with transparency," December 16, 2019. Attributed victim and responder account, not an independent forensic audit. https://news.microsoft.com/source/features/digital-transformation/hackers-hit-norsk-hydro-ransomware-company-responded-transparency

[5] Palo Alto Networks Unit 42, "Born This Way? Origins of LockerGoga," 2019. Original malware-family analysis. https://unit42.paloaltonetworks.com/born-this-way-origins-of-lockergoga/

[6] Hydro, Financial statements and Board of Directors' report 2019, Note 1.3, PDF page 40. https://www.hydro.com/globalassets/download-center/investor-downloads/ar19/financial-statements-and-board-of-directors-report-2019-web.pdf

[7] Hydro, Financial statements and Board of Directors' report 2020, Note 1.3, PDF page 46. https://integration.hydro.com/globalassets/06-investors/information-for-shareholders/agm2021/english/appendix-1-financial-statements-and-board-of-directors-report-2020.pdf

[8] Hydro, "Cyber-attack on Hydro," later retrospective, updated May 15, 2024. https://www.hydro.com/en/global/media/on-the-agenda/cyber-attack

Sources reviewed November 15, 2026. This date records research, not a new incident occurrence. Source-derived historical summaries are deliberately concise. Most of this study is original defensive analysis and explicitly hypothetical planning material.
