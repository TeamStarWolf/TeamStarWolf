# Texas Municipal Ransomware 2019: A Shared Dependency Became a Statewide Response

*A TeamStarWolf case study. Published 16 November 2026.*

[All case studies](/case-studies/README.md) · Related: [Ransomware Defense Reference](/RANSOMWARE_DEFENSE_REFERENCE.md), [Incident Response Reference](/INCIDENT_RESPONSE_REFERENCE.md), [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md), [Cyber Resilience and BCDR Reference](/CYBER_RESILIENCE_BCDR_REFERENCE.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Local-government and public-sector security teams, managed service providers, incident responders and resilience planners

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 19 min (4,305 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You want an evidence-bounded account of the 2019 Texas municipal ransomware event, you need to separate a regional incident from a single-organization one or a provider dependency from the malware, or you are planning coordinated multi-jurisdiction recovery

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Executive assessment](#executive-assessment), [Provider authority is a concentration of risk](#provider-authority-is-a-concentration-of-risk), [No payment is not the same as no cost](#no-payment-is-not-the-same-as-no-cost)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Ransomware Defense Reference](/RANSOMWARE_DEFENSE_REFERENCE.md), [Incident Response Reference](/INCIDENT_RESPONSE_REFERENCE.md), [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md), [Cyber Resilience and BCDR Reference](/CYBER_RESILIENCE_BCDR_REFERENCE.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## Executive assessment

A regional cyber incident is not merely a larger version of a single organization's incident. Multiple local governments can require help at the same time, depend on the same service provider, and compete for a limited pool of responders. Their technology may be similar while their public-service priorities, authority and recovery readiness differ. The coordination problem can become as important as the malware itself.

The August 2019 Texas ransomware event is a strong case for studying that problem. Contemporary state updates, later legislative testimony, an agency self-evaluation and federal allegations provide several views of the same event. They also contain distinctions that a careful account must preserve: twenty-two versus twenty-three entities at different reporting stages, restoration of critical services versus complete normal operations, and an indictment versus a conviction.

This study uses eight official source records. The historical section is compact and dated; the longer sections develop original defensive analysis for a regional response involving shared technology dependencies. They are not presented as the private procedures of a particular municipality or as a complete forensic reconstruction of the provider compromise. No ransomware, attacker service, leaked data or recovery tool was accessed or executed.

Three historical DIR releases were available in substantial indexed text, but their live URLs returned not-found errors when opened. That limitation is recorded rather than concealed. The later official testimony and report provide additional primary evidence, not a reason to rewrite the earlier statements as if their counts and milestones had never changed.

## The contemporary state account

DIR's August 16 announcement described a coordinated ransomware attack affecting at least twenty local-government entities. It identified DIR as response lead, emergency-management coordination through the State Operations Center, and deployment of support to critically affected jurisdictions. The announcement was an early operational report, not a final victim census. [1]

The August 20 update reduced the confirmed count to twenty-two. Responders had engaged all of them, more than a quarter had moved toward remediation and recovery, and some had resumed normal operations. The update stated that state systems and networks were unaffected and that evidence pointed to one threat actor while investigation continued. An early assessment of a common actor is not a named legal attribution. [2]

On September 5, DIR reported that by the evening of August 23 all affected entities had moved into remediation and recovery with business-critical services restored. More than half were described as back to normal operations, and follow-up visits were being scheduled. Ending the State Operations Center response was therefore not identical to declaring every local recovery task complete. [3]

These updates should be read as snapshots. They describe what the state was prepared to say at particular points in the response. A later narrative loses information if it compresses every status into either completely down or fully recovered, or if it treats an early count as an immutable final total.

## Later testimony and the shared-provider finding

In February 2020 Senate testimony, DIR Executive Director Amanda Crawford described twenty-three affected entities, no ransom payment, and a one-week transition to a point where state support was no longer required. She credited preparation and cooperation, while warning that an event several times larger could exceed the response model's design. The testimony thus contains both a success account and a capacity warning. [4]

DIR's later self-evaluation recounts twenty-three entities and approximately 740 computers. It states that the entities shared a private managed-services provider and that the attacker used the provider's server for remote ransomware execution. The report records a $2.5 million demand and no payment. These later totals are not silently substituted into the August 20 release's twenty-two figure; the consulted records do not explain the numerical reconciliation. [5]

Original analysis: the shared dependency is the organizing fact for the defensive lesson. A provider can give small customers capabilities they could not sustain alone. That same relationship can concentrate administrative authority and create simultaneous demand for recovery. The question is not whether outsourcing is inherently unsafe. It is how the authority, evidence and recovery arrangements work when the shared provider is itself part of the incident.

The source record supports the provider-mediated deployment description, but not every possible explanation of how the provider was initially compromised. This study does not supply an invented phishing message, vulnerability, credential theft sequence or exact remote-management product. Those details require evidence beyond a general statement that a provider server was used.

## Federal allegations and the limits of attribution

DOJ's November 8, 2021 announcement linked charges against Yevgeniy Polyanin to Sodinokibi/REvil attacks including Texas entities around August 16, 2019. It also discussed a separate defendant and the later Kaseya incident. The announcement included a seizure of alleged proceeds, not a statement that the 2019 Texas entities had paid or received reimbursement. The allegations must remain allegations. [6]

The Polyanin indictment alleges access to a service company's network, access to its clients, and ransomware deployment on August 16. Its overt acts use anonymized company and government-entity labels. Those labels should not be reverse-mapped to named towns without independent evidence. An indictment's selected counts are also not a census of every affected entity in the response. [7]

The FBI wanted page consulted for this study continued to describe Polyanin as wanted for alleged involvement. No conviction or custody outcome is asserted here. His listed nationality does not establish state direction of the operation, and a shared ransomware family does not make every incident or participant identical. [8]

Original analysis: attribution can develop over years while service recovery must proceed immediately. A local government's responsibility to restore trustworthy operations does not depend on knowing a perpetrator's name. Conversely, a later criminal allegation can add historical context without changing the evidentiary standard for what happened on an individual local network.

## Why the entity count needs a footnote

Original analysis: counts in a multi-organization incident have a definition problem as well as a discovery problem. An organization, a municipality, a department, a provider customer and a technical environment are not necessarily the same unit. A public update may count confirmed impacted entities, while a later retrospective may use a wider operational population. The analyst must check rather than assume.

For this case, the appropriate statement is that the contemporary August 20 update used twenty-two while later official accounts used twenty-three. The evidence consulted does not explain the change. Do not average the figures, select the most repeated headline, or manufacture a reason. Keeping the discrepancy visible is more accurate than presenting false precision.

A response team can reduce this problem by assigning stable entity identifiers and recording inclusion criteria. An entity might move from reported, to assessed, to confirmed affected, or be removed after review. Preserve that history. A dashboard that overwrites the original status may produce a clean current number while destroying the explanation for earlier public statements.

The same care applies to computers. Device totals should identify whether they count confirmed encrypted endpoints, examined systems, rebuilt devices or all assets in affected environments. A larger device number does not automatically mean a more severe public-service impact, and a smaller town can still have a critical dependency. Counts support decisions only when their units and limitations remain attached.

## Service prioritization across jurisdictions

Original analysis: when many entities request help, the response lead needs a common prioritization method. First-come, first-served allocation can reward whoever reports most quickly rather than whoever has the greatest need. The loudest requester may not have the most consequential service interruption. A defensible process considers public safety, time sensitivity, alternatives, dependencies and local capacity.

The intake should ask what the public can no longer do, not just which computers are broken. Can a necessary service operate manually? Is the manual procedure sustainable for hours or days? Does a local failure block another organization's work? Is there an immediate safety concern that needs a non-technical specialist? These questions connect technical triage to the mission.

Prioritization should be revisited as evidence improves. A jurisdiction initially thought to have a limited outage may reveal a missing dependency; another may have a reliable workaround. Record why a team is reassigned so that the decision can be explained later. Reprioritization should not be mistaken for inconsistency when it follows a documented change in circumstances.

This framework is a proposal, not a claim about the exact scoring method Texas used. It also does not authorize a remote responder to make decisions reserved for local officials. Technical advice, resource coordination and public-service authority may belong to different roles. A regional plan should make those boundaries explicit before the emergency creates pressure to blur them.

## A common operating picture without a common database of secrets

Original analysis: regional coordination needs shared status, but it does not need unrestricted copies of every local log or personal record. A common operating picture can identify entity, contact, critical functions, current impact, requested assistance, assigned team, evidence gaps and next milestone. Detailed sensitive artifacts can remain in appropriately controlled repositories.

The reporting cadence should be predictable and proportionate. If every responder spends excessive time answering overlapping requests, the coordination process consumes the capacity it was meant to organize. Use a standard update format and a clear owner for consolidation. Separate urgent changes from routine status so that critical information does not wait for the next scheduled meeting.

Confidence labels help. A report from a local user, a provider assertion and a responder-verified finding are different kinds of evidence. Preserve who supplied the information and when it was last checked. An old status should not appear current simply because it was copied into a new briefing.

Access to the shared record should follow need and responsibility. Public communications require a different level of detail from technical coordination. Information about a vulnerable system, a personal record or an investigative lead should not be placed in a broad mailing list by default. The shared picture should improve decisions without creating a new exposure channel.

## Provider authority is a concentration of risk

Original analysis: a managed-services relationship should be evaluated as an authority relationship, not only a purchasing arrangement. Identify what the provider can change, which customers can be reached from each administrative context, and whether exceptional actions require independent approval. The security question is the reach of a compromised authority, not merely whether the service has a familiar brand.

A useful review maps the path from provider identity to customer action. It should include routine administration, emergency access, automation and recovery. Different accounts can still share the same recovery channel or management server, so apparent separation may not represent an independent boundary. The map needs to reflect practical authority, not an idealized contract diagram.

Customer visibility matters. A local government should know which administrative actions can be observed independently and which records disappear if the provider's platform is unavailable. Relying exclusively on the affected party for evidence can make scope assessment harder. This does not presume provider dishonesty; the provider may simply be recovering the very system that held the necessary records.

The objective is to reduce unnecessary shared authority while preserving legitimate support. A blanket prohibition on remote management can be impractical and may produce less controlled alternatives. Better questions are whether access is scoped, attributable, time-bounded where appropriate, reviewed, and recoverable when trust in the provider's environment is interrupted.

## The shared-provider response dilemma

Original analysis: a customer may need to suspend the provider's access to contain risk, yet also depend on that provider to restore operations. This creates a sequencing problem. Reconnecting ordinary administration too early can restore an unsafe path; refusing all provider involvement can remove essential knowledge. The plan should identify an independent way to authorize and supervise recovery work.

A controlled recovery relationship can use verified personnel, documented scope, approved clean tools and access that expires when the assigned work ends. The customer or incident lead should know which actions are being performed and where the records will be retained. This is a general model, not a prescription for a specific product or a claim that Texas used a particular arrangement.

The provider also needs a customer communication method that remains usable if its normal systems are unavailable. Customers need a way to authenticate that message rather than trusting any urgent email that claims to come from support. Pre-established contacts and escalation routes reduce confusion and the opportunity for opportunistic impersonation.

A contract can describe these expectations, but a tabletop should test whether the people can actually use them. Who can approve emergency access outside business hours? Who has the local authority to accept a rebuilt system? Where is the asset inventory if the provider portal is offline? A plan that cannot answer those questions during an exercise is unlikely to become clearer under pressure.

## Evidence and restoration can proceed together

Original analysis: recovery and investigation should be coordinated, not treated as mutually exclusive goals. Some evidence can be preserved before a rebuild without indefinitely delaying essential services. Other evidence may require a deliberate choice because collection takes time or carries operational risk. The decision should be made by authorized people with both needs represented.

Record what was preserved, what was not, and why. A later investigator should be able to distinguish an unavailable artifact from an artifact examined and found unremarkable. Avoid claims such as no lateral movement observed when the relevant logs were never collected or did not cover the suspected period.

Multi-entity incidents create an additional correlation task. A common event time, management action or account may appear across several customers. Preserve timezone and clock reliability so that correlation is not based on misleading timestamps. Shared identifiers can help connect evidence, but personal data should not be circulated simply because it might be useful someday.

Restoration teams should receive the findings that affect safe rebuilding without needing access to every investigative detail. An operational instruction can identify a trust boundary to avoid or a validation requirement without disclosing an unrelated sensitive artifact. This division supports both efficient service recovery and responsible handling of evidence.

## Recovery states that mean something

The following original state model is designed for a regional response. It is not a reconstruction of DIR's internal dashboard.

| State | Evidence required | What it does not mean |
|---|---|---|
| Reported | Identified entity and credible contact | Impact has been independently confirmed |
| Assessed | Documented scope and priority | Every affected asset has been found |
| Contained | Defined access or propagation controls | All data and services are restored |
| Critical service restored | Function-specific owner acceptance | Every service operates normally |
| Local recovery continuing | Assigned tasks and accountable owner | Regional support is still required |
| Operationally closed | Validated agreed scope and handoff | No long-term improvement remains |

Each transition should have a timestamp, an owner and a short evidence reference. The labels should be understandable to local officials as well as technical staff. If an agency uses different terms, retain its definitions rather than assuming that a familiar word means the same thing everywhere.

Critical service restoration is especially important to define. It may represent a limited but usable function, with other tasks still outstanding. That can be a successful and proportionate milestone. It becomes misleading only when it is reported as complete recovery without the accompanying scope. The same principle applies to the end of a state-coordinated response: it can be a handoff, not the disappearance of all local work.

## Mutual aid has a capacity limit

Original analysis: a successful response at one scale should not be assumed to work at every scale. Responders need travel time, rest, equipment, trusted communications, local access and suitable skills. A list of willing volunteers is not equivalent to deployable capacity. Some specialists may also serve the same affected provider or several customers, creating hidden resource conflicts.

Capacity planning should include concurrent incidents and prolonged operations. Estimate what happens when the number of affected entities doubles, when a large geographic distance separates them, or when normal communications fail. Identify which tasks can be handled remotely and which require local presence or a specific authorized operator.

Pre-negotiated support can reduce administrative delay, but it must be maintained. Contact information, access assumptions, insurance arrangements and staff availability can change. A contract that exists only as an old document may not provide an effective surge option. Exercises should test activation and handoff, not merely confirm that a vendor's name appears on the plan.

The response also needs a demobilization model. Returning teams too early can leave local staff with an unsafe partial recovery; keeping every external responder indefinitely can exhaust the region's reserve. Define the minimum local capability and support path required for handoff. The handoff should include unresolved tasks, validation evidence, escalation contacts and the next scheduled review.

## Public communications for a geographically distributed incident

Original analysis: residents usually need service information more urgently than technical attribution. A useful message identifies the affected function, available alternatives, expected next update and safe contact route. It should not announce a precise restoration time unsupported by the recovery work. It should also avoid giving unnecessary details about exposed infrastructure.

Regional and local messages should be consistent without erasing local differences. One entity may have restored a payment function while another still relies on an alternative. A statewide statement that some services are returning should not cause every local office to promise normal operations. The central communications team needs a process for verifying the local facts it summarizes.

Count changes deserve a straightforward explanation when one is known. If the reason is not established in the public record, later researchers should say so rather than invent a correction. During an actual response, retain the history behind revisions so that officials can explain whether a number changed because of confirmation, scope or classification.

Public guidance should be tested for impersonation risk. An incident creates opportunities for fraudulent support messages or payment redirection. Residents should be directed to verified channels and should not be asked to submit secrets through an unfamiliar form. Communication planning is therefore part of the defense, not merely a final public-relations step.

## No payment is not the same as no cost

Original analysis: an account of recovery without ransom payment should not imply that recovery was free. Staff time, external assistance, replacement equipment, service interruption and follow-up work can impose costs. The case does not provide a complete audited cost total from the consulted sources, so no total is invented here.

The demand itself is also not a loss calculation. A criminal can demand an amount unrelated to actual restoration cost or public-service impact. Likewise, a later seizure associated with a broader criminal investigation is not evidence that the affected local governments paid that amount or received it back. Those are different financial facts requiring separate records.

A local government's after-action process should capture costs consistently enough to inform future investment. Distinguish emergency response from durable improvements and avoid counting the same shared resource several times. The purpose is to understand the effort required and the value of preparedness, not to inflate an alarming headline.

This document does not advise a current victim on payment, sanctions or legal obligations. It describes the official historical account and draws operational lessons. Decisions during a real incident require current qualified advice and the authority of the affected organization. Historical success should inform preparation without becoming a promise that every future incident will have the same options.

## A ninety-minute regional-response tabletop

This original exercise uses fictional municipalities and a fictional provider. Participants should include a regional incident lead, two local service owners, a provider representative, a technical responder, an emergency-management coordinator and a communications lead. Use synthetic records; do not contact a real provider or run malicious code.

For minutes zero through twenty, report simultaneous service interruptions at several customers. Give one jurisdiction a critical dependency and another an effective manual workaround. Ask the group to establish intake criteria, prioritize assistance and identify who can authorize containment. Score whether service consequences, rather than request volume alone, drive the initial allocation.

For minutes twenty through forty, reveal that the normal provider-management path cannot yet be trusted. The provider still holds useful configuration knowledge. Ask the team to design a limited recovery relationship, decide which evidence must be preserved, and establish a communication route independent of the affected system. The exercise should expose assumptions about authority and access.

For minutes forty through sixty, introduce a revised entity count and partial restoration at one site. Ask for a regional status update and a local resident message. Participants must explain the classification change, preserve uncertainty, and distinguish critical-service availability from full normal operations. Do not reward a tidy number if its definition is unclear.

For the final thirty minutes, remove a specialist team from availability and require a handoff decision. Ask which local capability is sufficient for continued recovery, what tasks remain open, and when outside help must return. The final product should be a decision record and an assigned follow-up plan, not a declaration that the whole incident is over because the exercise clock expired.

## A worked coordination decision

Consider a fictional town whose records service is unavailable while its essential field operations continue through a documented alternative. A neighboring town reports a smaller device count but no workable alternative for a time-sensitive function. The regional lead should not allocate support solely by the number of encrypted computers. The second town may need the first available specialist even though its technical footprint is smaller.

Now suppose both depend on the same provider, and the provider can supply configuration information but cannot yet establish trust in its administrative environment. The lead can separate knowledge transfer from unrestricted access. Local authorized staff can review proposed changes while the provider's ordinary management path remains suspended. This creates a practical way to use expertise without assuming the original trust relationship is already restored.

Later, one town passes its critical-function test but still has an unresolved records backlog. It may be ready for reduced external support with a documented local plan. Calling that milestone critical service restored is accurate; calling it all work complete would not be. The handoff should name the backlog owner, the validation criteria and the condition that would trigger renewed assistance.

This example is invented to illustrate the decision structure. It does not identify a real 2019 municipality or claim a specific service failure occurred there. Its value is in showing how evidence, mission impact and authority can support a proportionate decision without requiring perfect certainty about every technical detail.

## Measures that would improve the next response

Original analysis: measure whether the region can identify affected entities, authenticate contacts, prioritize services and deploy appropriate help. Useful measures include time to establish a verified local contact, time to identify a critical dependency, and the proportion of handoffs with explicit owner acceptance. Each measure needs a clear start event and coverage definition.

For provider risk, test whether customers can enumerate the provider's administrative reach and obtain relevant records when its usual portal is unavailable. Test emergency revocation and controlled restoration of access using approved non-production exercises. A policy statement that access can be disabled is weaker evidence than a documented exercise showing who can do it and how service continuity is handled.

For recovery, test representative public-service transactions rather than only host availability. Confirm that the restored function uses the correct records, permissions and dependencies. Retain the test evidence and identify what was outside scope. A service that responds to a network request is not necessarily ready for public use.

Finally, maintain a capacity model that is honest about limits. Record which assumptions fail as the number of concurrent entities grows and what additional arrangements would be required. The goal is not to promise unlimited mutual aid. It is to know when the plan needs reinforcement and to make that decision before exhausted responders become the limiting control.

## Conclusion

The Texas event illustrates both the danger of concentrated administrative dependencies and the value of coordinated preparation. The official record supports a successful regional response while preserving important qualifications about counts, recovery milestones and legal attribution. Those qualifications strengthen the case rather than weakening it.

A durable lesson is to plan for the failure of the shared service relationship itself. Customers need independent evidence and a controlled recovery path; regional responders need a common status model and realistic surge capacity. Local authorities need clear acceptance decisions and a supported handoff. Recovery is not simply the end of encryption. It is the restoration of trustworthy public functions within a response system that can explain its decisions.

## Sources and reading scope

[1] Texas DIR, August 16, 2019 announcement. Substantial indexed release text read; live URL returned 404. https://dir.texas.gov/news/ransomware-attack-hits-texas-government-entities

[2] Texas DIR, August 20, 2019 update. Substantial indexed release text read; count and recovery state retained as dated. Live URL returned 404. https://dir.texas.gov/news/update-august-2019-texas-cyber-incident

[3] Texas DIR, September 5, 2019 update. Substantial indexed release text read; critical services and normal operations distinguished. Live URL returned 404. https://dir.texas.gov/news/update-texas-local-government-ransomware-attack

[4] U.S. Senate hearing, Cybersecurity 2020, Amanda Crawford testimony. Selected oral testimony concerning the Texas response and capacity limits read, not the entire hearing. https://www.govinfo.gov/content/pkg/CHRG-116shrg40972/html/CHRG-116shrg40972.htm

[5] Texas DIR self-evaluation report, August 2023, 2024-2025 review cycle. Selected 2019 incident section, printed pages 198-199, read as extracted text. No full agency audit claimed. https://www.sunset.texas.gov/public/uploads/2023-10/~Texas%20Department%20of%20Information%20Resources%20Self-Evaluation%20Report%202024-2025_Corrected.pdf

[6] DOJ, November 8, 2021 announcement. Texas-related Polyanin allegations distinguished from separate Kaseya defendant and broader seizure. https://www.justice.gov/archives/opa/pr/ukrainian-arrested-and-charged-ransomware-attack-kaseya

[7] Polyanin indictment, filed August 24, 2021. Selected alleged overt acts and count descriptions read as extracted text; anonymized entities not reidentified. https://www.justice.gov/opa/press-release/file/1447121/dl

[8] FBI wanted page for Yevgeniy Igorevich Polyanin. Allegation and wanted status checked; no conviction asserted. https://www.fbi.gov/wanted/cyber/yevgeniy-igorevich-polyanin/

Accessed November 15, 2026. Historical analysis, not a present-day legal or payment recommendation. No full victim roster, initial-provider intrusion recipe, audited total cost or complete local recovery timeline is claimed.
