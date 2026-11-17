# WannaCry 2017: How an Unclosed Patch Gap Became a Healthcare Service Crisis

*A TeamStarWolf case study. Published 15 November 2026.*

[All case studies](/case-studies/README.md) · Related: [Healthcare Security Reference](/HEALTHCARE_SECURITY_REFERENCE.md), [Vulnerability Management Reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md), [Ransomware Defense & Resilience](/RANSOMWARE_DEFENSE_REFERENCE.md), [Incident Response Reference](/INCIDENT_RESPONSE_REFERENCE.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Vulnerability-management teams, incident responders, healthcare technology leaders and infrastructure owners

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 32 min (7,350 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You want an evidence-bounded account of the 2017 WannaCry outbreak and the NHS response, you need to separate an available patch from a verified one or infected from affected, or you are planning a continuity exercise

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Executive summary](#executive-summary), [6. NHS impact: count the right thing](#_6-nhs-impact-count-the-right-thing), [11. An original assurance model: from notification to service confidence](#_11-an-original-assurance-model-from-notification-to-service-confidence)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Healthcare Security Reference](/HEALTHCARE_SECURITY_REFERENCE.md), [Vulnerability Management Reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md), [Ransomware Defense & Resilience](/RANSOMWARE_DEFENSE_REFERENCE.md), [NotPetya 2017](/case-studies/NOTPETYA_2017.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

Key takeaways (reviewed 2026-11-17):

- On 12 May 2017, ransomware with automated SMB propagation created an international emergency. ([Executive summary](#executive-summary))
- Microsoft connected the spread to vulnerabilities addressed by MS17-010, published on 14 March, two months earlier. ([Executive summary](#executive-summary))
- The lesson is not that a patch existed, but that the distance between a published remedy and verified protection can mean interrupted care. ([Executive summary](#executive-summary))
- A defender needed to know which machines existed, which were reachable, who could change them, and what those changes would interrupt. ([Executive summary](#executive-summary))

<!-- meta:end -->

## Executive summary

WannaCry matters because the malware and the organizational emergency operated at different scales. An attacker needed a vulnerable machine and a reachable service. A defender needed to know which machines existed, which were reachable, who could change them, what those changes would interrupt and how to coordinate when normal communications failed. A security update could address a technical weakness without, by its mere publication, resolving any of those organizational questions.

On 12 May 2017, ransomware with automated SMB propagation created an international emergency. Microsoft's analysis connected the spread to vulnerabilities addressed by MS17-010, published on 14 March [1][2]. The central lesson is therefore not simply that a patch existed. It is that the distance between a published remedy and verified protection can become the distance between normal work and interrupted care.

England's NHS supplies unusually detailed public evidence about that distance. This study separates malware infection from precautionary shutdown, service dependency failure, cancelled appointments and later recovery expenditure. It also distinguishes contemporary technical observation, retrospective administrative reporting, government attribution and criminal allegations. These records answer different questions and should not be forced into one apparently definitive narrative.

Three conclusions guide the analysis:

1. **Exposure is an operational condition, not a notification.** An advisory, a downloaded update and a protected endpoint are different states.
2. **Continuity is a network of dependencies.** An organization can escape encryption while losing the information or services it requires from another organization.
3. **Evidence must retain its limits.** A sample's behavior is not every victim's history; a reported cancellation is not a measured health outcome; an attribution assessment is not a conviction.

The case closes with an original assurance model, a detailed tabletop scenario and testable restoration criteria. These are analytical proposals, not NHS procedures, validated product capabilities or activities performed for this study.

## 1. Scope, terminology and evidence discipline

### What is being reconstructed

The historical core is the May 2017 outbreak and the NHS response in England. Later material includes official reviews, attribution announcements through 2018 and subsequent cost descriptions. The study does not establish the first infected computer, a complete worldwide victim count, an exact global loss, present criminal-case status or a causal estimate of patient mortality.

“Confirmed” in this article means a specified primary record supports the bounded statement, not that every underlying event has been independently reproduced. A government publication can reliably establish what the government reported while still containing an estimate, a classification revision or a mistaken generalization. A vendor analysis can establish observed sample functionality without proving that functionality executed successfully on every host.

“Analytical” identifies this study's reasoning, proposed controls and hypothetical examples. Such passages should be judged as arguments with explicit assumptions. They are not hidden additions to the historical record. The same distinction applies to the ATT&CK mapping: classification helps organize observations but does not create additional evidence.

### Five distinctions worth keeping visible

**Vulnerability versus exploit versus malware.** A vulnerability is a weakness. An exploit uses a weakness. A malware family can contain multiple components, change over time and use an exploit written elsewhere. Treating those as synonyms obscures both remediation and attribution.

**Available versus installed.** Availability describes the supplier's action. Installation describes a change on an asset. Verification describes evidence that the intended protective state exists. A dashboard can confuse all three unless its fields are carefully defined.

**Infected versus affected.** Infection is a technical condition. Affected is a service-impact category that may include interruption without infection. The categories may be based on organizational reporting rather than a uniform retrospective forensic examination.

**Stopped spreading versus restored.** Interrupting propagation changes future risk. It does not reconstruct encrypted records, reconcile paper transactions or prove that a previously compromised machine is trustworthy.

**Attributed versus adjudicated.** A technical association, an intelligence assessment and a criminal charge have different authorities, methods and standards. A responsible case study preserves those differences even when the records point in a similar direction.

## 2. Before the outbreak: the warning-to-action gap

### The security bulletin

MS17-010 is a Microsoft bulletin, not a CVE. Its table covers CVE-2017-0143 through CVE-2017-0148. The most serious listed effects include remote code execution through specially crafted SMBv1 messages; one listed issue concerns information disclosure [2]. The distinction matters when building a vulnerability register: recording a bulletin as if it were a unique vulnerability can distort counts, patch applicability and exception handling.

Microsoft's contemporary malware analysis names CVE-2017-0145 in its account of EternalBlue-based propagation [1]. Historical accounts use exploit and vulnerability labels inconsistently. This study therefore does not silently assign the entire outbreak to a single CVE. The operational remediation reference remains the relevant update and platform applicability, while any narrower exploit claim retains its source.

The analytical lesson is to maintain a chain from vendor advisory to affected product version, asset, responsible team, planned change and verification result. A single “WannaCry patched” field cannot explain whether a machine received a suitable update, had the vulnerable service removed, became inaccessible across the relevant boundary or simply stopped reporting.

### What the NHS warning record actually says

NHS Digital's written evidence describes a 17 March weekly advisory, an independently published portal advisory on 25 April and a further weekly bulletin on 28 April. It says the March warning concerned the vulnerability, not a then-known WannaCry campaign. It also explains that limited knowledge of local architecture prevented precise targeting. Crucially, it later distinguished tracking patch downloads from confirming installation [17, sections 3.2 and 3.6].

Those details change the question from “Was anyone warned?” to “What happened after the warning?” A distribution list measures delivery opportunities. An acknowledgement measures receipt. A remediation plan measures intended work. None alone answers whether a particular machine remained exploitable when another host could contact it.

Consider an original hypothetical sequence. A central team emails a critical advisory. A local mailbox receives it. An engineer identifies most relevant servers but misses a vendor-managed appliance. A change ticket is approved for the servers. One machine cannot restart because it supports a time-sensitive service. The dashboard records the package as deployed because the installer ran. The exception is discussed in a meeting but lacks an expiry date. Every participant may have performed a recognizable task, yet the vulnerable condition can remain.

This is not a claim that this sequence describes a particular NHS trust. It demonstrates why assurance requires linked evidence rather than evidence of isolated effort. To close the loop, the process needs both positive proof of success and a visible account of what did not succeed.

### The maintenance dilemma is real, but not self-resolving

The Public Accounts Committee subsequently emphasized the difficulty of updating equipment without disrupting care, supplier-controlled systems and shortages of relevant skills. It also reported that all 200 trusts assessed at the time of its evidence session had failed the assessment, while noting the demanding standard and continuing patch failures [9]. That is a preparedness finding, not an infection total.

An analytical response should avoid two unhelpful extremes. “Patch immediately regardless of consequences” can ignore an immediate operational hazard. “We cannot interrupt the service” can become an indefinite exemption without a compensating measure. The useful decision is narrower: which change can be made safely now, what exposure remains until the rest is completed, who owns that exposure and when will the decision be revisited?

A meaningful exception names the device, dependency and constraint. It records what has been attempted, the supplier's position, permitted network paths, the fallback workflow and the next decision date. It must be possible to challenge the exception without first reconstructing months of informal discussion. Approval should not make the residual risk disappear from reporting.

## 3. Dated chronology: events, publications and revisions

The following table is a selective chronology, not an hour-by-hour reconstruction of every infection. Times in the NHS response rows are those printed in the cited British reports; they are not converted into a universal time zone.

| Date or time | Bounded event | Evidence category |
|---|---|---|
| 14 March 2017 | MS17-010 published | Vendor bulletin [2] |
| 17 March | Vulnerability included in CareCERT weekly advisory | NHS Digital's later account [17] |
| 14 April | Shadow Brokers release referenced in the later malware profile | Vendor reconstruction [14] |
| 25 and 28 April | Portal advisory, then weekly bulletin | NHS Digital's channel-specific account [17] |
| 12 May | Outbreak and technical investigation | Contemporary vendor reporting [1][15] |
| 12 May, 13:06 | Notification to NHS England's emergency-response team | NAO timeline [8, figure 2] |
| 12 May, 16:00 | National major incident declared | NAO timeline [8] |
| 12 May, 18:45 | NHS England response leadership decision recorded | NAO timeline [8] |
| 12 May | Researcher's domain registration interrupts the analyzed behavior | First-person account [5] |
| 13 May | Exceptional updates offered for additional older platforms | Microsoft emergency guidance [4] |
| 19 May, 17:30 | NHS England incident stood down | NAO timeline [8] |
| 27 October 2017 | NAO investigation published online | Official report landing page [3] |
| 19 December 2017 | UK public attribution | Government assessment [6] |
| February 2018 | CIO lessons review explains reclassification | Official review [11] |
| April 2018 | Parliamentary scrutiny and revised NAO printing | Committee findings and PDF front matter [9][8] |
| 6 September 2018 | Park Jin Hyok complaint made public | DOJ announcement of allegations [7] |

Two analytical cautions follow. First, detection time is not necessarily infection time. The first report reaching an incident team is an observation about communication, not proof of the attacker's first action. Second, the publication date of a page does not guarantee that every sentence was present on that date. Living advisories and revised PDFs need version-aware citations.

The interval between March's bulletin and May's outbreak is important without requiring an invented countdown of organizational negligence. A case study cannot infer how much usable maintenance time every owner had from calendar subtraction alone. It can, however, ask whether the organization used that interval to identify exposure, plan changes and verify completion.

## 4. The technical chain, with sample boundaries

### Propagation changes the shape of the emergency

Microsoft described a dropper with separate propagation and ransomware components, a connection check that could stop execution and a service named `mssecsvc2.0`. Its early report explicitly did not establish the precise initial entry vector [1]. Accordingly, “a phishing email caused WannaCry” is not adopted here as a universal explanation.

Talos observed scanning of both the local subnet and external addresses over TCP 445, along with use of EternalBlue and DoublePulsar-related functionality. Its report distinguished the ransom-display executable from the underlying encryption work and described attempts to interfere with recovery [15]. These are vendor observations about analyzed material, not a packet-level reconstruction of the NHS outbreak.

The analytical significance is the difference between repeated user action and automatic opportunity. A user-mediated delivery chain must repeatedly reach someone willing or able to execute a payload. A worm can instead turn one accessible vulnerable host into another scanning source. That changes the defender's useful unit of investigation: a single endpoint alert must prompt questions about reachable peers and trust boundaries, not only about the person using that endpoint.

This does not mean every scanned host is compromised. A connection attempt, a listening service, successful exploitation, payload execution and encryption are separate stages. A report that collapses them will inflate confirmed infections or obscure where an effective boundary stopped the chain.

### Storage damage is not identical to network spread

Secureworks' analysis describes local-subnet and external scanning, but distinguishes that propagation from file enumeration. Its sample targeted local, removable and mapped network drives rather than searching for unmapped shares. It describes hybrid RSA/AES encryption, recovery-inhibition commands, process termination intended to free data stores and Tor-based communications [13].

The distinction creates a useful two-axis investigation. One axis asks where code could travel. The other asks what data a running process could access. A file server might suffer damage through a writable mapping even when the ransomware did not execute on that server. Conversely, a host might receive a malicious executable without every business dataset being reachable from it.

For defenders, a network map without an access map is incomplete. The analyst should separately record source process, host identity, account context, storage path and evidence of modification. Where telemetry is missing, the report should say so rather than fill the gap with a plausible but unverified infection story.

### Persistence, encryption and the ransom interface

The Mandiant profile describes registry Run entries, service creation, an encrypted DLL providing encryption functionality, periodic checks for newly attached drives and distinct files used for configuration and key material. It also describes ransom-interface operations and communication through Tor [14]. The important architectural point is that the visible ransom window is only one part of a larger process.

This supports an analytical warning about superficial recovery. Removing a window, deleting a conspicuous file or making a machine boot again does not establish that all components are gone. Nor does disappearance of the user-visible symptom prove that accessible data remained unchanged. Recovery needs evidence about the machine's state and the service's integrity, not only a screenshot of a normal desktop.

A historical filename is useful as a lead, not a complete detection strategy. Names can change; legitimate software can produce superficially similar activity; logging may omit the relevant event. A stronger investigation relates multiple observations in time and checks whether they fit the proposed chain. Service creation followed by scanning and unusual file modification is a different evidential package from one isolated string match.

### Exceptional patches were an emergency measure

Microsoft's emergency guidance made updates broadly available for Windows XP, Windows 8 and Windows Server 2003, described as platforms in custom support. Its page also includes a later 22 May removal-tool update [4]. Neither statement should be read as a permanent restoration of ordinary support for obsolete platforms.

Analytically, emergency support is a bridge, not an operating model. If a system's continued use depends on a vendor choosing to publish an exceptional fix during a crisis, the organization has not established a dependable maintenance pathway. A migration plan should identify what remains dependent on that exception and what business decision is required to remove the dependency.

## 5. The domain intervention: mechanism before mythology

Marcus Hutchins' account describes registering an unregistered domain during analysis, initially without knowing that registration would inhibit the sample. Conflicting interpretations prompted a controlled comparison: successful connection was associated with non-execution, failed connection with ransomware activity. His proposed anti-sandbox explanation was a hypothesis, and he warned that altering the check could defeat the intervention [5].

The term “kill switch” is memorable but can hide conditions. For a control decision, the useful question is not whether a domain has a dramatic nickname. It is what the specific program does when a connection succeeds or fails, whether the affected host can make the required connection and whether the observed sample matches the one under discussion.

CERT-EU's evolving advisory documented additional variants and limited recovery possibilities. It warned that proxy arrangements could interfere with the connection behavior and later described a recovery tool that might work under particular conditions, including an unrebooted system [16]. That is not a universal decryptor or a guarantee of recovery.

The analytical distinction between interruption and repair is fundamental. Preventing another execution does not decrypt an already altered file. It does not prove that a machine is clean. It does not apply a security update. It does not re-create a lost appointment or undo a precautionary closure. Each of those requires a different action and a different form of evidence.

The case also illustrates why a generic rule such as “block every domain associated with malware” can be inadequate. A domain's role must be understood before an emergency control is applied. This historical example is not an instruction to change present network policy or contact an old indicator. Contemporary ownership, behavior and authorization would need fresh assessment.

A successful research intervention should therefore be treated as time gained. The responsible operational response is to use that time to close exposure and restore services, while planning for the possibility that the intervention will cease to work. Building continuity around the assumption that an outsider will discover another interruptible branch would confuse an exceptional rescue with a repeatable capability.

## 6. NHS impact: count the right thing

### A denominator ledger

The NAO's currently served PDF reports at least 80 affected trusts out of 236: 34 infected and locked out, plus 46 reporting disruption without that classification. It records 595 infected GP practices and eight other organizations. It distinguishes 6,912 identified cancellations from an estimated 19,494 total. Twenty-one additional trusts contacted the domain without being locked out; such traffic could reflect security activity [8, figures 1–2 and paragraphs 1.2, 1.8].

| Measure | Meaning in this study | What it does not mean |
|---|---|---|
| Affected trusts | Organizational impact category | Number of encrypted computers |
| Infected and locked-out trusts | Reported infection category | Every device in those trusts was encrypted |
| Disrupted without that classification | Service interruption, including precautionary action | No possible infected device anywhere in the organization |
| Infected GP practices | Practice-level count | Additional hospital trusts |
| Domain contacts | Investigative signal | Confirmed encryption or a unique victim count |
| Identified cancellations | Recorded service events | Complete total or number of distinct patients |
| Estimated cancellations | Estimate addressing incomplete reporting | Additional cancellations to add to the identified figure |
| Assessment failures | Preparedness result at an assessment date | Infections during the outbreak |

The distinction between a cancellation and a person is particularly important. A person may have more than one appointment. A cancellation can be rescheduled. A delayed result may disrupt care without generating a cancelled appointment in the same reporting system. These observations do not reduce the significance of disruption; they prevent a single administrative metric from pretending to describe every consequence.

### The 80-versus-81 discrepancy is explainable

The NAO landing page still gives at least 81 affected trusts [3]. The CIO review explains that four trusts challenged their categorization and reclassification changed the headline number from 81 to 80 [11, printed page 5, footnote 3]. The downloaded NAO PDF carries an April 2018 printing date while retaining the October 2017 report signature [8]. The older web summary and revised document should therefore be identified as different record states, not averaged together.

Other discrepancies remain. The CIO review gives 27 acute trusts within its infected category, whereas the NAO PDF gives 25. This study does not manufacture a reconciliation. It uses the broader categories and leaves the acute subtotal out of its headline. An explanatory note is preferable to selecting a figure because it makes a slide cleaner.

### Supported software can still be exposed

NHS Digital's written evidence says most infected systems ran Windows 7, with patching and firewall settings the central issues. It separately describes vendor-controlled medical equipment that could not simply be upgraded by local staff [17]. “An XP-only disaster” is therefore an inadequate account.

The analytical mistake in that slogan is broader than this case. Product age is a proxy, not a complete exposure assessment. Supported software can be unpatched. Unsupported equipment can be isolated, although isolation requires verification and carries operational constraints. A useful inventory must represent support status, installed state, reachability and business dependencies separately.

### Service failure can cross an uninfected boundary

Consider an original hypothetical diagnostic pathway: a machine acquires an image, a workstation processes it, a storage system retains it, a clinical application displays it and a referring service receives the result. If one link is unavailable, the patient-facing pathway can fail even when the acquisition device still works. If a receiving organization disconnects to protect itself, the interruption can cross an organizational boundary without malware doing so.

A continuity assessment should therefore follow a transaction from request to completed use, not stop at the availability of each individual component. “Scanner operational” is not the same statement as “clinicians can receive and interpret results.” The same reasoning applies to prescriptions, discharge information, laboratory processing and appointment scheduling, without claiming that each particular failure occurred everywhere during WannaCry.

## 7. Coordination: who can advise, decide and verify?

The CIO review assigns distinct roles to the department, NHS England, NHS Digital, oversight bodies and local organizations. NHS England coordinates the major-incident response; NHS Digital supplies technical support and national infrastructure expertise; local bodies retain operational responsibilities. The review recommends clearer accountability, supplier management, joint exercises and alternative communications [11, sections 4–5]. These are historical roles and recommendations, not a description of today's NHS structure.

### Why sending the right advice is insufficient

An analytical responsibility model needs four separate verbs: **identify**, **authorize**, **implement** and **verify**. The team identifying a vulnerability may lack authority to stop a clinical service. The executive authorizing downtime may lack access to the equipment. The supplier implementing a patch may not see the wider network. The person validating service restoration may not know what security exposure remains.

The failure mode is not necessarily that nobody owns anything. It can be that several people own adjacent tasks while nobody owns the handoff. A completed task can then become evidence of somebody else's assumed completion. The remedy is an explicit interface: what is delivered, to whom, by when, in what form and with what escalation if it does not arrive.

A proposed accountability record would identify:

- the service owner who can explain the consequence of downtime;
- the technical owner who can establish the asset's condition;
- the change authority who can approve the intervention;
- the supplier responsible for restricted equipment;
- the incident coordinator who resolves cross-service conflicts;
- the reviewer who checks closure evidence independently of the implementation claim.

These roles may be held by fewer people in a small organization. The distinction is about decisions, not organizational size. Adding committees without clarifying the decision can make a response slower rather than safer.

### Communications are part of the control environment

The parliamentary review reports fragmented reporting routes and the loss of normal email, with staff using personal phones and WhatsApp [9]. The analytical lesson is not to elevate a particular messaging application into a universal emergency standard. It is to establish a communication method whose availability, access and operating rules survive the incident being planned for.

A tested alternative should answer practical questions. Can the responder obtain the contact directory without the affected identity system? Can participants authenticate urgent instructions? Can shift replacements join? Can sensitive information be handled appropriately? Who records decisions made verbally? How does a regional team avoid requesting the same update from an overwhelmed local engineer through three separate channels?

An incident report should distinguish communication success from data quality. Everyone can receive a status message that is still stale or ambiguous. A concise shared status format should separate observed facts, estimates, actions underway, dependencies and decisions needed. “Restoring” is less useful than “application restored in isolation; authentication dependency unverified; service owner has not accepted return to use.”

### Staff effort is not a substitute for sustainable capacity

It is possible to recognize extraordinary effort while still criticizing the system that required it. An analytical review should ask which work depended on informal relationships, exceptional overtime or one person's memory. Those may have been effective during the emergency and still be unsuitable as the planned control for the next one.

A sustainable response needs relief shifts, decision logs, realistic task ownership and a mechanism for transferring context. Fatigue is not solved by adding another status call. It is managed by reducing duplicated demands, protecting focused restoration work and making the next shift able to understand what remains uncertain.

## 8. Attribution: preserve the level of the claim

On 19 December 2017, the UK publicly attributed the campaign to North Korean actors known as Lazarus Group, reporting an NCSC assessment of high likelihood [6]. On 6 September 2018, the U.S. Justice Department announced a complaint against Park Jin Hyok. Its account connected alleged participants to WannaCry development through malware and infrastructure relationships and expressly stated that charges were accusations, with the defendant presumed innocent unless proven guilty [7].

These are consequential statements, but they do not license a case study to invent a courtroom outcome. This study does not claim a conviction or current procedural status. It also does not equate the provenance of an exploit with the identity of the operator using it.

An analytical attribution ladder can help readers keep the reasoning straight:

1. A researcher identifies a behavior in a sample.
2. Multiple samples share code or configuration.
3. Infrastructure or operational records connect activity clusters.
4. An organization assesses responsibility using its evidence and methods.
5. A legal authority alleges specified conduct.
6. A court reaches a finding under its applicable process.

The existence of one rung does not establish all later rungs. A shared exploit can be widely available; a copied code fragment can have several explanations; an account can be used by multiple people. Conversely, refusing to distinguish evidence types does not make all attribution equally speculative. It makes the reader less able to evaluate the actual claim.

For a defender, actor naming and immediate protection are also different decisions. It can be appropriate to isolate a confirmed malicious process before knowing who operated it. It can be inappropriate to describe an individual as criminally responsible merely because a detection rule carries a familiar group label. Operational urgency does not remove the need for careful public language.

## 9. ATT&CK mapping as an analytical aid

MITRE's WannaCry software entry, S0366, lists behaviors including exploitation of remote services, Windows service creation, data encryption, file discovery, recovery inhibition and lateral transfer [12]. The table below selects a small subset. It is not a complete technique inventory or a claim that each technique occurred in every NHS organization.

| Behavior in the cited record | Analytical label | What an investigator would need |
|---|---|---|
| SMB-based remote exploitation [1][15] | T1210, Exploitation of Remote Services | Network and host evidence distinguishing attempts from success |
| Service creation [1][14] | T1543.003, Windows Service | Service event, binary identity, time and initiating context |
| Search for target files [13] | T1083, File and Directory Discovery | File-access or process evidence with an explicit visibility limit |
| Encryption of user data [13][14] | T1486, Data Encrypted for Impact | Confirmed changes, affected paths and a validated time window |
| Attempts to disable recovery [15] | T1490, Inhibit System Recovery | Relevant process activity and resulting recovery-state evidence |

The labels come from the current retrieved taxonomy; the evidence comes from historical technical analysis. That separation prevents a modern framework from being mistaken for a contemporary incident log.

Mapping is useful for organizing questions. It is much less useful when presented as a score that implies proven protection. A product's claim to cover T1210 does not show that the product was installed, correctly configured, receiving relevant telemetry or able to interrupt this incident under the affected organization's conditions.

An original validation plan would define the behavior to be observed, the available data source, the expected signal, the decision it should trigger and the limitations of the test. It would also record benign lookalikes. The output should be a statement such as “this controlled exercise produced the expected alert on these hosts with this configuration,” not “this technique is covered everywhere.” No such execution test was performed here.

## 10. What the figures can, and cannot, prove

### Cost is not ransom revenue

The 2023 government health-and-care cyber strategy reports an estimated GBP 20 million during the outbreak and GBP 72 million for restoration. Adding those figures gives GBP 92 million. Its cited cost reference is a 2018 trade-publication report, so the strategy is evidence that government repeated the estimate, not a newly performed cost audit [10].

The analytical point is to make cost categories explicit. Restoration invoices, internal staff time, lost output and cancelled activity can overlap. A later improvement program can include upgrades that would have been needed anyway. An estimate can omit important consequences while still being useful for a defined purpose. None of those complications is solved by calling a rounded number “the cost.”

A future incident cost ledger should distinguish incurred expenditure, estimated opportunity cost and unquantified effects. Each item needs a period, organizational scope, estimation method and overlap note. If an organization reports both staff overtime and the full cost of the same staff hours, the ledger must prevent double counting. If a cancelled service is later delivered, the economic question is not automatically identical to permanent loss of that service.

### Absence of a report is not proof of absence

The NHS record did not establish patient deaths or a quantified clinical-harm total from WannaCry. The relevant reports describe what organizations reported and acknowledge incomplete impact information [3][8]. A responsible article should neither invent harm nor translate a reporting limitation into proof that disruption had no consequences.

Analytically, this is a general measurement problem. A system designed to count cancelled appointments may not capture anxiety, extra travel, delayed communication or work deferred outside the reporting period. A technical incident register may record restored servers without capturing time spent reconciling records. Expanding the measurement plan is appropriate; retroactively assigning unsupported numbers is not.

The same principle applies to data theft. Encryption, exfiltration and confidentiality loss are different questions. A finding about the analyzed malware's functionality does not establish every event on every compromised system, and inability to read data is itself a serious availability problem without a claim that the data was stolen.

## 11. An original assurance model: from notification to service confidence

The following model is this study's proposed operational synthesis. It is not an official NHS standard and has not been validated through implementation. Its purpose is to turn the historical lesson into a set of decisions that can be inspected.

### Stage A: establish the asset population

Start with the service, then identify its technical dependencies. A management platform's inventory is a useful input, not automatically the complete population. Compare it with procurement records, network observations, supplier inventories and service-owner knowledge. Record disagreements rather than silently preferring the neatest dataset.

For each material asset, capture a stable identifier, owner, location or segment, supported function, maintenance authority, product state and last verified observation. Include devices that do not run the standard management agent. A system excluded from a patch report must appear somewhere else with an explicit reason.

The acceptance criterion is not “the inventory has many rows.” It is that the organization can explain how missing assets are discovered and how conflicting records are resolved. Sample a service pathway end to end. If its owner relies on a device absent from the technical register, the inventory process has found work to do, not an inconvenience to hide.

### Stage B: determine applicable exposure

Translate the advisory into a set of affected conditions. Avoid matching only on a product family when version, configuration or service state matters. Distinguish confirmed affected, confirmed not affected and unresolved. Unresolved must not default to safe merely because no agent response was received.

Reachability should be evaluated from the places that matter: external boundaries, neighboring segments, management networks and required suppliers. Document authorized business paths and test the actual boundary under approved conditions. A diagram showing separation is not evidence that an access rule enforces it.

A useful output is a short list of reachable unresolved assets tied to services and owners. This is more actionable than an enterprise-wide percentage that obscures a small number of highly consequential exceptions. Prioritization should remain transparent about uncertainty rather than presenting an invented risk score as a measured probability.

### Stage C: authorize a safe change

Bring operational and technical owners together before the maintenance window. Define what success looks like, what failure looks like and how the service will continue if the change cannot finish. Identify whether supplier approval or specialized validation is required. Set a decision time for escalation instead of allowing a stalled change to drift.

An exception must have an owner, residual exposure, compensating action and expiry. If the expiry arrives without a durable remedy, the organization should make a new explicit decision. Repeated extensions should be visible to the authority able to fund replacement or alter the service dependency.

This does not require pretending that every legacy system can be replaced quickly. It requires the opposite: an honest account of what cannot yet be done, why and what protects the service in the meantime.

### Stage D: verify the protective state

Use evidence appropriate to the mechanism. An installation log can support one part of the claim; an authenticated configuration check can support another; a controlled reachability test can support a boundary claim. Record observation time, scope and exclusions. A successful check on one server should not automatically populate every member of a cluster as safe.

Verification also needs failure states. “No response” may mean powered off, disconnected, unreachable by the verifier or unmanaged. It is not equivalent to “not vulnerable.” An assurance report should separate these conditions so that the business owner knows what confidence is justified.

For a sample of completed changes, have someone other than the implementer review the evidence. The aim is not ritual sign-off. It is to discover whether a recurring reporting shortcut is allowing the same error across many assets.

### Stage E: prove the service still works

A protected machine can support a broken service. Test a representative transaction with the people who use the system. Confirm required data access, downstream delivery and the ability to recover from a routine failure. Keep the service test distinct from the security-state check; both must pass for closure.

For a clinical environment, qualified local clinical and engineering authorities must determine the appropriate operational validation. This article supplies no medical procedure or device-maintenance instruction. The transferable principle is that technical teams should not declare a patient-facing service restored solely because its server responds.

### Stage F: retain and revisit exceptions

Protection is not a permanent property conferred by closing a ticket. Configuration changes, replacement devices, restored images and new dependencies can reopen exposure. Tie exceptions and verified states to review triggers. When an old system returns from storage or a supplier changes an integration, require the affected assumptions to be checked again.

A concise executive report should show verified completion, unresolved assets, overdue exceptions and service consequences. It should make the remaining decisions visible. A board can then act on a named dependency instead of being offered a reassuring percentage with an unknown denominator.

## 12. A detailed tabletop: restoring a regional service without normal tools

This is an original fictional exercise, not a reconstruction of a named trust. No malware should be deployed and no live clinical system should be disrupted to run it. Use prepared injects, synthetic logs and approved nonproduction demonstrations. The facilitator should stop any activity that would create an unapproved operational or information-security risk.

### Starting situation

A regional provider has three sites, a shared diagnostic workflow, a vendor-managed device and a central support team. A vulnerability notice was distributed weeks earlier. Most standard workstations show successful deployment, but several devices are absent from the report. The backup dashboard is green; no recent end-to-end service restoration has been witnessed by the service owner.

On a Friday afternoon, two locations report a ransom window. A third location disconnects its network before confirming infection. Email becomes unreliable. A partner asks whether results can still be exchanged. A supplier says the managed device needs a maintenance window and specialist approval before any update.

The exercise is designed to test decision quality under incomplete information, not whether participants remember the name EternalBlue.

### Inject 1: the first signal is ambiguous

Provide a screenshot, a host identifier and a report of unusual outbound connections. Ask the team to state what is known, what is suspected and what evidence would discriminate between alternative explanations. They should not label the entire estate infected from one screenshot, but they should not wait for perfect certainty before evaluating containment.

Expected output: an incident owner, an initial scope statement, a preservation plan and a list of immediate service risks. Record who can authorize isolation and what information that person needs. If nobody can make the decision, that is an exercise finding rather than a reason to invent authority.

### Inject 2: an uninfected site loses a critical dependency

Tell participants that the disconnected site cannot receive diagnostic results, although its local workstations appear normal. Ask them to classify the impact without adding it to the confirmed-infection count. Then require a service-preserving alternative agreed by the relevant operational owner.

Expected output: separate technical and service-status fields, a dependency owner, a safe fallback and a review time. The team should identify who else relies on the same dependency. The facilitator should challenge any claim that the site is unaffected merely because no encrypted device has been found.

### Inject 3: the patch dashboard contradicts local evidence

Supply a management report showing success and a synthetic local record showing the required protective state is absent. Ask the team to explain the discrepancy and identify which other assets might share it. The exercise should reward a revision of confidence, not defensive insistence that the dashboard must be right.

Expected output: a corrected asset status, a testable explanation, a scoped review of similar assets and a record of the reporting defect. The organization should preserve both observations with their times instead of overwriting history to make the final report look consistent.

### Inject 4: the normal contact directory is inaccessible

Make the usual identity service unavailable in the exercise. Require the next shift to join the response using the alternative contact process. Introduce a conflicting instruction supposedly from a senior leader and ask how it will be authenticated.

Expected output: a working alternate coordination route, verified participants, one decision log and a standard situation report. Participants should identify where confidential information can safely be exchanged and where only operational status should be shared. A personal messaging group may be part of an approved plan, but it should not be improvised without considering access, retention and confidentiality.

### Inject 5: technical restoration precedes service restoration

Announce that servers have been rebuilt and files restored. Then reveal that some records were created manually during downtime and one downstream interface contains a backlog. Ask who can accept the service back into use and what reconciliation is required first.

Expected output: evidence of clean technical state, verified data integrity, a backlog plan, explicit service-owner acceptance and monitoring for recurrence. A successful backup-job status is not sufficient. The response should distinguish “available for testing,” “available with restrictions” and “returned to normal operation.”

### Inject 6: the emergency is ending, the exception is not

The vendor-managed device remains isolated. Senior leaders want to close the incident. Ask the team to identify whether emergency status can end while a controlled exception remains, and what obligations survive that decision.

Expected output: a named exception owner, approved compensating measures, replacement or update milestones and a scheduled review. The exercise should not force the false choice between keeping the entire emergency open indefinitely and pretending every risk has vanished.

### Scoring the exercise without false precision

Use observable criteria: time to identify authority, quality of the impact classification, ability to communicate without normal tools, completeness of the exception record and evidence supporting restoration. Do not reduce the exercise to an unexplained numerical maturity score.

The most valuable finding may be a handoff that fails repeatedly. For example, the technical team may know which host is vulnerable while the service team cannot identify the supplier contract. That is an actionable process defect. “Improve awareness” is too vague unless it identifies who needs to recognize what and what decision should follow.

## 13. Questions an editor, investigator or board should ask

Before publishing a WannaCry figure, ask what is being counted, the observation period, the geographic scope and whether the number is observed, estimated or revised. Before publishing a mechanism, ask which sample or source supports it. Before publishing an attribution, preserve the speaker, date, confidence and legal status.

Before accepting a remediation claim, ask which assets were excluded, how installation was checked and what happens when the verifier cannot reach a device. Before accepting a segmentation claim, ask which paths were actually evaluated and who approved the remaining dependencies. Before accepting recovery, ask who used the restored service and what evidence shows its records and downstream operations are coherent.

These are deliberately different questions. A polished incident narrative can answer one while silently implying the others. The purpose of a long-form case study is not to overwhelm the reader with identifiers. It is to expose those boundaries so that the next decision is better grounded.

## Conclusion

WannaCry should not be remembered only as an old Windows vulnerability, an exceptional domain registration or a dramatic ransom screen. Its enduring value as a case study is the interaction between technical exposure and institutional coordination.

A remedy can exist without being deployed. A machine can be uninfected while its service is disrupted. A region can stop an emergency response while substantial restoration work remains. A public record can be authoritative yet revised or internally inconsistent. A behavior can fit an ATT&CK label without proving that a particular control will stop it.

The strongest practical lesson is to make each transition explicit: warning to owner, owner to action, action to verification, verification to service acceptance and temporary exception to durable resolution. That chain is less memorable than a single patch number, but it is the chain on which reliable protection depends.

## Sources and review limits

The complete extracted text of the 35-page NAO PDF and 42-page CIO review was read, including appendices. This is not a claim of pixel-by-pixel inspection of every graphic. Other sources were read at the relevant passages noted below, not every linked page, attachment or reference. No malware was detonated, exploit reproduced, live environment scanned or control tested. No new patient-outcome research or cost audit was performed. The accompanying PDF preserves this manuscript; the briefing is a selective summary with the same evidence boundaries.

[1] Microsoft Security, 12 May 2017, [WannaCrypt ransomware worm targets out-of-date systems](https://www.microsoft.com/en-us/security/blog/2017/05/12/wannacrypt-ransomware-worm-targets-out-of-date-systems/). Attack vector, dropper and ransomware passages; living page with later additions.

[2] Microsoft, 14 March 2017, [Security Bulletin MS17-010](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010). Executive summary and vulnerability/platform table.

[3] National Audit Office, 27 October 2017, [Investigation landing page](https://www.nao.org.uk/reports/investigation-wannacry-cyber-attack-and-the-nhs/). Web summary retains the earlier 81-trust figure.

[4] Microsoft MSRC, 13 May 2017, [Customer guidance for WannaCrypt attacks](https://www.microsoft.com/en-us/msrc/blog/2017/05/customer-guidance-for-wannacrypt-attacks). Emergency support announcement and dated update.

[5] Marcus Hutchins, 13 May 2017, [How to Accidentally Stop a Global Cyber Attacks](https://www.malwaretech.com/2017/05/how-to-accidentally-stop-a-global-cyber-attacks.html). First-person registration and behavior-testing account; intent hypothesis not adopted as fact.

[6] UK Foreign Office, 19 December 2017, [North Korean actor attribution](https://www.gov.uk/government/news/foreign-office-minister-condemns-north-korean-actor-for-wannacry-attacks). Attribution wording; not used as the authoritative NHS impact count.

[7] U.S. Department of Justice, 6 September 2018, [North Korean programmer charged](https://www.justice.gov/usao-cdca/pr/north-korean-regime-backed-programmer-charged-conspiracy-conduct-multiple-cyberattacks). Allegations and presumption-of-innocence statement; complaint itself not fully reviewed.

[8] National Audit Office, [Investigation PDF](https://www.nao.org.uk/wp-content/uploads/2017/10/Investigation-WannaCry-cyber-attack-and-the-NHS.pdf). Full extracted text read; retrieved version has April 2018 printing information and revised 80-trust headline.

[9] House of Commons Public Accounts Committee, April 2018, [Conclusions and recommendations](https://publications.parliament.uk/pa/cm201719/cmselect/cmpubacc/787/78705.htm). Preparedness, communications and equipment-maintenance findings.

[10] Department of Health and Social Care, 22 March 2023, [Cyber security strategy to 2030](https://www.gov.uk/government/publications/cyber-security-strategy-for-health-and-social-care-2023-to-2030/a-cyber-resilient-health-and-adult-social-care-system-in-england-cyber-security-strategy-to-2030). WannaCry case-study subsection and its cost footnote.

[11] William Smart, February 2018, [Lessons learned review](https://www.england.nhs.uk/wp-content/uploads/2018/02/lessons-learned-review-wannacry-ransomware-cyber-attack-cio-review.pdf). Full extracted text read; especially reclassification footnote, organizational responsibilities and recommendations.

[12] MITRE ATT&CK, [WannaCry, S0366](https://attack.mitre.org/software/S0366/). Technique table retrieved 14 November 2026; page shows version 1.1 and modification date 7 October 2026. Taxonomy reference, not a contemporary incident log.

[13] Secureworks Counter Threat Unit, [WCry ransomware analysis](https://www.sophos.com/en-us/research/wcry-ransomware-analysis). Original Secureworks address redirects to this hosting page. Delivery, infection, encryption and communications passages checked; not independent malware testing.

[14] Alex Berry, Josh Homan and Randi Eitzman, 23 May 2017, [WannaCry malware profile](https://cloud.google.com/blog/topics/threat-intelligence/wannacry-malware-profile). Mandiant/FireEye-origin analysis, now Google-hosted; selected component and encryption passages.

[15] Cisco Talos, 12 May 2017, [Player 3 Has Entered the Game: Say Hello to WannaCry](https://blog.talosintelligence.com/wannacry/). Scanning, components and recovery-interference analysis; investigation described as evolving.

[16] CERT-EU, advisory 2017-012, updated 22 May 2017, [WannaCry ransomware campaign](https://cert.europa.eu/publications/security-advisories/2017-012/). Version history, connection caveat and conditional recovery discussion.

[17] NHS Digital, 31 January 2018 version 1.2, [Submission for the Public Accounts Committee](https://www.parliament.uk/globalassets/documents/commons-committees/public-accounts/written-evidence/wca0004.PDF). Selected sections 1.2, 2, 3.2, 3.4 and 3.6; first-party account, not independent validation of every assertion.

[18] NHS England Digital, [Archived alert CC-1411](https://digital.nhs.uk/cyber-alerts/2017/cc-1411). Consulted for provenance and its explicit outdated/inaccurate-content warning; not treated as current operational guidance.
