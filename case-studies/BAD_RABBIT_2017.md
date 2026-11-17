# Bad Rabbit, 2017: One Fake Update, Several Ways to Spread

*A TeamStarWolf case study. Published 15 November 2026.*

[All case studies](/case-studies/README.md) · Related: [Ransomware Defense & Resilience](/RANSOMWARE_DEFENSE_REFERENCE.md), [Malware Analysis Reference](/MALWARE_ANALYSIS_REFERENCE.md), [Endpoint Security Reference](/ENDPOINT_SECURITY_REFERENCE.md), [Incident Response Reference](/INCIDENT_RESPONSE_REFERENCE.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Endpoint and identity defenders, incident commanders, vulnerability-management teams, service owners and security educators

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 19 min (4,344 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You want an evidence-bounded account of the 2017 Bad Rabbit outbreak, you need to separate a fake-update entry from exploit-driven and credential-driven spread, or you are planning a related tabletop exercise

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Executive summary](#executive-summary), [The analytical model: separate the transitions](#the-analytical-model-separate-the-transitions), [Defender worksheet: test the claims that matter](#defender-worksheet-test-the-claims-that-matter)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Ransomware Defense & Resilience](/RANSOMWARE_DEFENSE_REFERENCE.md), [Malware Analysis Reference](/MALWARE_ANALYSIS_REFERENCE.md), [Endpoint Security Reference](/ENDPOINT_SECURITY_REFERENCE.md), [Incident Response Reference](/INCIDENT_RESPONSE_REFERENCE.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## Executive summary

Bad Rabbit illustrates why an infection chain needs more than one label. The first visible step can be a person running a deceptive software installer. Later steps can use credentials, administrative services or an exploit to reach other computers. Calling the entire event a fake-update attack understates the network risk. Calling it an exploit-driven outbreak can hide the initial software-trust failure. Both shortcuts can lead a defender to choose a control that addresses only part of the problem.

The October 2017 outbreak also provides a useful lesson in the evolution of incident knowledge. Contemporary technical reports were updated as researchers clarified propagation and encryption behavior. A statement that no exploit was needed for the initial web-delivered installer does not mean no exploit was present anywhere in the malware's spreading behavior. A claim about a tested patch stopping one route does not establish that every route has been blocked.

This study treats those distinctions as the basis of a defensive model. It separates web exposure, authorized execution, local privilege, cross-host authority and recovery. Each transition has its own owner and evidence requirement. The model asks what prevents one employee's software decision from becoming a network-wide service interruption, then asks how the organization can prove that restoration has removed the conditions that enabled the spread.

The central recommendation is to test controls as a chain of bounded decisions. Verify how software becomes trusted. Verify what authority an ordinary workstation can exercise over other systems. Verify the scope of a patch result. Verify that recovery returns a useful service within a trustworthy administrative environment. These are proposed analytical practices, not findings about the internal defenses of any named victim.

## Scope and evidence discipline

The historical center is the outbreak observed on October 24, 2017. The main source set consists of original research by Kaspersky, Cisco Talos and ESET, a Microsoft retrospective and Microsoft's original MS17-010 bulletin. The technical blogs contain updates. Their final accessible text should not be assumed to have been available in full on the initial publication date.

Each source has a particular vantage point. Malware analysis establishes properties of examined samples. Telemetry establishes observations within a vendor's visibility. A patch test establishes an outcome under specified test conditions. A product retrospective explains the vendor's view of its defenses. None of those alone is a complete worldwide census of affected organizations or a verified account of every victim's entry path.

The local published case-study filenames and existing Drive draft folders were checked for a dedicated Bad Rabbit study. None was present. This is a focused addition alongside the existing NotPetya material, not a claim that the name was absent from every chronicle or historical file. The study does not import NotPetya's losses, attribution or recovery experience into Bad Rabbit.

The analysis below deliberately avoids reproducing exploit code, credential lists, distribution endpoints or operational malware instructions. Historical observations remain concise and cited. Most of the article is original defensive reasoning, proposed evidence artifacts and a fictional exercise. Those sections should not be mistaken for newly discovered facts about the 2017 campaign.

## Historical record: five sources, different questions

### 1. Entry and recovery properties in Kaspersky's analysis

Kaspersky described a fake Flash installer delivered through compromised websites, requiring manual execution and elevated privileges. Its updated analysis also identified EternalRomance in internal propagation. The same report distinguished Bad Rabbit's encryption design from ExPetr/NotPetya: its analysis suggested the attackers had a technical route to recover necessary disk-decryption information. That finding was not evidence that paying reliably restored a victim. The report also discussed recovery limitations and conditional opportunities, not a universal free decryption method. [1]

### 2. Talos's updated propagation account

Talos published on October 24 and added material on October 25 and 26. It described credential-assisted SMB movement as well as EternalRomance, while reporting no evidence of EternalBlue in the examined Bad Rabbit behavior. Its analysis identified both file encryption and disk encryption using DiskCryptor components. It assessed codebase and build-toolchain similarities with Nyetya at high confidence, but the proposition that the same authors were responsible at low confidence. Those are different claims and must retain their different confidence levels. [2]

### 3. ESET's patch test and telemetry caveat

ESET's October 27 update said installing MS17-010 stopped the tested propagation through the IPC share, confirming the exploit-related finding. Its distribution figures described observed dropper encounters within ESET telemetry, not a global count of compromised companies. The report raised possible preexisting access at some organizations as a hypothesis under investigation. This study does not turn that hypothesis into an established second entry vector. [3]

### 4. Microsoft's later comparison

Microsoft's January 10, 2018 retrospective described Bad Rabbit's fake-installer entry and spreading behavior in the context of the year's ransomware outbreaks. It discussed the interaction of multiple defensive layers and contrasted different initial vectors across incidents. The article is a historical product-vendor account. Its product-effectiveness statements should not be republished as a guarantee that a present-day operating-system name alone determines whether an organization is safe. [4]

### 5. The patch predates the outbreak

Microsoft published MS17-010 on March 14, 2017, addressing vulnerabilities in Windows SMB Server. That date precedes the October outbreak. The bulletin provides the authoritative historical update context. It does not say that applying one update eliminates credential misuse, deceptive installation or every subsequent configuration risk. Those broader conclusions would exceed the bulletin's scope. [5]

## A chronology of both events and corrections

| Date | Evidence checkpoint | Editorial implication |
|---|---|---|
| March 14, 2017 | MS17-010 publication [5] | The relevant patch context predates Bad Rabbit |
| October 24, 2017 | Outbreak and initial technical publications [1][2][3] | Early reporting was provisional and visibility differed |
| October 25–26, 2017 | Talos adds encryption, propagation and code-linkage analysis [2] | Preserve update history instead of quoting an early conclusion as final |
| October 27, 2017 | ESET adds patch-test confirmation [3] | Identify the tested route rather than generalizing to all spread |
| January 10, 2018 | Microsoft's retrospective comparison [4] | Later synthesis is separate from first-day observations |

A robust case study should keep a correction log. If a source initially emphasizes one propagation method and later identifies another, the lesson is not that every early source was useless. It is that a defender needs a way to revise scope and controls as evidence improves. The operational danger comes from treating an early statement as a permanent boundary on what the malware can do.

## The analytical model: separate the transitions

The following sections present original defensive analysis unless a historical source is explicitly cited.

The proposed model has five transitions. A user encounters a software request. A file gains permission to execute. Execution obtains consequential local authority. Activity crosses to another host. The organization loses access to data or a service. These transitions can occur close together, but they are different decisions or technical conditions.

A control at the first transition can reduce exposure while leaving the later environment fragile. A control at the third or fourth transition can limit damage even after the user makes a mistake. Recovery capability reduces the duration and consequences of the final transition, but does not substitute for investigating how authority crossed the earlier boundaries.

The model is intentionally not an executable attack chain. It is a method for assigning defensive ownership. Browser and endpoint teams may own the first two transitions. Identity and platform teams own much of the authority question. Network and service owners determine which remote interactions are necessary. Incident command and business owners define the restoration criteria.

The most useful review asks what evidence demonstrates that each boundary behaves as intended. A written policy may state that users cannot install arbitrary software, but a controlled test may reveal an exception. A network diagram may show separated segments, but a shared support account may have broad authority across them. The review should document those observations without claiming that every exception was exploited in 2017.

## Software trust is a workflow, not a warning banner

A fake update succeeds by borrowing an expected task: keeping software current. Training that simply tells employees not to update anything can conflict with legitimate security work. A better proposed design gives staff a known path for obtaining software and a clear way to verify an unexpected request without improvising.

That path should answer practical questions. Where do legitimate updates appear? Who approves an application that a department needs? What happens if a website demands a download before an employee can complete a task? How can staff report a suspicious prompt without losing their work or being blamed for interrupting a deadline? A policy that does not answer these questions leaves users to invent an operational process under pressure.

The organization's installation controls should reinforce that process. An ordinary task should not require standing administrative authority merely because granting it is convenient. Exceptions should have an owner, a purpose and a review condition. If a business application genuinely requires elevated maintenance, the organization should define how that maintenance occurs rather than silently turning every user's browsing session into a privileged software decision.

The exercise must also avoid making the employee the only defense. Even well-trained staff can encounter persuasive content in a familiar context. A mature design assumes that a deceptive file may occasionally reach execution and asks what limits its consequences. That shift makes the analysis more useful than retelling the incident as a story about a careless click.

## Initial compromise and internal propagation have different owners

Stopping a malicious download and stopping remote administrative abuse are related but distinct responsibilities. A web-filtering success does not prove that the internal environment would contain an endpoint that became compromised through another route. A patching success does not prove that the software-approval process is trustworthy.

For a proposed review, draw two separate diagrams. The first describes the software acquisition and execution workflow. The second describes the authority that a workstation or support identity can exercise over other hosts. Keep these diagrams conceptual and restrict detailed operational maps to the organization's authorized personnel. The purpose is to identify dependencies, not to create an unnecessarily distributable intrusion guide.

The second diagram should include authentication and administration, not only ports. An allowed connection can carry an unauthorized task when an account has excessive reach. Conversely, a denied connection can impede a legitimate recovery process if nobody planned an alternative. The review should therefore pair every restriction with a service owner who can explain its business purpose and acceptable failure mode.

A useful outcome is a short boundary statement: a named class of workstation may perform a named set of tasks against a defined service through an approved method. Anything outside that statement requires investigation or a documented exception. This gives analysts and administrators a shared standard for interpreting activity that is technically possible but operationally unexpected.

## Patch scope must remain visible

Patching is essential when a relevant vulnerability is present. The reasoning error is to convert a patch result into a declaration that all malicious movement is impossible. A multi-route incident can exploit a vulnerability on one host while using accepted credentials and remote administration against another. Removing the vulnerable route does not automatically remove the accepted authority.

A proposed patch-verification record should state the affected service, the vulnerability scope, the evidence that the update is installed or the mitigation is effective, and the test conditions. It should also state what the verification did not assess. That final field is valuable because it prevents the patching team's legitimate success from becoming an unsupported claim about identity, execution control or compromise status.

The same principle applies to emergency mitigation. A temporary network restriction can buy time, but its presence should not be confused with completed remediation. Record why the restriction exists, which services it affects, who can authorize changes and what evidence permits its removal. Otherwise a hurried recovery can reopen the original exposure before the underlying work is complete.

Historical references to an old bulletin belong in a case study, not in a present-day instruction to install a decade-old package without evaluating the platform. A current operational plan should use the organization's supported update process and authoritative current product guidance. This article uses MS17-010 to explain the 2017 evidence, not to prescribe a universal modern patch action.

## Credential exposure changes the restoration boundary

If an incident may involve credential misuse, restoring files on the visibly affected endpoint is only one part of recovery. The organization must consider which identities were available to that endpoint, what authority they held and whether their subsequent use can be trusted. This is an investigation question, not a reason to assume every credential in the enterprise was necessarily stolen.

A proposed identity worksheet starts with known observations and separates them from possible exposure. It records the account, the systems where it had authority, the relevant time window and the evidence supporting the scope. It assigns an owner to investigate or remediate the risk through the organization's approved process. Sensitive credential material should never be copied into the worksheet itself.

Credential replacement also has dependencies. Service accounts can support scheduled work, applications or recovery tooling. A coordinated response needs to understand those dependencies so that an authorized security action does not create avoidable business interruption. The aim is to restore trustworthy authority, not merely to maximize the number of password changes reported on a dashboard.

The worksheet should remain linked to service acceptance. If a restored application still depends on an administrative path that investigators cannot trust, the service owner needs that limitation before approving reconnection. A technical restore can be complete while the authorization to resume normal operation remains pending.

## Encryption capability, decryption possibility and real recovery

These terms answer different questions. Encryption capability describes what the examined program can do to information. Decryption possibility concerns whether the design preserves a technical means of reversing the operation under particular conditions. Real recovery asks whether the organization can obtain trustworthy, complete and usable data and return its services to operation.

A technically reversible scheme does not guarantee a working recovery outcome. The required information may be unavailable. A process may fail on some data. Restored content may still require validation. Other consequences of the intrusion, including compromised authority or altered system configuration, may persist. A ransom demand does not resolve those questions.

This study does not recommend paying a ransom or provide payment instructions. Payment decisions involve legal, organizational and operational considerations beyond malware taxonomy. For educational purposes, the important distinction is that the presence of a recovery mechanism in analysis is not evidence of a reliable service offered by an attacker.

A proposed recovery plan therefore begins with independently controlled copies and a tested restoration process. The test should demonstrate a useful business workflow, not only that files can be read. For a fictional newsroom, that might mean opening a current project, verifying its references and completing a controlled publication rehearsal. For another organization, a different service-specific scenario would be appropriate.

## The service owner needs more than a rebuilt desktop

A restored workstation may depend on shared storage, identity services, application licensing and operational records. If any of these remains unavailable or untrusted, the user may still be unable to do meaningful work. Recovery reporting should distinguish endpoint readiness from service readiness.

A proposed service acceptance record names the workflow being restored, its critical dependencies, the evidence of data integrity and the current restrictions. It identifies both a technical owner and a business owner. The technical owner explains the restoration and security checks. The business owner verifies that the workflow produces the intended result under the approved conditions.

Acceptance should include the data gap between the restored copy and the interruption. Staff may have completed legitimate work during that interval or continued through a manual workaround. The plan needs a controlled way to reconcile those records without duplicating transactions or silently discarding changes. A successful backup restore does not automatically answer that business-data question.

After acceptance, retain a monitored return period appropriate to the service. Watch for recurrence of suspicious activity and for functional problems introduced by restoration. Define who can suspend the return if new evidence changes the risk assessment. This makes recovery a managed transition rather than a binary declaration made when the first employee logs in.

## An evidence ledger for evolving reports

Bad Rabbit's public reporting history makes a simple ledger especially useful. Each entry should contain a claim, its source, the date or update time, its scope and the operational consequence if it is correct. A later entry can revise the claim without erasing the earlier record. The ledger supports both technical decisions and honest retrospective writing.

For example, a source may describe initial delivery without an exploit. The scope field should say initial delivery. If later analysis identifies an exploit in secondary propagation, that is not necessarily a contradiction. The two claims concern different transitions. A ledger that preserves scope prevents a misleading headline from driving the response plan.

The same structure works for attribution. Code similarity, shared tooling, common infrastructure and a named operator are different propositions. Evidence for one can inform another, but it does not collapse their uncertainty. Record the source's expressed confidence rather than selecting the most dramatic conclusion and discarding the qualification.

For telemetry, record the denominator. Is the figure about observed downloads, detections, unique devices, organizations or confirmed operational outages? A percentage without that definition is easy to misread. A vendor's regional distribution should not be turned into a worldwide victim ranking unless the underlying source genuinely supports that interpretation.

## Defender worksheet: test the claims that matter

| Defensive question | Evidence to request | What a positive result does not prove |
|---|---|---|
| Can an unexpected installer run? | Controlled execution-policy test and approved exception list | That all later credential use is safe |
| Is the relevant exploit route closed? | Platform-specific update or mitigation verification | That credential-assisted administration is impossible |
| Can one endpoint administer many peers? | Authorized privilege and service-access review | That broad authority was actually abused in this incident |
| Can analysts explain unusual remote work? | Identity, endpoint and service-owner context | That a technically valid login was a legitimate task |
| Can the business service recover? | Isolated restoration and witnessed workflow test | That every incident consequence has ended |
| Are published claims accurate? | Dated source ledger with scope and confidence | That a source's visibility covers every victim |

This worksheet is an original planning artifact. It is not a compliance standard or a finding that the affected organizations lacked the listed controls. Its purpose is to make a proposed control test useful by stating both the question it answers and the questions it leaves open.

## Ninety-minute tabletop: a software request becomes a service outage

This fictional exercise is inspired by the analytical issues in the case. It does not reconstruct a named victim's network. Participants include security operations, endpoint engineering, identity administration, network operations, service owners, helpdesk and communications. No malware or exploitation occurs during the exercise.

### Minutes 0–15: the plausible request

An employee reports running an installer after a familiar website displayed a software requirement. The employee is unsure whether the installation completed. Ask how the report reaches the response team, what information can be gathered safely and whether the employee knows what to do next. The goal is a useful report and a controlled response, not an interrogation that discourages future reporting.

### Minutes 15–35: a second machine behaves differently

A second workstation shows suspicious administrative activity but no evidence of a browser download. An initial briefing describes the event as a web-only incident. Ask whether the team can revise its scope without waiting for identical symptoms. Participants should identify the difference between a shared initial vector and internal propagation, then assign owners to resolve the uncertainty.

### Minutes 35–55: patching creates false reassurance

The platform team reports that a relevant historical vulnerability would be patched on most devices. An executive asks whether the incident is therefore contained. Identity staff report that a support account has broad reach. Ask what each fact establishes, what remains unknown and which approved checks can resolve the next decision. The exercise should not reward a patch-versus-identity argument. Both teams have part of the evidence.

### Minutes 55–75: the first restore works

A workstation returns from a clean image and a backup. The service owner cannot yet verify a shared project repository, and the identity investigation remains open. Ask what can be safely declared restored, what restrictions remain and who owns each missing acceptance criterion. The exercise tests whether endpoint progress becomes an unjustified whole-service recovery claim.

### Minutes 75–90: the report changes

A new technical bulletin identifies a propagation route absent from the first briefing. The communications team has already drafted a summary. Ask how the incident ledger records the revision and how affected decisions are revisited. Close by assigning one improvement to each boundary that lacked a clear owner or adequate evidence.

## Thirty-, sixty- and ninety-day improvement plan

In the first thirty days, document the approved software-installation path for a small set of important user groups. Review standing local privilege and identify exceptions with no accountable owner. Select a representative service and map its cross-host administrative dependencies. Confirm that staff can report suspicious software requests through a channel that does not depend on the potentially affected workstation alone.

By sixty days, test the selected boundaries in an authorized nonproduction environment. Verify execution policy, patch evidence and administrative scope separately. Exercise an identity investigation using synthetic records rather than real secrets. Restore a representative service from independently controlled copies and have the business owner witness the acceptance scenario.

By ninety days, run the tabletop with a revised-report inject and a shift handover. Measure whether the team preserves scope and uncertainty while making timely decisions. Resolve the highest-consequence gaps first and retest them. Extend the approach to additional services only after the initial artifacts prove understandable and useful to the people expected to maintain them.

This schedule is a proposal, not a statement of what any victim did. It should fit the organization's change controls, staffing and service commitments. The goal is demonstrated improvement at selected boundaries, not a large documentation exercise that creates a false sense of completion.

## Metrics and acceptance criteria

Measure the share of selected user groups with a clear installation path and tested enforcement. Track privilege exceptions by owner and review date. Measure how quickly an analyst can connect suspicious remote activity to the responsible identity and service owner. Count services with witnessed restoration tests rather than reporting backup-job success as a substitute.

For incident exercises, record the time between new evidence and a revised scope decision. Measure whether the team identifies which earlier assumptions changed. Track how many claims in the final summary have a source, date and explicit scope. These metrics address the information problem that fast-moving incidents create, not only the technical controls.

A useful recovery criterion should be observable. The restored service should complete the approved test, its critical dependencies should meet the defined trust requirements and unresolved restrictions should have owners. “Looks normal” is insufficient when nobody has specified what normal means. Equally, uncertainty should not be hidden merely because a dashboard requires a single color.

Do not use these metrics to claim an exact probability of future ransomware loss. They measure preparedness and evidence quality in a bounded set of conditions. Their value comes from exposing concrete work, not from producing a universal resilience score.

## Editorial pitfalls and limits

The most important correction is to avoid using EternalBlue and EternalRomance interchangeably. The reviewed Bad Rabbit analysis identifies the latter and explicitly distinguishes it from the former. Similarly, the absence of an exploit in one delivery step does not describe the entire propagation chain. A short summary should preserve those boundaries even if it omits lower-level technical detail.

Do not convert code similarity into certain attribution. The source's confidence in shared code and its confidence in common authorship were different. Do not assign NotPetya's reported financial losses or global reach to Bad Rabbit merely because contemporary articles compared the families. This study deliberately avoids a speculative aggregate cost.

Do not equate detected dropper encounters with successfully encrypted organizations. Do not treat a vendor's conditional recovery observation as a guaranteed decryption method. Do not turn a hypothesis about existing access into a confirmed fact. Each of those mistakes produces a more exciting story at the expense of a less reliable one.

Finally, the historical sources are not present-day product advice. Operating systems, support status and protective technologies have changed since 2017. A modern implementation should consult current authoritative documentation for the environment in question. This case study supplies a durable reasoning framework while keeping its historical claims tied to their dates.

## Conclusion

Bad Rabbit's defensive value lies in the transitions between its stages. A deceptive installation request, local authority, remote administration, an exploit route and data recovery each require a different kind of evidence. No single label or control describes the whole problem.

For a practical next step, choose one important service and trace how an ordinary workstation could influence its availability. Review software trust, administrative reach and restoration together, while testing each boundary separately. Preserve the scope of every result. That produces a more dependable defense than assuming one blocked download, one installed patch or one successful restore means the incident is fully understood.

## Source register

[1] Kaspersky Securelist, “Bad Rabbit ransomware,” October 24, 2017, with subsequent technical updates. Entry, propagation and decryption-assessment sections reviewed. https://securelist.com/bad-rabbit-ransomware/82851/

[2] Cisco Talos, Nick Biasini, “Threat Spotlight: Follow the Bad Rabbit,” October 24, 2017, updated October 25–26. Distribution, propagation, encryption and code-linkage confidence reviewed. https://blog.talosintelligence.com/bad-rabbit/

[3] ESET, Marc-Etienne M. Léveillé, “Bad Rabbit: Not-Petya is back with improved ransomware,” October 24, 2017, updated October 27. Patch-test result, telemetry scope and uncertainty reviewed. https://www.welivesecurity.com/2017/10/24/bad-rabbit-not-petya-back/

[4] Microsoft, Tanmay Ganacharya, “A worthy upgrade: Next-gen security on Windows 10 proves resilient against ransomware outbreaks in 2017,” January 10, 2018. Historical vendor retrospective, relevant Bad Rabbit section reviewed. https://www.microsoft.com/en-us/security/blog/2018/01/10/a-worthy-upgrade-next-gen-security-on-windows-10-proves-resilient-against-ransomware-outbreaks-in-2017/

[5] Microsoft, Security Bulletin MS17-010, published March 14, 2017. Historical SMB update context. https://learn.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010
