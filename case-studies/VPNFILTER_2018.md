# VPNFilter, 2018: When the Network Edge Became the Intrusion Platform

*A TeamStarWolf case study. Published 15 November 2026.*

[All case studies](/case-studies/README.md) · Related: [Network Security Architecture](/NETWORK_SECURITY_ARCHITECTURE.md), [Firmware and IoT Security Reference](/FIRMWARE_IOT_SECURITY_REFERENCE.md), [Incident Response Reference](/INCIDENT_RESPONSE_REFERENCE.md), [Threat Actors](/THREAT_ACTORS.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Network and edge-device security engineers, incident responders, threat-intelligence analysts and operations owners

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 16 min (3,788 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You want an evidence-bounded account of the 2018 VPNFilter botnet and its disruption, you need to separate a device estimate from a sinkhole IP count or disruption from eradication, or you are reviewing edge-device ownership, recovery and later attribution

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Executive summary](#executive-summary), [The network device as a trust boundary](#the-network-device-as-a-trust-boundary), [Why rebooting and eradication require different evidence](#why-rebooting-and-eradication-require-different-evidence)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Network Security Architecture](/NETWORK_SECURITY_ARCHITECTURE.md), [Firmware and IoT Security Reference](/FIRMWARE_IOT_SECURITY_REFERENCE.md), [Incident Response Reference](/INCIDENT_RESPONSE_REFERENCE.md), [Threat Actors](/THREAT_ACTORS.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## Executive summary

VPNFilter is a case study in an easily missed security boundary: the device carrying an organization's traffic can itself become an adversary-controlled computer. This paper examines the 2018 disclosure and disruption through contemporaneous research, government announcements and remediation reporting, with a separately labeled 2022 attribution update. It does not treat a compromised router, an exposed password and a confirmed downstream intrusion as interchangeable outcomes.

The most useful lesson is operational rather than sensational. A successful intervention can interrupt malicious activity without removing the condition that enables its return. A security team needs separate completion criteria for disruption, device recovery, credential protection and investigation of connected systems. None should be inferred merely because connectivity returns or an alert stops firing.

This study preserves uncertainty where it matters. Estimates have dates and units. Published malware capabilities are not a tally of actions performed against every victim. Names assigned to operators must be attached to their source and period rather than copied into a timeless synonym list. Recommendations, acceptance criteria and exercises below are original defensive analysis, not assertions about undocumented victim behavior.

## Scope, method and reading record

The historical spine uses six records: Cisco Talos's May disclosure and June follow-up; the Justice Department's May disruption announcement; Shadowserver's operational account; FBI Portland's consumer-facing explanation; and the NCSC's February 2022 retrospective context. Several records describe the same coordinated intervention. They are different perspectives, not six independent confirmations of every technical claim.

The Talos articles were read for their campaign narrative, stage distinctions, technical qualifications, defensive discussion and June capability updates. Indicator lists were consulted as historical context, not reproduced as an operational blocklist. The short DOJ, Shadowserver and FBI accounts were read for their stated scope. The NCSC background and VPNFilter sections, publication date and relevant guidance were reviewed; this is not a complete study of Cyclops Blink.

No malware was acquired, executed or emulated. No historical command infrastructure was contacted. No victim device, internal incident record or private telemetry was available. The article therefore cannot calculate a reliable final victim total, establish each device's infection route, measure total stolen information or verify eradication across the world. The practical sections deliberately work within those limits rather than filling gaps with a plausible story.

## Historical evidence: six bounded accounts

### 1. Talos's May 23 disclosure

Talos estimated at least 500,000 infected devices across at least 54 countries with partners, as of its May 23, 2018 disclosure. Research was unfinished. The team described a persistent first stage, a nonpersistent second stage and additional modules, with collection and destructive potential. It did not know the exploit used in each case. May 8 and May 17 increases in Ukrainian victims contributed to the decision to publish early. Code overlap with BlackEnergy was expressly not definitive attribution. These are dated findings and assessments, not a final census or proof that all advertised capabilities were exercised. [1]

### 2. The June 6 technical update

The follow-up expanded the affected-device scope and described additional modules. The ssler module could intercept and modify HTTP traffic and support malicious content injection toward endpoints. The dstr module provided destructive functionality. Crucially, the particular packet-sniffer sample examined for industrial traffic could observe rather than modify traffic; its port-502 handling logged addressing information without validating the traffic as Modbus. These distinctions constrain claims about industrial impact. A capability to interfere with traffic does not establish successful compromise of every downstream endpoint. [2]

### 3. The Justice Department intervention

On May 23, DOJ announced court-authorized seizure of a command-and-control domain to redirect certain stage-one communications to an FBI-controlled server, capturing victim IP addresses under legal process. Shadowserver would help distribute remediation information. DOJ explained that rebooting temporarily removed stage two while stage one remained, so additional action was necessary. Its announcement attributed the operation to the Sofacy Group and used a broad historical alias list. This study records that contemporary government description without adopting its entire alias list as a modern taxonomy. [3]

### 4. Shadowserver's operational perspective

Shadowserver described the sinkhole and victim-notification effort, while warning that remaining first-stage functionality still created risk. Its page reports approximately 14,000 unique IP addresses per day in the observation described there. That is a sinkhole metric, not a revised global device total or a measurement taken for this paper. The page carries a May 23 date but incorporates later findings; its snapshot should not be assigned a more precise observation date than the page establishes. Recommended actions included remediation of identified devices, attention to potentially exposed equipment and reducing unnecessary remote management. [4]

### 5. The FBI's public-facing explanation

FBI Portland's May 29 explanation distinguished the persistent first stage from later stages disrupted by rebooting. It framed the reboot as an interruption that could help identification and remediation, not complete eradication. It also advised stronger nondefault credentials, disabling remote management and updating firmware. This account is valuable because it communicates the difference between an immediately useful action and a finished recovery. Historical advice should still be translated into the exact device vendor's supported recovery procedure rather than applied as a universal button sequence. [5]

### 6. The 2022 attribution context

On February 23, 2022, the NCSC published a joint advisory context identifying Sandworm with the Russian GRU's GTsST and discussing VPNFilter as the framework preceding Cyclops Blink. It describes VPNFilter activity in the Sandworm context, including targeting before the 2018 Winter Olympics in the Republic of Korea. This later official account should be labeled as later evidence. It should not silently replace the cautious language of the initial research or turn historical shorthand into proof that every actor label refers to exactly the same organization. Cyclops Blink remains a separate framework and case. [6]

## A chronology that does not confuse discovery with activity

| Date or period | What the record establishes | Interpretation boundary |
|---|---|---|
| May 8 and May 17, 2018 | Talos described increases focused on Ukrainian victims [1] | Observation dates, not necessarily initial compromise dates |
| May 23, 2018 | Talos disclosure and DOJ disruption announcement [1,3] | Public disclosure is not the campaign's start |
| May 29, 2018 | FBI explanation of rebooting and further defenses [5] | An interruption is not an eradication certificate |
| June 6, 2018 | Talos expanded technical findings and device scope [2] | New knowledge is not proof a capability was created that day |
| February 23, 2022 | NCSC later attribution and successor-framework context [6] | Retrospective evidence must remain visibly dated |

For an investigator, the distinction between event time and knowledge time is indispensable. A report published on a particular day may describe behavior observed much earlier. A newly discovered function may have existed before researchers acquired the sample. A device first seen by a sinkhole may have been compromised long before its first observation. A chronology that merges these categories creates false precision and can distort both dwell-time estimates and response judgments.

An internal timeline should therefore include separate fields for the event timestamp, source timestamp, collection time, time zone and confidence. Where the event time is unknown, leave it unknown. The absence of earlier logs is a retention limit, not evidence that the adversary arrived at the beginning of the available record. This is an analytical recommendation, not a claim that a particular VPNFilter victim kept such a timeline.

## The network device as a trust boundary

A gateway is often described in functional terms: it provides connectivity, routes packets or hosts a service. Security planning needs a second description: it is a managed computer with software, credentials, administration paths and a recovery process. Treating that computer as an appliance does not remove those responsibilities. It can instead obscure them until a response depends on information nobody recorded.

The defensive question is not simply whether the router appears on a published model list. It is whether the organization can identify the device, determine who controls it, recover it through a trusted method and assess what flowed through it during the uncertain interval. A branch office may depend on equipment supplied by an internet provider, configured by a contractor and physically located in premises managed by another team. Each relationship can be legitimate while leaving incident ownership unclear.

A useful ownership record names the business service, technical custodian, provider contact, person authorized to approve interruption, physical access route and replacement option. It should also identify where configuration records are stored and who can read them. Those records can contain sensitive administration details, so creating an inventory does not mean putting passwords into a broadly shared spreadsheet.

This organizational model is intentionally broader than malware detection. A team that recognizes an indicator but cannot contact the responsible owner has discovered a problem without acquiring a practical means to resolve it. Conversely, a team with a clean replacement and tested handover can reduce exposure while deeper analysis continues. Detection, authority and recoverability are complementary capabilities.

## Why rebooting and eradication require different evidence

The historical stage distinction explains why a short instruction could be useful without being sufficient. [3,5] The broader lesson is that an action should be evaluated against the state it is intended to change. Restarting a process, interrupting a connection, resetting configuration and replacing software are not equivalent operations. Their names may sound reassuring while their effects differ substantially across products.

For modern defensive planning, write the intended outcome before selecting the procedure. Is the objective to stop active communication, remove a persistent component, eliminate a vulnerable configuration, replace an unsupported device or preserve evidence? A procedure that meets one objective may not meet another. Record what was changed and how the team knows, rather than merely recording that a technician followed a checklist.

Do not improvise destructive reset or firmware actions from a historical case study. Consult current vendor guidance for the exact model and hardware revision, coordinate with the owner and account for operational dependencies. A recovery step that removes network access may also remove the remote management channel needed to complete the work. Arrange an independent contact path and, where needed, local assistance before proceeding.

After recovery, validate the configuration that has been restored. A backup can preserve business settings, but its existence alone does not establish that every setting is trustworthy. Compare management exposure, resolver settings, allowed services and administrator identities with an approved baseline. Record exceptions and decisions. The acceptance condition is a supported, understood state with an accountable owner, not merely a successful boot.

## Disruption is a population-level intervention, not a local clean bill

The DOJ account describes an intervention designed both to disrupt and to support identification. [3] Such an intervention should be assessed at its actual scope. It can change an adversary's available infrastructure and produce useful remediation leads without visiting, inspecting or repairing every affected device. Confusing those outcomes encourages premature closure.

An organization receiving a notification should treat it as a dated investigative lead. Confirm the issuing organization through a trusted channel, retain the original report and identify which asset held the relevant address at the reported time. Internet address reassignment, network address translation and incomplete provider records can make that mapping difficult. The responsible team should document the mapping confidence instead of selecting the most convenient current owner.

The same caution applies to silence. A device absent from a report may not have communicated during the collection window, may be outside the observation path or may have been offline. Silence can become useful evidence when the team knows the expected behavior and measurement coverage. Without that context, it cannot bear the weight of a clean conclusion.

An internal dashboard should distinguish notified, attributed to an asset, contacted, contained, remediated, verified and unresolved. Combining those into a single completed percentage conceals important work. A closed ticket should explain which completion conditions were met and what remains outside scope. This is especially important when the response depends on organizations that do not share the same tools or service expectations.

## Counting infections without manufacturing certainty

The initial estimate and later sinkhole observation answer different questions. [1,4] A device estimate is not interchangeable with a count of unique public IP addresses in one day. A single device can use different addresses over time; a shared address can represent multiple systems; observation paths can miss populations. These are measurement considerations, not an alternative numeric estimate of VPNFilter's size.

A sound research table should retain the original metric's unit, measurement window, scope, source and uncertainty. Avoid subtracting one headline number from another to claim a percentage cleaned. That arithmetic requires a comparable population and measurement method. Where those prerequisites do not exist, the honest statement is that the available figures cannot establish the requested rate.

A business can still measure its own response. Useful denominators include known in-scope devices, devices with verified owners, devices assessed under the current procedure and devices for which remediation evidence was reviewed. Even those figures require care: discovering another branch router changes the denominator, and an unreachable device should not quietly disappear from it.

For reporting, show unresolved assets explicitly. A smaller unknown category is meaningful progress only if it reflects investigation, not relabeling. Distinguish devices retired with evidence from devices that simply stopped responding. If a team cannot verify what happened, use a status that preserves that uncertainty and assigns a follow-up owner.

## Capabilities, observations and consequences

The June account is particularly useful for showing why technical language needs careful scope. Its descriptions of HTTP manipulation and the examined industrial-traffic sniffer do not support an unqualified claim that all encryption was defeated or that industrial commands were changed. [2] A research paper should distinguish what an analyzed component can do, what telemetry shows it doing and what downstream consequences have been established.

For defensive analysis, use a four-part record. First, identify the artifact or behavior observed. Second, explain the associated capability with the conditions under which it operates. Third, record whether there is evidence that the relevant traffic or target was present. Fourth, state the demonstrated consequence, if any. Where the chain stops, stop the claim.

This framework also improves remediation decisions. Potential credential exposure may justify precautionary credential work even when theft is not conclusively demonstrated. That is a risk decision and should be documented as such. It should not later be converted into a factual claim that theft occurred merely because credentials were rotated.

Likewise, a device's ability to reach an industrial network is not evidence that a physical process changed. Industrial response should involve the relevant operational and safety personnel, preserve process records where available and avoid disruptive scanning or experimental recovery on production equipment. The aim is to reduce uncertainty without creating a new operational hazard.

## Investigating connected systems without assuming a universal breach

A network-edge finding creates a scoping problem, not a license to declare every connected endpoint compromised. Determine which business systems depended on the affected path, which identities used it and which independent records can help assess the interval. Prioritize systems by the sensitivity of their functions and the plausibility of exposure, while making the assumptions visible.

Independent evidence may include endpoint security records, identity-provider events, application access logs and centrally retained network records. A compromised device's own logs can be informative, but they should not be the only source used to certify its behavior. Document retention gaps, clock differences and collection limitations. A clean result from a source that did not cover the relevant period is not a meaningful negative finding.

Response teams should separate immediate protection from retrospective attribution. They can restrict unnecessary management access or provide a replacement path before determining the exact operator. Waiting for actor certainty can delay useful action. On the other hand, attribution confidence should not be inflated merely to strengthen the argument for a sensible defense.

The scope should also include service accounts and operational dependencies that people rarely associate with a router incident. That does not mean indiscriminately revoking everything. It means identifying which credentials, sessions or trust relationships might have crossed the affected boundary, choosing proportionate protective actions and ensuring that business owners understand the consequences.

## A practical acceptance matrix

The following matrix is an original response design. It is not a historical reconstruction of the FBI, Talos, Shadowserver or any affected organization.

| Workstream | Evidence of completion | What does not suffice |
|---|---|---|
| Asset ownership | Device mapped to service, custodian and location | Current IP address alone |
| Containment | Authorized change recorded and effect checked | A ticket marked urgent |
| Device recovery | Exact supported procedure completed and configuration reviewed | Internet connectivity restored |
| Account protection | Relevant identities assessed and decisions recorded | Unexplained blanket password reset |
| Connected-system review | Evidence sources, interval and gaps documented | A single current scan |
| Service restoration | Business function tested through trusted path | Device responds to a ping |
| Closure | Residual risks accepted by accountable owner | No new alerts for an arbitrary period |

The purpose is to make handoffs explicit. A provider may complete device replacement while the customer still needs to review account exposure. A security analyst may finish historical log analysis while the operations team is still arranging a supported replacement. Neither completion should erase the other team's outstanding obligation.

A case owner should reconcile these workstreams before issuing a final summary. The summary should distinguish verified actions, reasoned assessments, unanswered questions and accepted limitations. This is more useful than a binary clean or compromised label when evidence is incomplete. It also gives the organization a defensible record if later information changes the assessment.

## A fictional 90-minute tabletop exercise

This exercise uses synthetic evidence only. No malware, live attacker infrastructure or production-device disruption is required. The organization is a fictional regional service company with twelve branches, a central IT team and several internet providers. One branch's gateway is supplied and managed by a third party.

At minute zero, the facilitator provides a simulated notification identifying a public address and historical timestamp. Participants must verify the notification, map the address to a service and name a response owner. The first decision is not which malware family to announce. It is whether the team knows whose device it is and who can authorize changes.

At minute twenty, the provider says the router has already been restarted and service is normal. Participants must ask what the action actually changed and identify the remaining completion conditions. A strong response accepts useful containment without treating it as proof of removal. The team should arrange a communication route that survives loss of the affected connection.

At minute forty, an analyst reports that the available identity logs begin after the suspected interval. Participants must describe that gap accurately and choose proportionate protective steps. They should not write that no suspicious logins occurred during a period for which there are no records. They should also avoid claiming confirmed credential theft from an absence of visibility.

At minute sixty, management asks how many branches are clean. The facilitator introduces a newly discovered, undocumented gateway. Participants must revise the denominator, preserve unresolved status and explain why the dashboard changed. The exercise tests whether reporting rewards accurate discovery or pressures teams to hide it.

At minute eighty, the replacement is installed but a business application fails. Participants must coordinate service validation without restoring an unreviewed old configuration simply to make the problem disappear. The final ten minutes produce a closure draft with known actions, limitations, owners and deadlines. The exercise succeeds when the record is precise and usable, not when every fictional uncertainty is magically resolved.

## A 30-, 60- and 90-day improvement plan

During the first thirty days, establish an accountable inventory of edge devices and network storage supporting important services. Reconcile the inventory with provider records and local knowledge. Record exact models, support status, management responsibility and recovery contacts. Identify assets that cannot be maintained through a supported process and give those exceptions an owner and decision date.

By day sixty, test recovery for a representative nonproduction configuration. Verify access to trusted installation material, necessary configuration information and an independent communication path. Review the difference between restarting, resetting, reinstalling and replacing the selected equipment. Capture the exact success criteria so that future technicians do not have to infer them during an outage.

By day ninety, exercise a cross-organizational notification and closure workflow. Include a provider-managed device, an ambiguous historical IP mapping and a telemetry gap. Require both technical and business validation before the case is closed. Measure time to identify an owner, time to establish a trusted recovery path and the proportion of assets with verified recovery evidence.

Do not measure success solely by the number of devices updated. Updating is valuable, but an organization can have a high update percentage while its most consequential exception remains unsupported and unmanaged. Report exceptions in terms of business exposure and a specific next action. A smaller, evidence-backed improvement program is more useful than a large list of controls nobody can demonstrate.

## Conclusions

VPNFilter illustrates why network security cannot stop at monitoring the traffic that an appliance carries. The appliance's own software state, management authority and recovery process belong inside the security model. The historical record also shows why rapid disruption and durable remediation must be discussed separately.

The evidence supports a serious campaign with consequential capabilities, but rigor requires restraint. Preserve dates and measurement units. Separate potential from observed impact. Keep later attribution visibly distinct from initial assessment. Do not convert a limited observation path into a global verdict.

The practical outcome should be a better recovery system: identifiable devices, reachable owners, supported procedures, independent evidence and explicit closure criteria. Those capabilities remain useful even when the next incident has a different name, a different operator and a different technical mechanism.

## Sources and reading record

[1] Cisco Talos, William Largent, May 23, 2018. New VPNFilter malware targets at least 500K networking devices worldwide. Campaign narrative, stage descriptions, observations, defensive discussion and scope qualifications reviewed. https://blog.talosintelligence.com/vpnfilter/

[2] Cisco Talos, William Largent, June 6, 2018. VPNFilter Update: VPNFilter exploits endpoints, targets new devices. Introduction, ssler/dstr analysis, packet-sniffer scope and conclusions reviewed. No module execution or protocol reproduction. https://blog.talosintelligence.com/vpnfilter-update/

[3] U.S. Department of Justice, May 23, 2018. Justice Department Announces Actions to Disrupt Advanced Persistent Threat 28 Botnet of Infected Routers and Network Storage Devices. Full announcement reviewed; attached court filings not independently analyzed for this paper. https://www.justice.gov/archives/opa/pr/justice-department-announces-actions-disrupt-advanced-persistent-threat-28-botnet-infected

[4] Shadowserver Foundation, page dated May 23, 2018, with later findings incorporated. VPNFilter: FBI Sinkholing. Full operational text reviewed; numerical snapshot not treated as a current measurement. https://www.shadowserver.org/news/vpnfilter-fbi-sinkholing/

[5] FBI Portland, May 29, 2018. Oregon FBI Tech Tuesday: Building a Digital Defense Against the VPNFILTER Malware. Full public guidance reviewed. https://www.fbi.gov/contact-us/field-offices/portland/news/press-releases/oregon-fbi-tech-tuesday-building-a-digital-defense-against-the-vpnfilter-malware

[6] UK NCSC, February 23, 2022. New Sandworm malware Cyclops Blink replaces VPNFilter. Background, VPNFilter sections, relevant guidance and publication date reviewed. Separate linked malware annex not reviewed for this study. https://www.ncsc.gov.uk/news/joint-advisory-shows-new-sandworm-malware-cyclops-blink-replaces-vpnfilter
