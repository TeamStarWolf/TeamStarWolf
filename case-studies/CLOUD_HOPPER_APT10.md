# Cloud Hopper / APT10, 2016-2018: When Provider Access Became Customer Exposure

*A TeamStarWolf case study. Published 15 November 2026.*

[All case studies](/case-studies/README.md) · Related: [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md), [Identity and Access Management Reference](/IDENTITY_ACCESS_MANAGEMENT_REFERENCE.md), [Threat Actors](/THREAT_ACTORS.md), [Cloud Security Reference](/CLOUD_SECURITY_REFERENCE.md), [SolarWinds SUNBURST](/case-studies/SOLARWINDS_SUNBURST.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Managed-service providers, customer security teams, identity architects, incident commanders, procurement leaders and data owners

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 19 min (4,450 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You want an evidence-bounded account of the Cloud Hopper (APT10) MSP espionage campaign, you need to separate provider exposure from customer access from verified theft or attribution from allegation, or you are reviewing delegated administrative authority and tenant separation

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Executive summary](#executive-summary), [Why provider access changes the risk model](#why-provider-access-changes-the-risk-model), [Exposure, access and theft are separate findings](#exposure-access-and-theft-are-separate-findings)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md), [Identity and Access Management Reference](/IDENTITY_ACCESS_MANAGEMENT_REFERENCE.md), [Threat Actors](/THREAT_ACTORS.md), [Cloud Security Reference](/CLOUD_SECURITY_REFERENCE.md), [SolarWinds SUNBURST](/case-studies/SOLARWINDS_SUNBURST.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

Key takeaways (reviewed 2026-11-17):

- A managed-service provider's compromise reaches its customers: the customer's security boundary includes the provider's identities, tools and practices. ([Executive summary](#executive-summary))
- The record describes an espionage campaign through managed-service providers and their customers, followed by attribution and criminal charges. ([Executive summary](#executive-summary))
- Provider compromise can create customer exposure, but exposure, access and verified theft remain different findings. ([Executive summary](#executive-summary))
- Recovery requires restoring the trust relationship, not merely cleaning the computer where the first alert appeared. ([Executive summary](#executive-summary))

<!-- meta:end -->

## Executive summary

A managed-service provider can administer systems for many customers. That arrangement creates efficiency, but it also creates consequential trust relationships. The customer's security boundary includes the identities, tools and operating practices through which the provider performs its work. A contract can define responsibilities without making those technical relationships safe by itself.

Cloud Hopper makes this delegated-access problem visible. The public record describes an espionage campaign involving managed-service providers and their customers, followed by government attribution and criminal charges. It also contains broader APT10 activity that should not be indiscriminately merged into a single campaign. The defensive lesson depends on preserving that scope: provider compromise can create customer exposure, but exposure, access and verified theft remain different findings.

This study proposes a joint provider-customer assurance model. It asks which administrative authority crosses the boundary, how each customer is separated, which evidence both sides can retain and who can make a containment decision when ordinary support access becomes suspect. Recovery requires restoring the trust relationship, not merely cleaning the computer on which the first alert appeared.

The analysis avoids a simplistic conclusion that outsourcing is inherently unsafe. Organizations also concentrate privilege internally, and a provider can offer capabilities that a customer could not maintain alone. The useful question is whether delegated authority is bounded, observable and revocable without leaving essential services unmanaged. A strong relationship makes those properties testable before an incident.

## Scope and source discipline

The case focuses on the 2016-2018 period in which Cloud Hopper became publicly documented and attributed. Some reviewed sources discuss earlier APT10 activity. Those earlier dates provide context, not a reason to label every APT10 operation Cloud Hopper. Likewise, the existence of later reporting does not establish that a particular customer remained compromised until the date a report was published.

The source set includes the April 2017 PwC UK and BAE Systems report, its technical annex, the December 2018 UK attribution announcement, the U.S. Justice Department's charging announcement and the underlying indictment. These sources have different purposes. Research reports describe observations and assessments. Government attribution records an official judgment. An indictment contains allegations. None is a substitute for a complete victim-specific forensic record.

The main report and technical annex cover more than the MSP-focused campaign. In particular, they discuss directly targeted Japanese organizations as well as provider-mediated activity. A malware family listed in the annex should not automatically be assigned to every Cloud Hopper victim. The same care applies to victim counts in the charging materials, which describe multiple campaigns over a longer period.

No provider systems, customer records, stolen data or malware samples were accessed for this research.

Historical summaries below are intentionally concise. The rest of the article consists mainly of original defensive analysis, proposed evidence records and a fictional joint-response exercise. The proposed controls should not be read as allegations that a named provider lacked them. Detailed technical and legal claims should be checked against the original sources before further publication.

## The historical record in five bounded accounts

### 1. The April 2017 research report

PwC UK and BAE Systems described sustained activity against managed IT service providers and their clients, alongside a separate directly targeted Japanese campaign. Their report identified provider access and shared credentials as important paths into customer environments, and described data moving through a network of compromised organizations. It observed increased activity from 2016 and assessed that relevant MSP targeting likely extended earlier. The report explicitly distinguished observations from assessments and warned that the visible activity represented only part of the actor's operations. [1]

### 2. The technical annex has a broader scope than one victim

The companion annex explained the researchers' distinction between tools used to establish a foothold and tools used for sustained access. It discussed changes in the toolset from mid-2016, including custom development and adapted open-source components. Its stated scope covered the actor and two major campaigns. The annex therefore supplies technical context, not evidence that every listed tool or behavior appeared at each provider or customer. [2]

### 3. The UK attribution announcement

On December 20, 2018, the UK government announced its attribution of the activity to elements of the Chinese government. The NCSC assessed that APT10 (tracked in MITRE ATT&CK as G0045, menuPass) was almost certainly responsible for the MSP campaign known as Cloud Hopper since at least 2016 and that the access was highly likely used for commercial espionage. It also stated its assessment of an enduring relationship with the Ministry of State Security. This is a dated official assessment, not an independently reproduced finding by this study. [3]

### 4. The U.S. charging announcement

The Justice Department announced charges against Zhu Hua and Zhang Shilong on December 20, 2018. The release alleged association with the Tianjin State Security Bureau and described both an MSP theft campaign and broader technology-theft activity. The overall period extended beyond this study's focus. Its figure of more than 45 technology companies must not be relabeled as a count of Cloud Hopper MSP customers. The release stated that the defendants were presumed innocent unless proven guilty. This study does not assert a conviction or current case disposition. [4]

### 5. The indictment clarifies the campaign boundaries

The underlying indictment alleges at least two intrusion campaigns and describes an MSP-focused campaign beginning at least around 2014. It alleges that provider access supported unauthorized entry into client environments and theft of valuable information. These are charging allegations with a defined legal source. The difference between this longer alleged period and the UK announcement's since-at-least-2016 formulation should be preserved, not silently converted into a single exact start date. [5]

## Timeline: operation, publication and attribution

| Period or date | Record | Limit on interpretation |
|---|---|---|
| Earlier than 2016 | Research and charging materials discuss preceding activity [1][5] | Not every earlier APT10 operation is Cloud Hopper |
| 2016-2017 | Research describes increased scale and MSP-focused activity [1] | Visibility is incomplete and not a census of every customer |
| April 2017 | Main report and technical annex published [1][2] | Annex scope includes more than one campaign |
| December 20, 2018 | UK attribution announcement [3] | Official assessment must retain its source and qualification |
| December 20, 2018 | U.S. charges announced [4][5] | Allegations are not convictions; broader counts need their original scope |

The timeline has at least three clocks. Activity occurs in a target environment. Investigators later assemble evidence. Researchers or authorities then publish a finding. A public date is not automatically a first-compromise date or an eradication date. This distinction matters when a customer asks whether its own environment was exposed during a particular contract or support period.

## Why provider access changes the risk model

The remaining sections are original defensive analysis unless explicitly attributed.

An MSP relationship is a delegation of capability. A customer authorizes another organization to perform certain tasks in its environment. The capability may involve accounts, remote-management software, support infrastructure, automation or access to backups and operational data. The provider's identity becomes part of the customer's administrative system even when the provider's employees work elsewhere.

The risk is not simply that a provider could be compromised. Every organization faces that possibility. The consequential question is what a compromise of one provider component would allow elsewhere. If a single support identity, workstation or management service has broad authority, the failure can extend beyond the machine that first shows suspicious behavior.

A useful analysis therefore starts with delegated tasks rather than supplier names. What can the provider do for this customer? Which identities and tools permit that work? Which other customers or internal provider services share those dependencies? Who can revoke the authority, and what service would fail if it were revoked? These questions turn an abstract third-party risk into an inspectable trust relationship.

The model also explains why a product inventory alone is insufficient. Two customers can use the same management software with very different access boundaries. Conversely, different products can depend on the same broadly privileged identity. The security property belongs to the complete service design and operating process, not only the brand of a tool.

## Cloud Hopper is not a claim of a cloud-platform vulnerability

The campaign name can mislead readers into imagining a hypervisor exploit or an escape between cloud tenants. The reviewed material centers on managed-service access and the abuse of trusted relationships. This study does not claim that a cloud platform's underlying isolation mechanism was the central entry route.

That distinction changes the questions defenders ask. A customer may focus exclusively on its public-facing applications while assuming the provider connection is trusted by definition. A provider may focus on perimeter defense while assuming its internal support systems are outside the customer's security scope. The delegation sits between those assumptions.

A conceptual diagram for this case should show a provider administrative environment, a controlled customer-access boundary and separate customer environments. It should label those as analytical categories, not a reconstruction of a victim network. The diagram's purpose is to reveal where authority is shared and where evidence changes hands.

The same reasoning applies outside an MSP contract. An internal shared-services team, a systems integrator or a specialized maintenance provider can hold similar authority. The lesson is broader than a sourcing decision: concentration of administrative capability needs explicit containment and accountability wherever it exists.

## Tenant separation includes identities and operations

Network segmentation can help separate customers, but tenant separation also depends on identity and operating practice. A shared credential with authority in several environments can undermine an otherwise sensible topology. A common support workstation can become a shared trust dependency. A recovery tool can have more reach than the production application it protects.

A proposed tenant-boundary review should identify every administrative identity used for the selected customer service. It should distinguish named human accounts, service accounts, emergency access and automation. For each, record the authorized task and scope without storing the secret itself. The review should also identify how the provider prevents an action intended for one customer from affecting another.

Operations matter because exceptions accumulate. An emergency access arrangement created during an outage may remain available after the original need ends. A temporary shared account may become normal because it simplifies shift handover. A strong process records who approved the exception, when it expires and what evidence supports renewal. The goal is not to pretend emergencies never occur, but to prevent them from silently redefining the boundary.

Customers need enough visibility to evaluate their own exposure without demanding confidential information about other clients. The provider can demonstrate boundary properties and relevant assurance evidence without revealing another customer's data or topology. A joint exercise should test that information-sharing boundary as carefully as the technical one.

## Legitimate access still needs a legitimate task

An accepted login proves that a system recognized an authentication event. It does not by itself prove that the subsequent task was authorized, appropriate or performed by the intended person. In a provider relationship, this distinction is especially important because remote administrative activity may be common and consequential.

A proposed authorization record links a session or automated action to a service, task owner and approved purpose. The detail should be proportionate to the consequence. Routine monitoring and a high-impact configuration change need not have identical processes, but both should have an accountable explanation. The record should let an investigator distinguish expected support from unexplained activity.

The record also needs a usable exception path. If the approval system is unavailable during a genuine incident, staff require an established emergency procedure. That procedure should leave evidence and trigger retrospective review. Otherwise the organization may respond to a crisis by bypassing the very controls it needs to understand what happened.

The analysis should avoid assuming that all unusual work is malicious. Providers often operate across time zones and perform maintenance outside customer business hours. Context helps analysts assess an observation. It should not become a blanket reason to ignore it. The relevant question is whether the activity fits an authorized task within the intended boundary.

## Independent evidence prevents a shared blind spot

A customer should not have to rely entirely on the potentially affected provider environment to understand its own exposure. Similarly, the provider needs evidence that survives a compromise of one support workstation. Independence here means that a single administrative failure should not erase every record needed for investigation.

A proposed logging agreement identifies what events the customer can obtain, how long relevant records remain available and who can preserve them during an incident. It should cover access events and consequential administrative actions, with enough context to connect the event to a customer service. It should also define how the parties handle timestamps and identifiers so that their records can be correlated.

More logs do not automatically create better evidence. Records must be understandable and attributable. A generic service-account name used for unrelated tasks can make a large audit trail difficult to interpret. A useful test asks whether an analyst can explain a representative support action from the available records without relying solely on the memory of the person who performed it.

Evidence-sharing arrangements must protect unrelated customers and personal information. The provider should have a method to supply relevant records without exposing other tenants. During an incident, legal and privacy specialists may need to help define that boundary. This study proposes planning questions, not a universal legal disclosure rule.

## Exposure, access and theft are separate findings

Provider compromise can create potential exposure for customers. Evidence of a successful connection can establish access. Evidence about particular files or records may support a conclusion about data theft. These are related stages of an investigation, but they should not be collapsed into a single status.

A proposed customer-impact matrix uses separate fields for potential reach, observed access, assessed data involvement and confirmed findings. Each field should identify its evidence and uncertainty. A customer with no observed malicious activity may still require investigation if the logs are incomplete. Conversely, the existence of a broad provider account does not prove that every reachable customer's data was stolen.

This distinction improves communication. A notice can explain that a trust path was potentially exposed, identify the investigation underway and state what is not yet known. It should not make a definitive no-impact claim merely because a search found no familiar indicator. It should also avoid alleging theft from every customer on the basis of provider-level compromise alone.

Data owners should help interpret the significance of any confirmed access. The sensitivity and business value of information can differ from its file size or location. An investigation focused only on large transfers may overlook smaller but consequential records. The case study does not provide a data-exfiltration method; it emphasizes the need to connect technical evidence with the organization's understanding of its information.

## Joint containment without an unmanaged customer

When a provider access path becomes suspect, the customer may want to revoke it immediately. The provider may warn that essential support or recovery functions depend on that path. Both concerns can be legitimate. The response plan needs a decision structure that can reduce risk without leaving responsibility ambiguous.

A proposed joint-containment record identifies the affected capability, the risk of continued access, the consequences of restriction and the approved alternative. It names who can act on each side. It also records the review time, because a restriction that is appropriate during initial uncertainty may need adjustment as evidence improves.

The alternative may involve a separately trusted support path, a narrower service scope or temporary customer-operated work. This article does not prescribe a technical implementation. The appropriate arrangement depends on the service and must be approved by its owners. The important point is to plan a way to preserve necessary operations without relying blindly on the suspect administrative environment.

Containment should also consider coordination across customers without treating them as one undifferentiated group. A provider may need a consistent investigation method while applying different operational restrictions to different services. The impact matrix should preserve those distinctions. A global announcement of complete containment is premature if some customer boundaries remain unresolved.

## Recovery must rebuild the delegated trust relationship

Cleaning an infected host does not necessarily restore confidence in every account, tool and connection that supported the service. The recovery plan should identify the administrative dependencies whose trust must be re-established. It should distinguish technical restoration from authorization to resume normal provider access.

A proposed acceptance process has a provider evidence package and a customer acceptance decision. The provider package describes the scope investigated, remediation performed, relevant validation and remaining limitations. The customer evaluates that package against the service's requirements and its own investigation. Neither party should silently assume that the other has completed all necessary checks.

The acceptance decision can be bounded. A customer might approve a restricted support capability while retaining additional controls or postponing a broader restoration. Any restriction needs a named owner and review condition. Otherwise a temporary arrangement can persist indefinitely or disappear without a recorded decision.

After normal access resumes, monitor the service for both security recurrence and functional problems. Review temporary credentials and emergency exceptions through the approved process. Preserve the evidence used for acceptance so that later findings can be evaluated against the assumptions that supported the decision at the time.

## Procurement questions that produce usable evidence

A supplier questionnaire is more useful when its answers can be tested. Instead of asking only whether a provider uses segmentation, ask how it demonstrates that one customer's administrative authority cannot be reused for another customer's work. Instead of asking only whether logs exist, ask whether the customer can obtain the records needed to investigate a disputed support action.

The procurement process should involve the people who will operate the service. Security can identify technical assurance needs. Service owners can explain the consequences of losing access. Legal and commercial teams can translate agreed responsibilities into the appropriate contract. A checkbox completed without those perspectives may not survive the first real incident.

The agreement should address incident coordination before the parties need it. Relevant questions include how to reach an authorized responder, how to preserve evidence, how to communicate uncertain customer impact and how to approve restricted service restoration. Exact legal obligations depend on the relationship and applicable requirements. This study does not draft binding terms or determine notification duties.

Exit planning deserves attention as well. A customer should understand how delegated access ends when the service changes or the contract terminates. Offboarding involves more than disabling a named employee account. It may include automation, support tooling and retained operational data. The authorized owners should define and verify that process.

## A provider-customer evidence worksheet

| Question | Evidence to request | Common overstatement to avoid |
|---|---|---|
| What authority crosses the boundary? | Approved task and identity map | A contract alone proves technical separation |
| Can one customer affect another? | Bounded tenant-separation assurance | Different network labels prove complete independence |
| Was this support action authorized? | Task context linked to access records | A successful login proves legitimate intent |
| Which customers may be affected? | Impact matrix with scope and uncertainty | Every reachable customer suffered confirmed theft |
| Can evidence survive provider compromise? | Preservation and sharing process | Log volume alone proves useful visibility |
| What permits normal access to resume? | Provider evidence and customer acceptance | One cleaned host proves the relationship is trusted |

This is an original planning worksheet. It does not certify a provider or establish that any named company failed these checks. Its value lies in making the evidence needed for a consequential decision explicit.

## Ninety-minute tabletop: the support channel is under investigation

This fictional exercise uses a provider and two imaginary customers with different service needs. It does not reconstruct a victim network. Participants include provider incident command, customer security leads, identity administration, service owners, communications and legal or privacy advisers. No live access changes occur during the discussion.

### Minutes 0-15: a provider-side alert

The provider identifies suspicious activity on a support workstation. The account involved can perform tasks for several customers. The initial notification says there is no confirmed customer impact. Ask what that statement means, which evidence supports it and what customer-specific records should be preserved. Participants should distinguish a preliminary finding from a final assurance.

### Minutes 15-35: an unexplained customer session

Customer A finds an administrative session during a period with no matching work authorization. Customer B sees no matching session, but its relevant logs cover a shorter period. Ask whether the two customers should receive the same impact classification. The goal is to represent both evidence and visibility limits without assuming either universal compromise or universal safety.

### Minutes 35-55: containment affects operations

Customer A requests suspension of the provider's access. Its backup-monitoring service depends on the same support arrangement. The group must identify who can approve a restriction, what operational consequences follow and which trusted alternative is available. The exercise should expose missing decision rights rather than reward a reflexive yes or no.

### Minutes 55-75: recovery evidence arrives

The provider reports rebuilding the affected workstation and reviewing several accounts. Customer A asks whether shared tooling and other administrative dependencies were included. Customer B needs continued restricted support. Ask what evidence each acceptance decision requires and how the parties document different restoration scopes.

### Minutes 75-90: a later finding changes the picture

A newly recovered log expands the period under investigation. An earlier customer notice used language that now sounds too definitive. Ask how the impact matrix, preservation requests and communications are updated. Close by assigning owners to the weakest boundary and scheduling a safe retest of the decision process.

## Thirty-, sixty- and ninety-day improvement plan

During the first thirty days, select one consequential provider service and map its delegated authority. Identify customer and provider decision makers, emergency contacts and the evidence each party can obtain. Review whether the service's existing incident language distinguishes potential exposure from confirmed impact. Record any assumptions that cannot yet be verified.

By sixty days, test a representative support action and reconstruct it from both parties' records. Review tenant separation and shared administrative dependencies within the authorized scope. Exercise a temporary access restriction in a controlled setting or discussion, including the operational alternative. Resolve the most consequential gaps before expanding the review to every supplier.

By ninety days, run the joint tabletop and an acceptance exercise. Have each side state the evidence it would require before normal service resumed. Review offboarding and emergency exceptions. Retest weaknesses after remediation, and preserve the results so that future procurement and renewal decisions can use demonstrated capability rather than only policy statements.

The schedule is a proposed planning sequence, not a legal deadline or a claim about what the historical victims did. It should fit service criticality and available resources. The objective is a small set of proven trust boundaries that can then be extended across the relationship.

## Metrics that expose shared responsibility gaps

Measure the proportion of selected provider capabilities with a named customer owner and provider owner. Track whether support actions can be linked to an approved task using retained records. Measure the time needed to identify which customers a suspect identity could reach, while keeping that potential reach separate from confirmed impact.

For exercises, record how long the parties take to agree on a containment decision and an operational alternative. Track unresolved acceptance criteria by owner. Measure how quickly a later finding reaches the affected customers and changes the scope record. These are measures of coordination and evidence quality, not a formula for calculating espionage probability.

Avoid metrics that reward unsupported reassurance. A customer with incomplete logs should not automatically count as unaffected. A provider that closes an incident ticket quickly should not receive credit for full recovery if customer acceptance remains pending. The dashboard should make those limitations visible to the people responsible for the service.

Finally, evaluate whether the controls remain usable. Excessively cumbersome procedures can drive staff toward informal workarounds. A review should examine why exceptions occur and whether the approved path can support legitimate work. The purpose is dependable delegated administration, not paperwork that obscures how the service actually operates.

## Attribution and scope cautions

The reviewed sources support a serious account of espionage through provider relationships. They do not justify assigning every APT10 incident, tool or victim to Cloud Hopper. Preserve the distinction between the MSP campaign, direct targeting and the broader activity described in the charging materials.

The UK announcement is a government attribution with stated confidence. The U.S. indictment is a set of criminal allegations. Those are not identical forms of evidence, and neither should be rewritten as a conviction that this research did not establish. The current legal disposition was not verified for this historical study, so no present-tense claim about conviction or custody is made.

Avoid inventing a single global loss figure or exact customer count. The reviewed material provides important scope information but not a complete universal inventory. Do not identify unnamed providers or customers through speculation. Where a source withholds a name, the study should not fill the gap with an unsupported guess.

Slides should preserve these limits in their visible wording, not only in notes. A title about provider exposure should not imply that every customer experienced theft. A diagram should be labeled conceptual. These editorial details are part of technical accuracy because they determine what the audience believes the evidence establishes.

## Conclusion

Cloud Hopper shows how delegated administrative authority can connect the security of separate organizations. The provider's environment and the customer's environment remain distinct, but the service relationship creates a shared trust problem that neither side can solve alone.

The most useful next step is to choose one provider-managed service and prove its boundary in practice. Identify the authority, reconstruct a legitimate task from evidence, rehearse a restriction and define joint recovery acceptance. That turns third-party risk from an abstract supplier rating into a set of decisions that the people running the service can explain and test.

## Source register

[1] PwC UK and BAE Systems, Operation Cloud Hopper, April 2017. Foreword, executive summary, MSP-campaign scope and methodology sections reviewed. https://www.pwc.co.uk/cyber-security/pdf/pwc-uk-operation-cloud-hopper-report-april-2017.pdf

[2] PwC UK and BAE Systems, Operation Cloud Hopper: Technical Annex, April 2017. Foreword and tool-category scope reviewed. The annex is broader than one victim or one campaign. https://www.pwc.co.uk/cyber-security/pdf/pwc-uk-operation-cloud-hopper-technical-annex-april-2017.pdf

[3] UK Foreign & Commonwealth Office and NCSC, "UK and allies reveal global scale of Chinese cyber campaign," December 20, 2018. Official attribution announcement and notes to editors. https://www.gov.uk/government/news/uk-and-allies-reveal-global-scale-of-chinese-cyber-campaign

[4] U.S. Department of Justice, "Two Chinese Hackers Associated With the Ministry of State Security Charged with Global Computer Intrusion Campaigns Targeting Intellectual Property and Confidential Business Information," December 20, 2018. Charging announcement, not a conviction record. https://www.justice.gov/archives/opa/pr/two-chinese-hackers-associated-ministry-state-security-charged-global-computer-intrusion

[5] United States v. Zhu Hua and Zhang Shilong, indictment released December 2018. Overview and MSP-campaign allegations reviewed. https://www.justice.gov/d9/press-releases/attachments/2018/12/20/2018_12_20_united_states_v._zhu_hua_indictment_0.pdf
