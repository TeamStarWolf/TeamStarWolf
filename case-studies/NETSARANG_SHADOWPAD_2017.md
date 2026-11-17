# NetSarang / ShadowPad, 2017: A Trusted Software Release Became an Intrusion Path

*A TeamStarWolf case study. Published 15 November 2026.*

[All case studies](/case-studies/README.md) · Related: [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md), [Secrets Management Reference](/SECRETS_MANAGEMENT_REFERENCE.md), [Endpoint Security Reference](/ENDPOINT_SECURITY_REFERENCE.md), [Incident Response Reference](/INCIDENT_RESPONSE_REFERENCE.md), [CCleaner 2017](/case-studies/CCLEANER_2017.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Software release engineers, security operations teams, enterprise administrators, incident commanders and supplier-risk owners

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 17 min (3,968 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You want an evidence-bounded account of the 2017 NetSarang ShadowPad compromise, you need to separate exposure from execution from activation from impact, or you are reviewing release trust, signed-artifact assurance and endpoint authority

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Executive summary](#executive-summary), [Why a valid signature was not enough](#why-a-valid-signature-was-not-enough), [Exposure, execution, activation and impact](#exposure-execution-activation-and-impact)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md), [Secrets Management Reference](/SECRETS_MANAGEMENT_REFERENCE.md), [Endpoint Security Reference](/ENDPOINT_SECURITY_REFERENCE.md), [Incident Response Reference](/INCIDENT_RESPONSE_REFERENCE.md), [CCleaner 2017](/case-studies/CCLEANER_2017.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

Key takeaways (reviewed 2026-11-17):

- A supplier compromise reverses the update relationship: an ordinary install can introduce malicious code through a trusted package. ([Executive summary](#executive-summary))
- The question is not whether you downloaded from the right place, but whether the artifact matches an authorized, independently reviewed release. ([Executive summary](#executive-summary))
- A compromised package, execution of its embedded code, activation of further capabilities and verified data theft are different findings. ([Executive summary](#executive-summary))
- The record is bounded: Kaspersky documented the discovery and design, and NetSarang acknowledged the affected release. ([Executive summary](#executive-summary))

<!-- meta:end -->

## Executive summary

Software updates are normally a protective activity. A supplier compromise can reverse that relationship: a customer following an ordinary installation process may introduce malicious code through a package it reasonably expects to trust. The central problem is not simply whether the customer downloaded from the right location. It is whether the delivered artifact corresponds to an authorized and independently reviewed release.

The 2017 NetSarang incident is a particularly useful example because it involved software used for connectivity and administration. Its importance lies in the relationship between a trusted release, the host running it and the authority available on that host. The presence of a compromised package, execution of its embedded code, activation of further capabilities and verified data theft are different findings. A credible case study must not merge them.

The public record provides a bounded historical account. Kaspersky documented the discovery and technical design. NetSarang acknowledged the affected release in a statement reproduced by Kaspersky. National response organizations published affected-build and mitigation guidance. A detection vendor described a check for a known compromised library. These records support a strong supply-chain lesson without supplying a complete public account of how the attacker first entered the supplier.

This study proposes a two-sided response model. Publishers must establish trustworthy release production and distribution. Customers must stop deploying suspect artifacts, investigate affected hosts and review the authority those hosts could exercise. Neither side can complete the other's work merely by announcing that a clean update exists.

## Scope and research discipline

The focus is the July-August 2017 NetSarang distribution incident, not every later intrusion involving the ShadowPad family. Later use of a malware family does not automatically establish the operator or entry path in the original incident. This study deliberately retains the cautious attribution language of the contemporaneous research rather than importing a later actor label without a separate evidentiary argument.

Six primary records were reviewed: Kaspersky's research article and technical annex, its press release containing NetSarang's statement, the Canadian response alert, MyCERT's advisory and Tenable's plugin description. These are six records, not six independent investigations. Several repeat information from the same discovery and vendor notification process. That relationship matters when assessing corroboration.

The original NetSarang advisory URL returned a not-found response during this research. The vendor's statement remains available within Kaspersky's contemporaneous release, and the affected builds are preserved in national advisories. The missing original page is recorded as an access limitation, not silently treated as a page read in full.

No malware sample was downloaded or executed, no live infrastructure was contacted, and no customer or supplier internal records were accessed.

Most of the article is original defensive analysis. Proposed controls, evidence records and exercises are not assertions that NetSarang or a particular customer lacked them. Historical details are concise and traceable; the longer discussion explains how a defender can make better decisions when release provenance and endpoint trust become uncertain at the same time.

## The historical record in six bounded accounts

### 1. Discovery and the compromised release

Kaspersky's August 15 research account describes suspicious DNS activity investigated with a financial-sector partner and traced to NetSarang software. It identified an embedded payload in nssock2.dll, signed with a legitimate NetSarang certificate. It reported one confirmed activated payload at a Hong Kong company, not a worldwide count of successful follow-on intrusions. The researchers described source modification or changes on build servers as possible explanations, with investigation ongoing. Their attribution discussion noted similarities rather than a definitive responsible actor. [1]

### 2. The technical annex

The accompanying August 2017 annex describes a staged modular platform. An initial component sought configuration and activation information; a later stage coordinated modules and additional plugins. It documents encrypted configuration and storage, multiple communication capabilities and victim-dependent details. Those are findings about the analyzed implementation. They do not prove that every exposed customer received every possible module, experienced the same activity or lost information. The annex is a technical basis for defensive scoping, not a complete incident narrative for every affected organization. [2]

### 3. NetSarang's statement in the press release

Kaspersky's August 15 press release includes a NetSarang statement acknowledging that the July 18 release had unknowingly shipped with a backdoor. It describes the vendor's responsibility to customers and commitment to stronger safeguards. The surrounding release says NetSarang responded by removing the malicious code and providing an update. It also explicitly says observed similarities were insufficient to establish a precise actor connection. The vendor acknowledgment is primary testimony preserved by the publishing researcher, not a separately retrieved copy of the now-unavailable advisory. [3]

### 4. The Canadian response alert

The Canadian alert dated August 17 specifies distribution through the vendor website and application-update mechanisms from July 18 to August 4. It lists five affected builds. Its response guidance includes deploying the vendor remedy, isolating confirmed affected installations for forensic analysis and preserving connection logs. This is broader than treating the incident as a routine version upgrade. It does not establish that every installation resulted in activated malware or that every customer required an identical recovery plan. [4]

### 5. MyCERT's affected-build guidance

MyCERT's August 20 advisory lists the affected release builds and historical replacement builds. It identifies August 5 as the clean-update date and describes reports of potential Malaysian exposure based on downloads. Potential exposure is not a confirmed tally of activated backdoors. The advisory's build numbers are a historical reference for this incident, not a recommendation to install a 2017 version today. [5]

### 6. Tenable's detection boundary

Tenable's Xshell plugin description identifies a local check for a known compromised nssock2.dll using its hash. It was published August 23, 2017. Such a check can help identify a specific affected artifact, but its published scope is not a complete investigation into every product, every execution or later activity on the host. A negative result from that check cannot by itself close the whole incident. [6]

## The affected release: exact product scope

The following table preserves the historical build identifiers in the Canadian and MyCERT advisories. It is a scoping aid, not a current software-support matrix. [4,5]

| Product | Affected 2017 build | Replacement build listed by MyCERT |
| --- | --- | --- |
| Xmanager Enterprise 5 | 1232 | 1236 |
| Xmanager 5 | 1045 | 1049 |
| Xshell 5 | 1322 | 1326 |
| Xftp 5 | 1218 | 1222 |
| Xlpd 5 | 1220 | 1224 |

A product name alone is not enough for a reliable exposure decision. A suite can include shared components, and a current inventory can hide a previous installation. Capture the precise package, its version, its provenance and the installation interval. When records disagree, preserve both observations and investigate the difference instead of choosing the one that makes the inventory look complete.

An enterprise software catalog may describe what was approved, while an endpoint inventory describes what is currently visible. Neither necessarily shows what a contractor installed temporarily or what a remote administrator ran during a maintenance session. Historical deployment records, cache contents and endpoint evidence may therefore be necessary to reconstruct exposure.

## Timeline: distribution is not the same as execution

| Event | Supported historical date | Interpretation limit |
| --- | --- | --- |
| Affected release | July 18, 2017. [3] | Release date is not every customer's installation date. |
| Distribution interval | July 18-August 4. [4] | Packages cached elsewhere could remain available later. |
| Clean update | August 5, according to MyCERT. [5] | Release of a remedy is not universal deployment. |
| Research publication | August 15. [1,3] | Public disclosure is not the first investigation activity. |
| Canadian alert | August 17. [4] | The alert is guidance, not a new victim count. |
| Detection plugin | August 23. [6] | Publication of one check is not the start of all detection. |

For an internal investigation, maintain separate dates for acquisition, installation, execution, observed communications and remediation. Each answers a different question. A package downloaded during the affected interval but never run has a different evidentiary status from a host with observed suspicious activity. Both deserve handling, but the conclusions should remain specific.

The cached-package issue is an original defensive inference. Once an organization has copied an installer into its own repository or image, changes on the supplier's website do not necessarily remove that copy. The organization must find and retire its internal distribution paths rather than assuming the supplier's cleanup automatically reaches them.

## Why a valid signature was not enough

A code signature is an important authenticity mechanism, but it does not independently certify that the signed code is benign. The security decision must ask what was authorized to be signed and whether the released artifact matches the reviewed source and build process. This is a general trust distinction, not a claim that signatures are useless.

Treat release assurance as a chain of evidence. A change should be reviewed; the build should use controlled inputs; the output should be associated with that build; signing should authorize the intended artifact; publication should distribute the same bytes. If those steps are collapsed into one broad administrative authority, an attacker may be able to alter both the artifact and the evidence that appears to justify it.

Separation is valuable only when it changes what one compromised identity can do. Requiring two approvals that are both generated automatically from the same compromised job does not provide meaningful independence. A useful review asks what observation or decision remains outside that job's control and whether it can stop a suspect release.

Consumers face a related boundary. Downloading from an official location and checking a valid signature are sensible checks, but they should be complemented by inventory, staged rollout and post-installation observation appropriate to the software's risk. The goal is not to reject all updates. It is to retain the ability to notice and reverse an update that behaves outside its expected purpose.

## Administrative software and the authority available to it

An administration workstation is a consequential place to run any third-party code. It may contain connection profiles, access tokens, session material or access to systems that ordinary user endpoints cannot reach. This section is a risk model, not a claim that specific secrets were stolen in the NetSarang incident.

Begin by mapping the workstation's actual authority. Which accounts can it use? Which systems can it reach? Which actions require fresh authentication? Which sessions remain usable after the application closes? These questions define the potential impact of an endpoint compromise more accurately than the workstation's job title or asset category.

Separate ordinary browsing and communication from privileged administration where feasible. Limit standing permissions, constrain the destinations available to administrative tools and use a controlled method to obtain elevated access. The design should also preserve a safe alternative for urgent operations when the primary workstation is isolated.

Do not interpret the presence of a connectivity product as proof that all remote systems were reached. Potential authority, attempted access and successful use are separate evidence states. Investigators should use the authority map to prioritize review, then record what the relevant systems actually show. This avoids both under-scoping and an unsupported declaration that the entire environment was compromised.

## Exposure, execution, activation and impact

A useful incident record separates four stages. Exposure means the suspect artifact was present or available. Execution means relevant code ran. Activation means evidence supports the transition to additional malicious capability. Impact means a specific consequence, such as unauthorized access or verified information transfer, is supported by evidence. These are analytical categories for this study, not a universal incident taxonomy.

The stages are not a reason to delay containment until the worst case is proven. A confirmed affected installation may justify isolation while the investigation continues. The distinction instead protects the accuracy of statements about what happened and helps decide what additional evidence is needed.

For each host, record the strongest supported stage and the visibility limitations. A machine can remain in an uncertain category because necessary logs no longer exist. That uncertainty should influence recovery and risk acceptance rather than being converted into a clean result. Likewise, absence of a known domain lookup does not prove that a malicious library never ran.

Avoid treating observed activation counts as total exposure counts. Research visibility depends on customers, sensors, time and access. A report of one confirmed activation can establish that activation occurred within that observed scope; it does not establish that only one organization was affected worldwide. The article's historical account retains that distinction.

## DNS evidence: useful, incomplete and contextual

The discovery account makes network behavior an important part of the historical lesson. [1] The following detection discussion is original defensive analysis. DNS records can reveal unexpected relationships, but their usefulness depends on whether an investigator can identify the originating endpoint and, ideally, the process responsible.

An enterprise resolver may aggregate requests from many machines. A suspicious query tied only to that resolver is not automatically attributable to a particular user. Preserve relevant endpoint, resolver and network records with consistent timestamps. Document clock differences and collection gaps so that investigators do not infer a precise sequence from incomparable data.

Look for departures from expected software behavior rather than assuming every unusual domain is malicious. The application owner can explain normal update and licensing activity. Security analysts can compare the observation with package provenance and endpoint evidence. Combining those perspectives is stronger than making a decision from a domain's appearance alone.

Do not replay historical command-and-control communications against live infrastructure to test a theory. Use preserved evidence or an authorized, isolated simulation. Historical domains may change ownership or meaning, and sending traffic can create unnecessary exposure. A retrospective investigation should remain a controlled evidence exercise.

A detection should produce a decision record. What was observed, what could explain it legitimately, what supporting evidence exists and what action is proportionate? That discipline helps a team react quickly without turning a weak indicator into an unqualified accusation or ignoring it because the originating application is familiar.

## Publisher response: rebuilding the release boundary

The following is a proposed publisher workflow, not a reconstruction of NetSarang's internal response. First, stop further distribution of the identified suspect artifacts and preserve representative copies and release records under controlled access. The team needs enough evidence to understand the incident without leaving the material available for routine installation.

Next, determine which production steps can still be trusted. Source control, build workers, dependency caches, signing services and publication credentials may have different exposure. Replacing an installer alone does not establish that the next build is trustworthy. The recovery plan must identify the approved inputs and authority used to produce the replacement.

Have an independent reviewer compare the release decision with the available evidence. Independence means the review is not controlled by the same potentially compromised identity or process. It does not necessarily require a different company. The reviewer should be able to reject the release or require additional investigation.

Publish precise customer guidance. Identify affected versions and artifacts, explain the historical distribution interval, distinguish removal of the package from investigation of a host and provide a reliable channel for updates. Avoid claiming that customers are safe merely because a new package is available. The supplier cannot know every customer's installation history from its own release logs.

Finally, reconcile every distribution channel. Websites, automatic-update feeds, mirrors, enterprise partners and support attachments can have different owners. A signed completion record should show which artifacts were retired and how the team verified that ordinary customers would no longer receive them. Exceptions need owners and a containment plan.

## Customer response: stop redeployment before declaring success

Customers need a parallel workflow. Suspend deployment of the suspect release while confirming scope. Preserve relevant package and endpoint evidence. Identify affected installations and determine which hosts performed sensitive administrative work during the exposure interval. Use approved containment procedures that account for business and safety dependencies.

Search beyond currently installed software. Internal repositories, desktop images, virtual-machine templates, offline installer folders and automation scripts can preserve an obsolete package. A cleaned workstation may become exposed again if a standard rebuild process reinstalls the same artifact. Closing that path is part of remediation, not a separate housekeeping task.

Coordinate credential and session review with the evidence and authority map. A blanket credential change performed from a suspect endpoint can fail to restore trust. Changes need a trusted administrative path and a way to verify that relevant sessions or tokens no longer grant access. The precise response depends on the findings and the systems involved.

Record separately whether the affected package was removed, the host was investigated, the administrative authority was addressed and the internal distribution source was corrected. Those are different completion conditions. One owner may coordinate them, but each requires its own evidence before the case is closed.

The customer should also verify that the replacement meets operational needs. A rushed remediation that breaks the only administration path can encourage staff to restore the old installer informally. Provide a tested alternative and clear instructions so that the secure path is also workable during urgent support activity.

## Detection coverage is not incident closure

A scanner can answer a narrow question very well. The Tenable record is useful precisely because it describes a known-file check rather than claiming to reconstruct every action. [6] A complete response should preserve that narrow meaning when interpreting results.

For every check, document the population it reached, the credentials or telemetry it required, its failure modes and the interval it covered. A host that did not respond is not a negative result. A host scanned after reinstallation may no longer contain the original artifact even though its earlier activity remains relevant.

Complement artifact checks with historical deployment and behavior evidence. The strongest conclusion may be that a specific bad package is no longer present, while the investigation into prior access is still open. Keeping those findings separate allows operations to track remediation without pressuring analysts to overstate certainty.

Do not turn a product-specific check into a universal control. A check for one Xshell library does not automatically cover another product, a repackaged installer or an unrelated later ShadowPad variant. Coverage should be demonstrated against the actual scope of the investigation and revised when that scope changes.

## A proposed evidence and acceptance matrix

| Question | Evidence to retain | Completion meaning |
| --- | --- | --- |
| What was acquired? | Package identity, source and acquisition interval. | Exposure population is bounded. |
| What ran? | Endpoint and execution records with gaps noted. | Execution finding is supported. |
| What additional activity occurred? | Correlated host and network findings. | Activation and impact claims remain specific. |
| What authority was available? | Account, session and destination review. | Follow-on investigation is prioritized. |
| Can the bad release return? | Repository, image and automation checks. | Routine redeployment paths are corrected. |
| Is the replacement trustworthy? | Verified provenance and operational tests. | Reopening has a documented basis. |

This matrix is original guidance. It does not require every organization to collect the same data, and it does not override privacy or retention obligations. The aim is to make the basis for closure visible. An exception can be accepted by an appropriate owner, but it should not disappear inside a broad statement that remediation is complete.

## Ninety-minute tabletop: a signed package under suspicion

This fictional exercise is not an account of a NetSarang customer. Participants represent software deployment, security operations, identity, administration, procurement, communications and an executive decision owner. Use synthetic records and no live malicious software.

In the first thirty minutes, a supplier announces that one release was compromised. The enterprise inventory shows a small number of current installations, but a shared software repository contains the affected package. Ask the team to separate confirmed exposure from unknown coverage and decide who can suspend deployment. Require an explicit plan for administrators who depend on the tool.

In the next thirty minutes, a resolver log shows suspicious activity without a clear endpoint mapping. One administrator says the package was used only briefly and has already been removed. Ask what that statement establishes, which records might still exist and whether removal closes the access review. The team should identify evidence gaps without inventing a successful intrusion.

In the final thirty minutes, the replacement package passes a scan and a business owner requests immediate closure. A rebuild template still points to the old repository artifact. Participants must decide what can reopen, which issue prevents closure and who owns the remaining risk. The facilitator should challenge any response that equates a clean current scan with a clean historical record.

Score the exercise on accurate scope, controlled decisions and prevention of redeployment. A good result is not the largest number of isolated hosts or the fastest all-clear. It is a defensible account of what is known, what remains uncertain and which actions reduce the uncertainty or contain its consequences.

## Thirty-, sixty- and ninety-day improvement plan

During the first thirty days, identify the administrative software with the greatest authority and map how releases reach users. Record package provenance, deployment owners and emergency suspension authority. Choose a small sample of installations and verify that the inventory can reconstruct the installed version and its source.

By sixty days, test a simulated supplier recall. Use an innocuous test package and ask the team to find it across repositories, images and endpoints. Measure how long it takes to stop new deployments and identify exceptions. A recall process that reaches only the central catalog is incomplete if local copies remain routinely usable.

By ninety days, exercise trusted replacement and endpoint acceptance. Confirm that administrators can work through an approved alternative, that relevant logs remain available and that closure requires more than a version change. Feed failed tests into specific engineering work with named owners and repeat the checks after correction.

Useful measures include time to stop distribution, percentage of managed installations with verifiable provenance, unresolved historical coverage gaps and time to reconcile internal caches. Avoid presenting a large inventory count as proof of completeness. The important result is whether the organization can answer a precise recall question with evidence.

## Conclusions and publication cautions

The NetSarang case illustrates a failure of release trust rather than a simple instruction to avoid unfamiliar downloads. A customer can use the expected supplier channel and still receive a compromised artifact. That possibility does not make updating futile; it makes provenance, bounded privilege, observation and recall capability part of responsible software use.

The central defensive distinction is between replacing software and restoring confidence in the environment where it ran. Publishers can correct a release. Customers must still account for installation history, host activity and available authority. Both sides need precise communication because neither possesses all the evidence needed by the other.

Keep attribution, reach and impact qualified in any public version. The initial research's confirmed activation finding is not a global victim count. Potential access is not verified theft. A legitimate signature is not evidence of malicious intent by the publisher. The reviewed record does not establish a complete initial intrusion route into the supplier or a quantified aggregate financial loss.

The practical goal is a release process and customer response that remain useful when a trusted artifact becomes suspect. An organization should be able to stop distribution, find what it deployed, investigate what ran and resume through an independently justified path. Those capabilities can be tested before a real supplier notification arrives.

## Sources and reading record

[1] Kaspersky GReAT, ShadowPad in corporate networks, August 15, 2017. Research narrative, FAQ and scope qualifications reviewed. https://securelist.com/shadowpad-in-corporate-networks/81432/

[2] Kaspersky, ShadowPad Part 2: Technical Details, August 2017. Eleven-page PDF reviewed for staged architecture and defensive evidence implications; no sample execution or protocol reproduction performed. https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2017/08/07172148/ShadowPad_technical_description_PDF.pdf

[3] Kaspersky press release containing NetSarang statement, August 15, 2017. Release and attributed vendor statement reviewed. https://www.kaspersky.com/about/press-releases/shadowpad-how-attackers-hide-backdoor-in-software-used-by-hundreds-of-large-companies-around-the-world

[4] Canadian Centre for Cyber Security, Software Compromised with Backdoor Trojan, AV17-009, August 17, 2017. Full short alert reviewed. https://www.cyber.gc.ca/en/alerts-advisories/software-compromised-backdoor-trojan-0

[5] MyCERT, MA-678.082017: ShadowPad, August 20, 2017. Full advisory reviewed; historical version recommendations only. https://mycert.org.my/portal/advisory?id=MA-678.082017

[6] Tenable, plugin 102713: NetSarang Xshell 5 Backdoor Trojan. Description and coverage metadata reviewed. https://www.tenable.com/plugins/nessus/102713
