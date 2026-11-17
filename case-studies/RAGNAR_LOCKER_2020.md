# Ragnar Locker: Ransomware Inside a Virtual Machine

*A TeamStarWolf case study. Published 16 November 2026.*

[All case studies](/case-studies/README.md) · Related: [Ransomware Defense Reference](/RANSOMWARE_DEFENSE_REFERENCE.md), [Malware Analysis Reference](/MALWARE_ANALYSIS_REFERENCE.md), [Hypervisor Security Reference](/HYPERVISOR_SECURITY_REFERENCE.md), [Attack Campaigns Reference](/ATTACK_CAMPAIGNS_REFERENCE.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Ransomware defenders, detection engineers, virtualization and platform owners and incident responders

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 18 min (4,235 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You want an evidence-bounded account of Ragnar Locker, you need to understand why running inside a virtual machine does not isolate reachable host files, or you are tuning detection across the host and guest boundary

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Executive summary](#executive-summary), [The mechanism: shared access changes the meaning of isolation](#the-mechanism-shared-access-changes-the-meaning-of-isolation), [Containment should follow access, not only the executable](#containment-should-follow-access-not-only-the-executable)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Ransomware Defense Reference](/RANSOMWARE_DEFENSE_REFERENCE.md), [Malware Analysis Reference](/MALWARE_ANALYSIS_REFERENCE.md), [Hypervisor Security Reference](/HYPERVISOR_SECURITY_REFERENCE.md), [Attack Campaigns Reference](/ATTACK_CAMPAIGNS_REFERENCE.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## Executive summary

Ragnar Locker is a useful case for studying a security boundary that administrators can accidentally misunderstand. Running a program inside a virtual machine does not mean that every file it can reach belongs exclusively to that virtual machine. Deliberate integration features can expose host data to guest software. The distinction matters when a security product observes an apparently legitimate host application while harmful activity originates in a different execution environment.

This study centers on Sophos's May 2020 investigation of a ransomware deployment that used VirtualBox and a small Windows XP guest. It then separates that technical observation from the FBI's March 2022 intelligence summary and Eurojust's October 2023 account of international enforcement. Those sources describe different observation windows and different populations. They cannot be combined into a single complete victim list, a uniform intrusion sequence or a final determination of criminal guilt. [1][2][3]

The historical findings below are deliberately concise. Most of the document develops original defensive analysis, review questions and a safe fictional exercise. That material explains how to apply the evidence without inventing a victim's internal architecture. The central recommendation is to examine the authority and data access granted to an execution environment, alongside the name and reputation of the software running it. A recognized application can perform consequential actions under a compromised administrator's direction.

## Scope, method and evidence boundaries

Primary sources support this study: a vendor's direct incident analysis, an FBI FLASH, an official prosecutorial-coordination announcement and Oracle's product documentation. The first three supply historical observations. The fourth explains the general shared-folder mechanism in a later product version. Current documentation is not evidence that every option or default existed in the 2009 version used during the investigated attack.

The record does not establish that every Ragnar Locker incident used virtualization. It does not provide a complete initial-access history for every victim, independently verify every extortion claim or demonstrate that every affected organization recovered. The enforcement announcement is evidence of the actions the authorities reported and the allegations they described. It is not a conviction record. No criminal infrastructure, stolen information or malware sample was accessed for this research.

Where the text says an organization should collect an artifact or test a control, that is an analytical recommendation. It is not a statement that Sophos, the FBI or an unidentified victim actually performed that exact procedure. This distinction keeps a detailed case study useful without allowing plausible security advice to become fabricated incident history. Dates and counts remain attached to their source scope throughout.

## Historical evidence: the observed 2020 deployment

Sophos described an unsigned installer delivered through a Group Policy task. It deployed Sun xVM VirtualBox 3.0.4 and a stripped-down Windows XP SP3 guest. A roughly 49 kB ransomware component traveled within a much larger package: a 122 MB installer and a 282 MB virtual image. The configuration exposed host local, removable and mapped drives to the guest through writable shared folders. Host-side writes consequently appeared under the virtualization process rather than as the guest ransomware executable. The observed preparation also included service interruption and shadow-copy deletion. [1]

The report supports a specific evasion mechanism, not a universal claim that every endpoint product was helpless. Nor does it demonstrate exploitation of a hypervisor vulnerability. Configured access to host files explains the relevant boundary crossing. Treating it as a proven virtual-machine escape would substitute an unsupported exploit narrative for the more important administrative fact: the guest had been given useful access.

That distinction changes the defensive investigation. A suspected exploit would lead researchers toward a flaw in isolation. Abuse of sharing instead requires examination of installation authority, configuration changes and the permissions available to the host process. These are related security questions, but their evidence and remedies differ.

## Historical evidence: the FBI's later observation window

The FBI's March 7, 2022 FLASH said it first became aware of Ragnar Locker in April 2020. As of January 2022, it had identified at least 52 affected entities across ten critical-infrastructure sectors. The advisory described changing packaging, customized virtual machines, selective file handling and actions against recovery or management capabilities. It recommended measures including protected offline backups, multifactor authentication and attention to privileged access. [2]

These are bounded observations. First awareness is not proof of a malware family's birth date. The identified entities are neither a count of infected computers nor a certified worldwide total. A single organization can contain many endpoints, and a reporting agency can know only a portion of all incidents. The word "at least" matters because it preserves that incompleteness.

A defensive review can use the advisory to broaden its questions beyond one specimen. It should not assume that the absence of one historical filename proves safety. The underlying concern is whether an adversary can change the environment, interrupt protection and reach valuable data through authority already present in the organization.

## Historical evidence: the 2023 enforcement action

Eurojust reported coordinated activity during October 16-20, 2023. Its account described six suspects heard in four countries and nine servers taken down across the Netherlands, Germany and Sweden. Authorities suspected attacks against 168 companies internationally since 2020. The statement discussed a suspected developer appearing before examining magistrates and infrastructure used for exfiltration or publication. [3]

This account is a later legal and operational development, not part of the original May 2020 technical observation. Its 168-company allegation should not be subtracted from the FBI's earlier identified-entity count to calculate growth. The sources use different dates, methods and case definitions. The public material reviewed here does not establish a reconciled denominator.

Taking infrastructure down can disrupt an operation while leaving substantial victim work unfinished. An affected organization may still need to rebuild systems, assess disclosure and validate recovered information. Those are analytical implications of the distinction between an enforcement operation and an individual recovery project. The announcement alone does not establish eradication from every endpoint, destruction of every stolen copy or a final judgment against every suspect.

## The mechanism: shared access changes the meaning of isolation

Oracle's later VirtualBox documentation explains that shared folders expose host files to a guest through Guest Additions. They do not require ordinary guest networking, and access can be read-only or read-write. This supports the conceptual distinction between network isolation and file-sharing integration. It does not retrospectively prove every configuration detail of VirtualBox 3.0.4. [4]

Consider a clean virtual machine that has no connection to the internet. If the administrator deliberately makes a host directory writable from the guest, a guest application can still modify the exposed material. Removing a network adapter does not reverse the separate sharing decision. Conversely, granting read-only access can protect against writes through that particular path while leaving confidentiality concerns if guest software can read sensitive content.

A useful security model therefore records each bridge independently. Network access, folder sharing and other integration capabilities should not be reduced to a single "isolated" checkbox. The appropriate question is what information and authority cross each bridge, in which direction and under whose control. This model is general defensive reasoning. It does not imply that every listed integration capability participated in the Ragnar Locker attack.

## Why process reputation is incomplete evidence

A signed, familiar application can be trustworthy as software and still operate in an untrustworthy context. Reputation answers questions about origin and known behavior. It does not independently establish that the current invocation was approved, that the configuration is appropriate or that the account running it has a legitimate reason to access particular records.

For investigators, a host process name should be a starting point rather than a verdict. Useful context includes when the application appeared, who initiated installation, which management system authorized it, what guest image it loaded and which host paths were available to that guest. A development laptop with an approved image differs from an accounting server that unexpectedly acquired virtualization software during a maintenance window.

The operational lesson is to combine evidence from installation, identity and data access. Each record may look ordinary in isolation. Their relationship can be unusual: a newly deployed application using an administrative identity begins modifying a broad collection of business files after an unauthorized policy change. That relationship deserves investigation even when the executable belongs to a legitimate vendor.

This approach avoids indiscriminate product blocking. Organizations can retain necessary virtualization while making unexpected use visible. The exception process should identify a business owner and a permitted scope, rather than accepting the name of a popular application as an enduring approval for every future use.

## Deployment authority deserves its own investigation

A deployment system is designed to make changes on many computers efficiently. That same capability creates a consequential trust relationship. The Sophos observation makes management-plane review relevant, but it does not prove that every deployment platform or administrator was compromised in every related case. A local investigation must establish its own facts. [1]

An organization assessing a suspicious rollout should ask which identities could create the task, whether approval records exist and how the target population was chosen. The contents of a deployment package alone may not answer those questions. Policy history and administrative authentication records can explain who could cause the package to reach other systems, even if the package itself is already deleted.

Separation of responsibilities can reduce exposure. A person who prepares a package need not automatically possess authority to deploy it everywhere. Emergency procedures should specify how rapid approval works and how subsequent review occurs. Otherwise, an organization may discover that its most privileged pathway receives its weakest scrutiny precisely when unusual activity is easiest to dismiss as urgent maintenance.

These are design recommendations, not assertions about an identified victim. Their value is that they address the enabling authority before encryption begins. A control that notices only the final destructive activity has less time to prevent widespread impact than one that detects an unapproved change to distribution scope.

## Inventory must include configuration and purpose

A software inventory that records only product names can miss the relevant risk. For virtualization, a useful inventory also identifies ownership, approved guest images, data-sharing expectations and the systems on which installation is permitted. A workstation used for software testing and a production records server should not inherit identical assumptions merely because both can run the same installer.

Age is a useful review signal but should not become the sole detection rule. The historical package used an old version; a future unauthorized environment could use a newer one. An organization should therefore evaluate unexpected presence and unexpected configuration, rather than treating an old version number as the whole problem. Version controls and deployment controls answer different questions.

Temporary exceptions require expiration and removal evidence. A support team may legitimately install a virtual environment to diagnose an issue, then leave it behind. If the exception has no owner or end date, a later reviewer cannot distinguish sanctioned residue from unauthorized installation. Recording a narrow purpose makes both operations and investigation easier.

Inventory quality can be tested without malware. Select a sample of approved installations and ask whether the organization can identify their owners and permitted host access. Missing answers demonstrate a governance gap directly. They do not prove compromise, but they show that a future incident would be harder to scope accurately.

## Detection engineering across the host and guest boundary

A detection program should be explicit about where it collects evidence. Host telemetry, guest telemetry and central management records can observe different parts of the same event. No single perspective should be assumed to contain a complete account. This is especially important when a guest is newly introduced and was never enrolled in the organization's normal monitoring process.

A practical analytic hypothesis is an unauthorized virtualization deployment followed by unusual access to business data. The hypothesis can be evaluated using ordinary installation records, configuration changes and file-service activity. It should not automatically label all bulk writes as malicious. Backup jobs, indexing and legitimate migration can create substantial activity, so the evaluation needs a known operational baseline and an accountable owner.

Alert quality improves when the response question is concrete. "Is VirtualBox installed?" may produce an inventory task. "Who approved this new instance on a server that normally has no guests, and why can it modify these paths?" supports a focused investigation. The latter combines context without pretending that one vendor name is inherently suspicious.

Coverage testing should record failures honestly. If a sensor does not show guest process details, the result is a visibility limitation, not proof that the host sees nothing useful. If host records show file modification but cannot identify the guest program, other evidence may still narrow the cause. The goal is a documented collection plan with known gaps rather than a blanket assertion of complete visibility.

## Evidence preservation when a virtual image is involved

A response team may encounter the installer, a guest image, configuration files and host records. These artifacts have different roles. The installer helps explain deployment. The image may contain guest-side evidence. Configuration can establish which host resources were exposed. Host records can connect those artifacts to an account and time interval. None should be treated as a substitute for all the others.

Collection should follow the organization's established forensic process, including authorization, integrity records and appropriate handling of sensitive material. A virtual disk can contain confidential information even when it appears to be merely a technical artifact. Copying it to an unrestricted analysis location can create a new data-handling problem during an already difficult incident.

Preservation and containment sometimes conflict. Continued access may permit additional harm, while abrupt shutdown may change volatile evidence. The response lead should document the decision, the operational risk and the evidence that could not be retained. A justified containment action is preferable to leaving destructive activity active solely to pursue an ideal evidence set.

Analysis should occur in a controlled environment suitable for suspicious material. This case study does not provide malware execution instructions. For ordinary teams, the actionable step is to retain the right artifacts and obtain qualified assistance, rather than opening an unfamiliar guest image on a production workstation in an attempt to reproduce the attack.

## Containment should follow access, not only the executable

Removing one suspicious guest may stop one observed activity while leaving the authority that introduced it intact. If an attacker retains administrative access or control of a deployment mechanism, deleting a file does not establish durable containment. A response plan should therefore consider identity, management access and reachable data alongside the visible payload.

This does not mean every account must be disabled without regard to operations. The team needs an assessed scope, a route to maintain critical functions and a record of decisions. Broad emergency changes can disrupt legitimate recovery work. Narrow changes based on an incorrect scope can leave other systems exposed. The best available evidence should guide which boundaries are temporarily closed and which require closer observation.

Remote storage deserves particular attention because host-accessible paths can extend beyond the local disk. Investigators should establish what the affected identity could actually reach during the relevant interval. A drive name alone may not reveal the ownership or sensitivity of the underlying information. File-service access records and storage owners can help resolve that uncertainty.

Successful containment has observable criteria. For example, the organization can demonstrate that the unauthorized deployment path is disabled, affected identities have been addressed and the suspect environment no longer has access to production data. Those criteria should be checked rather than inferred from the disappearance of a ransom message.

## Backup independence and recovery acceptance

A backup is useful against ransomware only if it remains available and can support trustworthy restoration. The analytical question is which identities and systems can modify or delete it. A copy that is continuously writable through the same authority as production data may share the relevant failure mode, even when it lives on a different disk.

Recovery planning should separate the integrity of the backup from the cleanliness of the environment into which it will be restored. Valid historical data can be reintroduced into a still-compromised system. Conversely, a clean rebuilt system may receive incomplete or inconsistent records. Both tests matter, and neither is proven by a successful file copy.

Application owners should define acceptance criteria in advance. For a fictional order-processing system, that could include reconciliation of recent orders, validation of permissions and confirmation that scheduled processes behave as expected. The specific checks depend on the service. The point is to involve the people who can recognize correct business behavior, not only the team that can make a server boot.

The FBI's protective-backup advice provides historical context for this discussion, but these acceptance tests are original recommendations. [2] This study does not certify any particular backup product or suggest that every affected organization lacked protection. The available public record does not support such a victim-wide conclusion.

## Confidentiality and availability need separate conclusions

Ransomware creates a visible availability problem, but restoration does not by itself resolve questions about disclosure. An organization can recover files while remaining uncertain about what was copied earlier. Conversely, an extortion claim can exceed the evidence available to investigators. The correct response is neither automatic acceptance nor automatic dismissal of the criminal's account.

A defensible assessment identifies what is confirmed, what is possible and what remains unknown. Confirmed information might include a documented transfer or a verified access event. Potential exposure might arise from the permissions an attacker held during a gap in logging. Unknowns should remain visible, with the evidence needed to reduce them clearly stated. These are general analytical categories rather than findings about a particular Ragnar Locker victim.

Communications should preserve those categories. Saying that systems are operating again is different from saying that no information left the organization. The first may be supported by service checks while the second requires a different investigation. Combining them into a single reassurance creates avoidable ambiguity for customers and decision-makers.

The same discipline applies to leaked-data claims. This research did not visit a criminal publication site or inspect stolen records. Such access is unnecessary to explain the security lesson and can create further privacy risks. The case study therefore limits itself to legitimate primary reporting and expressly bounded analysis.

## Measurements that would improve a defensive review

Several measures can help an organization assess readiness without pretending to predict every attack. One is the proportion of virtualization installations with a current owner and approved purpose. Another is the time required to retrieve the configuration and deployment history for a sampled host. These measure administrative knowledge and evidence availability, not whether the organization is immune to ransomware.

A useful access measure asks how many critical data locations are writable by a sampled administrative or service identity. The result should be interpreted with context. Some broad access may be necessary for a legitimate operational role, but it should be deliberate and reviewed. The metric is valuable when it prompts a decision about unnecessary authority, rather than becoming a numerical target that teams satisfy by changing labels.

Recovery measures should include the time to validate business data after restoration, not merely the time to start infrastructure. Evidence measures should record retention gaps and the delay before investigators can obtain centralized records. Together, these reveal where the organization would lose time during an uncertain incident.

Historical victim counts cannot replace these local measures. The FBI and Eurojust numbers illuminate their respective reporting contexts. They do not yield an organization's probability of compromise, an expected financial loss or a reliable ranking of which industry is safest. Such calculations would require data and assumptions absent from this source set.

## Procurement and exception review

The case also suggests questions for a security-product evaluation. A prospective customer should ask what the product can observe when a legitimate host application mediates file changes initiated elsewhere. The answer should distinguish supported collection from automated interpretation. A product may record useful activity without automatically attributing it to the guest process, and a demonstration of one detection should not be generalized to every configuration.

An evaluation can use harmless documents in a disposable, authorized environment. The objective is to observe normal sharing and logging behavior, not to run ransomware. The team can compare its inventory record with the actual configuration, then determine whether an unapproved configuration change produces a reviewable event. Any test should use the organization's approved tooling and a plan that prevents access to real business information.

Exception governance is equally important after procurement. If a control excludes a virtualization process for performance reasons, reviewers should document the operational need, the affected systems and the compensating evidence. An exclusion with no recorded scope may become broader than intended over time. Approval should have a review date and an owner who understands both the performance requirement and the data that the process can reach.

The outcome of this exercise is a coverage statement, not a marketing verdict. It should explain which event classes the organization can collect, which require additional context and which remain unavailable. A clear limitation gives responders something to plan around. A vague assertion that a platform is fully protected encourages assumptions that may fail when administrators introduce a new guest, change permissions or expand a deployment group.

These recommendations are original analysis. No product comparison, penetration test or laboratory reproduction was performed for this study. They are intended to make a future authorized evaluation more precise while avoiding conclusions that the historical source material cannot establish.

## A safe fictional tabletop exercise

The exercise concerns a fictional professional-services company with an approved virtualization program on developer workstations. An administrator notices a newly installed virtualization package on a finance server. A support ticket mentions emergency troubleshooting, but the named owner is unavailable. Several shared business files have changed unexpectedly. Participants receive only synthetic records and written injects. No malware, real customer data or production changes are required.

The first decision is whether the team has enough evidence to treat the installation as authorized. Participants should identify the missing approval, the deployment identity and the intended scope. A plausible support explanation should be investigated, not accepted solely because it contains familiar product terminology. The facilitator can supply a second record showing that the installation targeted more machines than the ticket described.

The next decision concerns containment. Participants should explain which access they would restrict, which services would be affected and who can approve the disruption. They should request the guest configuration and identify which host paths were exposed. A statement that the guest lacks internet access should not end the analysis of writable shared data.

A later inject says that infrastructure is rebuilt but the records team cannot reconcile a recent reporting period. This tests whether participants distinguish technical restoration from business acceptance. The final inject is an unverified extortion claim. The communications team must draft a bounded update that reports known service status without asserting an unsupported confidentiality conclusion.

Scoring should reward documented reasoning and identified uncertainty. Successful teams preserve evidence proportionately, identify decision owners and explain what would change their assessment. Speed alone is a poor outcome measure if the team restores service through the same unexamined authority that enabled the suspicious deployment.

## Discussion questions and final assessment

Which part of a virtualization configuration establishes the relevant data access? What evidence would distinguish a sanctioned troubleshooting environment from an unauthorized one? Can the organization reconstruct a management-system change after the affected endpoint is rebuilt? Who decides that restored business records are correct? These questions turn the technical observation into an actionable review without requiring recreation of the attack.

The strongest conclusion from this case is precise: the observed deployment used legitimate virtualization and configured sharing to place harmful guest activity behind a different host-side process context. The historical sources do not justify a universal exploit claim or a complete account of every victim. Later intelligence and enforcement records add breadth, but their counts and legal language retain their own limits. [1][2][3]

For defenders, the durable work is to document approved execution environments, review the authority that deploys them and test the access granted across their boundaries. Detection then has a clearer baseline, containment has a more complete target and recovery can use explicit acceptance criteria. Those improvements remain useful even if an adversary changes the package, family name or particular virtualization product.

## Source register

1. [Sophos: Ragnar Locker ransomware deploys virtual machine to dodge security](https://www.sophos.com/en-us/blog/ragnar-locker-ransomware-deploys-virtual-machine-to-dodge-security). May 2020 original incident analysis. Read deployment and technical explanation. Findings concern the observed attack, not every family incident.
2. [FBI: Indicators of Compromise Associated with Ragnar Locker Ransomware](https://www.ic3.gov/CSA/2022/220307.pdf). March 7, 2022 FLASH. Read summary, technical description and mitigation text. Historical indicators are not reproduced as a current detection package.
3. [Eurojust: Major international operation against Ragnar Locker ransomware group](https://www.eurojust.europa.eu/news/major-international-operation-against-ragnar-locker-ransomware-group-eurojust-support). October 20, 2023. Read official announcement. Allegations and procedural status retained.
4. [Oracle VirtualBox 7.2: Guest Additions, Shared Folders](https://docs.oracle.com/en/virtualization/virtualbox/7.2/user/guestadditions.html). Read shared-folder mechanism and access options. Later-version conceptual context, not retrospective proof of all historical settings.

Research reviewed November 16, 2026. Capcom pages and PDFs returned access errors and were excluded from the evidence base. The Europol page did not expose substantive readable text in the research tool, so Eurojust supplies the enforcement account. This is a private research draft, not a current threat-intelligence feed, a legal determination or a tested recovery procedure.
