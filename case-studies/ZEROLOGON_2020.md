# Zerologon 2020: Domain Trust, Phased Enforcement and the Cost of Exceptions

*A TeamStarWolf case study. Published 15 November 2026.*

[All case studies](/case-studies/README.md) · Related: [Active Directory Security Reference](/ACTIVE_DIRECTORY_SECURITY_REFERENCE.md), [Identity Security Reference](/IDENTITY_SECURITY_REFERENCE.md), [Vulnerability Management Reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md), [CVE Reference](/CVE_REFERENCE.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Active Directory and identity engineers, vulnerability-management teams, detection engineers and incident responders

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 17 min (3,844 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You want an evidence-bounded account of CVE-2020-1472, you need to tell an installed update from an enforced policy or an exception from a removed one, or you are running a phased domain-controller enforcement

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Executive assessment](#executive-assessment), [What the August deployment actually changed](#what-the-august-deployment-actually-changed), [Original recommendation: manage exceptions as expiring decisions](#original-recommendation-manage-exceptions-as-expiring-decisions)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Active Directory Security Reference](/ACTIVE_DIRECTORY_SECURITY_REFERENCE.md), [Identity Security Reference](/IDENTITY_SECURITY_REFERENCE.md), [Vulnerability Management Reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md), [CVE Reference](/CVE_REFERENCE.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

Key takeaways (reviewed 2026-11-17):

- Zerologon (CVE-2020-1472) threatened a central source of enterprise authority: Active Directory domain controllers. ([Executive assessment](#executive-assessment))
- The response was more than a patch: understanding incompatible connections and moving to stronger enforcement. ([Executive assessment](#executive-assessment))
- Primary records support actual malicious use in 2020 but give no worldwide victim total or single attacker identity. ([Executive assessment](#executive-assessment))
- A deployment is incomplete if it delivers updated software while losing track of accounts still allowed weaker behavior. ([Executive assessment](#executive-assessment))

<!-- meta:end -->

## Executive assessment

Zerologon, CVE-2020-1472, demonstrates why a security update can be urgent while its complete deployment still requires careful dependency work. The vulnerability threatened a central source of enterprise authority: Active Directory domain controllers. The response involved patching those systems, understanding incompatible connections and moving to stronger enforcement. Treating those steps as interchangeable creates an inaccurate account of both the vulnerability and its remediation.

This is a vulnerability and exploitation case study, not a narrative of one fully documented victim organization. Primary records support actual malicious use in 2020, but they do not provide a complete worldwide victim total, a single attacker identity or a financial-loss figure attributable solely to Zerologon. The study therefore keeps exploitability, observed activity and confirmed organizational impact separate.

Its main lesson is organizational as much as technical. Compatibility exceptions can preserve essential operations during a security transition, but they also preserve risk. A deployment project is incomplete if it delivers updated software while losing track of the accounts still permitted to use weaker behavior. An exception must have an owner, an evidence-based reason and an end condition.

The article provides conceptual explanation and defensive planning. It deliberately excludes exploit procedures, credential manipulation commands, payloads and directions for compromising a domain. Original recommendations and a fictional training exercise follow the historical evidence. No live network was examined or changed.

## Research scope and source limits

This study uses seven primary records: Microsoft's deployment guidance and enforcement reminder, a Microsoft security-team account of observed activity, CERT/CC's vulnerability note, and three CISA-published bulletins. CISA's GovDelivery publication channel provides accessible official copies of its September and October 2020 statements. Some direct CISA pages and the original Secura whitepaper returned access errors. Those inaccessible documents are not represented as fully read.

CERT/CC credits the underlying research and describes the cryptographic issue. That allows a bounded explanation without claiming independent reproduction of the researcher's experiments. The article does not use secondary summaries as substitutes for missing technical proof. It also does not treat an official advisory's summary as access to all underlying victim evidence.

The Microsoft support article is maintained guidance containing historical deployment phases. The text here identifies those phases by their actual release dates rather than by a current browsing timestamp. The 2020 CISA emergency directive is discussed as a historical response, not as a representation of present legal obligations. A direct current-status page could not be retrieved during this research pass, so no current directive-status claim is made.

Research cutoff is 15 November 2026. Recommendations are original defensive analysis rather than claims about actions taken by named victims. The fictional organization and its numbers are invented. This is an unpublished research package, not a product certification or legal opinion.

## The technical failure at a safe conceptual level

CERT/CC's VU#490028 identifies reuse of a known zero-value initialization vector in AES-CFB8 within MS-NRPC. It explains that the flaw can allow an unauthenticated attacker to impersonate a domain-joined computer, including a domain controller, with potential domain-administrator consequences. The note was first released on 16 September 2020 and later revised. Its account concerns unsafe use of a cryptographic construction, not a general mathematical defeat of AES. [1]

Original analysis: the useful distinction is between a strong cryptographic building block and the protocol assumptions surrounding it. An implementation can use a recognized algorithm while violating conditions necessary for its safe use. A review that checks only the algorithm's name may miss the actual security boundary.

A domain controller is also a consequential target because other systems rely on its identity decisions. Compromise of that authority can affect trust across systems, rather than remaining confined to one ordinary workstation. This does not mean every possible downstream action happened in every observed attack. It means defenders must investigate the scope of authority at risk instead of assuming the impact stops at the initially exploited service.

The word unauthenticated describes the lack of a required preexisting authenticated session for the vulnerable interaction. It should not be expanded into a claim that any internet user can reach every organization's controller. Reachability still matters. Defensive architecture should consider which paths can contact identity infrastructure after an initial foothold, while avoiding the false reassurance that an internal service cannot become accessible to an adversary.

## What the August deployment actually changed

Microsoft's 11 August 2020 phase required updates across all applicable controllers, including read-only controllers. It enforced secure RPC for Windows machine accounts, trusts and controllers, while retaining compatibility handling for other devices. August provided immediate protection, not merely auditing. Third-party-device remediation required additional work. [2]

Events 5827/5828 identify denials, 5830/5831 exception-based allowances, and 5829 initially permitted vulnerable machine connections. Enforcement ended the 5829 behavior. These records alone do not prove successful exploitation. [2]

Original analysis: the phrase patch installed is too broad to close this kind of case. A good closure statement must identify which controllers were updated, which accounts fall under the enforced rules, which devices remain incompatible and which exceptions override the default. Those are separate facts with separate evidence.

The initial update provided material protection and should not have been deferred simply because a later phase existed. Equally, the later phase should not disappear from the story because an organization installed the first update. Historical accuracy requires preserving both propositions rather than choosing the more dramatic headline.

## February enforcement and the exception boundary

Microsoft's 14 January 2021 reminder announced that the 9 February security update would enable domain-controller enforcement by default. Windows and non-Windows devices would need secure RPC for the Netlogon secure channel unless an account had an explicit exception. The reminder again emphasized updating controllers, discovering incompatible devices and addressing them. [3]

The enforcement-phase update superseded the earlier FullSecureChannelProtection registry choice. Explicit exceptions still permitted vulnerable connections and retained risk. [2]

Original analysis: an exception list is part of the security configuration. It should be reviewed with the same seriousness as the enforcement setting itself. A screen showing the stronger default can coexist with a broad exception group that undermines the intended result. The policy's effective population matters more than its label.

The calendar alone also changes nothing on an offline or unmaintained system. A release date marks when an update becomes available or changes the behavior of updated software. It does not demonstrate that every customer installed it, restarted successfully or removed incompatible dependencies. A historical narrative should avoid implying that all exposure ended automatically on 9 February 2021.

## CISA: assumption became a report of active exploitation

CISA's 18 September 2020 bulletin announced Emergency Directive 20-04 and described the risk to Active Directory identity services from an unauthenticated attacker with network access to a controller. At that point, its wording said it assumed active exploitation, based on public exploit availability and adversary behavior. The bulletin distinguished the directive's federal applicability from its recommendation that other organizations patch. [4]

On 24 September, CISA published a more definite statement: it was aware of active exploitation. It urged immediate patching of all domain controllers and described the ability to obtain domain-administrator access through unpatched systems. This is an important evidentiary progression. An assumption on one date and awareness reported on a later date are not interchangeable quotations. [5]

Original analysis: incident history should preserve the confidence level of each dated statement. Rewriting the first warning as confirmed victim evidence would exaggerate what was publicly established at that moment. Conversely, repeating the earlier uncertainty after later confirmation would understate the documented threat.

The distinction also improves operational decisions. A defender need not wait for proof that their own organization is a victim before addressing a critical, reachable vulnerability. Remediation urgency and incident confirmation are different decisions. The former can rest on credible risk and known exploitation elsewhere; the latter requires evidence about the specific environment.

## Observed chains and the limits of attribution

CISA's 9 October 2020 advisory, with FBI contributions, reported advanced persistent threat actors combining older vulnerabilities with CVE-2020-1472. It described unauthorized access to some elections support systems while stating that, at that time, it had no evidence of compromised elections-data integrity. The advisory also cautioned that its analysis was ongoing and incomplete. Those qualifications are essential: access to a supporting system is not proof that votes or results were altered. [6]

Microsoft's 30 November account described a rise in alerts beginning on 13 September. Its observed population included authorized red-team activity as well as a limited number of real attackers. It described one malicious chain using an older SharePoint flaw for initial access before targeting controllers with Zerologon. The vendor's observations support actual malicious use, but its alert volume cannot be treated as a count of distinct confirmed criminal breaches. [7]

Original analysis: vulnerability chaining explains why an internal privilege-escalation issue remains urgent even when perimeter controls exist. A different weakness may supply the required foothold. The defender should therefore investigate entry points and identity escalation together without conflating their causes or pretending that one patch addresses the entire intrusion.

This study does not assign every Zerologon event to one state, criminal group or operator. Such attribution would require additional campaign-specific evidence. It also avoids transferring claims from a separate high-profile 2020 intrusion merely because the dates overlap. Shared timing or tooling does not establish shared responsibility.

## A chronology with distinct meanings

The historical sequence begins with Microsoft's 11 August update, followed by public technical attention and CERT/CC's September note. CISA's September warnings show escalating confidence about active use. October's joint advisory places the vulnerability inside observed intrusion chains. Microsoft's November account distinguishes legitimate testing from malicious activity. The January reminder prepares customers for the February enforcement transition. [1]-[7]

Original analysis: these dates represent different states of knowledge and defense. A vendor release is not deployment. A research demonstration is not victim impact. An alert is not necessarily malicious. A default-policy change is not removal of all exceptions. Keeping those distinctions visible makes the case useful for people designing a response rather than merely reading a timeline.

A chronology should also preserve negative findings exactly as bounded. A dated lack of evidence about one kind of impact does not prove absence of every form of compromise. Nor should it be inverted into an allegation that the unproven impact occurred. This matters particularly where a technical advisory touches election systems or other subjects with substantial public consequences.

For internal reviews, add organization-specific milestones only when records support them: discovery of an unpatched controller, installation confirmation, exception approval and final validation. Do not infer those dates from public announcements. The public and local timelines answer different questions.

## Original analysis: identity infrastructure changes the response scale

Ordinary server remediation can focus on restoring the service and correcting its weakness. Suspected compromise of identity infrastructure requires a wider question: which subsequent actions may have relied on authority an attacker could abuse? That question is more demanding than checking whether the vulnerable executable is now updated.

The investigation should consider administrative changes, trust relationships, privileged group membership and the integrity of management channels. This is a scope recommendation, not a claim that every Zerologon incident included every behavior. A qualified incident-response team should decide which records and systems matter based on evidence from the actual environment.

Patching closes a vulnerability pathway. It does not automatically remove persistence or invalidate all authority acquired before the patch. An organization with credible signs of compromise needs an incident-response workstream alongside its deployment workstream. Combining them into one ticket creates a dangerous shortcut: the installation completes, the ticket closes and the unanswered compromise question disappears.

Executives should receive two separate status lines. One reports vulnerability remediation coverage. The other reports investigation and recovery status. The first can reach completion while the second remains open. That is not failure to communicate progress. It is an accurate representation of different kinds of work.

## Original recommendation: inventory every controller and dependency

Start with a controller inventory that records domain, site, role, operating-system build, support status and accountable owner. Include read-only controllers, remote branches, disaster-recovery instances and systems maintained by service providers. Compare directory information with management records and network observations so that an overlooked system does not remain outside the denominator.

A dormant recovery image deserves attention even if it is not currently reachable. Restoring it later can recreate an old exposure or an incompatible configuration. The organization should define how restored infrastructure enters a controlled validation process before serving production clients. This is a broader recovery-hygiene lesson rather than a claim about a particular victim.

Map non-Windows dependencies separately. An appliance may rely on domain services while remaining outside the endpoint patch platform. Its owner may describe it by business function rather than by the authentication protocol it uses. The investigation needs a person who can connect those views and obtain authoritative vendor guidance.

The inventory should retain unresolved entries. Unknown version, missing owner and unreachable device are actionable states, not reasons to delete a record. A completion percentage based only on systems that answered the management tool can conceal the highest-risk systems. Report the assessed population and the unresolved population side by side.

## Original recommendation: separate four kinds of proof

First, prove update applicability. Match the product and role to the vendor guidance rather than applying a generic operating-system assumption. Second, prove installation on the actual controller. A successful deployment job may still require confirmation of resulting version and operational health.

Third, prove effective policy. Inspect which accounts receive default enforcement and which remain permitted through exceptions. Group membership and inheritance can change the effective result after the original change ticket. Fourth, prove business compatibility through representative workflows and observation. A secure policy that silently breaks an essential service will create pressure for emergency rollback.

These proofs should remain distinct in the record. The security team should be able to explain what each artifact establishes and what it does not. A build report cannot demonstrate absence of compromise. An event log cannot prove every controller was patched. A policy screenshot cannot show that a seldom-used appliance will work at month end.

Use approved, non-destructive validation where possible. Reading version information, reviewing event categories and checking normal business authentication can answer many deployment questions without exercising an exploit against production identity systems. Any additional security testing needs explicit scope, operational safeguards and a recovery plan, not improvised use of public demonstration code.

## Original recommendation: manage exceptions as expiring decisions

For each exception, record the exact dependency, owner, business justification, affected account or group, compensating restrictions and planned resolution. A justification such as legacy device is too weak. It should explain why the device cannot yet comply and what evidence supports the proposed replacement or update path.

Set an expiry date linked to a real action. A planned vendor release, procurement milestone or migration window is more useful than an arbitrary future date repeatedly extended without review. If the date changes, preserve the reason and the decision-maker. This creates a history of accepted risk rather than a silent permanent allowance.

Review exception-group membership after organizational changes. A group created for one appliance can accumulate unrelated systems over time because adding another member is easier than completing a compatibility investigation. The review should confirm that every current member still has an approved purpose and that retired accounts have been removed through normal authorized processes.

An exception also needs a communication boundary. The executive dashboard should never label a domain fully remediated while material allowances remain unexplained. A better status is deployed with named exceptions, followed by the owner and removal date. That phrasing is less tidy but materially more useful.

## Original analysis: logs describe behavior, not intent

The event categories in the vendor guidance support compatibility discovery and enforcement verification. Their meaning depends on the deployment phase and effective configuration. A warning about an allowed vulnerable connection can arise from an incompatible legitimate device. A denial can demonstrate a policy decision without proving that the source was an attacker.

Analysts should correlate relevant records with asset ownership, authorized testing windows and endpoint evidence. Keep raw observations separate from hypotheses. If a scanner or red team generated the activity, document that attribution with the corresponding authorization rather than dismissing it because the pattern looks familiar.

Coverage needs its own evidence. Are logs arriving from every controller? Are timestamps comparable? Did a collection failure begin before the suspicious period? How long do local and central copies persist? A quiet dashboard is reassuring only when the organization can demonstrate that the dashboard would have received relevant evidence.

After a phase transition, update the detection logic and operating procedure together. A rule built around a discontinued warning can become silent for perfectly ordinary reasons. Analysts need to understand changed event semantics so they do not interpret a reduction in one event type as proof that all incompatible behavior disappeared.

## Original recommendation: recover trust deliberately

When evidence supports a compromise concern, prioritize containment and preservation under an incident commander. Recovery of identity infrastructure can affect many dependent services, so it should follow a coordinated plan with qualified specialists. This article intentionally does not prescribe credential-reset sequences or domain-rebuild commands.

The plan should identify which systems can be trusted to perform recovery actions, which administrative channels are clean, and what evidence supports those judgments. Reusing a compromised management path can undermine otherwise correct remediation. Business continuity teams should prepare for authentication disruption while responders determine the scope.

Recovery criteria should be written before declaring success. They might include verified supported builds, reviewed privileged changes, resolved persistence concerns and demonstrated operation from approved management channels. The exact criteria depend on the incident. They should not be copied mechanically from this historical case into an unrelated production environment.

Record why the organization believes restored authority is trustworthy. A successful login proves availability, not necessarily integrity. The closure review should ask whether the response addressed the consequences of the suspected compromise as well as the original vulnerability. That question is the difference between repair of a symptom and recovery of the security boundary.

## Fictional tabletop: Alder County Services

The following exercise is entirely fictional. Alder County Services operates twelve domain controllers across central offices and branch locations. Its management dashboard reports eleven updated systems. A read-only controller at a remote site has not checked in, and a facilities appliance depends on an older integration. No actual county or incident is described.

First inject: the infrastructure team proposes reporting ninety-two percent complete. Participants must explain what the missing controller means for the assurance statement and assign a verified recovery or isolation decision through authorized processes. The objective is to prevent a percentage from concealing a consequential exception.

Second inject: the appliance vendor says a compatible release will take six weeks. Participants must identify the business service, determine who owns the risk and describe the narrowest temporary arrangement that leadership can evaluate. A blanket exemption for every device in the department should fail the exercise unless the team can justify its scope with evidence.

Third inject: a monitoring alert appears during an approved security assessment. The source matches the assessment inventory, but a second device does not. Participants must separate authorized activity from unresolved activity, preserve evidence and decide how to escalate. They should neither call every alert a confirmed intrusion nor dismiss the whole cluster as testing.

Fourth inject: a senior official asks whether an affected supporting system means public records were changed. Participants must draft a statement that distinguishes access, privilege and proven modification. They should name the evidence still needed rather than making an unsupported assurance or accusation.

Fifth inject: a restored recovery image reintroduces an old build. Participants must update the inventory, explain why the earlier closure evidence no longer applies and revise restoration controls. The exercise ends with an owner-assigned exception register, a revised validation checklist and separate remediation and investigation status statements.

## Original recommendation: a useful executive dashboard

A useful dashboard names all controllers, identifies unsupported or unverified systems and shows effective exceptions separately from installation status. It should report unresolved incompatible dependencies and the age of each exception. The information should remain understandable without requiring an executive to interpret raw event identifiers.

Keep incident indicators distinct from deployment blockers. A compatibility warning creates work for system owners. Evidence suggesting malicious activity creates work for responders. They may concern the same device, but they require different expertise and closure criteria. A single red or green indicator cannot express that distinction responsibly.

Measure whether the organization can demonstrate protection, not just whether it performed tasks. Examples include verified controller coverage, exception-removal progress and successful recovery-image validation. Avoid claiming a numerical count of attacks prevented unless the measurement genuinely supports that interpretation.

The final report should preserve uncertainty. If one remote site remains unverified, say so. If a telemetry gap limits retrospective conclusions, state the time window. If investigation found authorized testing rather than malicious use, explain the basis. Accurate limitation statements make the report stronger because they show exactly where its claims end.

## Final assessment

Zerologon shows how a weakness in a foundational authentication mechanism can become important within a broader intrusion chain. The historical record contains both urgent patch guidance and evidence of malicious use. It also contains a deliberately staged enforcement transition that required organizations to address compatibility rather than wait passively for the next release.

The case should not be reduced to either patching solves everything or the first update did nothing. Both are misleading. The stronger conclusion is that remediation must connect software state, effective policy, dependency ownership and evidence of actual compromise.

For future identity-infrastructure vulnerabilities, the durable practices are clear: maintain a complete inventory, validate the actual protection boundary, time-limit exceptions and keep incident recovery separate from patch completion. These are original operational lessons from the documented case, not claims that any current domain is secure.

## Source register

[1] CERT Coordination Center. VU#490028, Microsoft Windows Netlogon Remote Protocol uses insecure AES-CFB8 initialization vector. Released 16 September 2020, revised 19 March 2021. https://www.kb.cert.org/vuls/id/490028

[2] Microsoft Support. How to manage the changes in Netlogon secure channel connections associated with CVE-2020-1472. Deployment phases, event categories and exception behavior. https://support.microsoft.com/en-us/servicing/os/windows-server/2020/10/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472

[3] Microsoft Security Response Center, Aanchal Gupta. Netlogon Domain Controller Enforcement Mode is enabled by default beginning with the February 9, 2021 Security Update. 14 January 2021. https://www.microsoft.com/en-us/msrc/blog/2021/01/netlogon-domain-controller-enforcement-mode-is-enabled-by-default-beginning-with-the-february-9-2021-security-update-related-to-cve-2020-1472

[4] CISA. CISA Releases Emergency Directive on Microsoft Windows Netlogon Remote Protocol. Official GovDelivery bulletin, 18 September 2020. https://content.govdelivery.com/accounts/USDHSCISA/bulletins/2a171e8

[5] CISA. Unpatched Domain Controllers Remain Vulnerable to Netlogon Vulnerability, CVE-2020-1472. Official GovDelivery bulletin, 24 September 2020. https://content.govdelivery.com/accounts/USDHSCISA/bulletins/2a265d8

[6] CISA with FBI contributions. AA20-283A, APT Actors Chaining Vulnerabilities Against SLTT, Critical Infrastructure, and Elections Organizations. Official GovDelivery version, 9 October 2020. https://content.govdelivery.com/accounts/USDHSCISA/bulletins/2a528c2

[7] Microsoft Security Blog, Daniel Naim. Zerologon is now detected by Microsoft Defender for Identity. 30 November 2020. https://www.microsoft.com/en-us/security/blog/2020/11/30/zerologon-is-now-detected-by-microsoft-defender-for-identity/

All sources accessed 15 November 2026. Selected relevant passages reviewed. Direct CISA pages and the Secura whitepaper were unavailable in this pass. No live exploitation, public publication or user-system changes were performed.
