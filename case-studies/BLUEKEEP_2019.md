# BlueKeep, 2019: The Distance Between a Warning and a Verified Fix

*A TeamStarWolf case study. Published 15 November 2026.*

[All case studies](/case-studies/README.md) · Related: [Windows Hardening Reference](/WINDOWS_HARDENING_REFERENCE.md), [Vulnerability Management Reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md), [Network Security Architecture](/NETWORK_SECURITY_ARCHITECTURE.md), [CVE Reference](/CVE_REFERENCE.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Windows and vulnerability-management teams, network and remote-access owners, detection engineers and incident responders

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 19 min (4,423 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You want an evidence-bounded account of CVE-2019-0708, you need to tell an affected system from a reachable one or a deployment job from a verified fix, or you are acting on a wormable warning before an incident

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Executive assessment](#executive-assessment), [8. Original analysis: patching is a chain of evidence](#_8-original-analysis-patching-is-a-chain-of-evidence), [11. Original analysis: patch completion is not incident clearance](#_11-original-analysis-patch-completion-is-not-incident-clearance)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Windows Hardening Reference](/WINDOWS_HARDENING_REFERENCE.md), [Vulnerability Management Reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md), [Network Security Architecture](/NETWORK_SECURITY_ARCHITECTURE.md), [CVE Reference](/CVE_REFERENCE.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

Historical vulnerability and exploitation case study, with original defensive analysis. No operational exploit instructions, attack code, live infrastructure indicators or claims of a universal victim total are included. This is not a current operating-system support matrix.

## Executive assessment

BlueKeep illustrates why a vulnerability response should begin before a spectacular incident makes the evening news. Its historical significance lies in the combination of remotely reachable legacy services, potential automated propagation, exceptional patches for old platforms, and a long interval in which organizations had to act under uncertainty. The central management problem was not whether an attacker would eventually produce a more reliable tool. It was whether defenders could identify every relevant system, reduce exposure, install the appropriate correction, and establish that the correction actually took effect.

The name identifies CVE-2019-0708, not a single malware family or one organization's breach. A vulnerable service, an exposed endpoint, an exploitation attempt, a successful compromise and a malicious payload are different states. Collapsing them produces misleading claims about both the scale of infection and the success of remediation. This study keeps those distinctions visible throughout its chronology and recommendations.

A second distinction is equally important: a vulnerability capable of supporting a worm does not establish that observed attacks were self-propagating. Microsoft's November investigation described operator-driven activity and cryptocurrency-mining payloads, not proof that the feared global worm had materialized. Its initial May warning and later exploitation findings answer different questions at different times. [1][5]

The practical conclusion is demanding but achievable. Maintain an inventory that includes supplier-managed systems. Treat temporary network and authentication measures as qualified risk reductions rather than repairs. Verify deployment at the endpoint and reconcile exceptions. Investigate possible prior compromise separately from closing the software weakness. Finally, replace unsupported dependencies instead of allowing one emergency patch to become an excuse for indefinite retention.

## 1. May disclosure: a service flaw with exceptional urgency

On May 14, 2019, Microsoft released fixes for a critical pre-authentication remote-code-execution vulnerability in Remote Desktop Services, formerly Terminal Services. It explicitly distinguished the implementation weakness from the RDP protocol itself. No user interaction was required in the vulnerable unauthenticated scenario. Microsoft said it had not observed exploitation at publication, while warning that future malware could use the flaw to spread between vulnerable computers. [1]

That language should not be rewritten as a report of an ongoing worm outbreak. The warning concerned capability and expected adversary development. The appropriate defensive response could still be urgent without inventing an incident. An organization does not need evidence of its own compromise before removing an unnecessary publicly reachable attack surface or deploying an applicable security fix.

Microsoft's announcement identified Windows 7, Windows Server 2008 and Windows Server 2008 R2 among then-supported affected systems. It also supplied exceptional updates for Windows XP and Windows Server 2003, which were already outside ordinary support. Windows 8 and Windows 10 were not affected by this particular vulnerability. Network Level Authentication was only a partial mitigation: valid credentials could still permit exploitation of an unpatched affected system. [1]

These are historical product statements, not a recommendation to operate any of those platforms now. The emergency response should be understood as relief for a specific defect, not a renewal of a platform's entire security lifecycle. A system can be corrected for one CVE while remaining exposed to other defects, incompatible with modern monitoring, or dependent on obsolete operational practices.

## 2. Scope: affected software, reachable service, observed compromise

An asset inventory needs more than a field called Windows. The relevant questions include edition, version, architecture, installed updates, service configuration, network reachability, ownership and actual business use. A count of machines running an old operating system is not automatically a count of remotely exploitable endpoints. Conversely, counting only devices reachable from one external scanner can omit internal or supplier-connected systems that still require remediation.

NSA's June advisory listed XP, Server 2003, Vista, Server 2008, Windows 7 and Server 2008 R2. It mapped historical update families to those systems and urged supported operating systems, current patches, service reduction, access filtering and NLA. Its discussion of potential ransomware and exploit-kit adoption was a warning about future misuse, not a confirmed report that such payloads had already been delivered through BlueKeep. [2]

CISA's June 17 alert added a concrete laboratory result: it had achieved remote code execution on a Windows 2000 test machine. The alert named additional older systems and acknowledged limits on its testing. This was evidence of exploitability in a controlled setting, not evidence that every listed deployment had been attacked, and not a statement that every affected edition had an available vendor patch. [3]

The original CISA page could not be retrieved during this review. Its dated US-CERT distribution was read in a public mailing-list archive; that preservation route is recorded in the source notes. The archive is not a new independent experiment. Its content represents the historical agency alert, with Microsoft and NSA used to cross-check the central vulnerability and mitigation descriptions.

## 3. A chronology of changing evidence, not one outbreak date

The most useful chronology separates disclosure, remediation guidance, research capability, public tooling and confirmed malicious activity. May 14 marks Microsoft's patch announcement and its explicit statement of no observed exploitation at that time. June's government warnings increased the urgency of inventory and remediation. They did not turn a prediction into a known casualty count. [1][2][3]

NHS Digital's alert, initially published May 15, carried subsequent operational updates. Its July 25 entry recorded a commercially available exploitation module in Immunity's CANVAS toolkit. Its May and June updates also discussed update-installation issues and verification steps for some environments. Tool availability and deployment difficulties are different milestones, and neither should be relabeled as a universal date of first malicious compromise. [4]

Microsoft's November 7 research account described a September 6 public Metasploit module release, increased crash signals, later October activity and a November 2 report from researcher Kevin Beaumont's honeypot. Microsoft worked with Beaumont and Marcus Hutchins to examine evidence and confirm exploitation-related crashes. The analysis linked successful attempts in the observed campaign to cryptocurrency mining, while describing the initial activity as operator-driven rather than a demonstrated worm. [5]

The difference between observation date and event date matters. A report published in November can discuss activity occurring in October. A later investigation can reclassify earlier telemetry without proving it has identified the first exploitation anywhere. This study therefore avoids a singular, worldwide first-victim date. It also does not turn a tool release into a count of affected organizations.

## 4. What the November findings support, and what they do not

Microsoft reported that the unstable exploitation module sometimes crashed systems and sometimes resulted in a miner being installed. Its analysis connected the campaign with earlier mining activity through infrastructure relationships, using qualified attribution rather than naming a confirmed individual or state actor. As of the November 7 publication, Microsoft said it had not verified other attacks involving ransomware or other malware types. [5]

That last statement is time-bounded and telemetry-bounded. It does not establish that ransomware exploitation was impossible, that every observer had identical visibility, or that the statement remained true indefinitely. Equally, a forecast of more damaging payloads cannot be cited as evidence that those payloads had already occurred. A responsible historical article retains both halves: actual mining-related exploitation and a broader risk that remained plausible.

A service crash is also an ambiguous observation until investigated. It can be relevant evidence without being definitive proof of successful code execution. A failed attempt can still impose availability costs. A stable system can still have been compromised. The correct analytical response is to preserve records, correlate independent signals and state what the collected evidence can establish, rather than treating stability or instability as a complete security verdict.

No reliable global cost, universal victim count or complete list of targeted industries is established by the reviewed sources. Geographic detections and internet exposure studies are not a financial-loss model. This case therefore concentrates on the quality of operational decisions instead of presenting an impressive but unsupported dollar figure or infection total.

## 5. Warning sources and the limits of preservation

The July 2019 Health-ISAC bulletin referenced NCSC weekly threat reports dated May 17 and May 31, alongside Microsoft, Canadian, NSA and CISA guidance. It discussed sector concerns and supplier coordination, including medical-device dependencies. These are primary evidence of the sector body's warnings and recommendations, not proof that every manufacturer listed in its appendix had a vulnerable product or suffered compromise. [7]

The NCSC historical reports were pursued directly. The May 31 URL now redirects to an official page-removal notice; the May 17 URL and an attempted National Archives retrieval were unavailable to this research session. Accordingly, this draft does not paraphrase their unseen contents or claim to have independently verified NCSC's original wording. The surviving Health-ISAC references establish that it cited those reports, no more. [7][8]

This limitation is part of the evidence record, not a reason to substitute a plausible quotation. Removed pages can be valuable research leads, but a citation list is not the same as access to a document. A future editorial pass can add a verified archival copy while keeping the current Microsoft, NSA, NHS and preserved CISA evidence intact.

## 6. Original analysis: define the decision before choosing the metric

A BlueKeep response programme should start with the decision leadership needs to make: which business services remain exposed, what action is available, who can authorize interruption, and what evidence will close the exception. A dashboard showing a percentage of patched computers cannot answer those questions if the underlying denominator excludes unmanaged systems or if one remaining server supports a disproportionately important service.

Use several explicit states. An asset may be identified but not assessed; assessed as affected; temporarily isolated; awaiting an applicable update; corrected and technically verified; retired; or under compromise investigation. Preserve a separate unknown state for unreachable devices. Unknown should never silently inherit the same green status as verified remediation. The distinction prevents operational uncertainty from becoming statistical success.

Business context belongs beside technical state. Record the owner, service dependency, user population, maintenance constraints, fallback arrangements and consequence of loss. This is not a formula that reduces human consequences to one score. It is a way to ensure that the people making a patching or isolation decision can see both the exposure risk and the impact of their chosen response.

Define escalation before the next deadline is missed. If a system cannot be corrected within the agreed emergency window, require a named decision-maker, a compensating-control test, a dated review and a replacement or retirement plan. An exception without an owner and expiration is not a managed exception. It is simply work that has fallen out of view.

## 7. Original analysis: reconstruct the actual remote-access estate

Begin with approved management inventories, purchasing records, application registers, network configuration and supplier support agreements. Compare these sources rather than trusting a single discovery system. A computer may exist in an asset database under one name and appear in monitoring under another; an appliance may contain an operating-system component that the business owner does not recognize as a Windows endpoint.

Trace remote-access purpose in plain language. Who needs to connect, from where, to do what work, and at which times? Distinguish staff administration, vendor maintenance, interactive user sessions and emergency support. If nobody can describe a legitimate use, disabling the service through an authorized change may be more appropriate than preserving it indefinitely behind another control.

Include dormant and intermittently connected devices. A retired server image can return during recovery; a spare workstation can be powered on for a busy period; a vendor support unit can reconnect after months offline. The inventory should capture these return paths and make remediation verification a condition of re-entry. Otherwise, a completed campaign can be undone by the next routine operational event.

Discovery itself must respect operational constraints. Obtain authorization and choose techniques appropriate to the environment. This study does not recommend exploiting production systems to prove they need attention. Asset records, authenticated configuration evidence, vendor guidance and carefully scoped non-disruptive validation can often answer the decision without creating avoidable service risk.

## 8. Original analysis: patching is a chain of evidence

The word patched hides several steps: a correct package has been selected, its authenticity checked, prerequisites met, deployment attempted, installation completed, required restart performed and effective state independently verified. A central management console may accurately report that it dispatched work while saying nothing about whether a disconnected endpoint received it. Treat each handoff as an opportunity for uncertainty, not as a reason to distrust all automation.

For each relevant platform, document the approved update route and the evidence that demonstrates coverage. Modern cumulative updates can change the relationship between an old bulletin and current installed state. A historical knowledge-base identifier is useful context, but mechanically searching for one old package name is not always a sufficient verification strategy. Follow current vendor applicability and supersedence information when actually operating an environment.

Use a small representative validation group where safe and practical, with an explicit maximum duration and rollback decision. Representative means more than one convenient test laptop. Include relevant application dependencies, service roles and management configurations. Emergency testing should reduce uncertainty quickly; it must not become an indefinite waiting room in which every unresolved compatibility concern leaves exposure unchanged.

After deployment, reconcile the endpoint population. Review installation failures, pending restarts, unavailable systems, conflicting status records and devices whose owner has changed. Record whether the verification method examined the effective endpoint state or only a central record. Close the item when the necessary evidence exists, not when a deadline arrives or the management dashboard turns mostly green.

## 9. Original analysis: separate repair, access reduction and authentication

A software correction removes the specific flaw within its stated scope. Access restrictions reduce who can reach the vulnerable service. Authentication changes alter conditions under which an attacker can interact with it. These controls can reinforce one another, but they should not be described as interchangeable. A temporary boundary measure can fail through a different route while the underlying vulnerable implementation remains unchanged.

Microsoft's August guidance emphasized patching, stronger protection for internet-facing remote access and NLA. It also discussed visible endpoints lacking NLA as potential risk, not as a count of confirmed infections. Its chart used a May 13 label, while the dedicated MSRC announcement and November research article specify May 14; this chronology uses the explicit patch-release announcement rather than reproducing the chart discrepancy. [6][1][5]

For an operational plan, define the reachability question precisely. Is access blocked from the public internet, from ordinary workstations, from partner networks, and from administration paths that do not need it? A perimeter restriction can be useful while leaving internal routes open. A gateway changes architecture and authentication context, but does not by itself repair every backend system accessible through it.

Test the intended boundary with authorized, benign connection checks and configuration review. Document expected permitted and prohibited paths, and investigate differences. Avoid a statement such as completely isolated unless the evidence covers the actual environment and exceptions. The goal is an auditable reduction of exposure while definitive remediation or retirement proceeds.

## 10. Original analysis: credential controls do not erase vulnerable code

NLA's value in this case is easy to explain without overselling it. Requiring authentication changes the unauthenticated attack opportunity, but it does not patch the vulnerable service. Microsoft explicitly warned that an attacker with valid credentials could still exploit affected systems. This is why a remediation record should distinguish NLA enabled from vulnerability corrected. [1]

The organizational implication extends beyond password length. Review which identities can access the system, whether vendor accounts are individually attributable, how credentials are protected, how access expires and how elevated sessions are separated from ordinary work. These recommendations concern reducing the consequences of stolen or misused access. They are not a claim that the historical miner campaign followed one particular credential-theft route.

Avoid circular assurances. An organization cannot argue that vulnerable systems are safe because only trusted administrators can reach them while simultaneously allowing those administrators to authenticate from untrusted endpoints or share credentials across unrelated machines. The access model must account for a compromised account or management workstation, not just a cooperative user following the expected path.

A good review produces a short access map, named owners and explicit revocation procedures. A bad review produces a long policy document with no link to effective permissions. Test the administrative process using approved test identities and synthetic activity, then verify that logging records the meaningful action and that revocation ends the intended access without disrupting unrelated services.

## 11. Original analysis: patch completion is not incident clearance

If a system was reachable while vulnerable, installing the fix closes a future opportunity but does not establish that the machine was never compromised. Vulnerability management and incident investigation should therefore run as connected but separate workstreams. The former asks whether the defect remains; the latter asks what happened, what access persists and what trust must be re-established.

Preserve relevant records before routine cleanup destroys useful context. Depending on available telemetry and authority, investigators may examine service failures, unusual process behavior, new persistence, unexpected account changes and unexplained network activity. These are investigation categories, not a promise that a single indicator proves BlueKeep or that the absence of those observations proves innocence.

Document monitoring gaps honestly. Older systems may lack the logs, retention or endpoint tooling that analysts would prefer. A report should distinguish no suspicious evidence found in reviewed records from evidence demonstrating no compromise. Where uncertainty and business consequence justify stronger action, a controlled rebuild from trusted sources may offer more confidence than repeatedly scanning an old machine and hoping for a reassuring result.

Reconnection needs its own acceptance criteria. Verify the intended software state, identity changes, restored monitoring, restricted access and business-function tests. If credentials might have been exposed, coordinate the relevant response rather than assuming a patch invalidates stolen access. The decision to return a service belongs to accountable technical and business owners, with residual uncertainty recorded.

## 12. Original analysis: supplier-managed systems need enforceable ownership

A supplier-managed system is still part of the customer's operational risk. Contracts and support practices should make it clear who inventories the component, receives advisories, evaluates applicability, supplies fixes, authorizes downtime and verifies completion. Without that division of responsibility, both parties can reasonably believe the other is handling a critical task while nothing changes on the actual device.

Ask suppliers for evidence matched to the question. A statement that the product is supported may not answer whether this deployment contains an affected component. A statement that a patch is available does not show installation. A statement that remote access is normally disabled does not establish its effective configuration during maintenance or an emergency support session.

Clinical, industrial and other operational environments can have additional safety and availability constraints. The response should involve the relevant engineering and service owners, use manufacturer guidance and plan temporary safeguards. This is not permission to ignore security until the next annual refresh, nor an instruction to apply an unvalidated change to a safety-critical device. Both risks require an accountable decision.

Procurement should learn from emergency response. Future systems should have defined support lifetimes, accessible inventories, update procedures, recovery documentation and a practical way to restrict maintenance access. The most durable improvement is not another spreadsheet of exceptions. It is buying and operating systems for which those exceptions can actually end.

## 13. Original analysis: communicate uncertainty without creating complacency

Leaders need a concise distinction between what is known and what is feared. A useful briefing states the affected technology, confirmed local exposure, available corrective action, observed exploitation relevant to the decision, business consequence and unresolved exceptions. It does not need an alarming analogy on every slide. Comparisons with earlier worms can explain potential propagation, but should not imply identical victims, payloads or losses.

Use careful population labels. Internet-visible services are not necessarily unique computers, and unique computers are not organizations. A scan finding can be stale, incomplete or affected by filtering. A decline in observed exposure can reflect remediation, service removal or visibility changes. Report the method and date alongside a number rather than presenting it as a timeless measurement of global risk.

Communications to staff should also be actionable. Explain why a maintenance interruption is occurring, what approved alternative is available, and where to report operational problems. Avoid telling users that vigilance against suspicious email is the primary fix for a remotely exploitable service flaw. Human cooperation matters, but responsibility should follow the actual technical control rather than defaulting to awareness training.

For a retrospective, preserve the information available at each decision point. A prediction that did not manifest in the most catastrophic form does not prove precaution was irrational. A successful campaign does not prove every warning was perfectly calibrated. Evaluate whether decisions were proportionate to evidence and consequences, and whether the organization improved its ability to act on the next critical advisory.

## 14. Original analysis: a ninety-day control-improvement programme

During the first month, establish a reconciled remote-access inventory and assign owners to uncertain systems. Prioritize externally reachable and high-consequence services while reviewing internal and supplier routes. Separate corrected systems from temporary mitigations and unknown states. Publish a short exception list that includes a responsible owner, interim safeguard, verification method and decision deadline.

During the second month, test the response workflow rather than only its documentation. Use a lab or other approved environment to simulate an unreachable endpoint, a pending restart, a vendor dependency and an inconsistent management-console result. Confirm that each scenario creates a visible exception and reaches someone with authority to resolve it. No real exploitation is necessary to reveal these process failures.

During the third month, close priority lifecycle gaps. Retire unnecessary remote services, move suitable dependencies to supported platforms and incorporate re-entry checks into recovery procedures. Review supplier obligations and verify that remote access still matches current business needs. Retest the highest-value boundary and deployment controls after changes, because a process that worked once can drift.

Measure outcomes that explain remaining risk: verified corrections, unmanaged dependencies resolved, overdue exceptions, time to establish ownership, and time from deployment to effective verification. Do not turn the programme into a competition to maximize patches installed. A smaller number of well-evidenced corrections on consequential systems can be more meaningful than a large volume of unverified activity.

## 15. Fictional tabletop: the supposedly finished emergency patch

The following exercise is original and fictional. Use invented assets, synthetic logs and approved test accounts. The organization operates a regional service desk with a legacy supplier-maintenance system. It receives an urgent advisory and a management report soon shows almost complete deployment. Participants include infrastructure, security operations, procurement, the supplier liaison and the business owner.

Inject one: a device in a remote office has not checked in. Ask whether it is counted as corrected, unknown or retired, and what evidence supports the classification. The exercise should expose whether the team has mistaken an absent failure message for success. The controller should not provide a dramatic malware event merely to force participants into incident mode.

Inject two: the supplier says a service must remain available for maintenance, but the named business owner has left the organization. Participants must establish temporary decision authority and define a constrained access arrangement without silently granting broad permissions. Success means an explicit owner and defensible interim control, not an improvised assurance that the supplier is trusted.

Inject three: an endpoint has a successful deployment record but an unresolved restart state. Inject four: a crash appears in the same period as unusual administrative activity. Participants must separate patch verification from incident investigation, preserve useful evidence and explain what remains unknown. A crash alone should not be scored as proof of successful exploitation.

Inject five: a backup restoration returns an older machine image to service. Ask what prevents reintroduction of the vulnerability, how the restored asset obtains current configuration evidence, and who authorizes business use. Conclude with a short corrective-action list. Each action needs an owner, a due date, a test and an observable result; additional training alone is not a substitute for a missing technical control.

## 16. Conclusion

BlueKeep is a case about acting responsibly before certainty becomes expensive. The historical record supports a serious remote-service vulnerability, unusual legacy-platform patching, staged warnings and later confirmed mining-related exploitation. It does not support turning every exposed endpoint into a victim, every crash into successful compromise, or every warning about a worm into proof of a worm outbreak.

The enduring lesson is operational completeness. Know which systems matter, who owns them, how they are reached, what correction applies and how successful remediation will be verified. Retain uncertainty where evidence is missing. Treat access reduction as useful but qualified, and investigation as distinct from patching. A warning becomes protection only when those decisions reach the actual endpoint and survive the next reboot, reconnection, supplier visit or recovery exercise.

## Sources and review boundaries

Primary vendor and government material anchors historical claims. CISA's original distribution was accessed through a preservation archive because the direct agency page was unavailable. NCSC historical content was not recovered; its inaccessible references are disclosed rather than reconstructed. Original analytical sections and the tabletop are recommendations, not claims about a particular organization's internal response. No global victim or loss total is asserted.

[1] Microsoft MSRC, May 14, 2019: disclosure, historical platform scope, exceptional updates, no observed exploitation at publication and NLA limitations. https://www.microsoft.com/en-us/msrc/blog/2019/05/prevent-a-worm-by-updating-remote-desktop-services-cve-2019-0708/

[2] NSA, June 2019: legacy-platform advisory, historical patch families and qualified interim measures. https://www.nsa.gov/portals/75/documents/what-we-do/cybersecurity/professional-resources/csa-bluekeep_20190604.pdf

[3] CISA/US-CERT, June 17, 2019, AA19-168A: original agency distribution preserved in the SecLists CERT archive; Windows 2000 test and mitigation guidance. Direct CISA retrieval failed. https://seclists.org/cert/2019/137

[4] NHS Digital, CC-3057, initially May 15, 2019, later updated: sector alert, installation issues, mitigation qualifications and July commercial-tool milestone. https://digital.nhs.uk/cyber-alerts/2019/cc-3057

[5] Microsoft Defender Security Research Team, November 7, 2019: investigation of crashes, observed mining-related exploitation, operator-driven activity and time-bounded absence of verified other payload types. https://www.microsoft.com/en-us/security/blog/2019/11/07/the-new-cve-2019-0708-rdp-exploit-attacks-explained/

[6] Microsoft DART, August 8, 2019: patching, remote-access protection, NLA and potential exposure; chart-date inconsistency is noted rather than adopted. https://www.microsoft.com/en-us/security/blog/2019/08/08/protect-against-bluekeep/

[7] Health-ISAC, July 24, 2019 update: sector coordination and preserved references to NCSC May weekly reports; appendix is not a list of confirmed compromised products. https://health-isac.org/wp-content/uploads/H-ISAC-Vulnerability-Bulletin-072419-Update-CVE-2019-0708-Remote-Desktop-Services-Remote-Code-Execution-Vulnerability-VB008-TLPWhite.pdf

[8] NCSC historical May 31 report URL: retrieved page-removal notice only, not the original report. May 17 and attempted National Archives retrieval also unavailable. Not used as substantive BlueKeep evidence. https://www.ncsc.gov.uk/report/weekly-threat-report-31st-may-2019
