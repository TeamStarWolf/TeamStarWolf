# EternalBlue and MS17-010: What a Patch Response Must Prove

*A TeamStarWolf case study. Published 15 November 2026.*

[All case studies](/case-studies/README.md) · Related: [Windows Hardening Reference](/WINDOWS_HARDENING_REFERENCE.md), [Vulnerability Management Reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md), [Network Security Architecture](/NETWORK_SECURITY_ARCHITECTURE.md), [CVE Reference](/CVE_REFERENCE.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Windows and vulnerability-management teams, network and infrastructure owners, detection engineers and incident responders

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 19 min (4,382 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You want an evidence-bounded account of MS17-010 and EternalBlue, you need to tell a released correction from a verified fix or one propagation method from a whole campaign, or you are proving a patch response

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Executive assessment](#executive-assessment), [8. Patch verification and supersedence](#_8-patch-verification-and-supersedence), [13. The limits of patching one propagation method](#_13-the-limits-of-patching-one-propagation-method)

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

Key takeaways (reviewed 2026-11-17):

- Microsoft published MS17-010 on 14 March 2017; the public EternalBlue exploit and May's WannaCry made the gap consequential. ([Executive assessment](#executive-assessment))
- A correction that exists in a catalog does not establish the state of a particular machine. ([Executive assessment](#executive-assessment))
- A check for one historical update identifier is a weak substitute for understanding the installed OS and its update history. ([Executive assessment](#executive-assessment))
- A patch for one exploitation method does not remove every other route available to malware. ([Executive assessment](#executive-assessment))

<!-- meta:end -->

## Executive assessment

MS17-010 is an unusually useful case for studying the difference between a vendor releasing a correction and an organization establishing protection. Microsoft published the bulletin on 14 March 2017. The subsequent public availability of EternalBlue and the May WannaCry outbreak made the distance between those events consequential. A correction that exists in a catalog does not establish the state of a particular machine. A message telling administrators to patch does not establish whether they acted. [1][3]

This study examines that assurance problem rather than retelling the complete WannaCry or NotPetya incidents. It separates the bulletin, individual vulnerabilities, named exploit, malware families, and organizational outcomes. It also examines why a check for one historical update identifier is a weak substitute for understanding the installed operating system and its update history.

The evidence supports a layered conclusion. Correcting a vulnerable service matters. Reducing unnecessary network reachability matters. Knowing whether the correction actually took effect matters. None of these measures alone proves that earlier compromise did not occur, and a patch for one exploitation method does not remove every other route available to malware.

The primary-source record also contains traps for researchers. Contemporary documents use different CVE labels for EternalBlue. An older NAO website summary and its linked revised PDF report different NHS trust totals. Microsoft's verification article warns that its tables do not replace later supersedence data. Responsible research must preserve those distinctions rather than merge them into a tidy but inaccurate chronology. [2][3][4][6][7]

## 1. Scope, method and terminology

The historical discussion uses Microsoft's bulletin, support documentation and incident research, CERT-EU's contemporary advisory, a Canadian government alert, and the National Audit Office's inquiry materials. The reading focused on passages relevant to remediation, evidence quality and operational consequences. This is not a complete reverse engineering of EternalBlue, an exhaustive reading of every linked source, or a forensic investigation of any victim.

An exploit is a means of taking advantage of a weakness. Malware is software with a harmful purpose. An advisory or security bulletin describes an issue and its response. These categories can be connected without being interchangeable. Calling every use of a vulnerable service “EternalBlue,” or treating MS17-010 as the name of one malware family, hides information that defenders need.

Throughout the study, historical observations carry numbered source references. The later response model, metrics, training exercise and recommendations are original analysis. They are proposals for authorized defensive work, not claims that any named organization used those exact procedures. No exploit payload, attack sequence, scanning command or live-target test is provided.

The date of this draft is important. Version numbers and platform choices in 2017 documents describe the period. They should not be copied into a present maintenance plan without checking current supplier support and security guidance. A historically corrected system can still be obsolete or exposed to unrelated weaknesses today.

## 2. What the March bulletin covered

Microsoft's MS17-010 bulletin, published on 14 March 2017, addressed several SMBv1 server vulnerabilities. It grouped five identifiers as remote-code-execution issues, CVE-2017-0143, -0144, -0145, -0146 and -0148, and separately described CVE-2017-0147 as information disclosure. For the execution issues it explained that, in most situations, an unauthenticated attacker could reach the vulnerable processing through a crafted request. The update changed how the server handled those requests. [1]

This is enough technical detail to establish the defensive boundary without reproducing exploitation mechanics. The relevant risk was not limited to a person voluntarily opening a malicious document. A reachable service could process hostile network input. Its correction therefore belonged in operating-system maintenance and network exposure management, as well as ordinary endpoint protection.

A useful analytical distinction follows: a bulletin can contain multiple flaws and multiple platform-specific packages. A campaign may use only part of that scope. An inventory that stores only a famous exploit nickname cannot reliably answer which correction applies to every affected platform. The administrator needs the supplier's actual product and servicing information.

## 3. The chronology of availability and urgency

CERT-EU recorded that the Shadow Brokers release made EternalBlue publicly available on 14 April 2017, after Microsoft's March correction. Its advisory described the WannaCry campaign beginning on 12 May and warned that organizations still needed to install the patch. These dates establish a sequence of changing public risk; they do not establish what every defender knew or what every attacker possessed on each earlier day. [3]

The original March bulletin's disclosure and exploitation columns say “No.” That is a statement in a dated bulletin, not a timeless denial that exploitation ever occurred. A researcher who presents the archived table as the current threat state creates an artificial contradiction with later incident reporting. The correct interpretation follows the document's historical scope. [1]

The original response lesson is that escalation criteria should include changes in exploit availability and observed activity. A maintenance item can begin as a scheduled correction and become an emergency without its vulnerability identifier changing. Teams need a way to update deadlines and priorities while retaining the reason for the earlier decision.

An organization should also distinguish time since a vendor release from time since its own identification of an affected asset. Both matter. The first helps describe the length of opportunity for remediation; the second helps identify weaknesses in discovery and ownership. Treating them as one clock can hide a long inventory delay behind a short installation turnaround.

## 4. A naming discrepancy worth preserving

The Microsoft WannaCrypt analysis and CERT-EU's contemporary advisory associate EternalBlue with CVE-2017-0145. Microsoft's separate Petya threat description identifies CVE-2017-0144 as EternalBlue. This study retains that source discrepancy rather than silently correcting all historical documents to one label. The stable response reference across these records is MS17-010. [3][4][9]

The discrepancy does not mean that administrators should ignore CVEs. It means that an analyst should record the exact relationship asserted by a source and avoid inferring that an entire bulletin addresses only one issue. Names can travel faster than precise technical mappings, especially during an incident.

For a research register, useful fields include the source's terminology, publication or revision date, the referenced bulletin, and the particular claim being supported. If a later technical review resolves an ambiguity, that conclusion can be added with its own authority. The original statement should remain traceable.

This approach also prevents accidental amplification. A reused phrase in several advisories may come from one common source. Several pages repeating the same label are not necessarily several independent technical validations. Research quality depends on the provenance of the claim, not simply the number of URLs collected.

## 5. What the early WannaCrypt analysis did and did not establish

Microsoft's published analysis described a worm-like spreading mechanism and emphasized installing the March update. It also explicitly said that the exact initial entry vector had not been established in that early investigation. Possible entry scenarios appeared as hypotheses. Those statements should not be converted into a claim that phishing initiated every infection. [4]

The distinction between initial entry and later propagation is operationally important. An organization can investigate how the first machine became affected while separately stopping onward spread. Waiting for a complete origin story before containing a reachable vulnerable service would confuse two tasks with different urgency and evidence requirements.

Likewise, a malware sample's platform constraints should not be generalized into a statement that a whole operating-system family has no vulnerability exposure. A particular observed implementation may behave differently from another implementation or from a future variant. The relevant patch decision should follow the vendor's affected-product information, not a broad interpretation of one sample description.

Original research discipline therefore calls for separate records of vulnerability applicability, observed malware behavior and confirmed local compromise. Each answers a different question. One can be known while another remains uncertain, and that uncertainty should be visible in incident reporting rather than compressed into a single red or green status.

## 6. Exceptional support and the limits of emergency updates

Microsoft's customer guidance made updates broadly available for Windows XP, Windows 8 and Windows Server 2003 in response to the emergency. Its explanation distinguished those custom-support-only platforms from products that had received the March security release through the supported update process. Canada's 13 May alert likewise drew attention to the exceptional availability and urged administrators to test and deploy the vendor updates. [5][10]

An exceptional correction is valuable, but it is not a general promise of future maintenance. Original planning should treat it as an opportunity to reduce an immediate risk while continuing the platform replacement or retirement decision. Otherwise, a temporary intervention may become an excuse to keep a structurally unsupported service in operation indefinitely.

There are also distinct reasons why a device remains uncorrected. It may be outside ordinary support, absent from management tools, incompatible with a proposed update, awaiting a safe service interruption, or simply missed. These are not morally equivalent labels, and they require different organizational responses. A single category called “legacy” conceals the decisions needed to resolve them.

A useful exception record names the accountable service owner, why the correction cannot yet occur, the exposure that remains, the approved interim restriction, and the review date. It should also say what event ends the exception. A record that expires only when somebody remembers it is not a durable control.

## 7. The NHS evidence and versioned inquiry findings

The NAO's investigation documented the gap between national warnings and verification of local action. Its account said there had been no formal mechanism before the attack to assess compliance with the guidance. The linked revised report also records that the majority of infected NHS devices were unpatched but running supported Windows 7, according to NHS Digital. That observation challenges a simplistic explanation that unsupported Windows XP alone caused the disruption. [6][7]

There is a material version distinction in the available records. The website summary states at least 81 affected trusts and refers to 37 infected trusts. The linked PDF, carrying an April 2018 publication cover, records at least 80 affected trusts, with 34 infected and 46 disrupted without infection; it explains that three trusts initially classified as infected were reclassified. This study uses the revised PDF for those figures. [6][7]

Those numbers describe different outcomes. Precautionary shutdown and inability to communicate can disrupt services without establishing infection on the affected organization's own machines. A case study should not add every disrupted entity to a malware-infection count.

The original analytical lesson is that centralized warnings need a feedback mechanism. A recipient list proves distribution, not preparedness. Verification requires a defined response, evidence, escalation for non-response, and enough local authority to make the change. Without that loop, the central body may know that advice exists while remaining uncertain about the actual state of the system it oversees.

## 8. Patch verification and supersedence

Microsoft's verification article offers several ways to assess whether MS17-010 fixes were installed, including update history and operating-system-specific file versions. It explicitly warns that its historical tables do not replace supersedence information from normal update channels. The article also shows that some later security-only updates did not include the March correction, while relevant rollups could include it. [2]

The implication is subtle. “A newer update exists” and “this correction is included” are different claims. Conversely, failure to find the first March package identifier does not by itself prove a machine remains vulnerable. Later cumulative packages can change the evidence an assessor should expect.

The original verification model should therefore start with the platform and servicing branch, then use current vendor-supported evidence to determine inclusion of the correction. A flat list of old KB numbers is easier to search but can create both false reassurance and unnecessary work.

The same article discusses a “not applicable” installation message and possible prerequisites or package mismatches. That message is not an assurance result. A team should investigate why a package did not apply rather than recording the failed attempt as a completed protection task. [2]

## 9. An assurance record for each service

The following sections propose an original defensive workflow. They are not a reconstruction of a particular organization's actions in 2017. The aim is to make a patch response reviewable without requiring an exploit demonstration on production systems.

A record should connect a business service to the machines and dependencies that provide it. For each machine, the reviewer needs enough platform detail to choose the applicable maintenance evidence, plus the time at which that evidence was collected. The record should distinguish a machine that was inspected from a machine inferred to match its neighbors.

Completion should identify the active corrected state, not just an approved deployment job. A job may have failed on a subset of devices, completed only after the last report, or required a restart that has not occurred. The evidence should be specific enough to resolve those possibilities through approved management tools and vendor guidance.

This record can remain concise. Its value is in the relationship between the decision and the proof: which asset, which applicable correction, which observation, which owner, and which remaining uncertainty. Collecting large volumes of logs without answering those questions creates storage rather than assurance.

## 10. Inventory beyond the management console

A management console is a useful starting point, but its population is not automatically the whole estate. Devices that stopped checking in, systems temporarily offline, equipment embedded in a service, and recovery images can fall outside the active list. Original response planning should explicitly account for those categories.

The question is not simply how many computers exist. It is which systems could rejoin a relevant trust or network environment before their state is checked. A powered-off device may be harmless while disconnected and risky immediately after an ordinary reconnection. A team needs a controlled path for that return, with ownership and verification before normal access resumes.

Reconciliation can compare independently maintained records, such as service ownership lists, network inventories and deployment systems. Differences should create investigation tasks rather than be silently discarded. A device discovered through reconciliation should retain its discovery source and observation time so that future reviewers understand why it was absent from an earlier denominator.

Avoid assuming that a server name uniquely identifies a stable machine forever. Replacement, reimaging and reuse can break that assumption. Evidence should follow the actual installation or instance being assessed, while preserving the business-service relationship that tells the organization why the asset matters.

## 11. Reachability as a separate control

CERT-EU recommended restricting SMB reachability and disabling SMBv1 as well as applying the update. It also warned against relying on properties of a particular malware variant as a dependable defense. These were complementary measures, not a declaration that observing no ransomware screen established safety. [3]

Original analysis should describe the scope of a network restriction precisely. A rule at an external boundary may prevent one route while leaving internal communication unchanged. A rule on one host may have a different scope from a segmentation policy. Recording only “firewall enabled” says little about which paths remain possible.

Defensive validation should use authorized configuration review and controlled connectivity checks. It need not expose a live service to malicious traffic. The objective is to confirm the intended separation and preserve legitimate dependencies, with a documented rollback or recovery plan if business functionality is affected.

A successful restriction also needs maintenance. New network links, vendor access, restored rules or changed service locations can alter the original boundary. The owner of the business dependency should know that connectivity changes may reopen the earlier risk and require a review of the machine's corrected state.

## 12. Retiring a protocol without hiding dependencies

Removing a legacy protocol can reveal dependencies that were never formally recorded. The right response is neither an unreviewed mass change nor indefinite delay. Original planning should discover the affected workflows, identify supported alternatives, and decide which service interruption is acceptable while the safer design is established.

Some dependencies may belong to a supplier-managed device rather than a normal workstation. In that case, an administrator should obtain product-specific guidance instead of substituting arbitrary operating-system components or making unsupported modifications. The organization still owns its exposure decision even when the supplier controls the supported remedy.

A useful migration plan distinguishes discovery, change, validation and retirement. Discovery identifies who needs the connection. Change moves that workflow to an approved alternative. Validation confirms that the replacement works and that the old dependency is no longer necessary. Retirement removes the obsolete access rather than leaving it available as a convenient fallback.

The rollback plan deserves equal care. Restoring service after a failed change can accidentally restore the exact exposure the project was meant to remove. A rollback should therefore specify the temporary restriction and authorization needed while the team corrects the failure. Restoring functionality and restoring the old risk are separate decisions.

## 13. The limits of patching one propagation method

Microsoft's February 2018 Petya retrospective described both SMB exploitation and identity impersonation. In the cases it investigated, it observed more propagation through impersonation than through MS17-010 exploitation. It also described an organization with 97 percent endpoint patch coverage that nevertheless experienced enterprise-wide infection. These are scoped observations in that report, not a universal distribution of attack methods or a claim that patching was ineffective. [8]

The defensible conclusion is that correcting one method does not neutralize every method in a campaign. An organization should continue protecting credentials, limiting unnecessary authority and preparing recovery even after it verifies a specific software correction. This is a reason to complete the patch work and the adjacent controls, not a reason to abandon either.

Original risk reporting should avoid a category called “protected from malware” when the evidence actually establishes a narrower claim such as “this vulnerable component is corrected.” A precise label helps leaders understand which investment has worked and which risks remain.

This distinction is also essential when interpreting later compromise. If a corrected system is affected through another route, the right question is which boundary failed. Automatically treating the event as proof that the update did not work can send investigators toward the wrong evidence and weaken confidence in a valid control.

## 14. Maintenance and incident investigation

Maintenance establishes the software state. Incident investigation asks what happened while the system may have been exposed. Those tasks can run together, but they need separate closure criteria. A machine can be corrected now while uncertainty remains about earlier activity.

Original incident handling should consider whether useful evidence could disappear during restart, reinstallation or ordinary cleanup. The responsible team should balance preservation against the need to stop ongoing harm, using its authorized incident process. This study does not prescribe delaying urgent containment simply to collect every possible artifact.

The investigation should preserve uncertainty in its language. An attempted connection, a detection alert, and confirmed execution are not interchangeable. Absence of a particular indicator can reflect limited retention or collection, not proof that nothing occurred. Conversely, a generic scan should not automatically trigger a claim of successful compromise.

A closure report should identify the time period examined, evidence available, limitations, and actions taken because of the findings. When evidence is insufficient, that limitation may justify further containment or recovery decisions. It should not be hidden behind the successful installation of an update.

## 15. Recovery infrastructure in the same risk model

A patch response often concentrates on production machines while treating restoration infrastructure as an external safety net. Original planning should examine whether that safety net shares the same dependencies, access paths or administrative authority. A recovery service that depends on unavailable authentication or an affected management host may not be reachable when needed.

The practical question is whether the organization can restore a service without first relying on the service it is trying to restore. Recovery documentation, credentials, installation media and approved configurations should remain accessible through a tested arrangement with appropriate safeguards. This is a planning question, not permission to spread privileged access widely.

Recovery exercises should include a corrected baseline. Restoring an old image and immediately reconnecting it can reintroduce an earlier vulnerable state. The restoration procedure should include a controlled maintenance and validation stage before the system returns to normal reachability.

The team should also record recovery time realistically. A backup copy existing somewhere does not establish that people can find it, authenticate, restore it and verify the service under incident conditions. A small test that exposes missing prerequisites is more useful than a large inventory of untested backup claims.

## 16. Metrics that preserve the unresolved population

An original response dashboard should report the size of the assessed population and explain exclusions. Devices awaiting assessment, offline systems, supplier exceptions and failed deployments should remain visible. Removing them from the denominator improves the percentage while making the operational picture worse.

A useful distinction is between correction verified, exposure restricted pending correction, and status unresolved. These categories describe different states of confidence and should not be combined into one green figure. Leaders can then decide whether a temporary restriction is sufficient for a particular service while seeing that permanent work remains.

Time-based measures should include how long high-consequence exceptions have remained open and how quickly failed deployments receive investigation. An organization that patches most ordinary desktops quickly but leaves a critical shared service unresolved has a different risk profile from one with the same percentage and isolated low-impact exceptions.

Finally, sample completed cases. A small review of the evidence behind closure can reveal whether teams are recording active correction or merely successful scheduling. Metrics are useful when they improve decisions; they become harmful when they reward the disappearance of uncertainty from a report instead of its resolution in the environment.

## 17. Fictional exercise: Harbor Archive Cooperative

Harbor Archive Cooperative is a fictional training organization. It operates a public service portal, an internal records system and a supplier-maintained scanning appliance. Its coordinator receives a critical operating-system advisory and a request for a completion report before the next management meeting. No element of this exercise describes a real victim.

The desktop team reports high completion based on scheduled jobs. A service owner says an old KB identifier is missing and requests a reinstall, although the machine has a later rollup. The appliance supplier has not yet provided an applicability statement. Several laptops have not connected to management tools for weeks. A restored standby server is due to join the production network that afternoon.

Participants should establish what each observation actually proves. The scheduled-job figure needs results and active-state verification. The rollup needs an authoritative supersedence check. The appliance needs a supplier decision and an interim exposure plan. Offline laptops and the standby server need a controlled return process.

A later inject reports suspicious historical network traffic. The group must separate incident investigation from maintenance closure and decide who owns each. The purpose is to practice evidence-based coordination, not to reproduce an exploit or perform unauthorized testing.

## 18. Exercise answer framework

An acceptable response begins with named owners and a shared status vocabulary. The coordinator should avoid demanding a single optimistic percentage before the population is understood. Instead, the report should state which services have verified evidence, which have approved temporary restrictions, and which remain unresolved.

For the rollup case, reinstalling the original package without checking applicability may waste time or create a misleading failure. The team should first consult current supplier metadata and platform-specific evidence. For the appliance, a generic operating-system match is not enough to authorize an unsupported modification. The service owner should work with the supplier and maintain the exposure decision locally.

The standby server should not receive normal access merely because it is urgently needed. Its restoration workflow should establish the corrected baseline first. The same principle applies to laptops returning from a long offline period: their previous inclusion in an inventory does not make their present state known.

The suspicious traffic inject should produce a bounded investigation plan. Participants should record what the observation establishes, what additional evidence is available, and which containment or recovery decision depends on the answer. The exercise succeeds when uncertainty becomes an owned task rather than an invented conclusion.

## 19. Research lessons and conclusion

This case rewards careful reading of both technical advisories and organizational inquiries. The most famous name is not always the most precise unit of analysis. Historical pages may retain early statements, and a linked report can revise numbers that its landing page still displays. A strong research register records those discrepancies explicitly.

For defenders, the lasting issue is assurance. A vendor release creates the possibility of correction. Organizational work must identify the affected population, choose the supported remedy, establish that it took effect and control unresolved exposure. The work is incomplete when a notification or deployment attempt substitutes for evidence of the active state.

The broader security program remains necessary after that correction. Reachability, authority, recovery and incident investigation address questions that a single update cannot settle. The MS17-010 response is therefore a useful study in precision: describe exactly which vulnerability condition has been removed, exactly where confidence comes from, and exactly what remains unknown.

## Sources and reading scope

[1] Microsoft, MS17-010, published 14 March 2017. Bulletin scope, severity, identifiers, historical disclosure status and servicing notes. https://learn.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010

[2] Microsoft Support, How to verify that MS17-010 is installed. Verification methods, supersedence caveat, update-table distinctions and installation applicability. Retrieved 15 November 2026. https://support.microsoft.com/en-us/windows/security/how-to-verify-that-ms17-010-is-installed

[3] CERT-EU, advisory 2017-012, May 2017 revisions. Public exploit chronology, campaign context and bounded mitigation advice. https://cert.europa.eu/publications/security-advisories/2017-012/

[4] Microsoft Security, WannaCrypt ransomware worm targets out-of-date systems, 12 May 2017 with subsequent updates. Early analysis and explicit initial-entry uncertainty. https://www.microsoft.com/en-us/security/blog/2017/05/12/wannacrypt-ransomware-worm-targets-out-of-date-systems/

[5] Microsoft MSRC, Customer Guidance for WannaCrypt attacks, May 2017. Exceptional legacy-platform update distribution and supported-platform distinction. https://www.microsoft.com/en-us/msrc/blog/2017/05/customer-guidance-for-wannacrypt-attacks

[6] National Audit Office, Investigation: WannaCry cyber attack and the NHS, website summary. Historical compliance-verification gap; older counts differ from revised PDF. https://www.nao.org.uk/reports/investigation-wannacry-cyber-attack-and-the-nhs/

[7] National Audit Office, linked report PDF, HC414, April 2018 cover/revised figures. Selected summary and affected-systems passages; not a claim of complete word-for-word review. https://www.nao.org.uk/wp-content/uploads/2017/10/Investigation-WannaCry-cyber-attack-and-the-NHS.pdf

[8] Mark Simos, Microsoft Security, Overview of Petya, a rapid cyberattack, 5 February 2018. Scoped observations about impersonation and the limits of one-vector patch coverage. https://www.microsoft.com/en-us/security/blog/2018/02/05/overview-of-petya-a-rapid-cyberattack/

[9] Microsoft Security Intelligence, Ransom:Win32/Petya threat description. CVE-2017-0144/EternalBlue mapping in supplier record. https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=Ransom%3AWin32%2FPetya

[10] Canadian Centre for Cyber Security, AV17-068, 13 May 2017. Exceptional update availability and deployment recommendation. https://www.cyber.gc.ca/en/alerts/microsoft-security-updates-ms17-010-smbv1
