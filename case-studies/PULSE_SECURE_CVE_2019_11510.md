# Pulse Secure CVE-2019-11510: When a VPN Patch Could Not Revoke Stolen Trust

*A TeamStarWolf case study. Published 16 November 2026.*

[All case studies](/case-studies/README.md) · Related: [Internet-Facing Services Reference](/INTERNET_FACING_SERVICES_REFERENCE.md), [Edge Device Security Reference](/EDGE_DEVICE_SECURITY_REFERENCE.md), [Identity and Access Management Reference](/IDENTITY_ACCESS_MANAGEMENT_REFERENCE.md), [CVE Reference](/CVE_REFERENCE.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

VPN and edge-device owners, identity and access teams, detection engineers and incident responders

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 19 min (4,448 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You want an evidence-bounded account of CVE-2019-11510, you need to separate a pre-authentication file read from command execution or a patch from credential revocation, or you are planning recovery after VPN credential theft

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Executive assessment](#executive-assessment), [7. Patching could leave stolen credentials usable](#_7-patching-could-leave-stolen-credentials-usable), [11. Later Pulse Secure issues remain distinct](#_11-later-pulse-secure-issues-remain-distinct)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Internet-Facing Services Reference](/INTERNET_FACING_SERVICES_REFERENCE.md), [Edge Device Security Reference](/EDGE_DEVICE_SECURITY_REFERENCE.md), [Identity and Access Management Reference](/IDENTITY_ACCESS_MANAGEMENT_REFERENCE.md), [CVE Reference](/CVE_REFERENCE.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

Key takeaways (reviewed 2026-11-17):

- CVE-2019-11510 made a remote-access appliance a potential source of authentication material via unauthenticated arbitrary file reading. ([Executive assessment](#executive-assessment))
- Client certificates or two-factor authentication did not remove the vulnerable pre-authentication path. ([Executive assessment](#executive-assessment))
- The lasting problem was material already taken: CISA reported compromised AD credentials could stay useful months after patching. ([Executive assessment](#executive-assessment))
- A software correction could close the entry point without withdrawing access that had escaped into the surrounding identity environment. ([Executive assessment](#executive-assessment))

<!-- meta:end -->

Historical case study of the 2019 Pulse Connect Secure file-read vulnerability and subsequent credential-reuse reporting. Defensive analysis only. No exploit payloads, credential extraction instructions or live testing.

## Executive assessment

CVE-2019-11510 made a remote-access security appliance a potential source of authentication material. The vulnerability allowed unauthenticated arbitrary file reading, while related vulnerabilities in the same advisory had different prerequisites and effects. The distinction matters: a file-read flaw, a stolen session and an authenticated command-execution issue should not be compressed into one unexplained attack. CERT/CC documented the April 2019 correction and warned that client certificates or two-factor authentication did not remove the vulnerable pre-authentication path. [1]

The lasting incident-response problem was the material already taken. CISA reported that compromised Active Directory credentials could remain useful months after an organization patched its appliance. A software correction could close the original entry point without withdrawing access that had escaped into the surrounding identity environment. [2][3]

This study reconstructs the evidence, preserves differences between advisory-wide product lists and individual CVE scope, and develops an original recovery model covering sessions, credentials, appliance integrity and internal access. It separates historical observation from hypothetical exercises and does not claim that every exposed server suffered compromise. Later Pulse Secure and Ivanti issues are identified as separate vulnerabilities rather than treated as one continuous defect. The final training scenario is fictional and designed to test decisions, not offensive techniques.

## 1. Scope, sources and retrieval limitations

The evidence base includes CERT/CC's vulnerability note and vendor statement, JPCERT/CC, the UK NCSC, CISA's official repository and joint advisory, Canadian guidance, and an Ivanti historical update. The original CISA AA20-107A alert was read as an archived US-CERT mailing-list message because direct retrieval returned an access error. Its central credential-reuse claim was corroborated in an accessible CISA-hosted joint advisory and CISA's own repository. [2][3][4]

The historical vendor advisory SA44101 could not be independently retrieved through its old and current addresses. This limitation is recorded rather than concealed. The study relies on the vendor statement preserved by CERT/CC and named official sources for the claims they actually support. It does not pretend to have reviewed a complete current vendor remediation matrix.

Numbered references support historical statements. The response models and fictional exercise are original analysis. No victim logs, appliance images or confidential credentials were accessed. Product version numbers describe historical scope, not present-day installation recommendations. This document is an unpublished research draft, not a claim of performing incident response for any named organization.

## 2. The vulnerability existed before authentication

CERT/CC identifies CVE-2019-11510 as an unauthenticated arbitrary-file-read vulnerability and records researcher disclosure in March 2019 followed by software updates on 24 April. Its note also discusses separate authenticated issues and broader compromise consequences. [1] Preserving those distinctions helps explain why a device intended to enforce access control could expose information before the normal login decision.

The original architectural analysis focuses on where authorization begins. A web-facing component can process requests before a user successfully authenticates. If that processing can expose protected local data, stronger checks later in the normal login flow do not repair the earlier boundary. Security properties have to be evaluated at the point where information is disclosed.

This is not a reason to discard strong authentication. It is a reason to state what each control protects. An organization should maintain robust authentication while also correcting vulnerable software and examining any material exposed before the correction. Treating these controls as interchangeable can lead to the false conclusion that a well-configured login screen makes the underlying appliance immune to unrelated defects.

## 3. File reading and command execution are different claims

NCSC's October 2019 guidance lists CVE-2019-11510 as pre-authentication file reading and CVE-2019-11539 as post-authentication command injection. [5] Those labels describe different capabilities. A broader compromise may combine capabilities, but the evidence should identify the steps supported by the source rather than assign every effect directly to the first vulnerability.

The analytical consequence is a more useful threat model. File access can matter because of the information available and the trust attached to it. A stolen credential can enable actions through an ordinary interface. An authenticated vulnerability may then create an additional capability. Each transition depends on circumstances that should remain visible in a case study.

This article omits request paths, sensitive file locations and exploitation syntax. The goal is to understand why an information-disclosure defect can have consequences beyond the appliance. A defender can inventory the trust relationships and apply an authorized correction without recreating the offensive sequence. The resulting recovery plan should address what could have escaped, not merely whether a known exploit request now fails.

## 4. Public details and observations have separate dates

JPCERT/CC's alert was initially published on 2 September 2019 and updated on 6 September. It described scanning seen by its own sensors and separately relayed reports of an apparent attack. Its revision also clarified product and version scope for individual Pulse vulnerabilities. [6]

These are different forms of evidence. A sensor observation can establish that scanning reached that sensor. A third party's report can support a warning while remaining attributed to that reporting organization. Neither automatically identifies every successfully compromised appliance. A historical account should preserve that distinction instead of treating a scanner count as a victim census.

The original chronology method records disclosure, patch availability, public technical detail and observed exploitation as separate milestones. This allows readers to ask meaningful questions about response delay. An organization might have patched before broad scanning, after its own exposure began or only after a credential was already taken. Those differences affect retrospective investigation even when all organizations eventually report the same corrected software release.

## 5. Advisory-wide lists can overstate individual CVE scope

JPCERT/CC's September update distinguished the broader SA44101 product list from the narrower CVE-specific Pulse Connect Secure ranges. For CVE-2019-11510 it listed 8.2R1 through 8.2R12, 8.3R1 through 8.3R7, and 9.0R1 through 9.0R3.3. Its separate list for CVE-2019-11539 included an additional 8.1 branch. [6]

The original research lesson is to read revisions and labels before copying a table. A bulletin addressing several vulnerabilities can legitimately mention products that do not all share the same defect. Reusing its entire product list under one CVE can create false precision and confuse remediation ownership.

A defensible applicability record names the exact identifier, product family and relevant source revision. Where evidence is incomplete, the record should say so and request current supplier confirmation. This study uses the clarified historical scope without presenting it as a complete current support statement. A present-day operator should follow maintained vendor guidance rather than use an old research article as a substitute for a current lifecycle and patch assessment.

## 6. MFA did not repair this pre-authentication defect

CERT/CC reported confirmation from the vendor that requiring client certificates did not mitigate the vulnerability. It also warned against assuming two-factor authentication prevented exploitation, explaining that active-session material could be exposed. The vendor statement preserved by CERT/CC said there was no workaround for CVE-2019-11510 and recommended upgrading. [1][7]

The original defensive interpretation distinguishes authenticating a person from protecting an existing session. A system may require a strong initial login while later treating a session artifact as evidence that login already happened. Protecting that artifact is therefore part of the authentication boundary. A defect that exposes it requires attention even when the initial login procedure is sound.

Recovery should examine active sessions as well as passwords. A password reset and session termination are not assumed to have identical effects across every product and integration. The operator needs vendor-supported behavior and evidence that old access is no longer accepted. The case supports improving the completeness of authentication recovery, not weakening or abandoning MFA because another control failed.

## 7. Patching could leave stolen credentials usable

CISA's April 2020 alert warned that attackers who had stolen credentials could retain access after patching if those credentials remained unchanged. The agency described multiple response engagements and later repeated that compromised Active Directory credentials had been used months after appliance correction. [2][3]

The original causal model separates the vulnerable reader from the information it disclosed. Repairing the reader changes future access to the appliance's files. It does not reach into an attacker's possession and invalidate information already copied. Revocation must occur in the systems that still accept that information.

This distinction changes the closure criteria for a security ticket. A patch deployment record can support closing the software exposure task. It cannot, by itself, close an incident investigation or credential-recovery task. Those workstreams may run together, but each needs evidence appropriate to its conclusion. Calling a patched device clean can conceal an unresolved identity problem that now operates through legitimate interfaces rather than the original vulnerability.

## 8. CISA's detection utility had explicit limits

CISA's check-your-pulse repository describes a utility for finding indicators in appliance logs. It warns that matches after patching may be false positives and that absent pre-authentication logging leaves less reliable indicators. The repository is archived and read-only, with an archive date of 6 March 2022. Its README also contains a concluding link to the unrelated Citrix CVE-2019-19781. This study treats that link as a documentation inconsistency, not a reclassification of the tool. [4]

The original analytical lesson is to read a detection tool's claims and limitations before treating its output as a verdict. A utility can help locate evidence without proving that every match represents successful compromise. Its inability to find evidence may reflect limited telemetry rather than the absence of an attack.

No tool was installed or run for this study. The repository is historical evidence about a defensive response, not a current operational endorsement. Any contemporary use would require assessing its maintenance state, compatibility and data-handling implications in an authorized environment.

## 9. Logs describe what was recorded

NCSC noted that Pulse logging was configurable and recommended checking whether relevant requests appeared in logs. Its broader advice included reviewing suspicious account activity and recognizing limitations in network detection over HTTPS. [5] Canadian guidance similarly noted that logging for the relevant vector might not have been enabled and cautioned that address changes within a session could also have legitimate causes. [8]

The original investigation model begins with coverage. What events were retained, for which appliances, during what interval? Were timestamps comparable? Did a failover send activity to a different system? These questions determine the strength of any conclusion before a search result is interpreted.

A report should avoid the unqualified phrase no evidence of compromise when readers may hear proof of safety. It can instead state that no matching evidence was found in specified records and identify material gaps. That wording is not evasion. It is an accurate description of what the investigation established and helps decision-makers understand why additional recovery work may still be justified.

## 10. The same flaw appeared in different actor reporting

A CISA and FBI joint advisory on Chinese MSS-affiliated activity discussed CVE-2019-11510 in incident-response observations. A separate September 2020 advisory on an Iran-based actor listed the vulnerability among several exploited issues while emphasizing Citrix as the primary initial-access path in the described activity. [3][9]

The original attribution lesson is to preserve the scope of each report. Use of the same vulnerability does not establish that two events share an operator. The surrounding infrastructure, behavior and intelligence may differ, and an organization investigating its own exposure may lack enough evidence to attribute it at all.

A case study can describe the range of known use without manufacturing a single campaign. Defensive priority does not require a famous actor's name. If an appliance exposed credentials, recovery should address that exposure regardless of whether the eventual user was a state-linked group, criminal operator or unknown party. Attribution can inform broader analysis while remaining separate from the immediate evidence needed to restore trusted access.

## 11. Later Pulse Secure issues remain distinct

Ivanti's April 2021 update discussed CVE-2019-11510 alongside CVE-2020-8243, CVE-2020-8260 and the newly identified CVE-2021-22893. It described an investigation into a limited number of affected customers and a separate forthcoming correction for the new issue. [10]

The original historical discipline is to avoid turning a product name into a single incident. Different identifiers can involve different software paths, prerequisites and remediation instructions. A 2019 correction cannot be assumed to address a later vulnerability merely because the same appliance family appears in both reports.

This study therefore ends its main causal account with the 2019 flaw and subsequent credential-reuse evidence, using the 2021 update only to clarify boundaries. It does not merge later Ivanti campaigns or 2026 incidents into the same case. Readers comparing studies should track the exact issue, observation period and reported actor rather than rely on recurring product branding as a substitute for technical identity.

## 12. Inventory should follow access relationships

The following sections present an original defensive framework. An inventory of VPN appliances is necessary but incomplete. The important relationships include identity providers, administrative accounts, connected services and the resources reachable through each access policy. A standby appliance and a temporary emergency endpoint can be as consequential as the primary device.

For each deployment, identify who owns software maintenance and who owns identity recovery. These may be different teams with different change processes. The record should also name the business service that depends on the connection and the authority for temporarily restricting it. During an incident, missing ownership can turn a known technical fix into a prolonged organizational delay.

The inventory should support a concrete decision. If a credential may have been exposed, can the team identify where it remains valid? If an appliance is isolated, can the organization explain which users lose access? A list of IP addresses without these relationships may satisfy an asset-counting exercise while leaving the actual recovery problem unresolved.

## 13. Appliance correction and identity recovery need separate owners

The original response model assigns a clear owner to each workstream. The appliance team verifies supported software and configuration. The identity team assesses which credentials or sessions require revocation. The incident lead integrates evidence and decides whether the wider environment needs investigation.

This division should not become a handoff gap. Each owner needs to know what evidence the others require and when their changes can safely occur. A credential rotation performed before ongoing attacker access is contained may expose replacement material. A device patch completed without notifying identity administrators may leave stolen access active indefinitely.

A shared recovery record should state dependencies and completion criteria in ordinary language. It should distinguish planned work, successful changes and unresolved confidence. The purpose is not to create more paperwork. It is to prevent a narrow technical success from being mistaken for restoration of the whole trust relationship. A named coordinator should be able to explain what remains open without requiring every responder to reconstruct the incident from chat messages.

## 14. Revocation has several kinds of state

A recovery plan should distinguish account passwords, active sessions and other authentication material that may be relevant to the actual environment. These categories are not automatically revoked by the same action. The original analysis requires checking supported product behavior rather than assuming that a familiar reset procedure covers every form of access.

The team should identify where each affected identity is accepted and whether it has privileged roles. It should also examine exceptions such as service integrations that cannot follow an ordinary interactive reset process. Those exceptions need controlled replacement and verification, not indefinite postponement because they are inconvenient.

The final question is behavioral: does the old access still work anywhere it should not? Answering that does not require offensive use of stolen material. It requires approved administrative evidence and safe validation of the intended state. Documenting the revocation scope makes the recovery claim more meaningful than a count of changed passwords, especially when one credential can be accepted by several connected systems.

## 15. Administrative access deserves a different exposure model

An administrative identity may change policies, manage other accounts or reach systems beyond an ordinary user's access. The original model therefore assesses privilege separately from the number of exposed identities. A small set of high-privilege credentials can create a larger recovery problem than many low-privilege accounts.

Administrators should use appropriately separated accounts and trusted management contexts. During recovery, the team should determine whether administrative actions occurred outside approved changes and whether new access paths appeared. An unexplained modification is a reason for investigation, not automatic proof of one particular actor or technique.

This analysis also affects communication. Saying only that a few credentials were involved can minimize risk if those credentials controlled important systems. Conversely, saying that the entire domain was compromised without supporting evidence can overstate the conclusion. The report should describe the authority attached to the affected access and the evidence for actual use. That gives leadership a basis for deciding the scope and urgency of recovery.

## 16. Internal access can outlive the VPN entry point

Once an attacker has used exposed credentials to reach internal resources, the original VPN vulnerability may no longer be the only access path. The original response model follows observed activity and available authority beyond the appliance. It asks whether other accounts, endpoints or services require assessment.

This does not mean automatically rebuilding every system. The scope should grow from evidence and the trust relationships that could plausibly carry the exposure. Where telemetry is weak, the incident lead should explain how that uncertainty affects confidence and recovery choices. Narrowing the investigation solely because the appliance now runs corrected software is not a defensible substitute.

The model also separates initial access from subsequent persistence. Removing one malicious artifact or resetting one account may leave another authorized-looking path. Closure should address the paths actually identified and state what remains unverified. This keeps the investigation focused while avoiding a simplistic narrative in which one CVE explains every later action and one patch necessarily ends the incident.

## 17. Continuity planning should not recreate exposure

Remote access can support essential operations, especially when staff cannot use an office network. The original continuity plan identifies which work must continue during containment and which access can pause. It should provide approved alternatives rather than pressure administrators to reopen an uncertain appliance without evidence.

An alternate route must meet its own security requirements. Moving users to an unmaintained standby or bypassing authentication controls may replace one known problem with another. The decision should consider the destination, identity controls and logging that the temporary arrangement provides. Emergency exceptions should expire or receive an explicit review.

Communication to users should explain what changes and how they can continue authorized work. It should avoid unnecessary technical details that could expose sensitive incident information. A clear service notice can reduce help-desk pressure and make containment more sustainable. The technical team can then spend its time verifying recovery rather than repeatedly improvising exceptions for individual users who were not told what to expect.

## 18. Evidence handling protects the people behind the accounts

VPN logs and appliance data can reveal identities, source addresses and access patterns. The original research and response model treats that information as sensitive operational evidence. Collection should be authorized, proportionate and restricted to the people who need it for the investigation.

A case study does not need raw credentials, session values or identifiable employee activity to explain the vulnerability. Synthetic examples can illustrate reasoning without exposing real people. If an organization later publishes an incident account, it should review whether apparently harmless details could reveal internal architecture or associate a person with sensitive work.

Evidence retention also needs a purpose and an owner. Keeping unrestricted copies indefinitely can create a new risk, while deleting material prematurely can undermine investigation. The recovery record should identify what was preserved, where authorized responders can find it and what restrictions apply. This is original governance analysis, not a claim that the public advisories exposed private victim data or that this research collected any.

## 19. Rebuilding an appliance does not settle imported trust

A supported rebuild can improve confidence in the appliance software, but restored configuration and connected identities remain part of the recovery decision. The original framework identifies the provenance of backups and reviews changes that could affect access. A backup taken during an uncertain period is not automatically a trusted baseline.

The team should reconstruct required configuration from approved records where possible and explain any exceptions. It should test intended user access and administrative restrictions before normal exposure resumes. A successful boot or login verifies only a limited part of the service.

The same reasoning applies to deployment templates and replacement hardware. If normal recovery procedures reinstall an old vulnerable release or import unexplained policy changes, the organization can recreate the problem after the incident appears closed. Durable remediation therefore includes the materials used to build the next appliance, not just the state of the one currently online. The process should leave a clearer supported baseline than the organization had before the event.

## 20. Reporting needs distinct completion states

The original reporting model separates corrected software, revoked exposure and investigated integrity. These states may reach completion at different times. A dashboard that collapses them into patched or unpatched can hide the very risk illustrated by CISA's post-patching observations.

For each state, identify the evidence and remaining limits. Software correction can cite the applicable supplier release and running version. Revocation can cite the affected identity scope and completed administrative actions. Integrity assessment can cite the systems and time period reviewed, together with unresolved visibility gaps.

This structure helps avoid both false reassurance and endless ambiguity. It gives decision-makers a clear account of progress without claiming certainty beyond the evidence. It also supports handover when responders change shifts. The next person can see why a task is closed, what depends on it and which question remains unanswered. A good record should make the reasoning reproducible rather than merely preserve a green status indicator.

## 21. Fictional exercise: Alderhaven Engineering

Alderhaven Engineering is fictional. It operates a primary VPN appliance and a rarely used standby. The network team installed a correction after a public advisory and closed its patch ticket. Months later, the identity team notices unusual use of an account that previously connected through the appliance. Logging from the original exposure period is incomplete.

Participants receive a patch record, a limited identity timeline and a list of connected services. Their task is to distinguish what the patch proves from what it leaves unresolved. They must identify owners for appliance assessment, identity recovery and business continuity without assuming that unusual activity establishes a particular attacker.

The exercise deliberately includes legitimate travel and a shared service account to complicate interpretation. Participants should explain alternative hypotheses and the evidence that would distinguish them. No real credentials, exploit requests or production systems are used. The scenario evaluates whether the team can reason about escaped trust while preserving the privacy of the people whose access it is investigating.

## 22. Exercise injects and expected decisions

The first inject reveals that the standby still uses an older deployment image. The second shows that a password change did not terminate every relevant session. The third provides a detection-tool match dated after the primary appliance's correction. Participants must revise their conclusions instead of treating each new fact as automatic proof of compromise.

Expected decisions include preventing unsafe failover, confirming supported revocation behavior and examining the timing and meaning of the tool output. The team should preserve useful evidence and describe what remains uncertain. It should also plan a controlled route for essential remote work rather than restore access solely because users are frustrated.

A final inject supplies an actor advisory mentioning the same CVE. The correct response is to consider its relevance without assigning Alderhaven's event to that actor absent corroboration. Evaluation rewards supported conclusions, clear ownership and a recovery plan that another team could execute. It does not reward dramatic attribution or a high volume of password resets disconnected from an exposure model.

## 23. Measures and final lessons

An original measurement set should count appliances assessed, verified corrections, identities reviewed and completed revocations separately. Track unresolved visibility and the age of temporary exceptions. These measures show where the organization still depends on assumptions rather than compressing all work into a patch percentage.

Sample closed records for reproducibility. Could another responder identify the source used for applicability, the evidence for software state and the reason the credential-recovery scope was accepted? Test whether standby systems and rebuild procedures preserve the correction. Review whether incident communications helped users continue necessary work without creating unmanaged access routes.

Pulse Secure CVE-2019-11510 illustrates a boundary failure whose consequences could survive its repair. The defensible response joins software maintenance with identity recovery and evidence-based investigation. Strong authentication remains valuable, but it does not substitute for correcting a pre-authentication disclosure flaw. A complete recovery claim must explain what happened to the trust that may already have left the appliance.

## Sources and reading scope

[1] CERT/CC, VU#927237, Pulse Secure VPN contains multiple vulnerabilities, 16 October 2019, revised 23 October. Technical distinctions, disclosure chronology and authentication limitations. https://www.kb.cert.org/vuls/id/927237

[2] CISA/US-CERT, AA20-107A, 16 April 2020, read through the archived original mailing-list message because the direct CISA page returned 403. Credential reuse after patching corroborated by records 3 and 4. Operational examples omitted. https://seclists.org/cert/2020/97

[3] CISA and FBI, AA20-258A, Chinese Ministry of State Security-Affiliated Cyber Threat Actor Activity, September 2020. Selected Pulse-related incident-response observations, not attribution of every exploitation event. https://www.cisa.gov/sites/default/files/publications/AA20-258A-Chinese_Ministry_of_State_Security-Affiliated_Cyber_Threat_Actor_Activity_S508C.pdf

[4] CISA, check-your-pulse repository README. Purpose, indicator limitations and archive state reviewed; source code not audited or executed. Unrelated concluding Citrix link identified as a documentation inconsistency. https://github.com/cisagov/check-your-pulse

[5] UK NCSC, Vulnerabilities exploited in VPN products used worldwide, 2 October 2019, version 2 update 8 October. CVE distinctions, logging limits and credential recovery. https://www.ncsc.gov.uk/news/alert-vpn-vulnerabilities

[6] JPCERT/CC, JPCERT-AT-2019-0033, 2 September 2019, updated 6 September. Sensor observations and clarified CVE-specific product scope. Third-party exposure counts are not adopted as victim totals. https://www.jpcert.or.jp/english/at/2019/at190033.html

[7] Pulse Secure vendor statement preserved by CERT/CC, updated 16 October 2019. No-workaround and upgrade statement. SA44101 itself could not be retrieved through old/current vendor addresses. https://kb.cert.org/vuls/vendor/VU%23927237/

[8] Canadian Centre for Cyber Security, Active exploitation of VPN vulnerabilities. Selected Pulse session and logging discussion; operational requests and sensitive file paths omitted. https://www.cyber.gc.ca/en/alerts/active-exploitation-vpn-vulnerabilities-0

[9] CISA and FBI, AA20-259A, Iran-Based Threat Actor Exploits VPN Vulnerabilities, 15 September 2020, official notification copy. Selected initial-access scope only; Citrix-centered observations are not reassigned wholesale to Pulse. https://content.govdelivery.com/accounts/USDHSCISA/bulletins/2a0b926

[10] Ivanti, Pulse Connect Secure Security Update, 20 April 2021, originally Pulse Secure blog. Used to distinguish the 2019 issue from separate 2020 and 2021 vulnerabilities; historical instructions are not current guidance. https://www.ivanti.com/blog/pulse-connect-secure-security-update-1
