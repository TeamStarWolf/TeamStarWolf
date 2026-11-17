# PetitPotam: Authentication Coercion, Certificate Enrollment, and the Limits of a Single Patch

*A TeamStarWolf case study. Published 16 November 2026.*

[All case studies](/case-studies/README.md) · Related: [Active Directory Security Reference](/ACTIVE_DIRECTORY_SECURITY_REFERENCE.md), [Identity and Access Management Reference](/IDENTITY_ACCESS_MANAGEMENT_REFERENCE.md), [Windows Hardening Reference](/WINDOWS_HARDENING_REFERENCE.md), [CVE Reference](/CVE_REFERENCE.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Active Directory and identity owners, Windows platform teams, detection engineers and incident responders

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 12 min (2,671 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You want a shorter, evidence-bounded account of PetitPotam, you need to separate coercion from relay or a research tool from a complete compromise path, or you are judging whether a single patch (CVE-2021-36942) closed the relay risk

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Executive assessment](#executive-assessment), [3. Coercion and relay are separate behaviors](#_3-coercion-and-relay-are-separate-behaviors), [7. What the August correction did and did not establish](#_7-what-the-august-correction-did-and-did-not-establish)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Active Directory Security Reference](/ACTIVE_DIRECTORY_SECURITY_REFERENCE.md), [Identity and Access Management Reference](/IDENTITY_ACCESS_MANAGEMENT_REFERENCE.md), [Windows Hardening Reference](/WINDOWS_HARDENING_REFERENCE.md), [CVE Reference](/CVE_REFERENCE.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## Executive assessment

PetitPotam drew attention in July 2021 because a Windows authentication-coercion technique could be combined with insufficiently protected certificate enrollment services to threaten an Active Directory environment. The name became shorthand for a larger chain, but the original research tool and the complete compromise path are not the same thing. The researcher's repository describes coercing Windows hosts to authenticate through EFSRPC methods; it does not make the existence of the tool proof that every Windows domain is vulnerable to certificate-based compromise. [1]

The case is significant because a patch for a specific unauthenticated call did not remove the broader class of authentication-relay risks. CERT/CC described CVE-2021-36942 as a partial correction: it blocked the unauthenticated call exposed through LSARPC, while authenticated EFSRPC routes remained. Domain single sign-on could satisfy authentication without a person manually supplying a password. [2]

The appropriate conclusion is therefore neither "patches did nothing" nor "one patch finished the job." The correction and the service-hardening guidance addressed different parts of the risk. A faithful account must preserve those boundaries, along with the compatibility cost of retiring NTLM and the distinction between a certificate-derived authentication result and a forged Kerberos golden ticket.

## 1. Source method and historical boundaries

This study uses the original repository description, Microsoft's AD CS mitigation article, dated government advisories, CERT/CC's vulnerability note, Microsoft's explanation of Extended Protection for Authentication, and MITRE's definition of golden tickets. It reviews the defensive implications without supplying an operational domain-compromise procedure.

The live MSRC ADV210003 and the CVE-2021-36942 record returned JavaScript application notices during retrieval. The Microsoft Defender for Identity article did not return readable page text, although search excerpts were available. Those excerpts are not used to claim complete review of the article or its detection behavior. The substantive analysis instead relies on retrieved primary records. [9,10]

The original repository was read as a research disclosure. Its executable and source exploit files were not downloaded or run. No certificate was requested, no authentication was coerced, and no domain or server configuration was changed. Nothing in this article establishes the exposure of a particular live organization.

This distinction matters because a demonstration of a component behavior is different from an inventory of affected environments. Historical advisories describe conditions and consequences. They do not by themselves show which customer deployments combined all necessary conditions.

## 2. July and August chronology

JPCERT's August 11 notice identifies July 23 as the publication date of ADV210003 and relates the August Windows LSA spoofing correction, CVE-2021-36942, to that advisory. It stresses prioritizing domain controllers and also points to the separate AD CS mitigations. The structure of that notice is important: update deployment and protection of enrollment services were concurrent obligations, not mutually exclusive alternatives. [4]

Singapore's Cyber Security Agency published an alert July 26. Its July 29 update added Microsoft's recommendation to enable Extended Protection for Authentication and disable HTTP on AD CS servers. The original portion warned that disabling NTLM could break applications or systems that still depended on it. [5]

CERT/CC published VU#405600 on August 2 and last revised the retained note October 5. That later version explains the partial scope of the update. Its revision date should not be mistaken for the first disclosure date, nor should the current repository description be treated as an immutable snapshot of July behavior. [2]

The response evolved because the issue crossed protocol, application, and configuration boundaries. A chronology containing only a disclosure date and a patch date would hide why additional service configuration remained relevant after the August update.

## 3. Coercion and relay are separate behaviors

The researcher describes PetitPotam as a way of inducing a Windows host to authenticate to another machine through EFSRPC. The retained README also says disabling the EFS service did not appear to mitigate the behavior and identifies more than one interface route. That is a bounded first-person research statement, not a blanket guarantee about every later Windows build. [1]

Coercion answers the question of why an authentication attempt begins. Relay answers a different question: whether an intermediary can carry that authentication to another service that accepts it in the wrong context. Conflating them makes it difficult to explain why a fix on the source computer and a protection on the destination service can both matter.

CERT/CC explicitly cautions that other techniques can induce authentication and that services other than AD CS can be relay targets. Consequently, the name of one proof-of-concept tool is a poor substitute for describing the trust boundary being protected. [2]

A defender who blocks a particular coercion route may reduce exposure without correcting an accepting service's relay weakness. Conversely, a service that rejects relayed authentication can remain protected even if another coercion primitive exists elsewhere. Those statements are architectural inferences from the two-stage model, not claims of testing every permutation.

## 4. The password was not the object that had to be stolen

Microsoft's 2009 explanation of Extended Protection describes credential relay as abuse of an authentication exchange without learning the user's password. It explains that authentication must be tied to the intended service and, where TLS is present, to the same protected channel. [6]

This is the central difference from a password-cracking narrative. A relay can exploit where an otherwise valid authentication exchange is accepted. The immediate defensive question is not solely whether the password is long enough or whether a hash can be cracked offline. It is whether the target verifies that the authentication belongs to its own service context.

The age of that Microsoft explanation is itself informative. PetitPotam did not invent the entire class of NTLM relay attacks. A newly prominent coercion method exposed the consequences of an older authentication problem in a particularly privileged service combination.

That historical continuity should not diminish the 2021 issue. Reusing an established protocol weakness in a new or more accessible chain can materially change operational risk. It does mean the case should avoid claiming that NTLM relay or channel binding was first discovered in July 2021.

## 5. Why certificate enrollment changed the stakes

Microsoft's KB5005413 identifies Certificate Authority Web Enrollment and Certificate Enrollment Web Service as relevant AD CS services when protections against NTLM relay are absent. The issue is not the mere existence of an enterprise certificate authority; it is the authentication and protection state of the exposed enrollment services. [3]

The consequential boundary is the conversion of an accepted authentication context into a certificate. A certificate can serve as an authentication credential rather than merely a record that a web request occurred. That gives enrollment policy and the protection of enrollment endpoints a security significance beyond ordinary website access.

CERT-FR describes the domain-controller account as a highly privileged object and explains how relaying its authentication to an AD CS web interface can lead to issuance of an X.509 certificate usable to authenticate as a controller. Its discussion treats this as a path to wider directory compromise, not an assertion that every certificate issued by AD CS is malicious or overly privileged. [7]

The case-specific lesson is that certificate services belong in the identity security boundary. Their web interfaces cannot be assessed only as low-value auxiliary sites. A configuration defect there may authorize an authentication result with consequences outside the web server itself.

The article deliberately does not provide the sequence for obtaining or using such a certificate. The explanatory value lies in understanding the boundary crossed and why endpoint authentication context matters.

## 6. Why golden-ticket terminology needs care

CERT/CC's note uses golden-ticket language when discussing the potential certificate-to-TGT consequence. MITRE's ATT&CK definition is narrower: a golden ticket is a forged ticket-granting ticket created using the KRBTGT account's secret material. [2,8]

A certificate-enabled request for a ticket and the forgery of a ticket with the KRBTGT key should not be described as identical operations. Both can have serious identity consequences, but their prerequisites, evidence, and recovery questions differ.

This article therefore uses certificate-based authentication and ticket acquisition where that is what the reviewed chain establishes. It does not infer that the KRBTGT secret was obtained, that an attacker forged a ticket, or that a particular named organization suffered that later step.

The distinction is not a criticism of an advisory's overall warning. It is an editorial choice to avoid letting a familiar label silently introduce a technical claim the case evidence has not demonstrated. Precise nouns matter most when they imply different forms of compromise.

## 7. What the August correction did and did not establish

The retained CERT/CC note says the update blocks the unauthenticated EfsRpcOpenFileRaw call through LSARPC. It also describes continued authenticated access through EFSRPC and other authenticated functions through LSARPC. [2]

This makes the adjective "partial" concrete. It refers to remaining reachable behavior and the larger relay class, not to an assertion that the corrected path still worked unchanged. A patch can successfully remove one unauthenticated entry point while leaving administrators responsible for other trust relationships.

Nor should "requires authentication" automatically be read as "requires an administrator to type a password." In a domain environment, single sign-on may already provide the required authenticated context. The source distinguishes genuinely anonymous access from access satisfied by existing domain authentication.

A retrospective needs to preserve all three states: an anonymous path before correction, the specific behavior blocked by the correction, and authenticated alternatives described in later guidance. Compressing them into a single yes-or-no "fixed" label obscures what was actually changed.

The case does not use a historical patch statement as a current Windows build matrix. Modern servicing, product support, and configuration defaults require separate verification. This study explains the 2021 response and its limitations.

## 8. EPA and HTTPS were a combined requirement

KB5005413 recommends enabling Extended Protection for Authentication and requiring HTTPS on the relevant enrollment services. It identifies Required as the more secure EPA setting and notes that Certificate Enrollment Web Service also needs its configuration file updated consistently with the IIS setting. [3]

The important point is not the number of configuration screens. Protection depends on the effective application configuration, not merely the presence of a checkbox in a management interface. A setting displayed in one layer cannot be assumed to control every service that participates in enrollment.

Microsoft's earlier EPA explanation distinguishes accepting compatible clients from requiring the protection. It states that clients lacking the feature can still connect under an accepting policy, whereas a required policy rejects unsupported authentication. It also explains that both sides must support the protection for the connection to benefit. [6]

That difference creates a real deployment tradeoff. Optional compatibility may preserve service for older clients, but it is not equivalent to enforcing the protection. Administrators need to know whether their intended policy is actually required and whether legitimate enrollment clients can satisfy it.

TLS confidentiality alone should not be presented as proof that authentication cannot be relayed. The role of binding is to prevent an authentication exchange from being accepted in an unintended context. This is why the article treats HTTPS and EPA as related but distinct requirements rather than two names for the same feature.

## 9. NTLM retirement and compatibility evidence

Singapore's July alert warned that disabling NTLM could disrupt dependent applications. CERT-FR approaches this problem by recommending that privileged systems' outgoing NTLM use be audited before blocking it. Its guidance distinguishes audit events from blocked-authentication events and stresses qualification of operational impacts. [5,7]

The defensive value of this sequence is specific. Auditing reveals dependencies; it does not itself stop the relay class. Enforcement changes behavior; it should not be described as safe merely because a policy can be set. A migration plan must identify which critical systems still initiate NTLM and why.

This is also why a single server-side mitigation is not the only possible control point. The source of privileged authentication and the accepting service are distinct places where the risk can be reduced. The stronger design goal is to avoid permitting highly privileged authentication to be redirected in the first place, while still protecting services that accept authentication.

The article does not implement those settings or prescribe a universal rollout date. Changing production authentication policies can affect availability. Historical guidance supports the architecture and testing rationale; the user's actual environment would require a separate assessment and authorization.

## 10. Verification questions tied to the actual chain

The evidence suggests several precise verification questions rather than a generic security checklist. Which privileged hosts can still initiate NTLM? Which enrollment services are enabled? Is authentication bound to the intended protected channel? Are the effective application settings consistent with the administrative interface? Was the specific Windows correction applied?

These questions concern different failure modes. An inventory showing the patch installed does not answer how the enrollment service authenticates. A screenshot of a service setting does not establish that all relevant applications use it. An audit log does not prove blocking. A blocked coercion request does not prove every possible authentication source has been eliminated.

The correct result is not a universal test script. It is a record that states what evidence supports each conclusion and what remains untested. That is particularly important for a chain whose common nickname can refer to a tool, a coercion method, a specific CVE, or a larger relay-to-certificate scenario.

Recovery questions are different again. Preventing a future relay does not, by itself, establish that previously issued authentication material has been reviewed or invalidated. This is a logical incident-response distinction, not a finding that such material was issued in a named case here.

## 11. Findings and limits

The reviewed primary records establish a coercion technique, a high-impact AD CS relay scenario, changing July mitigation guidance, a bounded August correction, and the continued need for authentication and service protections. They do not establish a global victim count, an aggregate loss figure, or a complete incident history for every operation later associated with the name PetitPotam.

This study does not claim to have verified a named ransomware campaign through these sources. Public reporting of possible downstream abuse should not be converted into a specific attribution without examining the relevant original incident research. The scope here is the vulnerability and defensive architecture.

The strongest conclusion is that a chain has to be assessed at its boundaries. Updating the coercion source, protecting the authentication destination, and managing compatibility are separate technical responsibilities. PetitPotam made that separation visible because one prominent technique could connect existing Windows behavior to certificate-based identity consequences.

## Sources and reading scope

[1] Topotam, PetitPotam original repository README, retained version reviewed 16 November 2026. Coercion scope, interface distinction, and EFS-service observation; exploit files not downloaded or executed. https://github.com/topotam/PetitPotam

[2] CERT/CC, VU#405600, released 2 August 2021, revised 5 October 2021. Partial patch scope, SSO distinction, broader relay class, and terminology comparison. https://kb.cert.org/vuls/id/405600

[3] Microsoft, KB5005413: Mitigating NTLM Relay Attacks on Active Directory Certificate Services. Retained guidance reviewed 16 November 2026. Enrollment-service scope, EPA/HTTPS, CES application configuration; no settings changed. https://support.microsoft.com/en-us/servicing/os/windows-server/2021/07/kb5005413-mitigating-ntlm-relay-attacks-on-active-directory-certificate-services-ad-cs

[4] JPCERT/CC, JPCERT-AT-2021-0034, 11 August 2021. July advisory date and August update relationship, plus separate AD CS mitigation requirement. https://www.jpcert.or.jp/english/at/2021/at210034.html

[5] Cyber Security Agency of Singapore, PetitPotam NTLM Relay Attack, 26 July 2021, updated 29 July. Mitigation chronology and NTLM compatibility warning. https://www.csa.gov.sg/alerts-and-advisories/alerts/al-2021-045/

[6] Microsoft MSRC, Extended Protection for Authentication, 8 December 2009, links updated 28 July 2021. Authentication binding, password distinction, required versus optional compatibility. Historical explanation, not a current deployment recipe. https://www.microsoft.com/en-us/msrc/blog/2009/12/extended-protection-for-authentication

[7] CERT-FR, CERTFR-2021-DUR-001, Classe de vulnerabilites en environnement Active Directory. Retained guidance reviewed 16 November 2026. Privileged authentication, AD CS certificate consequence, audit-before-enforcement rationale. https://www.cert.cyber.gouv.fr/dur/CERTFR-2021-DUR-001/

[8] MITRE ATT&CK, T1558.001 Golden Ticket, retained version 1.2, modified 24 October 2025. Narrow terminology definition only; not evidence of a PetitPotam campaign. https://attack.mitre.org/techniques/T1558/001/

[9] Microsoft MSRC, ADV210003, retrieval attempted 16 November 2026. JavaScript notice only; full live page not inspected. https://msrc.microsoft.com/update-guide/vulnerability/ADV210003

[10] Microsoft MSRC, CVE-2021-36942, retrieval attempted 16 November 2026. JavaScript notice only; complete affected-build and revision tables not inspected. https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36942
