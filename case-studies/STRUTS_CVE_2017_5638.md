# Struts CVE-2017-5638: The Error Path That Turned Request Data Into Execution

*A TeamStarWolf case study. Published 15 November 2026.*

[All case studies](/case-studies/README.md) · Related: [Web Application Security Reference](/WEB_APPLICATION_SECURITY_REFERENCE.md), [Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [Vulnerability Management Reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md), [CVE Reference](/CVE_REFERENCE.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Application-security and web teams, vulnerability-management leads and incident responders

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 19 min (4,417 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You want an evidence-bounded account of CVE-2017-5638, you need to separate an error path from normal input handling or two bulletins (S2-045, S2-046) from one CVE, or you are verifying a patch actually reached the running application

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Executive assessment](#executive-assessment), [3. Error handling as a security boundary](#_3-error-handling-as-a-security-boundary), [11. Identifying applications rather than just hosts](#_11-identifying-applications-rather-than-just-hosts)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Web Application Security Reference](/WEB_APPLICATION_SECURITY_REFERENCE.md), [Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [Vulnerability Management Reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md), [CVE Reference](/CVE_REFERENCE.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

A vulnerability study of S2-045, S2-046 and the evidence needed to close a patch response. No exploit payloads, scanning commands or operational attack sequence are included.

## Executive assessment

Apache Struts CVE-2017-5638 illustrates why security review must include what happens when an application rejects input. A malformed request can still reach complex processing before the user sees an error. In the affected framework, exception handling and generation of an error message formed part of a remote code-execution path. The dangerous behavior was therefore not limited to the application's intended successful upload workflow. Apache's S2-045 and S2-046 bulletins describe different request-header vectors for the same vulnerability. [1][2]

The episode also supplies an unusually clear case of a defensive conclusion changing as new evidence arrived. An early test suggested that switching to an alternative parser avoided the demonstrated attack. Subsequent testing showed that the alternative remained affected. The revised advisory preserved the earlier result while explaining why it was no longer a sufficient basis for relying on the workaround. [3]

This study focuses on framework behavior, changing remediation evidence and organizational patch verification. It deliberately does not retell the Equifax breach as a substitute for analyzing the vulnerability. It does not infer a victim count, a single attacker or a financial impact from the existence of exploitation reports. Historical releases cited here explain the 2017 response, not what software should be installed today.

The principal original conclusion is that a patch response needs a chain of evidence linking an advisory to the deployed application and its active runtime. A notification received by an employee, a dependency changed in a repository and a successful deployment command are different milestones. None should silently stand in for the others. Equally, technical remediation and investigation of earlier activity require separate answers.

## 1. Scope and method

Primary material includes Apache's two security bulletins, contemporary JPCERT/CC and Hitachi response records, Cisco's product advisory, Cisco Talos observations, a SAS product assessment, CERT-EU's advisory and current Apache security guidance. Relevant passages were reviewed for the specific factual statements used below. This work does not claim a complete source-code audit, exhaustive packet analysis or a word-for-word reading of every linked document.

The article separates three kinds of content. Historical findings report what an identified source said or tested. Analytical sections explain the implications of those findings without assigning unreported behavior to real organizations. A later exercise uses a fictional organization to test response decisions. Readers should keep those categories distinct when reusing the material.

No exploit payloads, scanning commands or operational attack sequence are included. No target was tested, and no production system was changed. A security team applying the recommendations should use its own authorization, supported tools and approved maintenance process. Current platform choices require current supplier guidance; the historical remedy numbers below are not a maintenance baseline for 2026.

## 2. The affected component

Apache's S2-045 bulletin identifies the Jakarta Multipart parser in Struts 2 and rates the issue critical. It lists affected versions 2.3.5 through 2.3.31 and 2.5 through 2.5.10, with recommended historical upgrades to 2.3.32 or 2.5.10.1. Nike Zheng is the credited reporter. The described trigger is a malicious Content-Type value whose handling produces an exception and then a user-facing error message. [1]

Multipart processing supports requests that carry multiple parts, often including uploaded content. The important conceptual boundary is between a request supplied by a client and framework machinery running with server-side authority. An application may intend to accept only well-formed content, but it must also decide what to do when that expectation fails.

Original analysis should avoid equating a user-interface feature with all reachable framework processing. A missing upload button is not a complete inventory of the code that receives a request. Conversely, finding the word Struts in a system does not by itself establish that a particular vulnerable implementation is active. The correct question joins software identity, runtime configuration and reachable processing behavior.

## 3. Error handling as a security boundary

The flaw's importance lies in what happened after rejection began. S2-045 describes invalid header content entering an exception path, and S2-046 describes analogous behavior for other header values. Both connect that path to remote execution. [1][2] A high-level explanation is enough to identify the failure: information originating in an untrusted request influenced processing that carried more authority than ordinary display data should receive.

This suggests an original review principle: error construction deserves the same trust analysis as the main business operation. Developers should ask where an exception message originates, whether it includes user-supplied material, and which formatting or localization facilities interpret it. A string that appears to be merely diagnostic can still reach a feature with meaningful behavior.

The lesson should not be generalized into a claim that every exception or translation function is unsafe. The concern is a specific combination of untrusted input and interpretation. A useful review follows the data and states the intended invariant: rejected client content must remain inert when the application explains the rejection. That invariant is clearer and more testable than a vague instruction to sanitize everything.

## 4. Two bulletins, one CVE

S2-046 describes malicious Content-Disposition or improper Content-Length values as different vectors for the same CVE-2017-5638 issue. It retains the affected version ranges and historical fixed versions. It credits Chris Frohoff, Nike Zheng and Alvaro Munoz. The bulletin's alternatives are constrained: its replacement plugins apply only to specified release ranges, and removing the File Upload Interceptor is limited to Struts 2.5.8 through 2.5.10. [2]

The analytical consequence is that a second advisory number should not automatically create a second vulnerability count or a claim that the original corrected releases became vulnerable again. Advisory identifiers organize communication; CVE identifiers and the precise technical scope describe a different relationship.

A remediation database should preserve both references under the same case where appropriate. Otherwise, one team may duplicate work while another dismisses a later bulletin as already handled. The later communication can matter greatly for organizations using a workaround even when it does not change the recommended fixed releases. The record needs enough detail to distinguish those populations.

## 5. The alternative-parser correction

JPCERT/CC's initial testing used a sample Struts application on Tomcat and found execution in affected versions. Its displayed early results also showed no execution for a tested configuration using JakartaStreamMultiPartRequest. The advisory then explicitly superseded that implication: its 17 March update said the alternative was also affected and that attacks remained possible after the switch. It strongly favored updating. Its 21 March update explained that S2-046 used the same CVE and did not require a further change to the previously introduced corrected versions. [3]

This is an evidence-quality lesson rather than an opportunity to mock an early tester. A negative result can be accurate for the test performed while failing to establish a universal security conclusion. Additional inputs or a different path can reveal that the broader assumption was wrong.

An organization that recorded only "alternate parser tested safe" would lose that scope. A better record says what was tested, which build and configuration were involved, and which advisory revision supported the decision. It also specifies how new information will trigger review. The finding changes the justification for the workaround, even if nobody has changed the local system yet.

## 6. Hitachi's corroborating record

Hitachi's HIRT-PUB17006 provides a separate chronology for the alternative-parser finding. It records confirmation on 15 March, reporting to JPCERT/CC on 16 March, and publication alongside the revised alert on 17 March. It later identifies S2-046 as the same issue. The page recommends corrected software rather than relying on the parser substitution. [4]

That source strengthens the account because it documents the development of the correction from another participant's perspective. It also helps avoid a misleading historical narrative in which every workaround listed anywhere in an older page remains equally valid forever.

Original analytical practice should preserve the dates and authorship of corrective evidence. An operational exception can expire because its technical foundation changes, not only because a scheduled deadline arrives. Teams should therefore maintain a connection between exceptions and the advisory records on which they depend. When a source changes materially, the exception's owner should receive a concrete review task explaining which assumption no longer holds.

## 7. Active exploitation and observation limits

Cisco Talos's 8 March report described observed exploitation activity, including probing and attempts to deliver malware. It characterized the observed payloads as varied and discussed attempted persistence in some examples. The report also cautioned that aspects of the early timeline were unclear. These are first-party observations of the activity available to that research team, not a census of every affected server. [5]

CERT-EU's 9 March advisory reinforced the urgency of updating and described execution with the privileges of the service account. It identified the same affected ranges and corrected releases. [6] The combination supports treating the vulnerability as an actively relevant emergency in that period, while leaving organization-specific compromise questions to organization-specific evidence.

This study does not convert a network alert into proof of successful execution. It also does not assume that all exploitation shared an objective or an operator. A public vulnerability can attract unrelated actors with different goals. Attribution requires evidence beyond a common exploit mechanism. A case study can explain urgency without inventing a campaign narrative.

## 8. Product-specific exposure

Cisco's advisory lists affected products and directs readers to product-specific bug records for current fixed-release details. Its header states that no workarounds are available for the advisory, despite upstream framework documents discussing conditional alternatives. [7] That is a useful reminder that an application developer's option is not necessarily a supported change for a packaged commercial product.

SAS's assessment, completed 15 March, states that its managed custom Struts version was not vulnerable. It also explains that a flagged library in a particular component did not mean the affected functionality was used. [8] This is a supplier assessment with a defined product context. It should not become a general rule that any apparently unused library is safe to ignore.

The original response recommendation is to resolve supplier scope rather than improvise. Record the exact product, deployment and advisory. Request clarification when the vendor's statement does not match the installed edition. Do not manually replace embedded framework files in a product merely because a public upstream release exists; unsupported substitution can change behavior without establishing an approved remedy.

## 9. Later framework guidance

Apache's current security page warns against using incoming values in localization logic and against untrusted input in forced expression evaluation. It explains that text-provider methods can evaluate parameters during localization. These are present-day development cautions from the framework maintainers, retrieved in November 2026. They contextualize the broader trust problem but are not a claim that every modern option existed in 2017. [9]

The resulting original lesson concerns data provenance. A developer should know whether a value is a fixed application-controlled message identifier, a safe parameter to a message, or untrusted content passed into an interpretive facility. Those roles should remain visible in design and review.

Modern defensive controls can reduce risk, but naming a control does not prove the historical vulnerability is remediated. The specific advisory and supported release remain the starting point for that determination. Likewise, a correctly patched framework does not absolve custom application code from reviewing its own use of expression or formatting features. Maintenance and secure application design reinforce one another.

## 10. A response model based on evidence

The following sections are original defensive analysis, not claims about a particular historical victim. They develop a practical response model from the documented parser issue and the changing guidance.

A useful model distinguishes six states: the advisory is understood, affected applications are identified, a remedy is selected, an artifact is prepared, the artifact is deployed, and the active service is verified. The order may overlap during an emergency, but the evidence for each state should remain distinct.

For example, selecting an approved framework version answers a compatibility and security decision. It does not establish that a build includes that version. A completed build does not establish that every production instance runs it. A completed rollout does not establish that a stale standby node cannot rejoin later. These distinctions prevent status reports from overstating progress.

Use named application owners and a central coordinator. The coordinator reconciles exceptions and conflicting evidence; application owners establish what their services actually run. A broadcast message alone cannot create that accountability. It needs acknowledgment, a scoped determination and an evidence-backed result.

## 11. Identifying applications rather than just hosts

A host inventory is an incomplete unit of analysis for a framework dependency. One machine can run multiple applications with different libraries, and one application can run across many instances. The inventory should link a business service to its deployable artifacts and runtime locations.

Start with build manifests, packaged application contents, deployment records and supplier information. Use supported discovery mechanisms rather than assuming that an external service banner exposes the framework version. Keep the results associated with the specific application artifact and collection time.

Record uncertainty honestly. A product marked "awaiting supplier determination" needs an owner and deadline, not a guessed conclusion based on a similarly named product. A legacy application with no current maintainer should become an explicit risk decision. It should not disappear from the response merely because nobody can answer the initial email.

The central inventory can then support focused prioritization. Reachable critical services with uncertain exposure require different handling from retired artifacts retained only for records. The distinction rests on evidence of deployment and access, not on a filename alone.

## 12. Source code, packaged libraries and running code

A repository change is a promise about the next build. A packaged artifact is evidence of what that build contains. A running service is evidence of what users actually reach. Treating these as one object invites false closure.

For an internally developed application, retain the build identifier and the dependency resolution result. Confirm that the delivered artifact corresponds to the approved build. During rollout, record which instances changed and which did not. After rollout, establish that the intended artifact is active across the service's real serving population.

Also consider old artifacts that automation can restore. A rollback target or disaster-recovery image may preserve the vulnerable dependency. Those materials need a decision: replace, retire, or retain with a clear prohibition on unreviewed deployment. Merely changing the primary node leaves recovery procedures capable of recreating the problem.

This recommendation does not require deleting useful historical build evidence. Separate retention for audit from eligibility for production deployment. The organization can preserve provenance while preventing an obsolete artifact from returning through an emergency shortcut.

## 13. Evaluating workaround scope

A workaround should have a written claim narrow enough to test. State which condition it blocks, where it runs, which software versions it covers and what legitimate behavior it changes. Include the authority for that claim and the date it was reviewed.

Do not transform a conditional upstream suggestion into a universal configuration recipe. This case's alternative-parser correction demonstrates why naming a different implementation is insufficient. A product may not support the change, a release may fall outside the documented range, or a different vector may remain.

A temporary control also needs an exit condition. The record should identify the supported correction it is buying time to deploy. If the permanent remedy is blocked by compatibility, name the unresolved test or supplier dependency. "Business critical" explains the need for care but does not by itself explain why the exception must remain indefinitely.

Finally, consider the update mechanism for the workaround's own justification. New evidence can invalidate it before the calendar deadline. Whoever monitors advisories should know which local decisions depend on a particular recommendation, so the organization can reopen the right cases promptly.

## 14. Perimeter filters and application correction

Perimeter filtering may reduce some malicious traffic while a deployment proceeds. Its evidence should remain tied to its actual inspection point and coverage. A rule attached to one ingress path does not establish protection for a different administrative interface or an internal route.

Original analysis should also consider changes in request handling between layers. Gateways and applications may parse or normalize data differently. A defensive claim should therefore avoid assuming that every rejected-looking request at one layer receives identical treatment everywhere else. This is a review question, not a recipe for bypassing a filter.

Track the supported application remedy independently. If a filter becomes the reason a patch ticket closes, the organization may lose visibility into unresolved vulnerable software. A better status can say that exposure is temporarily reduced while correction remains pending, with precise scope and a scheduled review.

Observe legitimate traffic as well. Emergency filtering can break expected workflows, which creates pressure to remove it. Prepare an approved way to investigate those failures without silently disabling the control for every application sharing the gateway.

## 15. Regression testing that includes rejection

A normal feature test often verifies that valid input produces the expected result. This case shows why the rejection path also needs attention. A defensive test plan should establish that malformed or unsupported benign requests fail safely and predictably, without invoking behavior outside the application's intended authority.

The plan should be approved and scoped to a controlled environment. It need not use a public remote-execution payload to provide useful assurance about application handling. Combine supported version evidence with ordinary functional testing and review of the changed behavior. If specialized security validation is necessary, it belongs in an authorized process with clear safety boundaries.

Record test limitations. A successful sample cannot prove that every possible input is harmless. A test that covers one parser configuration cannot automatically cover another. Preserve enough information to understand what changed when a later advisory broadens the scope.

This makes regression evidence durable. A future reviewer can compare the test's claim with new information and decide whether it remains relevant, rather than treating an old "pass" label as a permanent security certificate.

## 16. Service identity and consequence

Remote execution occurs within a system that already has permissions. A response should identify the application's account and the resources available to it. That review determines plausible consequence and helps prioritize recovery if compromise evidence emerges.

Ask which credentials the service can access and which data stores accept them. Distinguish read permissions from modification rights. Consider whether several unrelated applications share one identity. If they do, a failure in one application may have a broader potential scope than its business function suggests.

These are risk questions, not automatic findings of data theft or lateral movement. Do not state that an attacker used a credential merely because it was present. Instead, retain the access model as context for investigation and recovery decisions.

Longer-term remediation should reduce unnecessary authority. An application that only needs a narrow database operation should not inherit broad administration privileges by convenience. That architectural work does not replace the framework fix, but it can reduce the potential impact of an independent future failure.

## 17. Investigation alongside maintenance

When a vulnerable service was reachable during observed exploitation activity, the organization may need to investigate prior events while deploying the correction. Keep the two workstreams linked but separately tracked. The patch work asks whether the active vulnerability remains. The investigation asks what happened before and what consequences require action.

Useful evidence may include request records, application errors, process activity, network events and changes to deployed files. Their usefulness depends on retention, integrity and the specific environment. A suspicious request provides a lead; it does not alone establish that a command executed.

Preserve evidence before routine maintenance destroys relevant context when feasible under the incident plan. At the same time, do not leave exposure open merely to collect an ideal dataset without weighing the risk. An incident lead should document the tradeoff and sequence the work.

If evidence establishes compromise, recovery can require more than replacing a library. Trusted redeployment and review of accessible credentials may be appropriate. The scope should follow the findings, with uncertainty stated explicitly where records cannot answer the question.

## 18. Metrics that measure closure quality

Counting updated hosts can conceal unresolved applications. Counting closed tickets can conceal weak evidence. An original response scorecard should make the unit of work explicit and report uncertainty alongside completion.

Useful categories include applications with verified corrected runtimes, services under time-limited controls, applications awaiting supplier decisions and deployments with unresolved ownership. Each category should have a defined entry and exit criterion. This prevents an unknown from being relabeled as not affected merely to improve the percentage.

Track how long critical unanswered questions remain open. A stalled determination may be more urgent than a low-risk application already scheduled for a supported update. Report exceptions by consequence and reachable exposure rather than presenting all tickets as interchangeable.

Review a sample of closure evidence after the emergency. The purpose is to improve the process, not to reward paperwork volume. A concise record that proves the active artifact is more valuable than many screenshots of successful commands that never establish which service was running afterward.

## 19. Fictional exercise: Northline Permit Services

Northline Permit Services is a fictional training organization. It operates a public permit portal, a staff-only records interface and a vendor-supplied administrative product. The coordinator receives an urgent framework advisory and asks each service owner for an exposure determination.

The portal team changes a dependency and reports completion before deployment finishes. The records team switches parsers based on an early recommendation. The vendor team finds a library name but has not matched the installed product to the supplier's advisory. A standby portal instance remains outside the current rollout inventory.

The exercise introduces the later alternative-parser correction. Participants must identify which prior decisions need reopening and explain why. They should avoid reopening every case indiscriminately if a corrected runtime is already established. They must also resolve the supplier question without manually modifying an unsupported product.

A final inject presents a suspicious request from the earlier exposure window. The team should preserve the distinction between a request received and execution confirmed. The exercise tests evidence, ownership and changing assumptions, not technical exploitation skill.

## 20. Exercise answer framework

For the public portal, an acceptable result connects the approved dependency change to a built artifact and a complete serving inventory, including standby behavior. A repository commit alone does not close the case. The team should show how a later failover avoids restoring the old artifact.

For the records interface, the later advisory directly challenges the workaround's justification. Participants should escalate the unresolved correction and evaluate supported containment while testing the update. They should not defend the earlier choice by quoting only the old test table and ignoring its explicit correction.

For the vendor product, the result should identify the exact product and an authoritative remedy or applicability statement. If the supplier cannot yet answer, the case remains unknown with a named owner and a risk-based temporary decision. A generic library match or unrelated vendor statement is insufficient.

For the suspicious request, participants should state the available evidence, its observation point and the next authorized investigative step. The facilitator should not manufacture a confirmed breach merely to force drama. A disciplined unresolved finding is better than a confident fiction.

## 21. Preventing stale advice from becoming permanent policy

Emergency decisions often persist beyond the circumstances that created them. A temporary parser change can become an undocumented default; a firewall rule can become the only remembered remedy; a copied email can outlive the advisory revision that corrected it.

Prevent that drift by storing the rationale with the decision. Identify the source revision, the applicable product and the condition that ends the exception. Link the decision to the service inventory so a new owner can discover it during handover.

When new information arrives, communicate the precise change. "The previous workaround no longer establishes protection for this configuration" is more useful than a generic request to review security. The recipient should know which assumption changed, what action is needed and what evidence will close the new work.

Preserve earlier reasoning for accountability without treating it as current guidance. A good incident record can show that a decision was reasonable under earlier evidence and still requires correction now. That encourages timely updates rather than defensiveness or concealment when technical understanding improves.

## 22. Research lessons and conclusion

This case rewards close reading of primary advisories. The later update in a document can change how an earlier table should be interpreted. A second bulletin can describe a new vector without changing the CVE or fixed releases. Supplier statements can differ because they address different products, not because one global answer must apply to every installation.

For researchers, these distinctions prevent inaccurate summaries. Avoid assigning every downstream compromise to one mechanism without incident evidence. Avoid treating a vulnerability rating as proof of a specific business loss. Keep historical release recommendations separate from current maintenance advice, and describe what a test actually established.

For defenders, the lasting contribution is an evidence-based closure process. Understand the advisory, locate the affected application, select a supported remedy and connect it to the active service. Revisit workarounds when their assumptions change. Examine rejection paths as carefully as successful workflows, and keep investigation separate from the maintenance task.

CVE-2017-5638 was a failure at an input-to-interpretation boundary. The organizational challenge was to respond accurately as knowledge evolved. A strong response needs both: correction of the specific software flaw and a process that can prove which systems received it without erasing uncertainty about earlier activity.

## Sources and reading scope

[1] Apache Software Foundation, S2-045. Problem, affected ranges and constrained workarounds; page shows March 2017 revision. https://cwiki.apache.org/confluence/display/WW/S2-045

[2] Apache Software Foundation, S2-046. Same-CVE relationship, additional header vectors and version-limited alternatives. https://cwiki.apache.org/confluence/display/WW/S2-046

[3] JPCERT/CC, JPCERT-AT-2017-0009. Initial March 9 alert and March 17/21 corrections; test scope and revised parser advice. https://www.jpcert.or.jp/english/at/2017/at170009.html

[4] Hitachi Incident Response Team, HIRT-PUB17006, updated 17 April 2017. Alternative-parser finding and coordination chronology. https://www.hitachi.com/en/hirt/publications/hirt-pub/hirt-pub17006/

[5] Nick Biasini, Cisco Talos, Content-Type: Malicious, 8 March 2017 with update. First-party exploitation observations; payloads not reproduced or executed. https://blog.talosintelligence.com/apache-0-day-exploited/

[6] CERT-EU, Security Advisory 2017-005, 9 March 2017. Service-account execution context and remediation warning. https://cert.europa.eu/publications/security-advisories/2017-005/

[7] Cisco, cisco-sa-20170310-struts2, initially 10 March 2017, final update 5 May 2017. Product applicability and fixed-release routing. https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170310-struts2

[8] SAS, CVE-2017-5638 security bulletin, assessment completed 15 March 2017. Supplier-specific not-vulnerable determination. https://support.sas.com/en/security-bulletins/apache-struts-remote-code-vulnerability.html

[9] Apache Struts, Security guidance, retrieved 15 November 2026. Current localization and expression-evaluation cautions; not reconstructed 2017 defaults. https://struts.apache.org/security/
