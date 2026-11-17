# Dirty Pipe: When Read-Only Data Lost Its Integrity

*A TeamStarWolf case study. Published 16 November 2026.*

[All case studies](/case-studies/README.md) · Related: [Linux Hardening Reference](/LINUX_HARDENING_REFERENCE.md), [Container Security Reference](/CONTAINER_SECURITY_REFERENCE.md), [Vulnerability Prioritization Reference](/VULNERABILITY_PRIORITIZATION_REFERENCE.md), [CVE Reference](/CVE_REFERENCE.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Linux platform and kernel engineers, vulnerability management leads, incident responders and container and cloud operators

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 20 min (4,708 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You want an evidence-bounded account of CVE-2022-0847, you need to separate an affected kernel from an exploitable one or an installed patch from an active one, or you are planning a kernel-patch exercise

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Executive assessment](#executive-assessment), [9. Distribution package identity beats a casual version comparison](#_9-distribution-package-identity-beats-a-casual-version-comparison), [20. Fictional exercise: Northbank Research Compute](#_20-fictional-exercise-northbank-research-compute)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Linux Hardening Reference](/LINUX_HARDENING_REFERENCE.md), [Container Security Reference](/CONTAINER_SECURITY_REFERENCE.md), [Vulnerability Prioritization Reference](/VULNERABILITY_PRIORITIZATION_REFERENCE.md), [CVE Reference](/CVE_REFERENCE.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## Executive assessment

Dirty Pipe, CVE-2022-0847, concerns a Linux kernel failure that allowed a local unprivileged process to modify cached content associated with files it could read. The security significance was the violation of an integrity boundary: the process could affect content despite lacking ordinary write permission. Ubuntu's security record identifies potential privilege escalation and classifies the issue as high priority. [1]

The story is more nuanced than a claim that every Linux installation was equally exploitable. The underlying initialization defect and the later behavior that enabled the described attack entered upstream history at different times. Distribution kernels also differed. Red Hat's assessment of RHEL 8 preserved the underlying flaw while explaining why the then-known attack path did not work there. [2][3]

This case examines the discovery, correction, product scope and evidence needed for a defensible response. It separates an upstream version from a distribution package, an installed kernel from the kernel actually running, and a vulnerable system from a confirmed compromised one. The recommendations and exercise are original analytical work, not an account of an unnamed organization's historical response.

Unlike a purely hypothetical vulnerability study, the later record includes a supplier warning about indications of targeted exploitation. That increases the importance of an evidence-based response without supplying a public victim census or a complete campaign narrative. The appropriate lesson is precise urgency: correct the applicable condition, investigate credible signs, and avoid inventing facts to make the threat sound larger.

## 1. Scope, dates and evidence method

This is a 2022 case in the expanded Team Star Wolf series. It is deliberately outside the earlier 2016–2021 focus and is not mislabeled as an event from that period. The primary material consists of the discoverer's account, an upstream correction record, distribution advisories and package records, and Android's May 2022 bulletin.

Selected relevant passages were reviewed. No proof-of-concept was executed, no production file was altered, and no independent kernel reproduction was performed. The original disclosure contains operational material that this study does not reproduce. A direct kernel.org correction link returned an access error, so the matching commit in the official torvalds/linux repository supplied the correction record.

The CISA catalog and its feed could not be retrieved through the research path used here, and the NVD page did not provide readable content. This study therefore does not depend on an unverified catalog entry or borrow a catalog date from a secondary site. It uses Android's accessible primary statement for the bounded exploitation discussion. Retrieval limits are retained rather than filled with assumptions.

## 2. Discovery began with an integrity symptom

Max Kellermann's account traces the investigation to repeated corruption in downloadable access logs. His timeline records the first support ticket on 29 April 2021, recognition of the kernel vulnerability on 19 February 2022, reporting to the kernel security team the next day, and public disclosure on 7 March. It lists stable fixes released on 23 February as Linux 5.16.11, 5.15.25 and 5.10.102. [4]

The original analytical lesson is that a reliability symptom can reveal a security boundary failure. A corrupted output should not automatically be treated as malicious activity, but repeated unexplained corruption deserves a structured investigation. The important shift is from repairing one artifact to asking why the system could produce that artifact at all.

A support process can help by preserving representative failures, environment details and the assumptions behind an initial diagnosis. A later engineer may recognize a pattern that the first responder could not see. Closing an individual ticket is sometimes necessary to restore service, but the closure record should not erase an unresolved systemic question when the same symptom returns.

## 3. Two changes, two different historical claims

Ubuntu's Dirty Pipe knowledge base distinguishes the older missing initialization, present from upstream 4.9, from the later merge-related behavior, present from 5.8, required by the described attack. It recommends a kernel update and reboot and states that no mitigation was available for that issue in its guidance. [2]

The distinction matters because bug introduction and practical exploitability are not interchangeable dates. A defect can exist before another change makes its consequences much more serious. It would be inaccurate to describe every kernel since 4.9 as equally exposed to the specific published attack, just as it would be inaccurate to assume that older affected code requires no correction merely because one attack path is absent.

An original historical account should record the separate milestones and their meaning. The date code entered a tree, the date a security consequence became possible, the date a maintainer recognized it, and the date a product delivered a correction answer different questions. Compressing them into one discovery date loses the causal structure that makes this case valuable.

## 4. The correction and what it proves

The official upstream commit 9d2231c5d74e13b2a0546fee6737ee4446017903 is titled around initializing flags in new pipe buffers. Its message identifies missing initialization in two functions and points to the earlier pipe-backed iterator change. The displayed change consists of two added lines in one file. [5]

That small diff is evidence about the correction's focus, not a measure of the incident's importance or the effort required to diagnose it. A missing assignment can have consequences that depend on object reuse, later feature changes and shared data semantics. Line count should not stand in for security impact, complexity of investigation, or confidence in deployment.

Original engineering analysis should ask which assumption the correction restores: a newly prepared object must have state appropriate to its current role rather than inherit authority from a previous use. The specific patch addresses the known defect. A broader review can then look for similar ownership and initialization assumptions without claiming that all superficially similar code contains the same vulnerability.

## 5. A conceptual model of the integrity failure

The relevant structure is `pipe_buffer`, whose `flags` field describes properties of the buffer. An anonymous pipe buffer can permit later data to be merged into its page. A buffer referring to a file's page cache must not inherit that permission: its page belongs to the file-cache relationship rather than to an anonymous pipe allocation. Kellermann traces the decisive later change to the per-buffer `PIPE_BUF_FLAG_CAN_MERGE` flag in Linux 5.8. The older missing initialization allowed a file-cache reference to retain inappropriate flags. [4]

The distinction is an ownership error, not a missing ordinary write permission on the file. The kernel can legitimately write cache memory, but the operation must preserve the difference between pipe-owned storage and a cached file page. The two-line correction initializes flags when constructing the relevant buffers. This explains why a small patch can restore a large trust boundary without making the diagnosis trivial. [4,5]

This model deliberately stops before an operational exploit procedure. For defensive review, the useful invariant is that a new file-backed buffer cannot inherit merge authority from a previous role. A regression test should verify that property across object reuse and legitimate reads, not merely check the presence of a version string.


For this study's non-operational model, separate the process's permission to read a file from the kernel's internal handling of references to its cached contents. The intended permission boundary says the process may observe content but may not alter it. A flaw in how the kernel manages that internal state can break the boundary even if ordinary application permission checks remain in place.

This explanation does not require an exploit sequence. The key concept is misplaced authority in shared state. An operation that appears to concern one object can affect another object when the implementation carries an incorrect assumption about ownership or mutability. Security review must therefore include the relationships between objects, not only the permissions visibly attached to a pathname.

The original defensive implication is to test the property that should remain invariant across legitimate operations. A read-only consumer should not be able to change the content other consumers receive. That is a broader and more useful assurance question than asking whether one particular demonstration program runs successfully on a test machine.

## 6. Memory state and persistent state require separate conclusions

Kellermann explains that a page-cache modification does not automatically mark the page for disk writeback. In some circumstances the change may disappear after cache eviction or reboot; persistence depends on other state and activity. His disclosure also identifies constraints, including the requirement for read access and limits on resizing and page-spanning modification. The overwrite also cannot begin at a page boundary; this is a distinct constraint from crossing a boundary. [4]

Original incident analysis should therefore avoid two opposite errors. The first is assuming that every observed effect necessarily persists on disk. The second is assuming that a transient effect is harmless or leaves the system trustworthy. Content consumed while altered can influence another process before the altered page disappears. A later clean file does not by itself answer what happened earlier.

The evidence plan should identify which state a particular observation represents. A stored artifact, a cached view, an application result and a historical log can each support different conclusions. When those observations disagree, record the timing and method rather than forcing them into a single narrative. An investigation should not promise that any one hash or reboot settles all integrity questions.

## 7. Local privilege escalation is still consequential

The local nature of the vulnerability means it should not be described as a stand-alone, unauthenticated network-entry mechanism. A response needs to account for where untrusted or less-trusted code can execute and what authority it already has. The relevant trust boundary concerns what that execution context should be prevented from changing.

Original prioritization should consider systems that intentionally run code from different trust levels, including development and processing environments. It should also consider the consequence if a lower-privileged service context gains influence over more privileged behavior. These are assessment questions, not claims that every listed environment was exploited through Dirty Pipe.

Calling a vulnerability local does not establish that every local actor is trusted, nor that an organization can ignore it until an administrator logs in. Conversely, a serious local flaw does not prove that an internet-facing service is already compromised. The correct response preserves the distinction between an initial foothold, a privilege boundary failure, and subsequent actions.

## 8. Red Hat's affected-versus-exploitable distinction

Red Hat rated the issue Important and identified affected products including RHEL 8. Its advisory says the known merge-flag attack vector was unavailable there, while the underlying defect remained and other exploitation possibilities could not be fully ruled out. It recommended corrected packages and said SELinux and kpatch did not mitigate this flaw. [3]

This is a useful example of why a supplier's exact language matters. A statement that the known exploit does not work should not be rewritten as an unconditional guarantee of safety. A statement that the underlying defect exists should not be rewritten as proof that a publicly demonstrated attack works on every affected build. The two assessments answer different questions.

An original internal tracking system should preserve both fields when necessary: defect applicability and documented exploitability conditions. That makes a remediation decision easier to explain and prevents analysts from fighting over a single overloaded affected label. The decision can still be to update, while the risk explanation accurately reflects the evidence for that product.

## 9. Distribution package identity beats a casual version comparison

Ubuntu's CVE record maintains a package-by-release matrix. It distinguishes base kernels from hardware-enablement and platform-specific packages, with different fixed or unaffected states. That structure demonstrates why an operating-system release name alone is insufficient for some fleet decisions. [1]

Original assessment should retain the distribution, package stream, architecture where relevant, installed package version and active kernel identity. An upstream version threshold is a useful research clue, but distribution backports and product-specific maintenance mean it cannot replace the supplier's applicability record. A simple numerical comparison may generate both false reassurance and false alarms.

The analyst should also record the date of the vendor assessment. A living security page may contain later status changes that were not available during the original disclosure week. For historical analysis, distinguish what the record now says from what responders could have known then. For current remediation, use the maintained guidance appropriate to the product rather than mechanically repeating a historical version string.

### Applicability and correction decision table

The following is a historical guide, not a current package prescription. Distribution-maintained records take precedence over a raw upstream version comparison. [1-4,6,7]

| Environment or milestone | What the evidence establishes | What closes the local question |
| --- | --- | --- |
| Upstream 4.9 lineage | Missing flag initialization predates the public attack path. | Identify the maintained product's assessment; do not label all 4.9-era kernels equally exploitable. |
| Upstream 5.8 lineage | Later merge-flag behavior enables the described attack. | Check branch and vendor corrections, not only the major version. |
| Stable fixes, 23 February 2022 | Discoverer lists 5.10.102, 5.15.25 and 5.16.11. | Verify the active corrected kernel or the vendor-supported backport. |
| Ubuntu releases and variants | Package streams have different fixed or unaffected states. | Match release and kernel package stream to the supplier matrix; verify update activation. |
| RHEL 8 | Underlying flaw present; known published vector unavailable in the assessed kernel. | Preserve this qualification and follow Red Hat's corrected-package guidance. |
| Android May 2022 bulletin | Dirty Pipe appears under the 2022-05-05 kernel patch level. | Verify applicable device/vendor update and reported patch level; do not infer all Android devices were affected. |

## 10. Ubuntu's correction includes a restart boundary

Ubuntu notice USN-5317-1, dated 8 March 2022, includes the Dirty Pipe correction and instructs users to reboot after the standard update. It also warns that the kernel ABI change requires attention to third-party kernel modules and provides release-specific package versions. [6]

The original operational lesson is that package installation and active correction are separate milestones. A successful update job can leave the old kernel running until the supported activation step occurs. The security task should not close solely because a package manager reports success or because the desired package exists on disk.

A restart plan should include service ownership, approved timing, health checks and a supported recovery path. The correction should become active without creating an avoidable availability failure. Where a system cannot be restarted immediately, document the remaining exposure and the decision owner. Do not convert scheduling difficulty into a claim that the installed package already provides the required runtime protection.

## 11. Android provides bounded evidence of exploitation

Android's May 2022 bulletin was published on 2 May and updated on 3 May. It places CVE-2022-0847 in the May 5 kernel-component patch-level section, classifies it as high-severity elevation of privilege, and states that there were indications it might be under limited, targeted exploitation. [7]

That wording is stronger than saying no evidence exists, but narrower than a public account of a widespread campaign. It does not identify a complete set of victims, attacker identities, intrusion routes, or losses. This case preserves the supplier's degree of certainty and does not turn the statement into an unsupported incident narrative.

Original response planning can use such a warning to raise priority and review relevant signs while keeping the reporting factual. A targeted-exploitation indication does not mean every unpatched device was attacked. Nor should uncertainty about scale be used to postpone correction indefinitely. Evidence can justify urgent preventive action without establishing every detail of an adversary's activity.

## 12. The cloud image and the running instance are separate assets

Ubuntu's knowledge-base timeline records updated packages on 8 March and updated cloud images on 9 March 2022. [2] The dates illustrate a distinction that matters beyond this specific case: a corrected source image does not establish that every previously launched instance has changed.

The following is an original cloud-response model. Track the template used for new deployments separately from the active fleet. Correcting the template prevents new instances from repeating a known condition. Updating or replacing existing instances addresses the current population. Both need evidence, and each can remain incomplete even when the other succeeds.

An autoscaling environment adds a recurrence risk if an outdated image remains selectable. Closure should therefore include the approved launch configuration as well as runtime checks. Preserve version and deployment records so a later review can identify whether a reintroduced old image explains a renewed finding. The purpose is prevention of regression, not an assumption that every cloud image in 2022 was vulnerable.

## 13. Container labels do not settle kernel ownership

An original platform assessment should identify which kernel actually supplies the relevant service boundary. Rebuilding an application image is a different action from correcting the kernel on the host that runs it. A container image's package list should not be treated as complete evidence about the host's vulnerability state.

At the same time, this study does not assert a universal container escape. Whether an attacker can cross a particular boundary depends on the actual configuration, accessible resources and vulnerability conditions. The existence of a shared kernel is a reason to examine ownership and isolation, not a substitute for an observed end-to-end compromise.

The practical coordination question is who can act on the kernel. An application team may be able to rebuild its image but lack authority over the worker nodes. A platform team may own the nodes but depend on service owners for safe migration. A sound task assigns those responsibilities explicitly so a technically correct action in one layer does not create false closure in another.

## 14. Read-only controls remain useful but cannot repair the defect

Original defensive analysis should distinguish an intended control from the component that enforces it. File permissions, immutable settings and read-only arrangements express valuable restrictions. Their usefulness does not make them a universal answer when the vulnerability concerns how a privileged implementation handles the associated content.

The correct lesson is not to remove those controls. It is to avoid claiming that the presence of a control proves protection against a flaw that can undermine the relevant enforcement path. Preserve the layered protections that still have value, apply the supported correction, and evaluate residual uncertainty in the actual product context.

This distinction also improves exception reviews. A risk owner should ask whether the proposed compensating measure has evidence for this vulnerability, rather than whether it sounds generally secure. A control that reduces another attack surface may still be useful, but it should be described as reducing that exposure, not as fixing the kernel's integrity failure.

## 15. An original inventory and decision record

A useful record begins with the asset, service, kernel supplier and update channel. It then identifies the relevant vendor assessment, the observed active state, the planned correction and the owner who can authorize maintenance. Keep the evidence source and observation time close to the decision so a reviewer can understand how the conclusion followed.

Use separate states for unassessed, unaffected by the applicable vendor record, correction available, correction installed but not active, active correction verified, and exception pending. The exact labels can change, but the distinctions should remain. One patched checkbox often hides the most important unfinished work.

An uncertain asset should create a specific next action. Perhaps the installed kernel stream is unknown, or a service owner has not approved a maintenance window. Those are different problems with different owners. Treating both as a generic backlog item delays resolution and makes an executive report less useful than a small, accurate list of concrete blockers.

## 16. Safe verification and functional confidence

Original verification should rely on supplier-supported evidence and safe observations of the active system. The objective is to confirm that the applicable correction is in force and that legitimate services still function. It does not require running public privilege-escalation code on a production machine to prove the risk was real.

Before deployment, test the supported update in an appropriate environment and include the workflows most likely to be affected by the kernel change. The ABI warning in the Ubuntu notice is a reminder to consider product-specific dependencies rather than assuming an update is operationally invisible. [6] The test plan should be proportional to the system's importance.

After activation, capture the relevant state and service checks. If a regression occurs, diagnose it through the approved change process. A rollback can restore service while reintroducing exposure, so the decision should name that tradeoff and its temporary controls. A rollback record should reopen the security task rather than leaving the previous closure status untouched.

## 17. Correction is different from recovery after compromise

An original response plan should separate two questions: has the vulnerability been corrected, and can the system's prior state be trusted? Installing a fixed kernel addresses future use of the known flaw. It does not automatically establish that no file, process, credential or decision was affected before the correction became active.

When credible compromise evidence exists, investigate according to the organization's incident procedure. Assess the scope of altered or potentially influenced state, preserve relevant evidence, and choose an authorized recovery strategy. This study does not prescribe blanket credential resets or reinstallation for every vulnerable machine. Such actions should follow the evidence and consequence assessment.

The distinction prevents both overreaction and underreaction. A vulnerability finding alone should not generate an invented breach. A confirmed breach should not be closed as merely a patching task. The same technical correction can belong to very different response workflows depending on the observed events.

## 18. Volatile evidence and the restart decision

A restart can activate a corrected kernel and can also change evidence that depends on transient state. An original incident lead should recognize that tension before acting. The decision should consider service risk, continued exposure, available preservation methods and the importance of the observations at issue.

There is no universal instruction to delay every restart. On some systems, immediate containment or restoration may be more important than preserving uncertain volatile evidence. On others, a short authorized preservation step may materially improve the investigation. The key is a recorded, accountable decision rather than an accidental loss of context caused by treating all vulnerable systems identically.

Investigative reports should say what was examined and what the method could establish. A clean disk image after a restart may not answer a question about earlier cached content. Conversely, a transient anomaly may have a nonmalicious cause. A careful report preserves these limits without using uncertainty as an excuse to avoid a reasoned conclusion.

## 19. Engineering lessons from object reuse

The correction record motivates an original review strategy focused on state transitions. When an object changes role or enters service after reuse, which fields carry authority, and who initializes them? Reviewers should consider whether a later feature could assign security significance to state that previously appeared harmless.

This is more than a recommendation to add one missing assignment. A durable test should express the intended property across legitimate operation sequences. For example, an unprivileged consumer's permitted read activity should not alter a shared file view. The test can be designed safely without borrowing an operational attack sequence from a public exploit.

Change review should also record assumptions that span components. If one function expects another to clear a field, the contract should be explicit and testable. A future refactor should not have to rediscover an undocumented dependency. These recommendations are original software-assurance analysis, not a claim that any particular maintainer ignored a known requirement or acted negligently.

## 20. Fictional exercise: Northbank Research Compute

Northbank Research Compute is a fictional organization that runs shared analysis servers, a small container platform and several managed field devices. No real organization, employee or incident is represented. The exercise starts when a security coordinator receives the Dirty Pipe bulletin and asks each service owner for a correction plan.

The first response says that every server package was updated overnight. The second says the application container image was rebuilt. The third says a vendor product uses a kernel whose familiar version number looks older than the published upstream threshold. Participants must determine what evidence is missing in each answer without assuming that all three represent the same condition.

The expected first output is an ownership and evidence map. It identifies the running kernels, the appropriate supplier assessment, the maintenance authority and the unverified transitions. The exercise rewards precise questions and safe decisions. It does not reward executing a privilege-escalation demonstration or declaring a breach merely because the vulnerability is serious.

## 21. Exercise injects and response criteria

The first inject reveals that several updated servers have not restarted. Participants should preserve the distinction between installation and active correction and arrange the supported activation step. The second reveals that a new deployment template is corrected but older instances remain. Participants should address both populations and prevent the old image from returning through normal automation.

The third inject presents a RHEL 8 assessment saying the underlying flaw exists but the known attack path is absent. The team should preserve that nuance while following the supplier's remediation advice. The fourth presents the Android warning about possible targeted exploitation. Participants should update priority without inventing a named campaign or a victim count.

A final inject reports inconsistent file content before and after maintenance. The team should establish observation methods, timing and preservation limits, then choose a proportionate investigation. A strong answer distinguishes correction, service recovery and confidence in prior state. The exercise ends with a clear list of closed facts, unresolved questions and named owners for the remaining decisions.

## 22. Measures that reveal unfinished work

Original metrics should show how many assets remain unassessed, how many have a supported correction available, how many need activation, and how many have verified active protection. Track exceptions separately and include their age. A fleet-wide percentage that excludes unknown systems can conceal the most consequential exposure.

Sample closure records for evidence quality. Can a reviewer identify the supplier assessment, package stream, active kernel observation and service validation? Can the reviewer distinguish a confirmed unaffected state from a failed scanner check? Include special-purpose systems and older deployment templates in the sample, not just the systems whose management tooling is most convenient.

The result should be a decision instrument rather than a decorative dashboard. If a metric cannot tell an owner what remains to do, simplify it. If an exception has no exit condition, escalate the underlying maintenance problem. The objective is reliable correction and accountable residual risk, not the appearance of completion.

## 23. Conclusion

Dirty Pipe demonstrates how a small initialization defect can undermine a major integrity assumption when later behavior gives stale state new significance. Its history also demonstrates why careful vulnerability work must separate upstream lineage, product applicability, active runtime state and incident evidence. The same identifier can require different explanations in different environments without making the underlying problem unimportant.

The primary record supports a serious local integrity and privilege-escalation case, with a later supplier warning about possible targeted exploitation. It does not support a universal claim that every Linux system was equally exploitable or that every affected asset was compromised. Precision strengthens the response by directing effort toward the actual condition that needs correction.

The original operational framework is to identify the kernel that matters, use the appropriate supplier record, activate the correction safely, and investigate credible integrity concerns as a separate task. The engineering framework is to make ownership and initialization contracts explicit. Together they turn a memorable vulnerability name into a durable lesson about evidence, shared state and trust.

## Sources and reading scope

[1] Ubuntu Security Team, CVE-2022-0847 record, published 7 March 2022, retrieved revision dated 4 July 2026. Description and selected package-scope rows reviewed; not a complete audit of every package row. https://ubuntu.com/security/CVE-2022-0847

[2] Ubuntu, DirtyPipe vulnerability knowledge base, published 10 March 2022. Distinct historical changes, update guidance and cloud-image timeline. https://ubuntu.com/security/vulnerabilities/dirtypipe

[3] Red Hat, RHSB-2022-002, public 7 March 2022, updated 10 May 2022. Product scope, known-vector limitations, mitigation statements and correction guidance. https://access.redhat.com/security/vulnerabilities/RHSB-2022-002

[4] Max Kellermann, The Dirty Pipe Vulnerability. Discovery timeline, stable-release fixes and selected impact/limitation passages. Operational exploit material is not reproduced or tested. https://dirtypipe.cm4all.com/

[5] Linux upstream correction, commit 9d2231c5d74e13b2a0546fee6737ee4446017903, official torvalds/linux repository. Commit message and correction scope reviewed; kernel.org retrieval failed. https://github.com/torvalds/linux/commit/9d2231c5d74e13b2a0546fee6737ee4446017903

[6] Ubuntu, USN-5317-1, 8 March 2022. Update activation, ABI warning and selected package information. https://ubuntu.com/security/notices/USN-5317-1

[7] Android Open Source Project, Android Security Bulletin, May 2022, published 2 May and updated 3 May. CVE placement, patch-level scope and bounded targeted-exploitation indication. https://source.android.com/docs/security/bulletin/2022-05-01
