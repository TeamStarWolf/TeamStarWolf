# Stagefright: Media Parsing, Patch Completeness and Android's Trust Boundaries

*A TeamStarWolf case study. Published 16 November 2026.*

[All case studies](/case-studies/README.md) · Related: [Mobile Security Reference](/MOBILE_SECURITY_REFERENCE.md), [Vulnerability Management Reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md), [Malware Analysis Reference](/MALWARE_ANALYSIS_REFERENCE.md), [CVE Reference](/CVE_REFERENCE.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Mobile platform and vulnerability-management owners, detection engineers and incident responders

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 19 min (4,408 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You want an evidence-bounded account of Stagefright, you need to separate a family name from an individual CVE or an incomplete patch from a complete one, or you are reasoning about media-parsing trust boundaries and fleet patch coverage

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Executive assessment](#executive-assessment), [6. Why the incomplete patch mattered](#_6-why-the-incomplete-patch-mattered), [8. Exposure estimates are not victim counts](#_8-exposure-estimates-are-not-victim-counts)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Mobile Security Reference](/MOBILE_SECURITY_REFERENCE.md), [Vulnerability Management Reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md), [Malware Analysis Reference](/MALWARE_ANALYSIS_REFERENCE.md), [CVE Reference](/CVE_REFERENCE.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

Key takeaways (reviewed 2026-11-17):

- The shorthand name hides the key distinctions: original flaws, an incomplete fix, later findings, and hardening were related developments. ([Executive assessment](#executive-assessment))
- The disclosure listed seven CVEs and estimated exposure, which were capability claims, not a census of compromised devices. ([Executive assessment](#executive-assessment))
- A shared media component receives content through many apps, and a source fix still has to reach the actual device. ([Executive assessment](#executive-assessment))
- A parser handling untrusted content should not hold more access than its task requires. ([Executive assessment](#executive-assessment))

<!-- meta:end -->

Expanded historical series: 2015 disclosure with a 2016 architectural follow-up. Original defensive analysis and fictional training exercise. No exploit construction or device testing.

## Executive assessment

Stagefright became a shorthand for a collection of Android media-processing vulnerabilities, but that shorthand can obscure the most important distinctions in the case. The original disclosures, an incomplete correction, later media-library findings, and subsequent architectural hardening were related developments rather than one identical flaw with one universal update. A useful case study must keep those developments separate.

Zimperium publicly described Joshua Drake's research on 27 July 2015. The announcement listed seven CVE identifiers and estimated exposure across a very large Android population. It described media delivery paths that could avoid the user interaction normally associated with opening a suspicious attachment. Those were vulnerability and capability claims, not a census of compromised devices. [1]

The operational challenge was broader than telling users to avoid an unexpected message. A shared media component could receive content through different applications, and a source correction still had to become a product update that reached the actual device. Later review showed that one original correction was insufficient. The case therefore tests patch completeness as well as update distribution.

The long-term lesson also concerns authority. A parser processing untrusted content should not possess more access than its task requires. Google's 2016 hardening discussion paired prevention measures with a redesign that reduced and separated media-service privileges. [8] This study uses that development to examine how a response can move from fixing individual defects to reducing the consequences of future ones.

## 1. Scope and evidence method

This case belongs to the expanded historical series. The initial disclosure is in 2015, with a 2016 design follow-up, rather than being forced into the earlier 2016-2021 incident range. The primary sources include the research announcement, a coordination note, supplier bulletins, a Project Zero analysis, Google's annual security report and its media-hardening explanation.

Selected relevant passages were reviewed. This is not a line-by-line audit of every media parser, a complete history of every later Stagefright-related vulnerability, or an independent reproduction of an exploit. Technical sources contain operational demonstrations that this study does not reproduce. No malicious media was generated, sent, opened or tested on a device.

The article distinguishes a source's historical publication date from later page metadata. It also records disagreements that affect correction guidance. A coordination source can be valuable for discovery while still requiring comparison with the supplier's exact CVE and build records. Original recommendations, review models and the fictional exercise are analytical proposals, not undocumented claims about how a named organization responded in 2015.

## 2. A family name should not replace vulnerability identity

The original Zimperium list includes CVE-2015-1538, -1539, -3824, -3826, -3827, -3828 and -3829. [1] CERT/CC's VU#924951, first released on 28 July 2015 and later revised, organizes multiple parser issues and documents additional media entry paths. Its catalog also shows that several individual processing flaws can share a CVE. [2]

The original analytical conclusion is that a memorable name is an index, not a complete technical specification. An asset record saying Stagefright fixed leaves open which issue, which product and which correction it means. The label may be adequate for a conversation, but it is insufficient for an auditable remediation decision.

A better record connects the issue identifier to the supplier's applicability statement and the specific deployed build. Where a family contains several relevant issues, preserve the set rather than collapsing it into one checkbox. This prevents a later variant from being mistaken for proof that every earlier correction failed, and prevents an earlier fix from being treated as coverage for every later issue bearing the same name.

## 3. Media handling can precede the action a user recognizes

The August Nexus bulletin describes remote-content paths including MMS and browser playback, and notes changes to Hangouts and Messenger so media would not automatically pass to vulnerable processes. It characterizes the relevant media service as privileged, while also acknowledging SELinux confinement. [3]

Original threat modeling should distinguish receiving content, inspecting it, extracting metadata, rendering a preview and consciously opening it. A user may regard only the final action as execution, while a system has already processed the input in earlier stages. That mismatch can make ordinary awareness advice incomplete even when the advice remains sensible for other threats.

The response should identify which processing actually occurs in the deployed workflow. A setting that changes one application's automatic behavior does not establish the state of every other application using the shared component. It also does not repair the parser itself. A precise mitigation claim names the path it reduces and preserves the remaining uncertainty, rather than promising that avoiding a click resolves the entire vulnerability family.

## 4. The relevant consequence is the process's authority

A media-parser flaw and unrestricted control of the entire phone are not interchangeable claims. The effect depends on where the code executes, the privileges that context possesses, and whether further boundaries can be crossed. The supplier's process-level description is therefore more useful than a blanket takeover headline.

An original architecture review should ask what the media process can access and which of those capabilities the parsing task genuinely needs. It should then ask what separates that process from other resources. A sandbox is an important control, but its value depends on the authority remaining inside it. The word sandbox alone does not establish that every possible effect is harmless.

This model also improves executive communication. Describe the supported consequence at the correct level and explain why it matters to the device's purpose. A precise statement can still justify urgent action. Exaggerating a component-level result into universal root access makes the story less reliable and can distract responders from the actual protection that needs to change.

## 5. August and September were different correction milestones

The August Nexus bulletin is dated 13 August 2015 and names LMY48I or later for its listed issues. [3] The September bulletin, dated 9 September, names LMY48M or later and explicitly identifies CVE-2015-3864 as a variant related to CVE-2015-3824 for which the original update was insufficient. [4]

These are supplier milestones with defined scope. They do not establish that every Android product received those exact Nexus builds, nor that every device activated an update on the bulletin date. A researcher should not turn a reference-device release into a claim about the whole ecosystem's correction status.

Original response management should allow a completed task to reopen when the supplier narrows or changes the assurance. Reopening is not an admission that the earlier deployment never occurred. It records that the evidence now supports a different requirement. A good audit trail preserves both the earlier action and the later reason for additional work, so the organization can learn without rewriting history.

## 6. Why the incomplete patch mattered

Mark Brand's Project Zero article, published on 16 September 2015, analyzes CVE-2015-3864 and demonstrates a scoped research exploit on Android 5.0 and later on a Nexus 5. It explains that an apparently adequate arithmetic check failed to account for different integer widths. It also identifies the September Nexus correction and credits multiple parties who noticed the problem. [5]

The original engineering lesson is that a patch should be reviewed against the property it must guarantee, not merely against the particular sample that exposed the defect. If the intended property concerns allocation size and subsequent data handling, the review must account for the relevant type ranges and conversions across supported environments.

A single successful regression test can show that one input no longer produces the old failure. It cannot establish that every related path preserves the intended boundary. That does not make regression testing unhelpful. It makes the test set and the reasoning behind it important. The strongest assurance combines focused tests with a clear explanation of why the correction covers the full input domain it claims to address.

## 7. Later media findings require exact source reconciliation

The retrieved CERT note describes a later Stagefright round using CVE-2015-6602 and -6610 and gives LMY48K language alongside November patch-level guidance. [2] The supplier records do not align cleanly with that summary. The October bulletin credits Drake for CVE-2015-3876 and -6602 and identifies LMY48T or later, including LMY48W, for its scope. [6]

The November bulletin names LMY48X or later and the November 1 Marshmallow patch level. It classifies CVE-2015-6610 as a local elevation-of-privilege issue with lower likelihood of remote exploitation, rather than presenting it as the same remote issue described by the broad coordination summary. [7]

This study preserves the discrepancy instead of silently combining the records into one remediation threshold. The practical decision rule is to use the exact supplier entry for the relevant CVE and product. The coordination note remains useful context, but it is not used here to assert a universal later-round build. This is a concrete example of why source comparison matters even when every source is reputable.

## 8. Exposure estimates are not victim counts

The original research announcement's large exposure estimate describes the population believed to contain relevant vulnerable code. [1] It should not become a claim that the same number of people were attacked or compromised. A vulnerable population, a reachable population, a tested device set and a confirmed incident population measure different things.

Original reporting should retain the date, method and uncertainty of any estimate. If the source does not provide enough detail to reconstruct the population, say so. Avoid adding precision through arithmetic that the evidence cannot support. A percentage applied to an approximate device population can create a deceptively exact number without improving the underlying knowledge.

For organizational decisions, a local inventory is usually more useful than a global headline. Determine which devices the organization owns or manages, what software they actually run and what correction path exists. The global estimate can explain why the research attracted attention, but it cannot answer which asset in the organization's fleet remains exposed today.

## 9. Demonstrated exploitability and observed incidents

Google's Android Security 2015 Year in Review, published in April 2016, distinguishes researcher demonstrations and reports of toolkit inclusion from successful exploitation of actual user devices. At the report's writing, Google said it had neither observed nor been made aware of successful Stagefright exploitation against actual users. [9]

That is a dated observation with a visibility boundary, not proof that exploitation was impossible or never occurred. It also does not erase the research demonstrations. The two kinds of evidence answer different questions: one concerns capability under specified conditions, the other concerns known real-world activity within the reporting organization's awareness.

Original incident communication should use the same discipline. A detection of vulnerable software does not establish compromise. A suspicious file does not automatically establish successful execution. A laboratory result does not identify a criminal actor. Prevention can proceed urgently while an investigation remains uncertain, but the report should never fill that uncertainty with invented victims, motives or losses.

## 10. Public update programs were an important institutional change

The annual report dates the expansion to a monthly public AOSP security update program to 5 August 2015 and describes a Nexus security-update lifecycle. [9] That is an institutional development separate from the 13 August publication date displayed by the first bulletin. The dates concern different events and should not be forced into a false contradiction.

Original analysis should recognize the value of making maintenance expectations visible. A public bulletin gives device owners and administrators a reference against which to ask questions about coverage. It does not, by itself, prove that every manufacturer, carrier or device followed the same schedule or delivered identical packages.

The useful evaluation question is whether the organization can connect the public requirement to its deployed assets. A schedule becomes operationally meaningful when someone can identify the applicable release, the responsible supplier, the actual delivery status and the evidence of installation. Transparency supports accountability, but it does not replace the work needed to complete the chain.

## 11. Prevention and containment address different failure stages

Google's May 2016 media-hardening article describes integer-overflow checks across the Android N media stack and a redesign that separates media responsibilities into more restricted processes. Its stated goals distinguish preventing bugs from becoming exploitable from containing the effect of a compromised component. [8]

An original security model should preserve that distinction. Prevention tries to stop the dangerous state from arising. Containment assumes a component might still fail and limits what it can affect. Investing in one does not make the other unnecessary, and the presence of both should not become a claim that all future parser vulnerabilities are impossible.

For a design review, ask what happens when an input is rejected, when a parser crashes and when a parser behaves maliciously after compromise. Those scenarios test different properties. A system that safely terminates one process may still need to preserve service availability and isolate sensitive resources. The goal is a controlled failure mode rather than a promise that complex media code will never contain another defect.

## 12. A parser's resource needs should be explicit

The following is original architectural analysis. Start with the specific job: interpreting a file structure, extracting metadata or decoding a stream. List the resources needed for that job and compare them with the resources available to the process performing it. Any difference deserves a reason grounded in functionality rather than convenience or historical inheritance.

Separating responsibilities introduces interfaces, and those interfaces require their own validation and ownership rules. Moving code into another process does not automatically make the design correct. The review should examine how data crosses the boundary, how failures propagate and whether a component can influence operations outside its intended authority.

This approach produces a more durable lesson than treating Stagefright as a one-time mistake. It makes least privilege an engineering question that can be checked in a design and maintained through changes. Future features should revisit the capability map so a restricted parser does not gradually regain broad authority through accumulated exceptions.

## 13. Fleet inventory needs product and application context

An original response inventory should include device model, hardware variant where relevant, operating-system build, patch-level information when supported, management status and update owner. It should also identify the media-handling applications relevant to the organization's workflows. Product scope and application behavior can both matter without being interchangeable.

A generic Android version label may conceal different supplier builds. A device in a desk drawer may remain outside routine reporting but return to service later. A loan pool may use a different update channel from assigned phones. The inventory should represent actual deployed and reusable assets, not only those easiest to see in the management console.

Unknown facts should remain visible as tasks. Do not count an unreported device as corrected, and do not automatically count it as compromised. Assign a person who can obtain the missing evidence or decide that the asset cannot remain in service. This keeps the response denominator honest and makes the remaining work concrete.

## 14. Mitigation claims should name the path they reduce

The original defensive recommendation is to describe an application-setting change narrowly. If it prevents automatic retrieval or changes when an application passes media for processing, record that behavior and the product version for which it was verified. Do not present it as a replacement for a supported platform correction.

A change can reduce one path while leaving another available. That is not a reason to reject every temporary mitigation; it is a reason to describe its scope accurately. The decision should include the remaining exposure, operational effect, owner and exit condition. A temporary restriction that quietly becomes permanent can hide an unsupported device lifecycle problem.

User instructions should remain understandable and compatible with the actual interface. Historical screenshots and menu labels should not be reused as current guidance without verification. The purpose of this case is to teach the reasoning behind a scoped mitigation, not to provide obsolete click-by-click instructions for messaging applications that may have changed substantially since 2015.

## 15. Supplier delivery and local activation are separate evidence

An original remediation record should distinguish source availability, product release, delivery eligibility, installation and active-state verification. These milestones often involve different people or organizations. A source patch does not establish a carrier-specific package, and a package announcement does not establish the state of the phone held by an employee.

The response should define the evidence required at each transition. A supplier statement may establish applicability. A management observation may establish the installed build. A functional check may establish that the device still supports its legitimate purpose after the update. No one observation should be credited with proving more than it can actually show.

If the supplier cannot provide a maintained correction, the organization needs a lifecycle decision rather than an endless reminder to update. Options may include replacing the device, changing the workflow or restricting its use for a defined period. The choice should account for service needs and residual risk, with an owner who can actually authorize it.

## 16. Regression testing should follow the repaired property

An original testing plan should begin with the security property the patch claims to restore. For media parsing, that may involve consistent handling of lengths, types and boundaries across supported environments. Tests should include legitimate edge cases and confirm that rejection happens safely, without reproducing an operational exploit chain.

A cross-version product can require more than one test environment. Differences in process architecture, library configuration and integration may affect whether a correction behaves as intended. The test record should state what was covered and what remains outside scope. Passing on one reference device should not silently become a claim about every product variant.

Functional validation also matters. A security correction that breaks essential media workflows can create pressure to bypass or roll back the change. Plan for that possibility with a supported troubleshooting path. If a rollback is necessary, reopen the security task and record the remaining exposure rather than allowing the earlier success status to survive unchanged.

## 17. Reopening a patch task should be routine and traceable

The incomplete-correction episode motivates an original process rule: new evidence can change the closure criteria without invalidating the record of earlier work. Preserve the previous requirement, the action taken, the later advisory and the reason for reopening. That helps distinguish a missed deployment from a changed technical understanding.

A team should not be penalized merely for acknowledging that a correction needs revision. If reopening is treated as failure to be concealed, people may keep a misleading completion label rather than report an important change. Accountability should focus on whether the team responds accurately and promptly to the new evidence.

The resulting history can also improve engineering feedback. Was the gap in the patch's logic, the product integration, the update delivery or the verification method? Those causes require different improvements. A generic statement that patching failed hides the causal information needed to prevent repetition and unfairly assigns responsibility to whoever last touched the ticket.

## 18. Investigation without invented certainty

An original incident assessment should start with a concrete observation: a suspicious message, an unusual process failure, a device-management alert or a user report. Establish the device and software state, the relevant application behavior and the timing. Keep hypotheses separate from facts while deciding whether additional preservation or containment is justified.

A missing visible message does not itself prove that an attacker deleted evidence. A media crash does not itself prove successful code execution. A clean application scan does not establish that every possible lower-level event was absent. Each observation has a scope, and the report should explain how that scope supports or limits the conclusion.

Preserve privacy as well as evidence. Investigating a work device may expose personal communications unrelated to the concern. Collection should be authorized, proportionate and limited to the question being investigated. The technical seriousness of a vulnerability does not grant unlimited permission to inspect every user's messages or media library.

## 19. Procurement should include a maintenance commitment

The following is original procurement analysis. A device's useful operational life can exceed its dependable security maintenance period. Buyers should therefore ask how long updates will be supplied, which organization controls delivery and how correction status can be verified. The answer should be tied to the actual product and channel rather than a general brand promise.

A maintenance commitment becomes more useful when it includes a way to resolve disputed applicability and an escalation route when an expected update does not arrive. The organization should also plan the cost and timing of replacement before support becomes an emergency. A cheap device with an uncertain correction path may impose a much larger operational burden later.

This does not mean every older device must be discarded immediately. It means its role should match a supportable risk decision. A training lab, a disconnected demonstration unit and a device handling sensitive communications may justify different choices. The decision should be explicit, periodically reviewed and supported by evidence about the actual use.

## 20. Fictional exercise: Cedarline Media Services

Cedarline Media Services is a fictional organization with company phones, shared tablets and field devices supplied through two purchasing channels. No real company, employee or compromise is represented. The exercise begins when a manager asks whether the organization has fixed Stagefright and receives three incompatible answers from different teams.

The first team says an August update was installed. The second says automatic MMS retrieval was disabled. The third says a vendor announcement promises a future release. Participants must identify the evidence each answer supplies and the questions it leaves open. None should be treated automatically as full correction or as proof of compromise.

The first deliverable is a device-and-issue map with accountable owners. It separates the original issue set, the later correction requirement and the supplier-specific product state. The team should also identify which devices are outside routine management and which workflows depend on media functions. No malicious test file or exploit demonstration is part of the exercise.

## 21. Exercise injects and expected reasoning

The first inject introduces the September incomplete-patch finding. Participants should reopen affected tasks with a documented reason and avoid deleting the earlier deployment history. The second inject presents the inconsistent later-round wording in the coordination note. The team should compare the exact supplier entries instead of choosing the most convenient build string.

The third inject is an executive draft claiming that the researcher's exposure estimate represents confirmed victims. Participants must correct the wording while preserving the need for preventive action. The fourth inject asks whether the absence of observed successful exploitation in Google's dated report proves the risk was imaginary. The answer should distinguish capability, visibility and actual incident evidence.

A final inject reveals that one device group has no reliable maintenance path. The team must make a supported lifecycle decision with the service owner. The exercise rewards precise scope, honest uncertainty and completed ownership transitions. It does not reward dramatic claims, unexplained percentages or unsafe attempts to reproduce the vulnerability on working devices.

## 22. Metrics that show real correction

Original response measures should distinguish assessed devices, confirmed applicable devices, available updates, completed installations and verified active states. Keep unsupported and unassessed assets visible. A single fixed percentage can hide a small but important group for which no one has established either applicability or a maintenance owner.

Sample closed records for quality. Can another reviewer connect the relevant CVE set to the supplier build and local observation? Does a temporary setting change have an exit condition? Does the record identify which advisory revision supplied the requirement? Include complicated product variants in the sample so the audit does not merely validate the easiest part of the fleet.

Track recurrence as well as completion. Loan devices and restored images can reintroduce outdated software after the main campaign ends. The response should leave behind a maintenance process that notices those returns. Otherwise, a correct one-time cleanup can slowly become an inaccurate assurance statement as the fleet changes around it.

## 23. Conclusion

Stagefright is a case about media parsing, but it is also a case about how security claims become operational decisions. The original family, the incomplete correction and later findings need distinct identifiers and supplier evidence. Large exposure estimates must remain separate from victim counts. Research demonstrations and dated observations of real-world exploitation must retain their different meanings.

The architectural follow-up adds another lesson: correction and containment can reinforce one another. Fixing known parser defects addresses the immediate problem, while reducing unnecessary authority can limit the effect of a future failure. Neither should be promoted into a guarantee that complex software will never contain another vulnerability.

The original defensive framework is to map the actual processing path, verify the exact product correction, reopen tasks when evidence changes and maintain devices throughout their useful service life. That framework remains relevant even though the 2015 build identifiers are now historical. The enduring value is a method for making careful, testable claims about where trust begins and how far a failure can travel.

## Sources and reading scope

[1] Zimperium, Experts Found a Unicorn in the Heart of Android, 27 July 2015. Original announcement, CVE list and researcher exposure/capability claims; marketing statements are not adopted as incident proof. https://zimperium.com/blog/experts-found-a-unicorn-in-the-heart-of-android

[2] CERT/CC, VU#924951, first released 28 July 2015, revised 8 January 2016. Coordination catalog and mitigation context. Later-round CVE/build wording differs from supplier records and is explicitly bounded in the article. https://www.kb.cert.org/vuls/id/924951

[3] Android Open Source Project, Nexus Security Bulletin, August 2015, displayed publication 13 August. Scope, build, media paths and application mitigation statements. https://source.android.com/docs/security/bulletin/2015-08-01

[4] Android Open Source Project, Nexus Security Bulletin, September 2015, published 9 September. CVE-2015-3864 correction relationship and LMY48M scope. https://source.android.com/docs/security/bulletin/2015-09-01

[5] Mark Brand, Project Zero, Stagefrightened?, 16 September 2015. Selected patch-completeness, platform-scope and arithmetic-type discussion. Operational exploit material is not reproduced or executed. https://projectzero.google/2015/09/stagefrightened.html

[6] Android Open Source Project, Nexus Security Bulletin, October 2015, published 5 October, updated 28 April 2016. Relevant CVE entries, acknowledgements and build scope. https://source.android.com/docs/security/bulletin/2015-10-01

[7] Android Open Source Project, Nexus Security Bulletin, November 2015, published 2 November. CVE-2015-6610 assessment and build/patch-level scope. https://source.android.com/docs/security/bulletin/2015-11-01

[8] Dan Austin and Jeff Vander Stoep, Android Security Team, Hardening the media stack, 5 May 2016. Prevention, integer checks and component-privilege separation. https://security.googleblog.com/2016/05/hardening-media-stack.html

[9] Google, Android Security 2015 Year in Review, April 2016. Selected pages 31 and 46 on the public update program and bounded exploitation observations; not a full line-by-line audit of the 49-page PDF. https://source.android.com/docs/security/overview/reports/Google_Android_Security_2015_Report_Final.pdf
