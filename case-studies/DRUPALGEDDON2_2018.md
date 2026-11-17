# Drupalgeddon2: The Difference Between a Patched Website and a Recovered Service

*A TeamStarWolf case study. Published 16 November 2026.*

[All case studies](/case-studies/README.md) · Related: [Web Application Security Reference](/WEB_APPLICATION_SECURITY_REFERENCE.md), [Internet-Facing Services Reference](/INTERNET_FACING_SERVICES_REFERENCE.md), [Vulnerability Management Reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md), [CVE Reference](/CVE_REFERENCE.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Web-platform and vulnerability-management owners, detection engineers and incident responders

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 18 min (4,255 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You want an evidence-bounded account of Drupalgeddon2, you need to separate the CVE-2018-7600 and CVE-2018-7602 labels or a patched website from a recovered service, or you are reasoning about mass-exploitation response and forgotten sites

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Executive assessment](#executive-assessment), [2. Three labels that should not be collapsed](#_2-three-labels-that-should-not-be-collapsed), [6. Remote execution does not automatically mean operating-system root](#_6-remote-execution-does-not-automatically-mean-operating-system-root)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Web Application Security Reference](/WEB_APPLICATION_SECURITY_REFERENCE.md), [Internet-Facing Services Reference](/INTERNET_FACING_SERVICES_REFERENCE.md), [Vulnerability Management Reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md), [CVE Reference](/CVE_REFERENCE.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

Key takeaways (reviewed 2026-11-17):

- Drupalgeddon2 let untrusted requests influence internal processing in ways that enabled unauthenticated remote code execution. ([Executive assessment](#executive-assessment))
- Once automated attacks were underway, an updated installation could still contain unauthorized changes left by an earlier compromise. ([Executive assessment](#executive-assessment))
- Drupal issued SA-CORE-2018-002 for CVE-2018-7600 on 28 March 2018, warning of automated attacks by mid-April. ([Executive assessment](#executive-assessment))
- The April follow-up, CVE-2018-7602, requires separate treatment, with a different identifier and prerequisites. ([Executive assessment](#executive-assessment))

<!-- meta:end -->

Historical case study: CVE-2018-7600 and the distinct April 2018 follow-up CVE-2018-7602. Defensive analysis only. No exploit requests, payloads, persistence instructions or live testing.

## Executive assessment

Drupalgeddon2 exposed a critical boundary inside a widely used content-management system: untrusted requests could influence internal processing in ways that enabled unauthenticated remote code execution. The central incident-response lesson was not simply that administrators needed to update. Once automated attacks were underway, an updated installation could still contain unauthorized changes left by an earlier compromise.

Drupal issued SA-CORE-2018-002 for CVE-2018-7600 on 28 March 2018. On 13 April, its security team warned of automated attack attempts, identifying 11 April as the date evidence had emerged and allowing for earlier targeted activity. [1][3] Those are dated observations and response assumptions, not a census proving that every unpatched site had been successfully compromised.

The April follow-up, CVE-2018-7602, requires separate treatment. It had a different identifier and prerequisites, and its patch instructions depended on the earlier correction. [5] A record that simply says Drupalgeddon fixed cannot communicate which issue was addressed or whether the site was assessed for compromise before or after that correction.

This study develops an original defensive framework around evidence of deployment, trustworthy recovery and uncertainty. It also examines the project's objection to counting vulnerable sites from public version text alone. A visible version string can be stale after a direct security patch, while a current version can coexist with an earlier backdoor. Correctness and trust therefore require different evidence.

## 1. Scope and evidence method

The historical core uses Drupal's advisories and public-service announcements, a first-hand Volexity monitoring report, Check Point's technical research and the project's recovery guidance. A June response about version-based scanning was available as a search-indexed excerpt, while repeated direct retrieval returned an error. That limited reading scope is disclosed rather than represented as a complete page audit.

This is a study of a vulnerability and the associated response environment. It does not claim to identify every affected organization or to calculate a total financial loss. It distinguishes observed attempts from successful compromises and separates researcher capability demonstrations from incident observations. No infrastructure was scanned, and no exploit was executed.

Numbered references support the historical facts. The later inventory, recovery and governance models are original analysis. The fictional exercise is explicitly imaginary. Its purpose is to test decisions under incomplete information, not to imply that a named organization experienced an undocumented Drupal incident.

## 2. Three labels that should not be collapsed

CVE-2018-7600 is the issue covered by SA-CORE-2018-002 and commonly called Drupalgeddon2. The related April issue is CVE-2018-7602, covered by SA-CORE-2018-004. [1][5] The older 2014 event is a different vulnerability and should not supply dates, affected versions or recovery evidence for this 2018 study merely because the names resemble one another.

An original case register should use the formal identifier as its stable key and the nickname as a search aid. The register should also retain advisory revisions. A page read years later may contain an exploitation status that was added after the initial publication, so its present wording is not automatically proof of what was known on day one.

This matters for accountability. A team may have completed a valid March correction and still needed to act again in April. Treating the second task as evidence that the first update was never installed would be a different and potentially unfair conclusion. The response history should make clear which requirement existed at each decision point.

## 3. The advance notice created preparation time

On 21 March, Drupal announced a highly critical release scheduled for 28 March, with a specified UTC window. It urged teams to reserve time because exploit development could follow quickly. The notice also described exceptional updates for older minor branches and stated that the release would not require a database update. Its change log records later additions to the notice. [2]

The original operational lesson is that advance notice can be converted into readiness without knowing the exploit details. A team can identify owners, confirm deployment access and establish a rollback plan before the patch arrives. It can also check whether an abandoned microsite or development copy still runs the affected platform.

Preparation does not mean pre-approving an unknown production change without review. It means deciding how the relevant review will happen quickly when the vendor supplies the correction. The organization should know who can authorize an emergency maintenance window, how it will verify normal service afterward and what temporary containment options exist if deployment fails.

## 4. The March correction was branch-specific

The March advisory specified Drupal 7.58 and Drupal 8.5.1 as corrected releases for their branches, with exceptional 8.3.9 and 8.4.6 releases for older minor branches. It also identified Drupal 6 as affected and end-of-life, referring users to its long-term-support arrangements. [1]

These are historical milestones, not suitable current installation targets. A modern deployment should use a currently maintained release and its current security guidance. The value of the old version numbers is that they let a researcher reconstruct the response accurately without confusing the first correction with later cumulative releases.

The original inventory rule is to track the actual branch and distribution. A site maintained through a packaged distribution, a hosting platform or a custom build may have a different delivery workflow from a direct upstream installation. The update plan should connect the vendor's applicable correction to the deployment artifact actually used by that site.

## 5. Untrusted data crossed an internal processing boundary

Check Point's 12 April research describes insufficient input sanitization involving Drupal's Form API and internal rendering structures. Its explanation supports the high-level conclusion that external data could influence behavior intended for trusted internal metadata. The article includes an operational demonstration, which this study does not reproduce. [4]

The original engineering lesson is to identify when data changes meaning. A web framework may carry a value through several layers before another component interprets it as a rendering instruction. Validation at one visible form field is not enough if the program accepts alternate representations or later treats the structure as something more consequential.

A defensive review should ask where untrusted input enters, what structure is allowed and which later component relies on that structure. The intended invariant should be explicit: user-controlled data must not acquire internal execution authority merely because it arrives in a shape that resembles trusted framework metadata. That property is more useful for regression work than memorizing one published attack request.

## 6. Remote execution does not automatically mean operating-system root

Volexity described unauthenticated code execution with the privileges of the account running the web server and Drupal. [7] That consequence is already serious. It should not be inflated into a claim that every successful attempt immediately obtained unrestricted operating-system authority on every deployment.

The original consequence model begins with the application's real permissions. What can that account read? Which files can it modify? What credentials can the application access for its normal work? Which other services trust its requests? A seemingly ordinary web-service identity may still have access to sensitive databases or deployment secrets.

Least privilege can reduce the consequences of an application failure, but it cannot repair the application defect. Similarly, a restricted service account does not prove that confidential information was safe. The investigation needs to connect the compromised execution context to the resources available in that particular environment, then separate supported observations from plausible but unconfirmed effects.

## 7. Automated attempts changed the response problem

The 13 April public-service announcement explicitly said it was a follow-up about the same vulnerability, not a new vulnerability. It warned that sites unpatched by 11 April might be compromised and that targeted activity could have preceded the observed automated attempts. It also warned that patching would not remove existing backdoors. [3]

The original decision model separates urgent correction from retrospective investigation. Correction addresses further use of the known entry point. Investigation asks whether the entry point was used while available and what changed afterward. Both tasks may run in parallel, but neither should be quietly treated as a substitute for the other.

A team should document the exposure window it can establish and the gaps it cannot. A missing deployment timestamp, an incomplete access log or an unknown historical origin route should remain visible. Those gaps may justify a conservative recovery choice, but they should not be rewritten as certain proof of a specific attacker action.

## 8. Observed payloads establish breadth, not a universal outcome

In its 16 April report, Volexity described thousands of scan and exploitation attempts observed through its monitoring service since early 13 April. It reported varied activity, including attempts to install backdoors and cryptocurrency miners. Its assessment of one activity cluster's relationship to earlier attacks remained an analytical attribution, not a named-person conviction. [7]

The original reporting lesson is to preserve the observer's scope. A monitoring provider sees traffic and systems available to that service. Those observations can establish active exploitation pressure without supplying a global count of unique affected sites. Attempt totals should not be relabeled as confirmed victims.

The range of possible post-compromise activity also argues against a single symptom checklist. A high CPU load might reveal a miner, but a quiet backdoor could have a different profile. A defacement would be visible to an editor, while unauthorized access to a database might not alter the homepage at all. Investigation should follow the environment and evidence rather than one popular payload story.

## 9. The April follow-up was a separate correction

The 23 April notice scheduled an out-of-band release for 25 April. [6] The resulting advisory covered CVE-2018-7602, with corrected releases 7.59, 8.5.3 and the exceptional 8.4.8. Its risk vector included a user-authentication requirement, unlike the original issue's unauthenticated vector. It stated that direct patches required the earlier SA-CORE-2018-002 fix to be present. [5]

The original change-management lesson is that security tasks can have dependencies. A patch file that applies cleanly is not sufficient evidence that all required earlier changes exist. A deployment process should record the baseline to which a correction was applied and verify the combined result through an approved method.

This also prevents a common narrative error. The appearance of a related issue does not mean the original public-service announcement was a second CVE, and it does not make the April advisory identical to the March one. Exact identifiers and prerequisites keep a compressed timeline from turning into a technically false account.

## 10. Public version strings are imperfect evidence

In a June 2018 response, the Drupal Security Team disputed vulnerability counts based on public CHANGELOG.txt version information. Its indexed statement explained that direct security patches could leave version text unchanged and that vendor mitigations might also protect a site without changing that file. Direct retrieval of the page failed during this review, so the source register labels the excerpt-only access. [8]

The original measurement principle is broader than Drupal. A public version signal is an indicator requiring interpretation. It can support an inventory lead, but it cannot always prove the state of a backported correction. Researchers should disclose what their method measures instead of promoting a convenient observable into ground truth.

The reverse inference is equally weak: a current-looking version cannot prove the absence of earlier malicious modifications. Vulnerability status and incident status are separate dimensions. A strong report therefore records both the correction evidence and the trust assessment, rather than combining them into a single green status whose meaning changes from row to row.

## 11. An unexpected patch can itself need investigation

Drupal's April public-service announcement warned that a site appearing patched without its owner's action could be a symptom of compromise. It noted that attackers had previously applied corrections to exclude competitors. [3] This is a warning about provenance, not evidence that every unexplained update was malicious.

The original investigative question is who made the change and under what authority. A hosting provider might legitimately apply an emergency correction, while an undocumented deployment job might explain another case. The team should verify those possibilities through independent records rather than relying solely on the altered website.

A trusted maintenance record should connect the change to an approved actor, a known artifact and a deployment event. If those elements cannot be established, the uncertainty remains material even if the vulnerable code appears corrected. Security depends on trustworthy control of the service, not only the presence of one repaired function.

## 12. Inventory must include forgotten and indirect sites

The following is original operational analysis. A public-facing CMS deployment can outlive the project that created it. Event sites, old campaign pages and staging copies may remain reachable after their original owner moves on. An urgent platform advisory should trigger a search of the organization's own authoritative asset records and hosting accounts, not unauthorized scanning of unrelated infrastructure.

For each discovered instance, assign a business owner and a technical owner. Record its exposure route, including whether traffic can reach an origin server outside the usual proxy path. A defensive control applied to the main domain may not cover an old hostname or a separately accessible backend.

Inventory should reflect service relationships. Multiple sites may share a host, a deployment account or database infrastructure. That does not prove they are all compromised, but it helps define the scope of assessment when one site loses trust. The response team should not discover those dependencies only after rebuilding the most visible homepage.

## 13. Temporary containment needs an exact claim

Original containment planning should identify the path the control actually blocks. Taking a vulnerable application out of service at the serving layer is different from hiding a menu link or disabling one visible feature. A temporary measure must be tested against the intended exposure model without using a production exploitation attempt as a shortcut.

An application firewall can provide useful protection when its rule and deployment scope are well understood. It should not be described as proof that every possible attack route is covered. The team needs to know whether all relevant traffic passes through that control and whether the origin remains reachable by another route.

Temporary controls need an exit condition. If the plan says protected until patched, someone must own the transition to a supported corrected build and the verification afterward. Otherwise an emergency measure can become an undocumented permanent dependency, with nobody monitoring whether later infrastructure changes bypass it.

## 14. Evidence preservation and containment compete for time

Drupal's recovery guide recommends preserving a forensic copy and considering whether to recover, rebuild or retire the service. [9] An original response plan should make the timing decision explicit: continued exposure can cause harm, while hasty destructive cleanup can erase evidence needed to understand what happened.

The right balance depends on the case. A site actively serving malicious content may need immediate containment. An isolated host may allow additional preservation before rebuilding. The decision record should identify what was preserved, what was lost and why the chosen sequence was reasonable under the circumstances.

Preservation should include context, not just a directory of files. Relevant logs, deployment records and infrastructure configuration can explain how the service was reached and what authority it had. Access to that material should remain restricted to the response purpose. A case study should not turn live credentials, private customer records or collected personal data into demonstration material.

## 15. A backup is a recovery input, not proof of cleanliness

The original recovery model asks when the backup was made and what evidence supports treating it as a trustworthy baseline. A recent backup may already contain an unauthorized change. A much older backup may remove the intrusion but also discard legitimate business activity. The team needs to evaluate both integrity and operational consequences.

Rebuilding from known-good code can reduce uncertainty about application files, but content and database restoration still need review. Blindly importing every old configuration or uploaded file can reintroduce the state the rebuild was intended to remove. Recovery should preserve necessary business information without assuming every component of the old service deserves trust.

Testing should establish that the reconstructed service performs its intended functions and uses corrected maintained software. The site should not be returned to normal exposure merely because its homepage loads. Authentication, publishing and relevant integrations need their own checks, with a record of what remains unverified and who accepts that remaining risk.

## 16. Shared hosting changes the scope of trust

Drupal's recovery guidance discusses the possibility that control of one site can affect other sites or services on the same host or network. [9] The original investigation framework therefore maps actual shared permissions and credentials instead of assuming either perfect isolation or universal compromise.

Two sites on the same physical infrastructure may have strong separation, while sites on different servers may share a high-privilege deployment credential. The relationship that matters is the authority an attacker could reach through the compromised context. That requires environment-specific evidence rather than a simplistic count of hostnames.

The response team should involve the hosting owner when relevant, preserve responsibility boundaries and document what each party verified. A provider's statement that its platform is patched does not necessarily cover the customer's application files or stolen application secrets. Conversely, a customer patch does not establish that the underlying host remained trustworthy.

## 17. Credential recovery follows the exposure model

The following is original defensive analysis, not a claim about a particular 2018 victim. A compromised application may have had access to database credentials, service tokens or other secrets needed for normal operation. Credential response should follow what the execution context could access and what the evidence indicates, with priority given to credentials that could maintain access after rebuilding.

Replacing a secret while leaving the attacker in control of the system that receives it can undermine the replacement. Recovery sequencing should therefore establish a trustworthy place to store and use the new credential. The team should also identify dependent services so the change does not silently break essential functions.

This does not mean publishing secrets in an incident spreadsheet. The response record should identify the credential class, owner and rotation status without copying sensitive values into broadly shared notes. Access and retention should match the investigation's purpose. Good documentation makes the action auditable without creating a new exposure.

## 18. Detection should connect signals to conclusions

An original detection model distinguishes a suspicious request, evidence of code execution and evidence of a subsequent action. A request resembling a published exploit may have failed, reached a corrected site or targeted a non-Drupal service. It should trigger the appropriate review without automatically becoming a confirmed-compromise count.

Likewise, a clean search for a few known filenames cannot establish that no unauthorized change exists. Published indicators describe observed activity and can become incomplete as attackers vary their methods. Baselines, deployment history and process or network evidence can help answer different parts of the investigation.

The final assessment should state the strongest supported conclusion and its limits. No evidence found within retained logs is different from no attack occurred. That distinction is especially important when retention is short or the application could alter its own local records. Confidence should reflect the visibility available, not the team's desire to close the incident.

## 19. Emergency updates need a durable release process

The original release-management lesson is to reduce the distance between receiving an advisory and safely changing production. A repeatable build, known configuration and tested rollback make urgent updates less dependent on one person's memory. The organization should know how a direct emergency patch will later be reconciled with the normal maintained release.

That reconciliation matters because an undocumented hotfix can disappear in a later deployment. A team may correctly patch the current host while leaving the source artifact or reusable image vulnerable. The next routine release can then recreate the original exposure without anyone intentionally reversing the security change.

Closure should therefore cover both the active service and the mechanism that reproduces it. Verify the corrected artifact in the deployment system, remove obsolete vulnerable baselines from normal use and document any temporary exception. This is original process guidance derived from the case's distinction between visible version text, direct patches and actual deployed state.

## 20. Unsupported branches require a migration decision

The exceptional historical releases reduced immediate barriers to correction, but they did not transform older branches into indefinitely maintained platforms. [1][2] An original governance process should separate emergency stabilization from the longer task of moving to a supported release.

A migration decision needs a service owner, budget and deadline that reflect the actual dependency. Custom modules or an old integration may complicate the work, but leaving the reason unnamed does not reduce the risk. The organization should evaluate whether the service should be upgraded, replaced or retired rather than accumulating permanent emergency exceptions.

Retirement can be a legitimate security improvement when a site no longer serves a necessary purpose. It should preserve required records and ownership decisions, not simply delete a service in frustration. The important point is that support status becomes an explicit business decision instead of an accidental property of a forgotten server.

## 21. Fictional exercise: Rivermark Public Archives

Rivermark Public Archives is fictional. It operates a public research portal, an old event microsite and an internal editorial staging copy. The exercise uses a reconstructed 2018 decision environment with invented staff and systems. It is not an allegation about a real organization.

The team receives a March correction notice, followed later by an April automated-attack warning. The main portal reports an updated version, but the deployment record is incomplete. The microsite shows an old version string, while its contractor says a direct patch was applied. The staging site shares a service credential with production.

Participants must build a site-by-issue evidence matrix. They should separate correction status from trust status, identify the records needed to validate each claim and define a containment plan for unresolved exposure. Success requires justified decisions, not immediate certainty. The exercise contains no exploit request or instruction to compromise a test host.

## 22. Exercise injects and expected decisions

The first inject reveals that a firewall rule covers the main hostname but not an alternate route to the origin. Participants should reassess the containment claim and identify the owner who can close the exposure. The second introduces a successful-looking patch with no approved deployment event, requiring provenance review rather than instant reassurance.

A third inject supplies the distinct April follow-up and its prerequisite on the earlier fix. Participants must avoid treating one completed task as coverage for both identifiers. The fourth presents a recent backup that may fall inside the uncertain compromise window. The recovery team should explain what additional evidence it needs or why a rebuild is the more defensible option.

Evaluation should reward careful scope, traceable assumptions and privacy-conscious evidence handling. Teams should be able to explain what they know, what they infer and what remains unknown. A strong final briefing also identifies who owns the remaining migration or retirement work after the immediate service returns.

## 23. Metrics and final lessons

Original program metrics should separate sites inventoried, sites assessed, sites corrected and services recovered to a trusted state. Report unresolved assets explicitly. Measure time to contain exposure separately from time to finish an investigation, because those tasks serve different purposes and can proceed at different speeds.

Review a sample of closure records for reproducibility. Could another administrator identify the artifact, the active deployment and the evidence supporting the trust conclusion? Did the record preserve an emergency direct patch and its later reconciliation? Did a related advisory reopen the appropriate tasks? These checks reveal whether the process can survive personnel changes.

Drupalgeddon2 demonstrates that a security update is one necessary part of a larger response. The engineering failure concerned a trust boundary in request processing. The operational challenge concerned the trustworthiness of a service after exposure. Careful research keeps those problems connected without collapsing them into a single version number or an unsupported claim that every vulnerable website suffered the same outcome.

## Sources and reading scope

[1] Drupal Security Team, SA-CORE-2018-002, 28 March 2018; current page notes patch-link edits in February 2020. Issue identity, branch-specific historical corrections and supported-scope caveats. https://www.drupal.org/sa-core-2018-002

[2] Drupal Security Team, PSA-2018-001, 21 March 2018, with dated subsequent additions. Advance notice, release window and exceptional branch update plan. https://www.drupal.org/psa-2018-001

[3] Drupal Security Team, PSA-2018-002, 13 April 2018. Automated-attempt warning and the distinction between patching and recovery. Selected passages only. https://www.drupal.org/psa-2018-002

[4] Eyal Shalev, Rotem Reiss and Eran Vaknin, Check Point Research, Uncovering Drupalgeddon 2, 12 April 2018. Conceptual trust-boundary discussion reviewed; operational demonstration is not reproduced or executed. https://research.checkpoint.com/2018/uncovering-drupalgeddon-2/

[5] Drupal Security Team, SA-CORE-2018-004, 25 April 2018. Distinct CVE-2018-7602, corrected branches and prerequisite on the earlier fix. Current page includes an updated exploitation statement. https://www.drupal.org/sa-core-2018-004

[6] Drupal Security Team, PSA-2018-003, 23 April 2018. Advance notice of the separate 25 April follow-up release. https://www.drupal.org/psa-2018-003

[7] Matthew Meltzer and Steven Adair, Volexity, Drupalgeddon 2: Profiting from Mass Exploitation, 16 April 2018. First-hand monitoring scope and payload categories. Exploit requests, scripts and live infrastructure are not reproduced or tested. https://www.volexity.com/blog/2018/04/16/drupalgeddon-2-profiting-from-mass-exploitation/

[8] Drupal Security Team response to recent news articles relating to SA-CORE-2018-002 and SA-CORE-2018-004, 7 June 2018. Search-indexed primary-source excerpt reviewed; repeated direct page retrieval returned 503. Limited to the stated objection to CHANGELOG.txt-based conclusions. https://groups.drupal.org/node/520149

[9] Drupal documentation, Your Drupal site got hacked. Now what?, page last updated 4 April 2018. Selected preservation, rebuilding and shared-host assessment guidance. Historical commands and legal assertions are not adopted as current operational or legal advice. https://www.drupal.org/node/2365547
