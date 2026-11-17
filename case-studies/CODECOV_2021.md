# Codecov 2021: When the Build Helper Became a Credential Boundary

*A TeamStarWolf case study. Published 15 November 2026.*

[All case studies](/case-studies/README.md) · Related: [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md), [DevSecOps Reference](/DEVSECOPS_REFERENCE.md), [Secrets Management Reference](/SECRETS_MANAGEMENT_REFERENCE.md), [Data Security Reference](/DATA_SECURITY_REFERENCE.md), [CCleaner 2017](/case-studies/CCLEANER_2017.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

CI/CD and release-engineering security owners, incident responders, secrets and credential owners, and downstream consumers of build tooling

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 19 min (4,286 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You want an evidence-bounded account of the 2021 Codecov Bash Uploader compromise, you need to separate execution from exposure from credential use from repository access, or you are reviewing build-step authority, secret minimization and credential rotation

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Executive summary](#executive-summary), [3. Original analysis: the authority inherited by a build step](#_3-original-analysis-the-authority-inherited-by-a-build-step), [4. An investigation model that does not overclaim](#_4-an-investigation-model-that-does-not-overclaim)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md), [DevSecOps Reference](/DEVSECOPS_REFERENCE.md), [Secrets Management Reference](/SECRETS_MANAGEMENT_REFERENCE.md), [Data Security Reference](/DATA_SECURITY_REFERENCE.md), [CCleaner 2017](/case-studies/CCLEANER_2017.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

Key takeaways (reviewed 2026-11-17):

- Codecov is a case of inherited authority: a narrow coverage-upload step sat in an environment with authority far beyond uploading a report. ([Executive summary](#executive-summary))
- Unauthorized uploader changes ran from 31 January to 1 April 2021, across 108 affected windows rather than one continuous interval. ([Executive summary](#executive-summary))
- The cause was an HMAC key recoverable from an intermediate layer of Codecov's public Docker image, used to alter the stored uploader. ([Executive summary](#executive-summary))
- A customer detected an unexpected SHA256 mismatch and reported it on 1 April, surfacing the compromise. ([Executive summary](#executive-summary))

<!-- meta:end -->

## Executive summary

This case study examines the 2021 Codecov Bash Uploader compromise as a problem of inherited authority. A coverage-upload step had an apparently narrow business purpose, but the environment around that step could contain authority far beyond uploading a report. The central question is not merely whether a downloaded script was authentic. It is what that script could reach once the build system chose to execute it.

Codecov's published update identifies January 31 through April 1, 2021 as the period containing unauthorized uploader changes, with 108 affected windows rather than one continuous interval. Its April 15 disclosure described possible export of CI environment information and repository remote information; an April 29 update provided additional impact information. Codecov did not conclusively identify the responsible actor in that notice. These are historical findings, not a claim that every customer, every pipeline, or every build was compromised [1].

The provider's root-cause report described an HMAC key recoverable from an intermediate layer of its public self-hosted Docker image. That key enabled alteration of the uploader stored in Google Cloud Storage. A customer detected an unexpected SHA256 mismatch and reported it on April 1. The affected execution path included the Bash Uploader and integrations using it. Codecov subsequently described credential rotation, image-build changes, distribution monitoring, and a replacement uploader with signature and checksum verification [2].

The downstream record is especially instructive. HashiCorp disclosed an exposed release-verification signing key, while distinguishing that exposure from evidence of malicious releases. Twilio and Rapid7 reported unauthorized repository access with different information consequences [3][4][5]. Those accounts cannot be combined into a universal impact statement. They can be used to develop a better response model: establish which code ran, identify what authority it inherited, investigate the use of that authority, and separately evaluate the data or artifacts reached.

This manuscript separates a bounded factual reconstruction from original defensive analysis. Its operational exercises are proposals for a hypothetical organization, not claims about controls absent at any named company. No exploit testing, customer-system access, or malware execution was performed.

## 1. Case orientation and evidence rules

| Field | Scope |
|---|---|
| Event | Codecov Bash Uploader supply-chain compromise |
| Principal period | January through May 2021 |
| Primary boundary | Third-party build code executing in a customer's CI environment |
| Downstream comparison | HashiCorp, Twilio, Rapid7 public incident accounts |
| Research stance | Provider statements are attributed, not treated as access to raw forensic records |
| Not established | Complete victim population, total financial loss, conclusive actor attribution, universal secret theft |

### 1.1 Four kinds of sentence

A historical fact in this study has a numbered source. A provider finding states what the provider reported about its investigation. An analytical interpretation explains why a boundary or distinction matters. A proposed practice describes what a defender could implement now after validating it against that defender's own systems. Mixing these categories creates a misleading impression that every recommendation was an observed failure in 2021.

This distinction also protects against hindsight. Once the outcome is known, it is easy to imagine that the suspicious behavior would have been obvious to every operator. A useful study asks what evidence was observable at a particular point, who owned it, and what decision could reasonably follow. A supplier may see distribution changes but not all downstream identity events. A customer may see an unusual repository clone but not the supplier's image-build history. Neither viewpoint is complete.

### 1.2 Why scope words matter

Potential exposure means an asset could have been available through the affected execution path. Observed transfer means evidence supports movement of information. Credential use means an identity was exercised. Repository access means an information container was reached. Malicious modification means content was changed without authorization. These are different states. A responsible investigator records them separately rather than compressing them into a single checkbox labeled compromised.

Likewise, no evidence is a description of the investigation's findings, not a mathematical proof that an event did not occur. Its strength depends on logging, retention, coverage, detection capability, and the exact question being asked. A well-written report can express a firm operational decision while preserving those limitations.

## 2. The bounded historical record

### 2.1 Timeline

| Date | Publicly documented development | Source |
|---|---|---|
| January 31, 2021 | Beginning of the reported period containing unauthorized uploader changes | [1] |
| April 1, 2021 | Customer checksum discrepancy reported; Codecov discovery and remediation | [2] |
| April 15, 2021 | Codecov public disclosure and affected-user notifications | [1] |
| April 22, 2021 | HashiCorp bulletin publication; Twilio later described GitHub notification that day | [3][4] |
| April 29, 2021 | Additional Codecov environment-variable and impact information | [1] |
| May 4, 2021 | Twilio public response account | [4] |
| May 13, 2021 | Rapid7 public response account | [5] |

The timeline deliberately does not invent a timestamp for initial credential extraction, each affected download, or each downstream access. It distinguishes supplier discovery from public disclosure and from a customer's later notification. For incident management, those timestamps answer different questions: when could exposure begin, when did containment occur, and when could a downstream team act with useful information?

### 2.2 HashiCorp: repairing a verification relationship

HashiCorp's HCSEC-2021-12 bulletin reported exposure of the GPG private key used to sign release hash files. It revoked the old key, introduced a new key, and validated and re-signed existing releases. Its account said the investigation had not found unauthorized use of that key. It explicitly separated this mechanism from macOS signing/notarization, Windows Authenticode, and Linux package signing, which were unaffected by that particular key exposure. The April 27 FAQ reported no evidence at that point of malicious changes to its code or binaries or disclosure of customer data [3].

The analytical lesson is that key replacement is also a consumer-coordination problem. A producer can stop using a key before every downstream verifier has updated its trusted configuration. A secure response must preserve both integrity and usability. Otherwise a signature failure can tempt a hurried operator to disable verification, turning a recovery action into a new risk. This is a general consequence of distributed trust, not evidence that HashiCorp customers actually disabled checks.

### 2.3 Twilio: moving from secrets to repository contents

Twilio's May 4 account described limited uploader use and an April 22 GitHub notification involving an exposed user token. GitHub identified repositories cloned before Codecov's notification. Twilio then examined their contents, identifying a small number of customer email addresses. It reported no indication that repositories were modified and no evidence of other customer information being accessed at that time. Its response included rotating potentially exposed credentials and secrets found in possibly exposed repositories [4].

The analytical point is the change in investigative object. A token inventory answers which authority might escape. A repository-content review answers what information might be reached with that authority. Completing the first review does not complete the second. Even a repository considered internal tooling can contain samples, configuration history, support artifacts, or other information requiring a separate assessment.

### 2.4 Rapid7: internal tooling still carries information value

Rapid7 reported use on one CI server building and testing internal MDR tooling, not product-code CI servers. It said unauthorized access reached a small subset of internal-tooling repositories containing internal credentials and alert-related data for a subset of MDR customers. It reported credential rotation, no unauthorized repository changes, and no access to other corporate systems or production environments. Its account also said it found no evidence of access to its Insight platform or products or customer data stored in or sent through them [5].

The analytical lesson is not that all internal tools are production systems. It is that the label internal is not a data classification. A low-visibility engineering repository can still carry operational context. The response boundary should follow information and permission relationships rather than relying solely on a system's position in the product release pipeline.

## 3. Original analysis: the authority inherited by a build step

The remainder develops a defensive model from the evidence above. It does not reconstruct undisclosed victim networks or claim a verified sequence beyond the public accounts.

### 3.1 Business purpose is narrower than process authority

A coverage tool's intended output is a measurement artifact. The operating system does not infer that purpose and automatically restrict the process to it. Actual authority comes from files, environment, credentials, network access, service permissions, and execution context. If a process can read a credential, describing the process as reporting-only does not make the credential inaccessible.

This creates an important review question: what is the minimum authority required to perform the coverage-upload task, and what authority is present merely because it is convenient to reuse a broad build job? A narrow role description is not an enforcement boundary. A separate worker, identity, filesystem view, and egress policy can create boundaries, but each has to be tested rather than assumed.

### 3.2 Three inventories, not one

A dependency inventory says which tools a project uses. An execution inventory says which bytes actually ran in which job. An authority inventory says what those bytes could access at that moment. The inventories overlap, but none is a substitute for the others.

A dependency declaration may point to a wrapper that fetches another script at runtime. A job record may preserve the wrapper's version without preserving the fetched content. An identity inventory may describe a token's default role while missing temporary elevated access. The practical objective is therefore a joined record: job identity, source revision, resolved tool identity, runner identity, accessible credential identifiers, and relevant policy versions. Record identifiers and metadata, not secret values.

### 3.3 Distribution and execution need independent controls

A supplier-side protection aims to prevent unauthorized content changes. A consumer-side protection aims to reject unexpected content before execution. Isolation limits the consequence if prevention and verification both fail. Logging helps determine what happened after the fact. These controls solve different problems and should not be scored as duplicates.

A checksum only establishes agreement with the expected digest supplied to the verifier. If the same compromised trust path can replace both artifact and expected digest, the check may still pass. A signature shifts trust to a signing identity and its protection, not to magic safety in the artifact. A pinned artifact can reduce unexpected movement but can also preserve a vulnerable version indefinitely if update review is neglected. Each control needs an owner, a trust source, a failure mode, and a renewal process.

### 3.4 Secret minimization is a containment decision

Consider a hypothetical pipeline with test, coverage, package, and release stages. A broad credential injected into the entire pipeline simplifies configuration but exposes that credential to more code paths. Narrowly supplying it only to a separate release stage reduces reachable authority. A short-lived credential limits how long a copied value may work, but does not prevent abuse during its validity. An audience restriction limits where it can be used, but not necessarily what an authorized audience will permit.

No single adjective, including ephemeral or least-privilege, proves containment. The test is concrete: can a coverage worker authenticate to the release service, read another project's repository, mint new credentials, or alter a verifier's configuration? The answer must come from evaluated policy and controlled tests, not from the job's name.

## 4. An investigation model that does not overclaim

### 4.1 Build an exposure ledger

Create one row per potentially affected execution, or a defensible group of executions with identical relevant properties. Record the repository, job, time range, integration path, artifact evidence, accessible credential identifiers, runner type, network evidence, and confidence. Do not record live credentials in the incident spreadsheet. Link to protected evidence and note who can retrieve it.

Each row should distinguish confirmed affected execution, plausible exposure, ruled-out execution, and insufficient records. A lack of retained artifact bytes should not silently become ruled out. A present-day workflow definition should not automatically be treated as the historical definition. Include changes in inherited templates and organization-level settings because those may affect many repositories without appearing in each local file.

### 4.2 Follow authority into each downstream system

For every credential identifier in scope, identify the issuer, authorized resources, permitted actions, expiration, revocation mechanism, and audit owner. Then search the relevant authorized audit records for use during the exposure and response periods. Decide in advance what counts as suspicious, such as use inconsistent with the normal job identity or resource scope. Preserve uncertainty when shared credentials make attribution difficult.

The investigation should also ask whether the exposed identity could create persistent alternatives: additional tokens, new deploy keys, changed access policies, or new automation. Revoking the original credential does not prove that all authority derived from it has ended. This is a hypothesis to investigate in an affected environment, not a claim that the 2021 actor performed every action listed here.

### 4.3 Evaluate information separately from access

If a repository was accessed, classify its contents and relevant history. Do not stop at the currently checked-out branch. Determine whether sensitive material existed in the reachable object history, supporting artifacts, release attachments, or configuration stores within the granted scope. Have an appropriate data owner review ambiguous business information; security personnel should not guess whether a sample contains real customer data.

Describe conclusions at the level evidence supports. For example: the available audit record confirms a clone operation; a review identifies customer contact information in the reachable repository; the exact files selected by the actor are not visible. This is more useful than saying either nothing happened or everything was stolen. The bounded description supports targeted containment, notification review, and honest follow-up.

### 4.4 Treat negative findings as coverage statements

A negative finding should identify the systems searched, time interval, record type, and relevant blind spots. If logs cover only part of the suspected period, report that. If the tool could not distinguish a legitimate build from a stolen shared token, say so. Incident leadership can still decide to rotate and rebuild without waiting for impossible certainty.

An evidence table should contain a confidence field and a reason field. High confidence can reflect preserved bytes and strong audit correlation. Moderate confidence may reflect configuration evidence without complete execution history. Low confidence may reflect missing logs or broad shared identities. Avoid assigning numerical probabilities unless a defensible method supports them.

## 5. Response workstream design

### 5.1 Containment without evidence destruction

A proposed response begins by pausing the untrusted execution path or removing its access to meaningful authority, while preserving available job records, cached artifacts, and configuration history. The exact order depends on ongoing risk. If a credential is actively being abused, containment takes priority over a perfect collection plan. Record that tradeoff explicitly.

Do not rerun suspect production jobs merely to observe their behavior. Do not print all environment values into a shared log in order to inventory secrets. Prefer configuration metadata, secret-store identifiers, and controlled examination by authorized responders. If execution is necessary for analysis, use an isolated environment with synthetic credentials and no production connectivity.

### 5.2 Rotation as a dependency graph

A rotation list is not enough. For each credential, identify every legitimate consumer, replacement method, validation test, and rollback constraint. A service can issue a new credential while the old one remains active. A pipeline can begin using the new credential while a forgotten scheduled job still relies on the old one. A successful health check can coexist with continued unauthorized access through an unrevoked identity.

A robust completion record therefore includes issuance, consumer migration, old-credential revocation, denial validation, downstream-access review, and ownership. Prioritize credentials by reachable impact and current evidence of abuse, not by alphabetical order. Keep recovery access separate from suspect build infrastructure, and verify that replacement credentials are not immediately injected into the same untrusted path.

### 5.3 Release integrity is a separate track

Where signing or publishing authority could be exposed, inventory artifacts released during the relevant interval. Establish a trusted basis for comparison, investigate signing and publication events, and decide whether rebuilding, re-signing, revoking, or withdrawing artifacts is justified. Those decisions have different consequences and should not be collapsed into regenerate everything without a plan.

A release verifier needs clear instructions about expected trust changes. Communicate the relevant product, signature mechanism, transition timing, and verification behavior. Preserve a secure failure mode. Do not advise users to bypass validation simply because a new trust anchor creates friction. The recovery objective is restored justified trust, not merely an installation command that stops reporting errors.

### 5.4 Communications should track the evidence state

Use a stable incident page or controlled customer channel with dated updates. Separate what is confirmed, what is still being investigated, what action is required, and what will trigger a further update. Avoid saying all clear while a major scope question remains unresolved. Equally, avoid assigning harm to every customer just because the affected dependency appears somewhere in the organization.

Prepare customer-specific information carefully. A generic notice may establish awareness but still leave the recipient unable to act. Useful details can include relevant repository identifiers, time intervals, and credential categories without exposing the credentials themselves. Have appropriate privacy and legal specialists assess notification requirements; this study is not jurisdiction-specific legal advice.

## 6. A proposed control acceptance matrix

| Control objective | Acceptance evidence | Failure it does not eliminate |
|---|---|---|
| Know executed content | Resolved artifact digest retained per job | Trusted artifact may itself be malicious |
| Validate before execution | Controlled mismatch test stops the job | Compromised signing authority |
| Isolate reporting tasks | Test identity cannot reach release resources | Abuse of legitimate reporting permission |
| Minimize credentials | Documented necessity and constrained scope | Abuse during valid lifetime |
| Monitor distribution | Authorized change produces timely alert | Downstream misuse of already copied secrets |
| Investigate identity use | Correlated issuer and resource audit records | Missing historic logs |
| Revoke completely | Old identity denied; derived access reviewed | Data already copied |
| Recover safely | Clean execution path and integrity evidence | Every future supplier compromise |

The matrix is an original assessment aid. It is not a maturity score for Codecov or the downstream organizations. A team should tailor each test to its actual architecture and document exceptions with accountable owners. Tests must use authorized environments and synthetic secrets.

### 6.1 Metrics that describe risk reduction

Track the proportion of high-impact jobs with resolved executable identities, the proportion of external-tool steps without unrelated production authority, the time needed to identify affected consumers of a credential, and the time from revocation decision to validated denial. These measurements make gaps operationally visible.

Avoid a dashboard that celebrates only numbers of rotated secrets or completed tickets. A large count may indicate activity without proving that the highest-impact credential was handled. Pair throughput metrics with a small set of critical assertions: every affected release identity has an owner; no replacement secret enters an untrusted worker; all remaining unknown-scope rows have a decision and review date.

## 7. Ninety-minute tabletop: the coverage job that knows too much

This is a fictional exercise for an authorized internal team. No part of the scenario describes an undisclosed real customer.

### Minutes 0-15: ambiguous supplier notice

The facilitator provides a notice that a build helper was intermittently altered during the previous month. Several teams say they do not use the helper, but a shared workflow template references a wrapper around it. Ask the participants to produce an initial inventory method and identify the owner of inherited configuration. The deliverable is a scope hypothesis with confidence labels, not a false complete list.

Discuss which jobs can be paused, which business functions depend on them, and what temporary alternative preserves the core service without granting new broad access. Record who has authority to make that tradeoff. If the team cannot identify an owner, treat that as an exercise finding rather than having the facilitator invent one.

### Minutes 15-30: missing execution evidence

The next inject states that workflow files are retained, but downloaded helper bytes are not. One team wants to treat all successful builds as safe because tests passed. Another wants to rebuild every artifact immediately. Require participants to distinguish test success, artifact identity, and release integrity. They must propose a prioritized evidence collection and containment plan.

Ask what would increase confidence and what cannot be recovered. A strong answer does not pretend current configuration proves past behavior. It identifies available job logs, caches, dependency resolution records, supplier information, and downstream identity records, while acknowledging that some rows may remain uncertain.

### Minutes 30-45: a broad token appears

A shared repository token was accessible to one affected job. Its owner is unclear. Participants must determine the issuer, resources, consumers, revocation path, and business consequence of immediate revocation. Add a simulated audit event showing access outside the expected job schedule. The team must avoid treating the event as conclusive attacker attribution without additional correlation.

The exercise output is a rotation dependency map and a downstream investigation task list. Credit the team for protecting replacement credentials and considering derived access. Deduct confidence if the only plan is to change the value in a configuration file while leaving the original credential valid.

### Minutes 45-65: repository contents change the stakes

The facilitator reveals that an accessed repository contains historical support fixtures. Data owners cannot immediately tell whether they are synthetic. The team must assign a content review, preserve the relevant history, and prepare a bounded internal statement. The correct outcome is neither automatic public notification nor automatic dismissal.

Ask the communications lead to write three sentences: what is confirmed, what remains unknown, and what the organization is doing next. The statement should avoid promising that rotation erases copied information. It should also avoid claiming that every customer was affected without evidence.

### Minutes 65-80: verification starts failing

A hypothetical release-verification key is rotated, and one downstream consumer requests permission to skip signature verification to meet a deadline. Participants must propose a secure transition path and an escalation decision. This inject tests whether recovery procedures protect the trust relationship under operational pressure.

Require a written restart gate. It should include trusted execution, validated identity changes, integrity assessment, and known residual uncertainties. A business sponsor may accept a defined residual risk; the technical record must still state what has and has not been demonstrated.

### Minutes 80-90: close the exercise

Each owner produces one concrete improvement with a deadline and acceptance test. The facilitator separates urgent configuration work from longer-term architectural changes. The final record includes unresolved questions, not just successes. Schedule a small follow-up test proving that the chosen improvements work in practice.

## 8. A staged improvement plan

### First thirty days: make authority visible

Inventory externally obtained code executed in high-impact pipelines. Identify credentials and permissions reachable from each stage. Remove clearly unnecessary authority, assign owners to unknown credentials, and document how to stop suspect integrations. Preserve current evidence needed for a future investigation without collecting secret values into ordinary telemetry.

Pilot the acceptance matrix on one representative pipeline. The pilot should include a negative test proving that the reporting step cannot access a release resource. Choose a workflow that reflects normal organizational complexity rather than a specially simplified demonstration. Record any gap between documented policy and observed behavior.

### Days thirty-one through sixty: create enforceable separation

Move high-impact signing and publication decisions behind narrow, separately controlled boundaries. Evaluate short-lived identities and resource restrictions where the platform supports them. Add verification and artifact-identity recording at the point of execution. Define controlled update procedures so that pinning does not become indefinite neglect.

Exercise emergency rotation with synthetic credentials and a small set of representative consumers. Measure how quickly owners can identify dependencies, migrate safely, revoke, and verify denial. The goal is not a flawless rehearsal. It is discovering hidden consumers before a real adversary forces the schedule.

### Days sixty-one through ninety: prove recovery and communication

Run the tabletop, test the restart gate, and review supplier incident information requirements. Confirm that customer-facing teams can translate technical scope into useful action without overclaiming. Review the retention period of each evidence source against the realistic time needed to discover a supplier incident.

Finish with an independent challenge: ask a reviewer who did not design the pipeline to explain what an untrusted reporting tool could do. If the answer depends on tribal knowledge, the documentation is insufficient. If the answer contradicts a controlled test, the control is insufficient. Both findings are valuable and should remain visible until resolved.

## 9. Editorial guardrails and open questions

This study does not assign a named threat actor, assert that all Codecov users were affected, or equate an exposed signing key with a malicious release. It does not claim a complete count of stolen secrets or affected organizations. It does not treat a provider's absence-of-evidence statement as independent forensic certification.

Further research could add preserved contemporary advisory revisions, additional affected-organization disclosures, and a deeper comparison of historical CI integration behavior. Such expansion should preserve the same distinctions between execution, exposure, use, access, and modification. It should not inflate length by repeating the same facts under new headings.

The durable finding is a boundary problem: the authority granted to an automated helper may exceed its stated purpose. Prevention matters, but a mature response also needs evidence about what actually ran and a credible method to repair every trust relationship that may have been reached. A patched helper is one repaired component. A recovered build system is a set of tested claims.

## Sources

[1] Codecov, Bash Uploader Security Update, April 15, 2021, with April 29 update. https://about.codecov.io/security-update/

[2] Codecov, Post-Mortem / Root Cause Analysis (April 2021). https://about.codecov.io/apr-2021-post-mortem/

[3] HashiCorp, HCSEC-2021-12: Codecov Security Event and HashiCorp GPG Key Exposure, April 22, 2021; FAQ April 27. https://discuss.hashicorp.com/t/hcsec-2021-12-codecov-security-event-and-hashicorp-gpg-key-exposure/23512

[4] Twilio, Twilio's Response to the Recent Codecov Vulnerability, May 4, 2021. https://www.twilio.com/en-us/blog/company/communications/response-to-the-codecov-vulnerability

[5] Rapid7, Rapid7's Response to Codecov Incident, May 13, 2021. https://www.rapid7.com/blog/post/2021/05/13/rapid7s-response-to-codecov-incident/

All five primary provider accounts were read on November 15, 2026. Historical summaries are deliberately bounded. Sections 3 through 8 are original analytical and educational material, not additional evidence of what any named organization did.
