# ASUS ShadowHammer 2018-2019: Broad Distribution, Narrow Selection, Broken Release Trust

*A TeamStarWolf case study. Published 15 November 2026.*

[All case studies](/case-studies/README.md) · Related: [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md), [Endpoint Security Reference](/ENDPOINT_SECURITY_REFERENCE.md), [DevSecOps Reference](/DEVSECOPS_REFERENCE.md), [Incident Response Reference](/INCIDENT_RESPONSE_REFERENCE.md), [CCleaner 2017](/case-studies/CCLEANER_2017.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Software producers and consumers, release-engineering and endpoint owners, detection engineers and incident responders

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 20 min (4,634 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You want an evidence-bounded account of the 2018-2019 ASUS ShadowHammer compromise, you need to separate broad distribution from narrow selection or receipt from execution from follow-on activity, or you are reviewing release trust, code signing and selective-targeting triage

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Executive summary](#executive-summary), [3. Original analysis: a five-link release trust model](#_3-original-analysis-a-five-link-release-trust-model), [4. Broad reach and selective execution](#_4-broad-reach-and-selective-execution)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md), [Endpoint Security Reference](/ENDPOINT_SECURITY_REFERENCE.md), [DevSecOps Reference](/DEVSECOPS_REFERENCE.md), [Incident Response Reference](/INCIDENT_RESPONSE_REFERENCE.md), [CCleaner 2017](/case-studies/CCLEANER_2017.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## Executive summary

Operation ShadowHammer illustrates a difficult supply-chain problem: a widely distributed, apparently legitimate update can serve as a selective entry mechanism for a much smaller set of systems. The breadth of distribution and the narrowness of intended follow-on activity are not contradictory. They describe different parts of the same operation.

Kaspersky's March 25, 2019 disclosure placed the observed ASUS Live Update campaign between June and November 2018. It reported more than 57,000 affected users within its own telemetry, while explicitly saying that a worldwide count could not be calculated from that dataset. The report described modified installers distributed from official ASUS update infrastructure and signed with legitimate ASUS certificates. It also reported more than 600 distinct MAC addresses recovered from over 200 samples as targeting selectors. Those figures are not a verified count of successful second-stage infections [1].

The April technical report explained that analyzed samples compared hashes of local network-adapter MAC addresses against embedded tables. Some conditions used paired entries. Matching systems could be directed toward a subsequent download; nonmatching execution could leave a marker file. The researchers did not offer a definitive explanation of how the signing capability had been compromised, and they stated that the ultimate victims and the origin of the target identifiers remained unknown [2].

This case therefore requires at least three separate questions: did a system receive maliciously modified software, did that software execute, and did the system proceed to a further stage? A signature check, a version check, or a target-list lookup cannot independently answer all three. Recovery likewise has to distinguish repair of the distribution path from assessment of already exposed endpoints.

The core conclusion is not that software updates or code signing should be abandoned. Both remain important mechanisms. The lesson is that a release needs more than a recognizable publisher identity: it needs a defensible relationship among approved source, produced artifact, signing decision, published bytes, and observed endpoint behavior. This manuscript develops that relationship as an original defensive model rather than pretending the public record reveals every internal failure at ASUS.

## 1. Scope and evidence boundaries

| Field | Scope |
|---|---|
| Incident | ASUS Live Update supply-chain compromise known as ShadowHammer |
| Campaign and disclosure | Observed 2018 activity, publicly detailed in 2019 |
| Primary question | How should defenders handle signed, supplier-distributed software with selective malicious behavior? |
| Evidence | Original researcher accounts, contemporary response advisory, and maintained ASUS support guidance |
| Distinct from | Proof of firmware infection, compromise of every ASUS product, or complete victim attribution |
| Testing | No malware obtained or executed; no third-party endpoint scanned |

### 1.1 Evidence labels

Researcher observation refers to the samples or telemetry described by the named research team. Researcher interpretation refers to conclusions drawn from those observations, including relationships to other campaigns. Advisory guidance records what a response organization recommended at the time. Vendor guidance records the supplier's published instructions, including later maintenance changes. Original analysis is this manuscript's own reasoning about defense, investigation, and recovery.

These labels prevent several misleading substitutions. An observed artifact is not the same as a complete incident timeline. A target identifier is not a named human victim. A similarity between malware samples is not automatically a proven identity for every operator involved. A historical update recommendation is not necessarily appropriate software-selection advice years later.

### 1.2 Why the word infected needs qualification

In ordinary discussion, infected can mean a malicious file was downloaded, a first-stage component ran, a later payload arrived, or persistent access was established. Those meanings differ materially. A team should state which condition its evidence supports instead of relying on the emotional force of the word.

This study uses exposure for a plausible delivery path, malicious-artifact receipt for evidence of the modified package, execution for evidence that its code ran, selector match for a condition matching the known targeting logic, and follow-on activity for evidence beyond that selection. These are analytical categories, not a claim that every affected organization preserved enough evidence to populate them.

## 2. What the surviving record establishes

### 2.1 A compact timeline

| Date or period | Record | Evidence boundary |
|---|---|---|
| June-November 2018 | Campaign period reported in initial research | Observed interval, not a complete history of supplier access [1] |
| January 2019 | Discovery described by Kaspersky | Research discovery, not the first malicious execution [1] |
| March 25, 2019 | Initial public research | Early scope and targeting findings [1] |
| March 26-27, 2019 | CERT-EU advisory and revision | Contemporary response advice, including supplier fix information [3] |
| March 27, 2019 | ReversingLabs analysis | Additional sample investigation [4] |
| April 23, 2019 | Expanded technical publication | Sample behavior and remaining uncertainties [2] |
| December 2025 | End-of-support notice now shown by ASUS | Later product lifecycle information, not part of the 2019 response [6] |

### 2.2 Signed bytes were still malicious bytes

The published research reported valid signatures on modified installers, not merely a forged filename or a download from an unrelated imitation website [1][2]. That matters because a normal consumer might see several familiar signals together: the expected supplier, the expected update channel, and a signature associated with that supplier.

The analytical distinction is between identity assurance and release authorization. Signature validation can establish a relationship between bytes and a signing credential under the verifier's rules. It cannot independently establish that the organization's approved release process intended those bytes, that the source was reviewed, or that the code is harmless. Those additional claims need additional evidence.

### 2.3 Selectors narrowed behavior, not responsibility for investigation

The technical research reported differing embedded hash tables across samples and warned that the complete sample population might not be known. It also discussed a widely reused virtual-adapter identifier and paired conditions intended to make selection more specific [2]. A response based only on a single identifier can therefore be misleading.

A selector is a condition used by code. It is not necessarily a one-to-one map to a unique physical computer, much less a verified person or organization. It may reflect a combination of interfaces or a historical configuration that differs from the current one. A responder should preserve the exact known condition and the available historical inventory rather than reduce everything to a simplistic match-or-safe result.

### 2.4 Independent research broadened the sample view

ReversingLabs described starting from a published malicious installation package, using functional similarity to identify ten additional candidate samples, and examining extracted resources and debugging information. Its March 27 account presented this as continuing research, with further details still under investigation [4].

That contribution is useful because sample discovery is an iterative process. A dataset can expand through similarity analysis, shared metadata, or new submissions. The discovery method also has limits: related structure is a lead for examination, not automatic proof that every similar file is malicious or belongs to the same operation.

### 2.5 Response guidance had more than one scope

CERT-EU's March 2019 advisory distinguished broad possible delivery from narrow targeting and updated its guidance after ASUS released version 3.6.8 and a diagnostic tool. It recommended updating and described tools for checking known targeting information [3]. Huntress's contemporary response article separately discussed evidence of modified-updater execution and checking whether identifiers appeared in the known target set [5].

These were historical response resources. They should not be silently repurposed as a current instruction to install an old utility. The maintained ASUS FAQ now states that LiveUpdate support ended on December 4, 2025 and identifies 3.6.15 as the final version, while retaining older 3.6.8-or-later language. It also notes that newer laptops may use MyASUS instead [6]. This study records the lifecycle change so that readers do not confuse historical remediation with present-day product guidance.

## 3. Original analysis: a five-link release trust model

The remaining sections are original defensive analysis and proposed exercises. They are not findings that ASUS lacked every control described.

### 3.1 Source approval

The first link is the decision that a change belongs in a product. It may involve code review, dependency review, test evidence, and approval by an accountable owner. A signed artifact can still contain an unapproved change if the approval record is disconnected from what the build actually consumes.

A useful acceptance question is whether the organization can identify the approved source revision and inputs associated with a released binary. The answer should not depend only on a human remembering which branch looked correct. A release record should survive staff turnover and be retrievable during an incident when ordinary workflows may be suspended.

### 3.2 Build identity

The second link is the transformation from inputs into an artifact. A build environment has its own authority and dependencies. Generated files, packaging steps, toolchains, and externally obtained components can influence the result even when the main application source has not changed.

The defensive objective is not to claim that every build can be made perfectly reproducible overnight. It is to understand which inputs are controlled, which are variable, which are recorded, and which can be independently checked. A reproducibility claim should specify the scope of comparison rather than becoming a vague badge applied to the entire product.

### 3.3 Signing authorization

The third link is permission to apply a trusted signing identity. Strong protection of the key matters, but a key can remain technically protected while an authorized signing service is misused through a weak approval path. Conversely, a suspicious signature does not by itself reveal whether the key was copied, a signing host was compromised, or a legitimate service signed unauthorized content.

An investigation should preserve these hypotheses separately until evidence narrows them. A control review should ask who can request a signature, what artifact identity is presented, what policy is evaluated, and whether the request is bound to an approved release. The signer should not become a generic service that confers trust on whatever bytes arrive from a broadly privileged caller.

### 3.4 Publication integrity

The fourth link is the relationship between the approved signed artifact and the bytes distributed through the update channel. A publisher needs controls over storage, metadata, promotion between release stages, rollback packages, and administrative access. A customer needs a way to know which artifact was actually delivered.

Protecting transport is important, but it is not the same as ensuring that the content at the trusted endpoint was authorized. A secure connection can faithfully deliver an unauthorized artifact from a compromised distribution system. The question is not merely whether the connection was encrypted; it is whether the release identity remained intact across the publication path.

### 3.5 Endpoint execution and behavior

The fifth link is what happens after delivery. A release can arrive correctly and still behave in an unexpected way. Endpoint records should connect the downloaded artifact to the process that executed and to relevant subsequent actions, within the organization's privacy and retention constraints.

This final link also prevents a common investigative shortcut. Finding a cached package does not prove it ran, and finding a current clean version does not prove a prior malicious version never ran. A reliable response joins distribution, execution, and behavior evidence instead of choosing whichever single source is easiest to query.

## 4. Broad reach and selective execution

### 4.1 Why mass distribution can serve a narrow objective

A supplier channel can reach many endpoints without the adversary needing to contact each target individually. A local selection condition can then limit follow-on activity. From a defender's perspective, this means scale and selectivity must be measured separately.

An organization should avoid two opposite mistakes. The first is declaring every recipient a confirmed victim of the most severe possible payload. The second is dismissing the event because only a small subset appears to have been selected. Both mistakes erase the first-stage trust failure. Even a nonselected endpoint may provide important evidence about delivery, execution, or the campaign's distribution.

### 4.2 Quiet behavior can produce false reassurance

A test system may execute a modified package without showing the behavior that would occur on a selected system. A short observation window, an unrepresentative environment, or a missing external dependency can also limit what is visible. Absence of conspicuous behavior is therefore a bounded observation, not a universal clean bill.

This does not mean every quiet installer is suspicious. It means that behavioral testing should be combined with artifact review and provenance evidence. The test report should say what environment was used, which behaviors were observed, and which conditions were not evaluated. A negative result is most useful when its coverage is explicit.

### 4.3 Selector matching needs historical context

Hardware identifiers can change with adapter replacement, virtualization, docking, repairs, or configuration changes. A current inventory can help, but it may not fully describe the environment at the time of execution. Where available, use historical asset records, endpoint inventories, and relevant configuration snapshots.

Avoid treating a partial match as proof of full targeting. Conversely, do not treat a current mismatch as proof that the system never matched. The exact logic of the specific sample matters. If the sample is unavailable, record the uncertainty rather than substituting a generic rule from another variant.

### 4.4 Privacy still matters during fleet triage

A fleet investigation can collect hardware identifiers and associate them with users or locations. That information may be useful, but collection should be proportionate and access-controlled. A responder should not publish a detailed inventory or submit it to an external checker without considering authorization and the purpose of the transfer.

A safer organizational pattern is to compare authorized local inventory against a vetted indicator set within the organization's own investigation environment. If external assistance is needed, share the minimum necessary information with a verified recipient. This is a proposed privacy-preserving workflow, not a claim about how every 2019 diagnostic tool handled data.

## 5. An evidence ledger for supplier-update incidents

### 5.1 Separate the stages

| Stage | Useful evidence | What it does not prove alone |
|---|---|---|
| Product present | Software inventory | Receipt of a malicious release |
| Artifact received | Cache, download record, digest | Execution |
| Artifact executed | Process and installation records | Selector match or follow-on success |
| Selector condition met | Sample-specific logic and historical configuration | Successful payload retrieval |
| Follow-on request | Network and process correlation | Complete payload execution |
| Further activity | Endpoint and identity evidence | Full extent of data access or persistence |

The ledger should contain the time interval, evidence source, confidence, owner, and unresolved questions. Categories can overlap. Counts should state their denominator and should not be added as if they represented separate devices.

### 5.2 Preserve the actual artifact identity

A filename is a weak identity. Many legitimate packages use names such as setup.exe, and an installer can retain a familiar product version or appearance. Preserve cryptographic digests, signer information, timestamps, package metadata, and the acquisition source when safely available.

Do not use an old malicious sample as a test installer on an ordinary workstation. If specialist analysis is needed, preserve evidence under the organization's controlled malware-handling process. This manuscript does not provide a reproduction procedure or require obtaining malware to perform the management and architecture exercises.

### 5.3 Treat marker files as contextual evidence

A marker filename can be useful for triage, but a common-looking name is not a complete verdict. Validate its path, contents, timestamps, relationship to an execution event, and consistency with the relevant sample analysis. A file could be absent because it was deleted, never created under that condition, or outside the collection scope.

The inverse is also important. A file with the same name could have an unrelated origin. A good detection process records why the match is meaningful and what corroboration is needed. The result should be an investigation lead with confidence, not an automatic declaration of a particular second-stage compromise.

### 5.4 Explain missing records honestly

Months may pass between delivery and discovery. Logs may have expired, endpoints may have been rebuilt, and staff may have changed devices. A complete historical reconstruction may be impossible. The response should identify those gaps and make a risk decision rather than manufacture certainty.

For example, an endpoint might have evidence of a suspect package but no retained execution records. The organization can decide to rebuild it and review relevant credentials while recording that execution was not established. The remediation decision and the historical finding are related but need not have identical certainty thresholds.

## 6. Response: repair the supplier relationship and the endpoint separately

### 6.1 Contain the suspect release path

A proposed response first identifies which update channel, product, package, and interval are in scope. Restricting a known suspect path can be appropriate while investigation proceeds. A blanket prohibition on all updates indefinitely creates another security problem by leaving unrelated defects unaddressed.

Define a temporary alternative with an owner and an expiry condition. It might involve a vetted release path, staged deployment, or a specific hold on one component. The exact arrangement depends on the environment. The important point is that temporary containment should not quietly become permanent maintenance abandonment.

### 6.2 Assess the endpoint's reachable authority

If malicious code executed, ask what the process could access in that environment. Consider local data, credentials, sessions, network resources, and software-management privileges. Do not assume the worst possible authority without evidence, but do not limit investigation to the updater's intended business purpose.

The response should follow the actual execution context and observed activity. If evidence supports further access, extend the scope accordingly. If records are incomplete, document the rationale for precautionary actions. Avoid presenting a routine software update as proof that every consequence of earlier execution has been reversed.

### 6.3 Rebuild and credential decisions need sequencing

A clean rebuild can reduce uncertainty about an endpoint's current software state, but it does not revoke credentials already copied or undo access to external systems. Credential changes should be performed from a trusted environment and coordinated with the removal of the untrusted execution path.

Likewise, restoring a backup can reintroduce a suspect package or configuration if the restoration point is not evaluated. Recovery planning should identify the trusted source of operating-system and application media, the treatment of user data, and the validation performed before the device resumes normal access.

### 6.4 Validate the replacement trust path

A replacement package should be evaluated through a documented process rather than trusted merely because it is newer. Establish its source, artifact identity, relevant vendor guidance, and appropriate deployment testing. Where the supplier has changed signing or distribution mechanisms, confirm how the consumer should validate the new state.

The recovery gate should record what has been repaired: distribution, endpoint software, credentials, monitoring, or all of these. A statement such as remediation complete should have a defined meaning that a later reviewer can test.

## 7. Signing-system lessons without unsupported root-cause claims

### 7.1 Do not infer key theft from the signature alone

A valid signature on malicious content is strong evidence of a failure in the release trust relationship. It is not, by itself, a complete account of how that failure happened. Possible paths include misuse of signing services, compromise of a release workflow, or exposure of signing material. Those possibilities require evidence to distinguish.

The public technical report's uncertainty should remain visible. A case study becomes less accurate if it replaces unknown mechanism with a familiar explanation solely because the explanation sounds plausible. Defensive controls can address several hypotheses while the history remains unresolved.

### 7.2 Measure signing decisions, not only key storage

A key stored in specialized hardware may still sign unauthorized bytes if the service's authorization policy permits an attacker-controlled request. Strong key custody is valuable, but the release gate also needs to bind the request to an approved artifact and accountable process.

Proposed audit questions include: which identity requested signing, what digest was approved, which release record authorized it, what policy was evaluated, and where the signed result was published? A useful record supports investigation without exposing private keys or secrets. Audit retention should cover realistic discovery delays.

### 7.3 Revocation has operational consequences

Changing trust in a signing identity can affect legitimate software as well as malicious artifacts. A response plan should understand which products, versions, and verification paths depend on that identity. Consumers need clear guidance that distinguishes known malicious artifacts from legitimate artifacts affected by a trust transition.

This section does not assert a particular certificate-revocation timeline for ShadowHammer. It identifies a general recovery problem that follows from compromised release trust. A historical claim about revocation would require a dated primary record beyond the sources used here.

## 8. Fictional tabletop: the update is signed and the lab looks quiet

This original ninety-minute exercise uses synthetic packages, test accounts, and fictional organizations. It requires no live malware or unauthorized access.

### Minutes 0-15: conflicting scope numbers

The facilitator provides a supplier-update warning containing a large estimated distribution number and a smaller known target-selector count. Participants prepare an initial internal statement. They must explain the difference without declaring either that every endpoint suffered the same harm or that the event is irrelevant to nonselected devices.

The deliverable is a scope table listing product presence, possible delivery, known artifact receipt, execution evidence, and selector information. Each row needs an owner and confidence level. The facilitator should challenge any single-number dashboard that conceals these distinctions.

### Minutes 15-30: familiar signature, unfamiliar artifact

A test package has the expected publisher identity but does not match the organization's retained artifact record. Participants must determine whether the release was expected, how to validate its provenance, and whether to suspend deployment. They should not assume that either the signature or the mismatch alone resolves the incident.

Require a list of supplier questions: release identifier, approved digest, affected interval, signing scope, replacement guidance, and known limitations. The request should seek actionable evidence rather than a generic assurance that security is taken seriously.

### Minutes 30-45: the analysis system shows no follow-on behavior

A controlled test reports no conspicuous network activity. Another team proposes closing the incident. The facilitator reveals that the package may use environment-dependent selection. Participants explain what the negative test establishes and what remains outside its coverage.

The output is an evidence plan, not an attempt to make the package activate. The team should identify static-analysis needs, historical configuration records, and endpoint telemetry that could answer scope questions safely. No participant should reproduce the attack on production devices to obtain certainty.

### Minutes 45-60: inventory changed after the incident window

A device's current network adapters differ from its recorded configuration during the relevant month. Participants evaluate a target-list mismatch and decide how to label the result. A second device has a common marker filename but no corroborating process record.

The team must avoid both false reassurance and unsupported attribution. It should preserve the distinction between current configuration, historical evidence, and sample-specific conditions. The facilitator rewards a clear unresolved state with an action owner rather than an invented definitive answer.

### Minutes 60-75: replacement and business continuity

Operations needs to resume updates for an unrelated urgent security issue. The original suspect updater is still under review. Participants define a safe temporary update route, an approval process, and conditions for ending the hold. The objective is to contain the supplier incident without creating an indefinite patching gap.

Add a hypothetical endpoint-rebuild decision. Ask how backups, credentials, and administrative access will be handled, and what evidence will be retained before rebuilding. The plan should identify what rebuilding resolves and what external-access questions remain.

### Minutes 75-90: recovery claims and lessons

Participants write a recovery statement separating fixed distribution, assessed endpoints, completed credential actions, and unresolved historic scope. They then define three measurable improvements to the release trust model. Each improvement must have an acceptance test, not just a procurement request or a policy slogan.

Close by asking an independent reviewer to challenge the strongest claim in the statement. If the team cannot identify the evidence supporting that claim, revise it. A truthful bounded conclusion is preferable to a confident but untestable declaration that the fleet is clean.

## 9. A practical improvement roadmap

### First thirty days: inventory and evidence

Identify vendor updaters and their ownership across the fleet. Record which channels can execute privileged code, how artifacts are validated, and whether installed-package identity is retained. Prioritize systems with high-impact access or difficult recovery rather than assuming all endpoints have equal consequence.

Review retention gaps that would obstruct a delayed supplier-incident investigation. A modest retained artifact manifest can be more useful than a large volume of unstructured logs. Define the minimum evidence needed to connect a release to a device and an execution interval, with privacy safeguards and controlled access.

### Days thirty-one through sixty: controlled release intake

Pilot staged deployment and artifact identity checks for one important supplier channel. Review unexpected changes in package structure, signer, behavior, or privilege. The process should create an escalation route for anomalies without automatically blocking every legitimate update that differs from the previous version.

For software producers, test the signing authorization boundary with benign synthetic artifacts. Verify that an unauthorized request is rejected even when it reaches the signing service through a technically valid connection. Record the decision and ensure the test cannot accidentally enter a real distribution channel.

### Days sixty-one through ninety: recovery assurance

Rehearse supplier incident intake, endpoint scoping, and a clean restoration path. Validate the ability to distinguish receipt from execution and execution from follow-on activity. Test the communication process with a scenario in which historical logs are incomplete and a perfect answer is unavailable.

Review the temporary-update exception process. It should have an expiry date, an accountable owner, and a way to resume ordinary maintenance safely. Finish with a decision about remaining residual risks and a schedule for testing improvements again after significant architecture or supplier changes.

### Acceptance matrix

| Goal | Evidence to retain | Residual limitation |
|---|---|---|
| Know the delivered artifact | Digest, source, release identifier, device association | Delivery does not prove execution |
| Constrain signing | Approved artifact bound to signing decision | Approved source may still contain defects |
| Detect unexpected behavior | Correlated endpoint events and review | Selective behavior may remain unobserved |
| Interpret targeting accurately | Sample condition plus historical configuration | Unknown variants may exist |
| Recover endpoints | Trusted rebuild or validated remediation record | Previously copied data cannot be recalled |
| Maintain safe updates | Vetted temporary route and restart gate | Supplier assurance is never absolute |
| Communicate scope | Defined measures, date, confidence and limitations | Some historical uncertainty may remain |

## 10. Editorial conclusions

ShadowHammer is best understood as a failure of release trust combined with selective behavior. The public record supports the existence of maliciously modified, legitimately signed supplier-distributed installers. It does not support turning every possible recipient into a confirmed second-stage victim or assigning every unknown detail to a particular actor with certainty.

The distinction between widespread delivery and narrow selection is the case's most useful teaching point. Defenders need to investigate both. A narrow target list does not undo the distribution failure, and a broad distribution estimate does not establish identical harm on every endpoint.

A durable response protects the entire release relationship: approved inputs, controlled build, authorized signing, intact publication, and accountable execution. It also preserves a route for timely legitimate updates. The answer to a compromised update channel is not permanent distrust of all maintenance; it is a better-evidenced, more recoverable trust process.

## Sources

[1] Kaspersky GReAT, Operation ShadowHammer, March 25, 2019. Original disclosure and telemetry limitations. https://securelist.com/operation-shadowhammer/89992/

[2] Kaspersky GReAT, Operation ShadowHammer: a high-profile supply chain attack, April 23, 2019. Original technical analysis, selector logic, and unresolved questions. https://securelist.com/operation-shadowhammer-a-high-profile-supply-chain-attack/90380/

[3] CERT-EU, Security Advisory 2019-007, March 26, revised March 27, 2019. Contemporary response guidance drawing on research and supplier statements. https://cert.europa.eu/publications/security-advisories/2019-007/

[4] ReversingLabs, Forging the ShadowHammer, March 27, 2019. Original additional-sample analysis. https://www.reversinglabs.com/blog/forging-the-shadowhammer

[5] Huntress, Rapid Response: ASUS Live Update Attack (Operation ShadowHammer), contemporary response article. https://www.huntress.com/blog/faq-asus-liveupdate-attack-operation-shadowhammer-9fc9c03b2da9

[6] ASUS, How do I ensure that my device has the latest and safest version of ASUS Live Update?, maintained FAQ showing December 2025 support notice. https://www.asus.com/support/faq/1018727/

Sources reviewed November 15, 2026. The original 2019 ASUS press-release link now redirects to the pressroom; this manuscript does not claim to have recovered that original statement directly. Sections 3-9 are original analysis and proposed exercises, not additional forensic findings.
