# KRACK 2017: Wi-Fi Key Reinstallation and the Problem of Security State

*A TeamStarWolf case study. Published 15 November 2026.*

[All case studies](/case-studies/README.md) · Related: [Wireless Security Reference](/WIRELESS_SECURITY_REFERENCE.md), [Network Security Architecture](/NETWORK_SECURITY_ARCHITECTURE.md), [Cryptography Reference](/CRYPTOGRAPHY_REFERENCE.md), [Vulnerability Management Reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Network and wireless engineers, endpoint and vulnerability-management teams, detection engineers and incident responders

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 16 min (3,783 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You want an evidence-bounded account of the 2017 KRACK disclosure, you need to tell potential exposure from confirmed compromise or a router firmware change from endpoint remediation, or you are running a Wi-Fi patch program

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Executive assessment](#executive-assessment), [What the researchers demonstrated](#what-the-researchers-demonstrated), [Protocol engineering: retries must preserve invariants](#protocol-engineering-retries-must-preserve-invariants)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Wireless Security Reference](/WIRELESS_SECURITY_REFERENCE.md), [Network Security Architecture](/NETWORK_SECURITY_ARCHITECTURE.md), [Cryptography Reference](/CRYPTOGRAPHY_REFERENCE.md), [Vulnerability Management Reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## Executive assessment

KRACK belongs in a cyber case-study collection as a vulnerability-disclosure and engineering case, rather than as a documented mass breach. The public record examined here establishes a serious weakness and a coordinated response. It does not establish a named criminal campaign, a global victim count, stolen-data totals or a financial-loss estimate. Treating potential exposure as confirmed compromise would make the story more dramatic and less accurate.

The central defensive lesson is about state: a security system must remember what it has already done. An operation that is harmless during initial setup may become dangerous when repeated after communication has begun. Engineers therefore need to specify the consequences of duplicate, delayed and out-of-order events, rather than merely prove that participants can agree on a secret.

This study separates a short source-grounded historical record from original defensive analysis. It explains the impact boundaries without providing an exploitation sequence, radio configuration, attack code or instructions for intercepting another person's traffic. Recommendations concern authorized asset management, patch assurance, application protection and controlled validation. A fictional exercise at the end tests decisions rather than offensive technique.

The headline recommendation is a two-sided remediation process: account for wireless endpoints as well as infrastructure, verify the actual update installed, and keep unsupported equipment on an explicit exception register. A router firmware change alone should never become an unsupported declaration that every connected device is safe.

## Evidence boundary and research method

The sources include the original Vanhoef and Piessens research paper, the researcher's explanatory website, CERT/CC's coordinated vulnerability note, CERT-EU's advisory, Android's November 2017 bulletin and Cisco's contemporary implementation guidance. These are primary research, coordination or vendor records. The paper's abstract, introductory explanation and selected relevant passages were reviewed. This is not a claim to reproduce its complete experimental work or independently validate every affected implementation.

The historical pages remain useful evidence about what was disclosed and advised at the time. They are not a current supported-product catalogue. A device's present exposure requires its actual model, role, software build, relevant vendor notices and deployment configuration. No user equipment or live network was tested for this study.

A separate Apple security-content page was located in search, but direct retrieval returned a rate limit. It is deliberately excluded from the substantive evidence and final source register. That avoids implying a complete vendor review where access was incomplete. The six retained sources are sufficient to support the case's limited factual claims.

Sections labeled original analysis are recommendations drawn from the case, not claims that a particular organization adopted them. The fictional institution, its numbers and its decisions are invented for training. Research cutoff: 15 November 2026.

## What the researchers demonstrated

Mathy Vanhoef and Frank Piessens's 2017 paper describes key reinstallation: repeated installation of an existing key can reset associated nonce and replay state. The vulnerability concerns protocol handling rather than a mathematical break of AES. Outcomes depend on the handshake and confidentiality protocol. The paper distinguishes replay and decryption under AES-CCMP from the additional frame-forgery consequences under TKIP or GCMP. It also describes an especially severe all-zero-key behavior in affected Android 6.0 implementations. These are research findings under specified conditions, not evidence that every device had identical capabilities or consequences. [1]

Original analysis: a useful executive explanation needs three separate boxes. The first is agreement on key material. The second is the implementation's decision to install or reinstall that material. The third is the continuing state used to protect packets. Success in the first box does not automatically make the others safe. This separation is valuable beyond wireless networking because software often treats a completed setup operation as though repeating it has no consequences.

A nonce is a value whose required uniqueness helps a cryptographic construction work safely. It is not simply a second password that an administrator can make longer. A replay counter tracks freshness or ordering. Resetting state can violate assumptions even when the secret itself remains unknown to an observer. This conceptual distinction explains why security reviews must examine lifecycle operations, not only algorithm selection.

## Disclosure and public response

The researcher reports initial vendor notifications around 14 July 2017 and a broader CERT/CC notification on 28 August. Public disclosure occurred on 16 October. The research website explains that changing the Wi-Fi password does not address the flaw, that compatible implementation patches are possible, and that affected clients and access points need appropriate fixes. It also cautions that ordinary access-point fixes differ from special protections for unpatched clients. The researcher did not claim to know whether the weakness was being exploited in the wild. [2]

CERT/CC released VU#228519 on 16 October 2017 and revised it on 16 November. Its note groups ten CVE identifiers spanning four-way, group-key, fast-transition and other exchanges. The note requires wireless proximity to an affected access point and client, describes conditional confidentiality and integrity consequences, and recommends vendor updates. Its vendor list is explicitly non-exhaustive. CVE-2017-13082 identifies the fast-transition issue. [3]

CERT-EU issued advisory 2017-021 on 17 October. It explains the distinct roles of authentication and subsequent traffic-key establishment and recommends software or firmware updates across wireless devices as vendors provide them. This is a useful contemporaneous coordination record, not proof that all vendors released fixes on the same day. [4]

Original analysis: disclosure dates describe different events. Research completion, vendor notification, public explanation, code availability and installation on an organization's last device may be months apart. A timeline that ends at announcement misses the part defenders actually control: converting a published remedy into verified protection across their environment.

## Vendor evidence and its limits

Android's November 2017 bulletin was published on 6 November and updated on 8 November. It specifically places KRACK fixes under the 2017-11-06 security patch level, rather than treating every November patch date as equivalent. It also notes that partners may need chipset-manufacturer fixes. Its statement that it had no reports of active customer exploitation concerns the bulletin's newly reported issues at that time. It cannot establish that exploitation never happened anywhere or that every Android device promptly received an update. [5]

Cisco's 27 October 2017 guidance addresses particular wireless-controller deployments. It distinguishes client and infrastructure exposure and discusses temporary protections alongside rogue-device detection. It warns that reducing retransmission tolerance can disrupt slow clients or unreliable radio environments. Its scope does not cover every handshake variant. The introductory fast-transition CVE contains a typographical omission; this study uses CERT/CC's CVE-2017-13082. Cisco also distinguishes the affected session from retrospective decryption of arbitrary earlier traffic. [6]

Original analysis: these examples show why remediation evidence must be granular. A month label is weaker than a precise security patch level. A controller workaround is narrower than endpoint repair. A detection feature is not a guarantee that all attacks become visible. Even a useful vendor document may contain a typo that should be resolved against an authoritative coordination record rather than copied into every downstream article.

## Scope: proximity, implementation and protected applications

Original defensive analysis: describe an exposure as a set of conditions, not as a binary property of the word Wi-Fi. Relevant questions include the device's wireless role, which software implements that role, what features are enabled, and where the endpoint travels. A laptop that leaves the managed office has a different assurance boundary from equipment that remains on one controlled network.

Wireless proximity is not the same as having physical access to a locked server room. Conversely, it does not mean an arbitrary internet host can perform this radio-layer attack against any organization worldwide. Security teams should evaluate their actual premises, adjacent public areas and mobile-work patterns without publishing speculative distance guarantees. Radio environments differ, and a building's perimeter is not automatically the perimeter of its wireless exposure.

Application encryption is another boundary. Properly authenticated, correctly implemented end-to-end protection can preserve content confidentiality even when the local network becomes untrusted. That statement does not excuse incomplete wireless remediation. Some applications may use insecure transport, accept invalid certificates or expose traffic outside a protected tunnel. A good assessment distinguishes verified application controls from an assumption that all modern software must already be protected.

An observed rogue access point should trigger investigation rather than an immediate conclusion that sensitive records were stolen. Likewise, an absence of such alerts does not establish that no relevant activity occurred. The organization must understand sensor coverage, retention and alert logic before converting observations into claims about impact.

## Why password rotation is the wrong primary response

Original analysis: emergency password changes are attractive because they are visible and familiar. Employees can receive a new credential, administrators can count completed changes, and executives can see activity. But action counts are a poor substitute for a causal match between the weakness and the remedy.

A credential rotation project may still be justified by separate evidence of credential disclosure, ordinary lifecycle policy or another concurrent incident. The mistake is reporting it as remediation for a state-handling vulnerability. That confuses two independent security controls and leaves the uncorrected mechanism in place while consuming the same people needed to deploy actual fixes.

Incident communications should therefore state both the action and its purpose. A patch corrects a specific implementation behavior. An application control protects specified communications. A replacement removes an unsupported component. A password change addresses a credential risk. Mixing these categories makes later audit impossible because nobody can tell what assurance an action was intended to provide.

The same logic applies to changing a network name or hiding it. An administrative adjustment may meet a separate operational goal, but it needs a documented mechanism before it can be counted as protection against a published vulnerability. The burden of proof belongs with the claimed mitigation, not with the person questioning the reassuring dashboard.

## Inventory: the endpoint is part of the network

Original recommendation: build a remediation ledger that starts with devices and roles rather than departments. Each record should identify its owner, hardware model, operating system, wireless component when known, location or mobility pattern, support status, relevant advisory and evidence source. A record can explicitly say unknown. An honest unknown is more useful than an invented software version.

The inventory should include personally assigned laptops, shared terminals, phones, printers, conferencing equipment, scanners, embedded systems and devices supplied by contractors. Ownership boundaries can conceal operational dependencies: the network team may see the association, while another department controls the update process. The ledger should assign one accountable person without pretending that one team owns all layers.

Separate installation from availability. A vendor release demonstrates that a remedy exists for a product. A deployment job demonstrates that an organization attempted installation. Device evidence demonstrates what actually runs. Successful reconnection and application checks demonstrate that the change did not prevent essential work. None of these records should automatically substitute for the next.

An inventory also needs a denominator. Reporting that nine hundred devices are updated is incomplete if the total population is unknown. Track the last observation of each device and distinguish retired equipment from equipment that simply has not connected recently. Otherwise an apparently improving completion percentage can result from disappearing evidence rather than reduced exposure.

## Prioritization without fabricated precision

Original recommendation: prioritize by verified exposure and business consequence. Unsupported equipment carrying sensitive activity deserves attention, as do portable endpoints that operate outside managed wireless environments. Infrastructure providing essential mobility services deserves a carefully planned change window. There is no need to invent a universal numerical probability of compromise to make those distinctions useful.

For each exception, document why immediate remediation cannot occur, what functions the device supports, which compensating measures are actually available, and who accepts the remaining risk. The exception should expire. An undated note that a device is too important to update can become a permanent exemption precisely because the device is important.

Replacement planning should consider how the successor receives future updates. Purchasing new hardware solves little if its support period is short or the organization still cannot distribute firmware. Procurement can ask for published support commitments, update mechanisms, component visibility and the ability to verify installed versions. These requirements improve readiness for future vulnerabilities without claiming that a particular product is immune.

A prioritization meeting should also preserve operational safety. If wireless devices support clinical, industrial or emergency work, untested interruption can create serious consequences. The security objective is to reduce total risk through staged validation and documented alternatives, not to maximize the number of devices disconnected in the first hour.

## Remediation stages and acceptance evidence

Original recommendation: use four distinct states in the tracker: assessed, remedy available, deployed and verified. Add a separate exception state for cases requiring compensating controls or retirement. Avoid a single green status that conceals whether the team merely read an advisory or confirmed a fixed build on the device.

Assessment should match each component to the relevant vendor scope. Remedy availability should name the intended update and any prerequisites. Deployment should record job results and failures. Verification should confirm the resulting build and the continued function of important workflows. For devices that cannot report remotely, an authorized local check may be necessary. The evidence method should be written down so that future reviewers can reproduce the determination.

Use a representative pilot before a broad rollout. Include different chipsets, older supported hardware, roaming users and devices with tight availability requirements. A pilot dominated by identical recent laptops can miss the systems most likely to fail during production change. Have the business owner identify what functioning normally means, including authentication, roaming and access to the required application.

Rollback must be a controlled decision. Restoring an older vulnerable image may recover availability while reopening exposure. If that tradeoff becomes necessary, the incident record should show the reason, duration and alternative protection. A deployment system should not silently roll back and leave the device marked remediated.

## Temporary controls and the danger of overclaiming

Original analysis: a temporary control deserves a scope statement in plain language. It should identify where it operates, which population benefits, what conditions limit it and when it will be removed. A control applied on a managed network cannot automatically protect a portable device after it leaves that network.

Network-based protections can also change reliability. Before adopting a vendor workaround, test slow devices and weak-signal locations, and define the failure signals that would trigger review. A workaround that causes frequent disconnects may prompt users to create unsanctioned alternatives. That is a foreseeable operational consequence, not a reason to ignore the vulnerability.

Monitoring should support the decision process with specific questions. Which authorized infrastructure identities exist? Where can sensors observe the relevant radio channels? How quickly can analysts investigate a suspected impersonation? Who can inspect the physical area without disrupting operations? These are better preparedness questions than assuming that a generic network alert proves or disproves compromise.

Avoid active interference with unfamiliar wireless equipment as an improvised response. Nearby networks may belong to other organizations or private individuals. An investigation should remain within authorized monitoring and established legal and operational procedures. This study provides no instructions for wireless interception or disruption.

## Protocol engineering: retries must preserve invariants

Original analysis: retry behavior often enters a system as a reliability feature. A sender expects occasional loss, so it repeats an operation. Security trouble appears when a receiver treats the repeated operation as a fresh instruction with destructive side effects. Reviewers should ask what remains invariant across retries and how the implementation recognizes an already completed transition.

An invariant is a condition the system must keep true. Examples for a design review include preserving the required uniqueness of state, preventing a completed installation from resetting active counters, and rejecting transitions that contradict the session's current status. These are review objectives, not a substitute implementation specification for a wireless stack.

Testing should cover interruption and recovery, including duplicate events, delayed responses, process restarts and transitions between modes. The question is not simply whether two devices eventually connect. The question is whether every permitted recovery path preserves the security properties expected after connection. Functional interoperability tests and security tests answer related but different questions.

A useful organizational practice is to connect the protocol model to the actual calls that install material in hardware or drivers. A design document can appear sound while an implementation boundary introduces different state semantics. Review responsibilities should cross that boundary rather than end at the source file maintained by a different team.

## Incident evidence and responsible impact language

Original recommendation: when an organization finds relevant suspicious activity, preserve the observations that support each claim. Record sensor location, timestamps, clock quality, affected-device versions and the distinction between raw observations and analyst interpretations. Retention should follow the organization's privacy and legal requirements. Capturing unnecessary private content is not a prerequisite for documenting a vulnerability-response decision.

A report should separate vulnerability, opportunity, attempted exploitation, successful exploitation and business impact. Each step requires additional evidence. A vulnerable model in an inventory proves exposure requiring remediation. It does not prove that an attacker was nearby. A suspicious radio event may justify escalation. It does not by itself establish theft of a customer's data.

Absence-of-evidence language should be equally precise. State what telemetry was reviewed and its coverage limitations. A statement such as no relevant alerts were found in the retained controller records is narrower and more defensible than no attack occurred. Where records are unavailable, report that gap without pretending it demonstrates either safety or compromise.

Do not insert a threat actor into the narrative simply because another incident in the collection involves one. This case's source set supports a research discovery and coordinated vulnerability response. Attribution would require separate evidence connecting an actual campaign to an operator. Speculation would distract from the documented engineering lesson.

## Fictional tabletop: Northbridge Learning Campus

This exercise is entirely fictional. Northbridge Learning Campus operates office laptops, classroom tablets, wireless presentation equipment and a small fleet of older inventory scanners. The network team manages access points, while separate departments own the endpoints. Its initial dashboard reports infrastructure fully updated. The exercise begins when a department asks whether that means its unsupported tablets are safe to use elsewhere.

First inject: the team discovers that thirty devices have not checked in for six weeks. Participants must decide whether to exclude them from the denominator, classify them as unverified or initiate an ownership search. A strong answer preserves the unknown population and assigns follow-up. It does not improve the completion percentage by silently removing inconvenient records.

Second inject: a vendor workaround improves protection for one managed network but causes intermittent scanner disconnects. Participants must identify affected business workflows, propose a controlled test, and document an exception if immediate repair is unavailable. The exercise is successful when the team can explain the tradeoff and its duration. It is not scored by whether everyone agrees to disable equipment immediately.

Third inject: a senior manager asks for a statement that no data was exposed. The available records show no relevant alerts, but sensor coverage was incomplete. Participants should draft a narrowly supported statement, explain what is unknown, and identify additional evidence worth collecting. They should not manufacture certainty to shorten the meeting.

Fourth inject: an endpoint update job reports success, but a local check shows the old build after an automatic rollback. Participants must correct the tracker, investigate the reason and choose a supported recovery path. This tests whether the organization measures attempted deployment or verified protection.

The facilitator should record unresolved ownership, missing evidence and decisions needing an executive risk owner. Outputs should include an exception register, a revised communication paragraph and a verification checklist. No live attack, traffic interception or exploitation demonstration is needed to achieve the learning objectives.

## What a defensible closure record contains

Original recommendation: closure should identify the population reviewed, the source of the inventory, the fixed versions or applicable vendor determinations, unresolved exceptions and the evidence supporting completed work. It should also preserve changes made during remediation, including any temporary controls still active. A future administrator needs to know why a setting differs from the standard configuration.

The closure meeting should include endpoint and infrastructure owners. Each should acknowledge the boundaries of their assurance. Security staff should check that an executive summary does not broaden a technical conclusion. Business owners should confirm that essential functions work and that exception dates are realistic.

Useful measures include the proportion of inventoried endpoints with verified applicable fixes, the number of unsupported devices with approved retirement plans, the age of unverified inventory entries and the number of temporary controls without an expiry date. These measures expose the work remaining. They do not estimate how many attackers were deterred or how many hypothetical records were saved.

Finally, preserve the lesson in engineering and procurement processes. An incident-response team should not have to rediscover ownership and update mechanisms during every future wireless advisory. The most durable improvement is a repeatable ability to establish what exists, determine what applies, deploy a remedy and demonstrate that the intended state holds.

## Final assessment

KRACK's importance lies in the gap between a familiar security label and the detailed behavior that makes the protection work. A well-known protocol, a strong cipher and successful connectivity are all incomplete assurances when state transitions have not been examined carefully.

For defenders, the case supports disciplined remediation rather than panic. Keep factual impact conditional, validate endpoints as well as infrastructure, and resist substituting highly visible but causally unrelated changes for the required fix. For researchers and engineers, it reinforces the value of examining repeated operations and the boundary between formal reasoning and implementation behavior.

This is a historical research draft with practical analysis, not a current certification of any network or product. Its strongest conclusion is deliberately operational: a security claim should name the conditions that make it true and the evidence used to verify those conditions.

## Source register

[1] Mathy Vanhoef and Frank Piessens. Key Reinstallation Attacks: Forcing Nonce Reuse in WPA2. ACM CCS, 2017. Original research paper, abstract and selected relevant passages. https://papers.mathyvanhoef.com/ccs2017.pdf

[2] Mathy Vanhoef. KRACK Attacks research website and FAQ. Original researcher explanation, disclosure history, mitigation boundaries and uncertainty. https://www.krackattacks.com/

[3] CERT Coordination Center. Vulnerability Note VU#228519. Released 16 October 2017, revised 16 November 2017. https://www.kb.cert.org/vuls/id/228519

[4] CERT-EU. Security Advisory 2017-021. Released 17 October 2017. https://cert.europa.eu/publications/security-advisories/2017-021/

[5] Android Open Source Project. Android Security Bulletin, November 2017. Published 6 November, updated 8 November 2017. https://source.android.com/docs/security/bulletin/2017-11-01

[6] Cisco. Wireless KRACK attack client side workaround and detection. Document 212390, updated 27 October 2017. Selected scope and operational-impact guidance. https://www.cisco.com/c/en/us/support/docs/wireless-mobility/wireless-lan-wlan/212390-wireless-krack-attack-client-side-workar.html

All sources accessed 15 November 2026. Historical claims remain date-bound. No public publication or changes to a live system are part of this package.
