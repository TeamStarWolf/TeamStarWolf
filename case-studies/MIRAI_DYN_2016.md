# Mirai and Dyn, 2016: When Unmanaged Devices Became an Internet Availability Problem

*A TeamStarWolf case study. Published 15 November 2026. Historical reconstruction and proposed defensive exercises, not an independent forensic examination.*

[All case studies](/case-studies/README.md) · Related: [Firmware and IoT Security Reference](/FIRMWARE_IOT_SECURITY_REFERENCE.md), [Network Defense Reference](/NETWORK_DEFENSE_REFERENCE.md), [Network Monitoring Reference](/NETWORK_MONITORING_REFERENCE.md), [Incident Response Reference](/INCIDENT_RESPONSE_REFERENCE.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Vulnerability-management teams, network defenders, DNS and service owners, procurement teams and incident commanders

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 20 min (4,490 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You want an evidence-bounded account of the 2016 Mirai botnet and the Dyn disruption, you need to connect unmanaged-device security to enterprise dependency risk, or you are testing availability under a failure outside your control

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Executive summary](#executive-summary), [Part 2: the operational model](#part-2-the-operational-model), [Part 5: an evidence-led response playbook](#part-5-an-evidence-led-response-playbook)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Firmware and IoT Security Reference](/FIRMWARE_IOT_SECURITY_REFERENCE.md), [Network Defense Reference](/NETWORK_DEFENSE_REFERENCE.md), [Network Monitoring Reference](/NETWORK_MONITORING_REFERENCE.md), [Incident Response Reference](/INCIDENT_RESPONSE_REFERENCE.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## Executive summary

The Mirai story crosses two different administrative boundaries. One organization owns a poorly secured connected device. Another operates a service that receives unwanted traffic. A third depends on that service. The people who can prevent device recruitment may have no contractual relationship with the people who suffer the downstream outage. That separation makes this an unusually useful case for exposure management.

This study examines the 2016 Mirai episode and the October 21 disruption involving DNS provider Dyn. It deliberately keeps the incident history separate from its proposed engineering lessons. The public sources below establish malicious activity and significant availability consequences. They do not provide a complete inventory of every infected device, a universal downtime duration, or a single reliable worldwide loss figure.

The central recommendation is to maintain two linked but distinct programs: stop assets under your control from becoming attack infrastructure, and demonstrate that critical business services can tolerate failures outside your control. A clean vulnerability scan of your servers does not answer the second question. A resilient DNS arrangement does not excuse insecure devices on your own network.

### Five conclusions for decision-makers

1. Device ownership must include an accountable support and retirement decision, not just a purchase record.
2. Availability reviews should follow a customer transaction through its dependencies rather than stop at the application server.
3. Malware lineage cannot establish that every related attack has the same operator.
4. Metrics need explicit populations and clocks. An address count, device estimate, attack rate and customer downtime measure describe different things.
5. A proposed safeguard becomes credible when a controlled exercise produces evidence that it works without creating unacceptable operational harm.

These conclusions are the author's interpretation and proposed practice. They should not be mistaken for findings from direct access to Dyn or an infected device.

## Scope, evidence and limitations

The historical core covers 2016, with later research and public legal milestones through 2020. A 2020 NIST publication is used as retrospective design guidance, not as a requirement that existed during the incident. Sources were retrieved on 14 November 2026. This is a selected-source case study, not an exhaustive legal history or measurement replication.

| Label | Meaning in this study |
|---|---|
| Research observation | A named research team describes its own methods or measurements. |
| First-party account | An affected organization or individual describes what it experienced. |
| Official legal account | A government announcement describes a plea, sentence or court-document account. |
| Proposed practice | An original recommendation, hypothetical example or exercise developed for this study. |
| Unknown | A question these sources do not resolve. |

No malware was downloaded or executed. No public host was scanned. No flood, credential trial or denial-of-service test was conducted. There are no reusable attack commands, credential lists or botnet instructions in this package. The defensive exercises use approved test resources and synthetic evidence. Their applicability to a specific environment requires local engineering and change-control review.

One especially important source limitation is the original Dyn postmortem link. The historic URL redirected to the Oracle Blogs home page during this review [8]. A redirect is not access to the old article. This study therefore avoids presenting an exact Dyn mitigation timeline or traffic-volume claim as independently read from that missing postmortem.

## Part 1: a carefully bounded historical record

### What the research established

Antonakakis and colleagues published a seven-month retrospective in 2017, using multiple measurement perspectives rather than a single victim log. Their study followed activity from August 2016 through February 2017 and reported a peak of roughly 600,000 infections. It described a botnet built largely from embedded devices, with Internet scanning and weak default credentials contributing to its expansion [1]. **Research observation.**

The paper's measurements describe its observed ecosystem and methodology. They should not be repurposed as the number of devices attacking Dyn at one moment. Nor should an infection estimate be described as an exact count of unique people, households or businesses. The remainder of this study does not attempt to reproduce those measurements.

### What the September victim account established

Brian Krebs reported that the September 20 attack against his site began around 8 p.m. Eastern Time. His September 21 account revised an initial estimate of 665 Gbps to approximately 620 Gbps following additional analysis. The account credited Akamai's engineers with keeping the site online during the attack described in that post [2]. **First-party account with provider-attributed measurements.**

The revision itself is instructive. A draft timeline should preserve an estimate's provenance instead of treating the earliest number as permanent truth. This article does not extrapolate the September rate to the later Dyn incident. Separate targets and separate intervals require their own measurements.

### What the Dyn legal account established

The Justice Department announced a guilty plea on December 9, 2020 by an individual whose name it withheld because the conduct occurred while the individual was a juvenile. According to the announcement's account of court documents, a Mirai variant was used in October 21 attacks intended to disrupt the PlayStation Network. The attacks affected Dyn and made several dependent services unavailable or intermittent for hours. The announcement reported Sony's estimated net-revenue loss of approximately $2.7 million [3]. **Official legal account.**

That financial figure is a named company's estimate in a particular account, not the total cost of the incident. The account also illustrates why intended target and actual impact should occupy different fields. A history should not silently convert the downstream effect into a proven original intent.

### What the original-operator case established

A September 2018 Justice Department announcement described the sentencing of Paras Jha, Josiah White and Dalton Norman after guilty pleas concerning operation of the original Mirai botnet. It reported probation, community service and restitution, along with substantial cooperation. It distinguished the defendants' original involvement from subsequent use of Mirai variants by others after source-code release [4]. **Official legal account.**

That distinction matters more than a dramatic attribution label. The original authorship case and the later Dyn-related plea account cannot be collapsed into one set of defendants merely because both refer to Mirai. This study reports those announced milestones without claiming to have inspected every docket entry or established the full present legal status of all participants.

### A chronology that does not invent missing precision

| Period | Supported milestone | Boundary |
|---|---|---|
| August 2016-February 2017 | Observation window of the published retrospective [1]. | Research coverage, not proof of a single continuous operator. |
| September 20-21, 2016 | Attack against Krebs and publication of his account [2]. | The rate estimate belongs to this event. |
| October 21, 2016 | Dyn-related disruption described in the later plea announcement [3]. | No universal duration for all users. |
| October 2017 | FBI consumer guidance discusses insecure IoT recruitment [5]. | Later guidance, not an incident-specific forensic report. |
| September 2018 | DOJ announces original-botnet sentencing [4]. | Distinct legal proceeding. |
| May 2020 | NIST publishes the device-capability baseline [6]. | Retrospective reference here. |
| December 2020 | DOJ announces the Dyn-related guilty plea [3]. | An announcement date, not an attack date. |

## Part 2: the operational model

### Three roles, three different investigations

The following model is analytical, not a diagram recovered from the incident. It separates the recruited device, the attacked service and the dependent business. One organization can occupy more than one role, but each role needs its own evidence.

A recruited-device investigation asks which asset communicated unexpectedly, who owns it, which software it runs and whether its permitted network behavior matches its business purpose. An attacked-service investigation asks where capacity or processing failed and which controls changed traffic handling. A dependent-business investigation asks which customer journeys failed and what options remained available.

Without this separation, an incident bridge can spend an hour arguing about whether “we were compromised” while participants mean different things. The website team may mean unauthorized code execution. The network team may mean a local device emitting unwanted traffic. Customer support may mean users cannot log in. All three statements can require attention without being interchangeable.

A recommended incident record therefore includes an explicit role field. Do not automatically classify an organization suffering a DNS-dependent outage as a malware-infected victim. Likewise, do not assume that an operational camera is healthy simply because its video feed still works. Intended functionality and unauthorized secondary behavior are independent questions.

### Why a small device can create a larger obligation

The security review of a connected device should include what it can cause beyond its immediate job. A camera's business value might be its video stream, but its network permissions can be much broader than the stream needs. A procurement specification that checks only image quality and uptime can miss whether the device is maintainable, observable and replaceable.

This is a proposed risk model rather than a claim about any one Mirai victim. Consider a hypothetical organization with five hundred cameras across leased premises. The facilities team owns the installation contract, a supplier manages the recorder, and the network team sees only addresses. If nobody can identify a support end date, the organization does not have an enforceable maintenance plan even when every camera appears in an inventory.

The exposure is not resolved by assigning a generic asset owner field to the facilities director. Ownership should include authority and budget: who can approve a maintenance window, validate a firmware release, replace unsupported hardware and accept a temporary loss of video coverage? An owner who cannot perform or fund those actions is only a contact person.

### Why the dependency view changes the outage question

A customer-visible service involves more than an origin server. Name resolution, identity, external APIs and communications can each influence whether a transaction completes. The important unit of availability is the customer's intended operation, not one infrastructure team's green dashboard.

Use a hypothetical online appointment system. Its web servers respond normally, but some users cannot resolve its name. Others can reach the page but cannot authenticate because a separate dependency fails. A monitoring probe that reuses cached data and an existing session might continue reporting success. None of those observations is necessarily false. They sample different paths.

A useful test plan distinguishes first-time visits from returning sessions and tests from more than one network. It records the failed stage rather than reducing everything to “site down.” That precision helps choose whether to investigate DNS, identity, application processing or connectivity. These are proposed diagnostic practices, not a reconstruction of a particular Dyn customer's topology.

## Part 3: what the evidence can and cannot count

### Device estimates and address counts

An IP address is an observation key, not automatically a physical-device identifier. Address assignment can change, and more than one device may share an outward-facing address. A case-study author should reproduce the researcher's unit instead of replacing it with a more familiar but stronger noun.

For a local incident, create separate columns for observed addresses, authenticated device identifiers, inventory matches and unresolved observations. Preserve timestamps. If two observations may represent the same asset, record that uncertainty. A small unresolved population can matter more than a large cleanly counted population if it contains equipment that cannot be isolated safely.

A proposed dashboard could show “28 observed source addresses, 21 matched inventory records, 7 unresolved” without asserting that exactly 28 physical devices are infected. That example is illustrative. Its purpose is to make uncertainty visible enough to investigate.

### Traffic rate and service impact

A rate describes traffic within a measurement interval. It does not by itself describe customer harm. The same reported bandwidth can have different effects depending on the receiving system, traffic characteristics and available defenses. An analyst should request the unit, sampling interval, measurement point and whether the number represents offered or accepted traffic.

For management reporting, pair technical measurements with service outcomes. Examples include transaction completion rate, affected geographic test regions and the time when a previously failing customer journey succeeded again. Avoid claiming a service is fully restored because a traffic graph has declined. Restoration requires evidence from the operation users actually need.

### Financial totals and false precision

The named estimate above should remain attached to its source and scope. It should not be combined with speculative hourly revenue multipliers to produce a worldwide total. Gross sales, net revenue, remediation expense and reputational effects are different categories. Adding unlike categories can double count losses or imply accounting assurance that does not exist.

A proposed internal loss worksheet should distinguish measured transactions, estimated missed transactions, direct response expenditure and unresolved items. Each estimate needs its owner, method and confidence. A blank is preferable to an invented number. If leadership needs a decision before the accounting closes, provide a range with the assumptions exposed rather than presenting false precision.

## Part 4: defensive lessons with explicit limits

### A historical advisory and a later baseline

The FBI's October 2017 advisory described recruitment of Internet-accessible devices using common default credentials. Its recommendations included changing defaults, isolating IoT networks, applying updates and evaluating manufacturer support [5]. Those are useful historical recommendations, but the advisory should not be read as proof that one password change eliminates every possible compromise.

NISTIR 8259A, published in May 2020, defines a core device-capability baseline covering identification, configuration, data protection, access to interfaces, software updates and cybersecurity-state awareness [6]. This study uses those categories as a later evaluation vocabulary. It does not suggest the baseline is a universal certification or that it was available to 2016 responders.

### Procurement as an operational acceptance test

The following is an original proposed procurement exercise. Ask the supplier to demonstrate a device through its entire intended life, including retirement. A presentation that promises secure updates is weaker than evidence that a nominated operator can discover the installed version, obtain the correct update and confirm its outcome.

Begin with identity. Require a way to distinguish a physical asset from its current network address. Then inspect management access. Ask whether the organization can disable unneeded services and recover control without a shared permanent supplier password. Establish how a lost administrator credential is handled and whether recovery changes other security settings.

Next, test maintenance under realistic constraints. A fleet in remote buildings may not tolerate a procedure requiring a technician at every device. Conversely, automated deployment may be inappropriate when a failed update could interrupt a safety-related function. Document those tradeoffs before purchase. The lowest unit price can hide a costly operational exception.

Finally, define the exit. Establish what data the device retains, how it is removed, what evidence confirms sanitization and what happens when support ends. A replacement date with no funded plan is a risk acceptance decision, not remediation.

### Segmentation without operational self-harm

Segmentation is only useful when its permissions match real dependencies. A simplistic instruction to block all outbound traffic can interrupt required services and provoke an emergency rollback that restores excessive access. Build a permitted-flow inventory with the application or facilities owner before enforcing changes.

In an approved test segment, observe required behavior across normal operation, restart, maintenance and fault recovery. A device may behave differently during an update than during ordinary service. Record the smallest workable permissions and the evidence used to justify them. Validate that the monitoring path still functions after restriction.

For devices associated with physical processes, the safety owner must participate. Do not disconnect equipment based on an uncorroborated alert without considering operational consequences. The safe action may be a staged restriction, a switch to a redundant process or a planned replacement. This is a decision framework, not a universal isolation order.

### DNS diversity requires an exercised operating model

Buying a second provider does not establish successful failover. A proposal should explain who maintains consistent records, how credentials are protected, how changes propagate and what happens when the preferred management interface is unavailable. It should also identify shared dependencies that could defeat the intended separation.

A second service can create new failure modes. Stale records, inconsistent changes or an untested emergency procedure may turn a protective arrangement into an outage. The acceptance criterion should therefore be an observed customer journey during a controlled dependency-loss exercise, not merely two contracts or two names in a configuration screen.

Do not change production delegation reactively from this article. The exercise needs domain-owner authorization, a reviewed plan, rollback criteria and vendor-specific guidance. This study intentionally omits universal DNS commands because the correct procedure depends on the arrangement and an incorrect change can make recovery harder.

## Part 5: an evidence-led response playbook

### Stage 1: establish the symptom and preserve a baseline

Create an incident record before changing multiple systems at once. Capture when the symptom was first observed, the observer's network and the exact customer operation that failed. Record the result of a comparable successful test if one exists. “Cannot access the site” is a starting report, not a sufficiently precise diagnosis.

Assign separate owners for customer-impact validation and technical containment. This prevents mitigation progress from being mistaken for restored service. Maintain a log of changes with timestamps and expected effects. When the team cannot tell which intervention helped, the subsequent lessons will be weak and the rollback decision harder.

Preserve evidence consistent with local policy. Avoid unnecessary collection of device contents or customer data. A diagnostic need does not justify capturing everything. Record which logs are unavailable so later reviewers do not interpret silence as absence of activity.

### Stage 2: test competing explanations

Write at least two plausible explanations before declaring the cause. For example, a dependency failure and an application deployment defect might produce similar symptoms. Select safe observations that distinguish them. A failed test from one network should not be generalized to all users without additional evidence.

If a provider reports an incident, retain the update and time of observation, but continue validating your own customer impact. A provider's global status and your particular integration can recover at different times. Likewise, a local alert suggesting botnet activity should be corroborated before labeling a specific asset infected.

### Stage 3: contain within the organization’s authority

If an owned device is credibly implicated, use the reviewed isolation or restriction procedure appropriate to its function. Ensure an accountable operator understands any loss of service. Coordinate with the network provider when upstream action is required. Do not retaliate against apparent sources or scan unrelated systems in search of the attacker.

If the organization is a downstream service consumer, focus on available continuity options rather than promising control over the upstream incident. The public update should identify observable impact, available alternatives and the next update time. It should not claim data theft, a named actor or complete recovery without supporting evidence.

### Stage 4: verify recovery from the outside

Test customer journeys from representative vantage points. Include a new session and any critical dependent action. Confirm that recovery does not depend on one responder's cached state or privileged account. Track failures that remain after the main symptom improves.

For a remediated device, verify both required functionality and the closure of the identified exposure. Record installed software, access changes and observed network behavior. A reboot followed by a quiet graph is insufficient evidence of a durable resolution if the original exposure remains open.

### Stage 5: close with an evidence package

The closure package should include the timeline, affected scope, unresolved scope, changes made, verification results and assigned follow-up actions. Separate immediate restoration from long-term risk reduction. The incident can be operationally contained while procurement, replacement or architectural changes remain open.

A useful corrective action names an owner and a testable finish condition. “Improve IoT security” cannot be verified. “Demonstrate that the nominated facilities operator can identify and update every supported camera model in the approved pilot” can be evaluated. The example is a proposed action format, not a claim about a historical victim.

## Part 6: a 90-minute tabletop exercise

This scenario is fictional. It uses no malware, no live flooding and no third-party scanning. The facilitator supplies synthetic logs and status updates. Participants should include a service owner, network engineer, facilities representative, communications lead and incident commander.

### Scenario setup

The organization runs an appointment portal and a fleet of building cameras. Customers report intermittent access problems. Internal application monitoring is green. A network provider separately reports unusual outbound behavior from an address associated with one branch office. The organization does not yet know whether these observations are related.

Participants receive an asset inventory extract, a simplified dependency map and an incomplete contact list. Deliberately omit the support status of one camera model. The point is to test the investigation and decision process, not to reward guessing “Mirai” from the exercise title.

| Exercise time | Inject | Required decision |
|---|---|---|
| 0-15 minutes | Two customer reports from different networks, one successful internal test. | Define impact and choose additional safe observations. |
| 15-30 minutes | Upstream provider acknowledges a service issue without an estimated restoration time. | Decide what can be communicated and what remains unverified. |
| 30-45 minutes | Branch traffic alert maps to a shared external address. | Identify the internal asset without assuming one address equals one device. |
| 45-60 minutes | Facilities warns that abrupt isolation would remove needed camera coverage. | Select a safe containment path with an accountable operational owner. |
| 60-75 minutes | Provider declares improvement, but new-session tests still fail in one region. | Decide whether the incident remains open and what evidence is required. |
| 75-90 minutes | A supplier cannot provide a support commitment for the suspect model. | Assign a funded replacement or explicit risk-decision path. |

### Scoring criteria

Award credit for clear evidence and bounded claims, not speed alone. A team that refuses to name an actor without evidence is performing well. A team that distinguishes the branch alert from the customer outage until it has a connection is performing well. A team that labels every symptom “the botnet” has skipped an essential reasoning step.

Use five scores from zero to two: impact definition, ownership, safety of containment, quality of external communication and recovery verification. Zero means absent, one means partially demonstrated and two means demonstrated with an artifact. The maximum is ten, but the written evidence matters more than the total.

The facilitator should record which missing information delayed decisions. If the supplier contact could not be located, the corrective action concerns contact maintenance. If the network team could not map an address to a device, the action concerns observability or inventory. Do not solve every exercise failure by purchasing the same security tool.

## Part 7: a measurable exposure-management backlog

The following plan is proposed and should be adapted to local risk. Its ordering favors actions that clarify responsibility and reduce uncertainty before large architectural changes.

| Horizon | Deliverable | Evidence of completion |
|---|---|---|
| First week | Identify critical connected-device populations and accountable operators. | Inventory sample reconciled with physical or management records. |
| First month | Review support status and management exposure for the highest-impact population. | Documented support dates, approved exceptions and verified access paths. |
| First month | Map one critical customer journey through external dependencies. | A dependency diagram validated by service owners. |
| Following month | Exercise a safe containment procedure for a representative device. | Recorded authorization, operational checks and rollback outcome. |
| Following quarter | Exercise an approved continuity option for a critical external dependency. | Customer-journey results under the simulated failure condition. |
| Ongoing | Review unresolved assets and expiring support. | Named decisions with dates, rather than indefinitely open tickets. |

Avoid a dashboard that rewards only the number of scanned devices. Coverage matters, but a high count can coexist with unowned equipment and untested containment. Add measures that reflect usable control: percentage with a verified support decision, percentage with an operator who can perform recovery, and percentage of critical journeys exercised under a dependency failure.

These measures should retain denominators and exclusions. If a device class cannot be safely assessed by the standard method, show it as an exception requiring another method. Do not quietly remove it from the denominator and report improved coverage. The purpose of exposure management is to make difficult decisions visible, not to make the chart green.

## Part 8: common editorial errors and exact replacements

| Avoid writing | Prefer this wording |
|---|---|
| Mirai took down the whole Internet. | The October 21 incident disrupted access to multiple services that depended on affected DNS infrastructure. |
| The 600,000 bots all attacked Dyn. | The research paper reported an ecosystem peak near 600,000 infections; that is not an attack-specific simultaneous count. |
| The Mirai creators were the Dyn attackers. | Keep the original-botnet case and the later Dyn-related plea account separate. |
| The attack cost $2.7 million. | DOJ's 2020 announcement reported Sony's estimated net-revenue loss of approximately $2.7 million. |
| Changing passwords fixes Mirai. | Close the identified access exposure, restore trustworthy device operation and verify the outcome. |
| A second DNS vendor guarantees availability. | A second arrangement needs consistent operation, dependency review and a successful controlled exercise. |

The replacement wording is intentionally less dramatic. It gives the reader enough precision to avoid repeating an unsupported claim. In a professional portfolio, that discipline is a strength: a reader should be able to distinguish what the evidence establishes from what the author recommends.

## Conclusion

This case is valuable because the security problem does not stay inside one asset inventory. Device maintainability, malicious traffic, service capacity and customer dependency become linked while remaining under different owners. Effective defense requires both local accountability and a tested understanding of what the business relies on elsewhere.

The most useful follow-up is a small, verifiable demonstration. Choose one connected-device population and one customer journey. Establish ownership, support and permitted behavior for the devices. Establish observable failure and recovery criteria for the journey. Then run an approved, non-disruptive exercise. The result will be more actionable than an unqualified claim that the organization is protected against Mirai.

## Source register

[1] Antonakakis et al., [Understanding the Mirai Botnet](https://www.usenix.org/system/files/conference/usenixsecurity17/sec17-antonakakis.pdf), USENIX Security 2017. Research paper. Used for bounded ecosystem and method facts, not a Dyn-specific device total.

[2] Brian Krebs, [KrebsOnSecurity Hit With Record DDoS](https://krebsonsecurity.com/2016/09/krebsonsecurity-hit-with-record-ddos/), September 21, 2016. Affected-site account. Used for the September event and revised rate estimate.

[3] U.S. Department of Justice, [Individual Pleads Guilty to Participating in Internet-of-Things Cyberattack in 2016](https://www.justice.gov/archives/opa/pr/individual-pleads-guilty-participating-internet-things-cyberattack-2016), December 9, 2020. Official announcement. Used for the distinct Dyn-related plea account and attributed financial estimate.

[4] U.S. Attorney's Office, District of Alaska, [Hackers' Cooperation with FBI Leads to Substantial Assistance in Other Complex Cybercrime Investigations](https://www.justice.gov/usao-ak/pr/hackers-cooperation-fbi-leads-substantial-assistance-other-complex-cybercrime), September 18, 2018. Official announcement. Used for the original-operator sentencing and distinction from later variants.

[5] FBI Internet Crime Complaint Center, [Common Internet of Things Devices May Expose Consumers to Cyber Exploitation](https://www.ic3.gov/PSA/2017/PSA171017), October 17, 2017. Historical public advisory. Used for recruitment context and bounded defensive guidance.

[6] NIST, [IoT Device Cybersecurity Capability Core Baseline, NISTIR 8259A](https://nvlpubs.nist.gov/nistpubs/ir/2020/NIST.IR.8259A.pdf), May 2020. Later guidance used retrospectively, not represented as a 2016 requirement.

[7] RIPE NCC analysis republished by APNIC, [A quick look at the attack on Dyn](https://blog.apnic.net/2016/10/26/quick-look-attack-dyn/), October 26, 2016. Additional measurement reading. Not used to manufacture a universal outage duration or device count in this manuscript.

[8] [Historic Dyn analysis URL](https://dyn.com/blog/dyn-analysis-summary-of-friday-october-21-attack/). Retrieval on November 14, 2026 redirected to the Oracle Blogs landing page. Included as a source-availability limitation, not as a successfully read original postmortem.
