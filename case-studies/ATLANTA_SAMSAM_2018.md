# Atlanta and SamSam, 2018: Restoring a City Requires More Than Decrypting Its Files

*A TeamStarWolf case study. Published 15 November 2026.*

[All case studies](/case-studies/README.md) · Related: [Ransomware Defense Reference](/RANSOMWARE_DEFENSE_REFERENCE.md), [Incident Response Reference](/INCIDENT_RESPONSE_REFERENCE.md), [Cyber Resilience BCDR Reference](/CYBER_RESILIENCE_BCDR_REFERENCE.md), [Baltimore and RobbinHood, 2019](/case-studies/BALTIMORE_ROBBINHOOD_2019.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Public-sector CISOs and IT leaders, municipal incident responders, business-continuity and communications owners, and finance leaders

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 20 min (4,681 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You want an evidence-bounded account of the 2018 Atlanta SamSam incident, you need to separate Atlanta-specific figures from campaign-wide totals or criminal from geopolitical attribution, or you are reviewing municipal recovery, reconciliation and public communication

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Executive summary](#executive-summary), [Analytical model: five recovery states](#analytical-model-five-recovery-states), [Reconciliation is a distinct recovery programme](#reconciliation-is-a-distinct-recovery-programme)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Ransomware Defense Reference](/RANSOMWARE_DEFENSE_REFERENCE.md), [Incident Response Reference](/INCIDENT_RESPONSE_REFERENCE.md), [Cyber Resilience BCDR Reference](/CYBER_RESILIENCE_BCDR_REFERENCE.md), [Baltimore and RobbinHood, 2019](/case-studies/BALTIMORE_ROBBINHOOD_2019.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## Executive summary

A municipal ransomware incident is not simply an endpoint-security failure. It is a disruption to the relationships between records, people, deadlines, public services and the authority to make decisions. Restoring a server is useful only when the people who depend on it can complete a trustworthy transaction. A functioning login page does not establish that the underlying records are complete, that a resident's request was preserved or that an interrupted payment will not be processed twice.

Atlanta's March 2018 SamSam incident offers a focused way to study that distinction. The public record supports serious disruption, but it does not support describing every city function as destroyed. It also supports a criminal charging narrative, not an unrestricted claim that nationality establishes government direction. The case should be explained using dated evidence rather than dramatic shorthand.

This study combines a bounded historical account with an original municipal recovery framework. The framework treats containment, clean restoration, service acceptance, backlog reconciliation and public communication as separate workstreams. Each needs an owner, an evidence standard and an explicit handoff. The result is a practical way to measure whether recovery has improved life for residents rather than merely increased the number of available computers.

The most important editorial rule is equally practical: do not let a malware family's general behavior become an invented reconstruction of one victim's intrusion. The precise initial access method for Atlanta is not established by the sources reviewed here. General references to phishing, remote access or vulnerable servers are not interchangeable proof. That uncertainty should remain visible in both the article and its presentation.

## Scope and evidence boundaries

The primary subject is the City of Atlanta incident in March 2018. The broader SamSam prosecution is included only where it provides context for the malware and the charges. Financial figures are dated statements with limited scope, not a final audited estimate. This document does not assess Atlanta's present security, reproduce malicious software, provide exploit instructions or investigate residents' records.

Research was reviewed on 15 November 2026. Accessible primary records included the Justice Department's Atlanta charging announcement, the New Jersey indictment, the mayor's written congressional testimony in a National Security Archive copy, and Treasury's designation announcement. The testimony is an original statement preserved by an archive, not independent forensic verification of every assertion. An indictment contains allegations, not a conviction.

Several contemporary City of Atlanta pages and the historical CISA advisory were discoverable but returned access errors when opened. Their snippets are not treated as full-document reviews. The historical narrative below rests on accessible documents instead. This matters because a search preview may omit qualifications, later updates or the surrounding explanation that changes what a sentence means.

The second half of this article is original defensive analysis. It proposes governance, evidence and service-restoration practices for an authorized organization. It is not a claim that Atlanta used, failed to use or currently needs each practice. Operational changes, contractual decisions, notifications and retention actions require the responsible organization's approval and current professional guidance.

## Historical account: four bounded sources

### Atlanta-specific federal account

The Justice Department's 5 December 2018 announcement describes charges against Faramarz Shahi Savandi and Mohammed Mehdi Shah Mansouri. Its account identifies roughly 3,789 affected city computers, including servers and workstations, and a demand of 0.8 Bitcoin per computer or six Bitcoin for the group. It says the city did not pay and that the payment-related webpage subsequently became unavailable. The described activity spans approximately 10-22 March 2018. These are the government's dated charging assertions, not a complete public forensic timeline. The release expressly preserves the defendants' presumption of innocence. [1]

### The broader campaign is a different denominator

The New Jersey indictment alleges a campaign involving more than 200 victims, over USD6 million in ransom receipts and additional losses exceeding USD30 million. Those are campaign-wide allegations, not Atlanta's cost. It describes operator involvement in deployment, reconnaissance, coordinated encryption and attempts to impair backups. The document identifies Atlanta activity on 22 March 2018 but does not justify assigning every campaign technique to every city computer. A campaign model provides investigative hypotheses; host-level conclusions still need local evidence. [2]

### The mayor's service and recovery account

In written testimony dated 25 June 2019, Mayor Keisha Lance Bottoms described disruption to municipal court hearings and ATL311, while stating that emergency services and the water supply were not affected. She reported approximately USD7.2 million in recovery costs to that point, anticipated further costs, and discussed partial insurance reimbursement. The testimony described a roughly USD51,000 demand that the city refused to pay. These are dated statements, not a final ledger or a claim that every administrative function supporting emergency services was untouched. [3]

### Financial facilitation is not state-direction proof

Treasury's 28 November 2018 announcement designated two Iran-based financial facilitators associated with converting SamSam proceeds and identified related digital-currency addresses. It distinguished transactions associated with the addresses from transactions specifically connected to the ransomware. The designation supplies context about financial facilitation; it does not by itself establish that the Atlanta incident was ordered by a national government. Nor should every transfer through an identified address be labeled an Atlanta payment. [4]

## Timeline and interpretation

| Period | Evidence-backed milestone | Interpretation boundary |
|---|---|---|
| March 2018 | Atlanta intrusion and encryption activity described in federal account | Not a complete host-by-host forensic chronology |
| 22 March 2018 | Major operational disruption described by the mayor | Different services had different operational states |
| November 2018 | Broader prosecution and Treasury action announced | Campaign totals are not city-specific totals |
| December 2018 | Atlanta-specific charges announced | Charges do not establish guilt at trial |
| June 2019 | Mayor reports service effects and recovery expenditure to date | Neither final audited cost nor present security assessment |

This table intentionally avoids implying that the public announcement date was the first day of unauthorized access. It also avoids giving one date for complete recovery. A city can restore one service while another remains impaired, and technical availability can return before transactions are reconciled. A defensible chronology should identify exactly which event each timestamp describes.

For a case-study editor, the practical choice is to maintain a claim ledger. A ledger entry should name the source, the date, the population or asset scope, and the condition that would change the claim. If a later audit refines a cost estimate, the old estimate remains part of the historical record but should not survive as an unqualified headline. If a fuller forensic account establishes an entry point, update the relevant paragraph rather than treating earlier uncertainty as incompetence.

## What this record does not establish

The reviewed sources do not establish one named vulnerability as Atlanta's definitive initial access route. They also do not justify a blanket statement that phishing caused this incident. A discussion of a common attack method in testimony is not equivalent to a finding that the same method was used against the speaker's organization. The correct technical description is narrower than the easiest narrative.

The sources do not establish that all city information was stolen. Encryption, loss of access, destructive modification and exfiltration are different outcomes. A ransomware label should not automatically become a confirmed data-theft claim. Equally, lack of a public exfiltration finding is not proof that confidentiality was fully preserved. An incident team would need evidence appropriate to each question, and a public study must not pretend to possess that evidence.

The record used here also does not establish a final all-inclusive recovery cost. A ransom demand, a contractor invoice, an emergency appropriation, a forecast, an insurance reimbursement and a long-term modernization project are different accounting objects. They cannot be combined simply because they appeared in coverage of the same event. A compelling case study can explain the financial burden without manufacturing a precise total.

Finally, criminal attribution and geopolitical attribution require different evidence. A charging document identifying individuals does not license conclusions about all people sharing their nationality, or about state sponsorship. This article preserves the specific official allegation and stops short of broader claims that the reviewed material does not support.

## Analytical model: five recovery states

The following model is an original proposal, not a reconstruction of Atlanta's internal response. Its purpose is to help municipal leaders distinguish progress from appearances. It separates five states that are often compressed into the word restored.

First is contained. The organization has taken justified steps to restrict further unauthorized access or damage, and has evidence supporting the scope of that containment. This is not synonymous with switching off everything. An indiscriminate outage can interrupt important services while leaving an overlooked access path available. Containment decisions should reflect dependencies, safety and the authority of the incident lead.

Second is technically rebuilt. A system has been reconstructed from an acceptable source with the needed configuration, identities and monitoring. Rebuild completion does not prove that every restored record is trustworthy. Nor does it prove that the environment to which the machine will reconnect is ready. The rebuild should produce an evidence package rather than just a successful installation screen.

Third is operationally accepted. A named service owner verifies that representative work can be completed safely, correctly and at an adequate volume. The test includes dependencies such as identity, printing, payment processing and interdepartmental exchange where relevant. The service owner should have the authority to reject premature reopening even when technical teams are under pressure to report progress.

Fourth is reconciled. Requests, payments, appointments and decisions accumulated during the disruption have been matched to the restored system. Duplicates and unresolved discrepancies are identified. A service can be available but still unreconciled, with consequences for residents who relied on a temporary process. This phase is part of recovery, not an optional administrative cleanup.

Fifth is stabilized. Monitoring, staffing, vendor obligations, residual risk and maintenance are sustainable after emergency teams leave. Temporary privileges and emergency exceptions have owners and expiry conditions. A stabilized service does not require heroic work every night to remain functioning. The distinction makes long-term recovery visible without pretending that all risk disappears.

## Start with services, not a device count

A municipal asset inventory is necessary, but it is not a recovery priority list. The city needs a service map that connects systems to outcomes. One record-processing service may depend on several applications, a shared identity platform, a document store and a print workflow. Conversely, a large group of workstations may support a service that can temporarily operate through another controlled channel.

For each service, record the accountable business owner, the minimum viable function, the consequence of delay and the population affected. Include residents without reliable internet access, people with disabilities and those who depend on translated information. A digital workaround that only helps confident online users can conceal a worsening service gap for everyone else.

Prioritization should also consider deadlines. A delayed recreational booking and a delayed legally significant filing may use similar technology but have very different consequences. The technical team should not make that judgment alone. Legal, departmental and executive owners need a documented process for resolving competing priorities and approving temporary accommodations where they have authority.

A useful service card is short enough to use during a disrupted meeting. It should show current state, safe alternative, next decision, owner and evidence location. If the card requires access to the affected collaboration platform, retain an approved offline or separately accessible copy. The plan's accessibility is itself a dependency that deserves testing.

## Identity and administrative authority

Recovery is fragile when rebuilt systems reconnect to an identity environment whose trust has not been reassessed. The relevant question is not only whether an account password changed. It is what the account can do, where its authority is accepted, which devices hold its sessions and whether an unauthorized actor could regain influence through another administrative path.

An organization should map human administrators, service accounts, vendor access and recovery credentials. The map needs practical scope rather than merely directory membership. A rarely used account with authority over a deployment platform may matter more than many ordinary users. A service account can carry important business dependencies that make an unplanned change disruptive.

Separate emergency administration from normal work where feasible, and establish a controlled process for temporary access. Record who approved it, the scope granted, the reason, the duration and the evidence of removal. A hurried exception can otherwise outlive the incident and become an undocumented part of the permanent environment.

Credential rotation and access revocation should follow a coordinated plan. Changing everything at once without understanding dependencies can break recovery tooling or essential applications. Changing too little can leave an attacker with a working path. The plan needs verified sequencing, recovery options and named owners rather than a single universal command.

## Backups: demonstrate a service, not a successful job

A backup dashboard can show that copying occurred while saying little about whether a service can be restored. A meaningful test reconstructs an isolated representative environment, validates the data needed for actual work and measures the time and dependencies required. The test should include failure conditions, not only the fastest successful scenario.

Protection must consider both stored data and the authority that can modify or delete it. A repository separated from production is less useful if the same compromised administrator can reach it through a different console. Review recovery credentials, management services, vendor access and the retention mechanism together. Physical or logical separation is a claim to verify, not a label to accept.

A recovery point also needs a trust assessment. The latest copy may contain unwanted changes, while an older copy may omit important transactions. This is a business and investigative decision as well as a technical one. Record why the chosen version is acceptable and how the missing interval will be reconciled. Do not silently replace a complete but uncertain dataset with an incomplete one and call the problem solved.

Recovery exercises should use synthetic or appropriately protected data. They should not require malware execution or uncontrolled copying of sensitive records. A harmless simulation can establish whether the team can retrieve a clean configuration, provision required resources, validate permissions and demonstrate a working service. The learning objective is recoverability under pressure, not realism at the expense of safety.

## Manual operations need integrity controls

Paper and telephone workflows can reduce immediate disruption, but they are not automatically safe or equitable. A temporary form needs a unique reference, a timestamp, a responsible staff member and a clear statement of what has and has not been completed. Residents should be able to prove that a request was accepted even before it appears in a restored system.

A manual payment process needs special care. Staff must not invent informal collection methods or route money through personal accounts. Approved finance personnel should define permitted channels, receipt requirements, reconciliation responsibilities and fraud checks. Where a safe temporary payment channel is unavailable, the responsible authority should decide the operational alternative rather than leaving individual employees to improvise.

Data collection should remain minimal. A service interruption does not justify collecting every possible identifier on unsecured worksheets. Use only the information necessary for the temporary task, protect access and storage, and establish how the records will be entered, checked and retained. Physical documents can create privacy risks even when the original incident is primarily about availability.

Manual work also accumulates debt. Every temporary request eventually needs reconciliation, a closure decision or an explanation of why it cannot be completed. Estimate that workload early. A reopened portal with an invisible queue of unresolved paper requests can make recovery statistics look good while the public experiences continued failure.

## Reconciliation is a distinct recovery programme

Reconciliation should begin with a defined cutover boundary. Identify the period during which the normal system could not be trusted or used, and the channels through which work continued. Not every department will share the same boundary. A single citywide timestamp may be convenient but misleading if service restoration was staggered.

Build a ledger of temporary transactions with unique references and status fields. Match them to restored records using approved identifiers. Ambiguous matches should go to a review queue rather than being forced into the closest available record. A person with a common name should not inherit someone else's payment or appointment merely because the team is trying to reduce a backlog quickly.

Define duplicate handling before bulk entry. A resident may have submitted the same request through several channels while unsure whether any one worked. The system should preserve evidence of each contact without automatically issuing multiple obligations or benefits. Service owners should decide how conflicting timestamps and duplicate submissions affect outcomes under applicable rules.

Reconciliation closure needs a measurable standard. Count unresolved items, aging, material discrepancies and the population still awaiting a decision. A declining total alone is insufficient if the remaining cases are the most consequential. Report exceptional cases separately so they are not buried by large volumes of straightforward work.

## Public communication as an operational service

A public status update should help a person decide what to do next. It should identify which service is affected, what alternative is available, which deadlines or arrangements have actually changed and when the next update is expected. Vague statements about ongoing restoration provide little help to someone deciding whether to travel to an office.

Avoid claiming that a service is normal because its website loads. Explain material restrictions such as reduced processing capacity, limited historical records or a temporary submission channel. If an alternative process does not produce an immediate final decision, say so. Clear limitations reduce repeat visits and prevent staff from having to correct unrealistic expectations individually.

Use channels that do not all depend on the affected environment. Keep approved messages consistent across call centers, physical offices and online channels. Provide accessible formats and translations appropriate to the community. Staff who answer resident questions need the same verified information as the public spokesperson, plus a way to escalate cases the public statement does not cover.

Correction should be routine rather than embarrassing. Maintain the time of each update and state when a previously published instruction no longer applies. A correction history can prevent residents from following an old screenshot after the underlying process has changed. The aim is dependable guidance, not an appearance of certainty before the evidence supports it.

## Procurement, insurance and financial accountability

Emergency contracting should accelerate necessary work without making expenditure untraceable. Record the service requested, the approval authority, the expected deliverable, the rate basis and the acceptance criteria. A recovery engagement should produce usable evidence and knowledge transfer, not leave the municipality dependent on a contractor's inaccessible notes.

Maintain separate cost categories for containment, forensic investigation, restoration, temporary operations, communications, legal support and modernization. Record commitments, invoices and payments as distinct states. Include dates and whether amounts are gross or net of reimbursement. This structure makes a public explanation more honest than a single number that changes meaning between updates.

Insurance coordination should have a designated owner and a record of decisions, notifications and documentation requests. A policy may shape practical response steps, but the presence of insurance does not itself establish technical safety or guarantee reimbursement. Coverage questions belong with qualified advisers and the actual policy terms, not assumptions based on another organization's experience.

Long-term improvements should be justified separately from restoring the former service. Some modernization may be a sensible part of recovery, but labeling every future project as incident cost obscures both the damage and the investment. A transparent ledger can show why a change was needed without pretending it was a direct invoice for encryption damage.

## Detection hypotheses for authorized testing

These hypotheses are original proposals, not historical Atlanta indicators. They are designed to test observability and decision-making using benign events. Each should be adapted to the organization's technology and approved before execution. A successful alert in a lab is not evidence that the same control covered the historical environment.

The first hypothesis is unusual administrative reach. A test identity attempts authorized access to a deliberately limited set of representative systems outside its normal role. The objective is to determine whether the organization can distinguish expected administration from unexpected expansion, identify the owner and escalate with enough context to act. The exercise should never probe systems outside its permission scope.

The second hypothesis is suspicious bulk file activity. Use disposable synthetic files in an isolated environment to test whether a monitored pattern produces a useful alert. Do not encrypt production data or interfere with backups. Measure whether the event includes process, account, host and service context rather than only a count of file operations.

The third hypothesis is recovery-control interference. Simulate a benign configuration change or failed attempt in a test backup environment and determine who notices, who can approve a response and where the evidence is retained. The test should verify that production compromise would not automatically suppress every record of a recovery-system event.

The fourth hypothesis is an off-hours decision gap. Introduce a simulated incident through the normal on-call process. Measure acknowledgement, ownership, access to the playbook and escalation quality. A technically accurate alert that sits unattended cannot protect service availability. The exercise should respect staff agreements and avoid creating a false real emergency.

## A practical ninety-day improvement plan

### Days 1-30: establish ownership and measurable uncertainty

Choose a small set of representative public services rather than trying to solve every system at once. Build their dependency maps and define minimum acceptable operations. Confirm who can authorize containment, temporary workflows, public statements and service reopening. Record missing information as an assigned task, not a reason to invent confidence.

Review the evidence available for those services: inventory, access records, recovery copies, configuration sources and vendor contacts. Test whether the information remains accessible when the primary collaboration tools are unavailable. Establish a simple claim ledger for readiness statements, including what was tested and what remains assumed.

### Days 31-60: prove recovery and temporary operations

Conduct isolated restoration tests for selected services. Have business owners perform realistic synthetic transactions, including exception cases. Measure time to usable service rather than time to an operating-system login. Test temporary forms, receipts and resident guidance, and identify how the resulting records will be reconciled.

Review identity and recovery authority as a connected system. Prioritize changes that reduce unnecessary reach while preserving required functionality. Each approved change should have an owner, a verification step and a rollback plan where appropriate. Record residual risks that cannot be addressed within the current resources or authority.

### Days 61-90: exercise the whole handoff

Run a cross-functional tabletop with service owners, technology staff, communications, finance, legal advisers and relevant partners. Include uncertain evidence, competing service priorities, a misleading early status report and a backlog of temporary transactions. Require each participant to identify the decision they own and the evidence they need from others.

Close the exercise with a short set of funded, assigned improvements. A long report without owners is unlikely to change the next response. Retest the most important failed handoff and record the outcome. The purpose is to create repeatable capability, not to declare that a city is now immune to ransomware.

## Metrics that reveal whether residents are recovering

| Measure | Useful definition | Misleading substitute |
|---|---|---|
| Service acceptance | Named owner validates representative end-to-end work | Servers powered on |
| Recovery readiness | Isolated restoration completes with documented dependencies | Backup jobs marked successful |
| Backlog resolution | Temporary transactions reconciled with exceptions tracked | Number of forms entered |
| Access control | High-impact authority verified and exceptions owned | Password-reset count |
| Communication quality | Residents receive current, usable instructions | Number of press statements |
| Financial visibility | Dated commitments and payments separated by purpose | One unexplained headline total |

Each metric needs a denominator and a stated limitation. Testing three services does not establish readiness for fifty. A completed exercise may reveal that the organization can restore one workflow only with an unusually experienced employee present. That is valuable evidence of a dependency, not a reason to hide the result.

Leaders should also track fatigue and staffing continuity. Recovery sustained through repeated overnight work can produce mistakes, delay ordinary obligations and increase dependence on a few people. A stable service needs support arrangements that can survive normal absence and turnover. Human capacity belongs in the recovery plan alongside storage and compute capacity.

## Tabletop: a city available on paper but not in practice

This exercise is fictional. It uses synthetic records and a simulated municipal environment. No historical malware, criminal infrastructure, real resident information or production disruption is needed.

Inject one: several departments report inaccessible files while others continue working. Ask the incident lead to define what is known, what is isolated and which services remain usable. Success is a bounded operational statement, not an unsupported declaration that the entire city is down or safe.

Inject two: the technical team can rebuild a shared server quickly, but its identity dependencies remain uncertain. Ask who accepts the risk of reconnection and what evidence is required. Success is an explicit decision with conditions, not automatic reconnection because the rebuild task is complete.

Inject three: a temporary intake process collects requests without unique receipts. Ask the service owner how residents can prove submission and how duplicates will be handled. Success is a controlled method that preserves fairness and traceability without collecting unnecessary data.

Inject four: a spokesperson has announced restoration while staff can process only a small share of normal volume. Ask the communications and service owners to correct the message and manage demand. Success is useful public guidance with limitations and a next-update time, not defensiveness about the earlier announcement.

Inject five: a contractor quotes a substantial recovery package that includes future modernization. Ask finance and technical owners to separate immediate restoration from longer-term investment and define acceptance criteria. Success is an accountable decision, not the cheapest number or an unexplained emergency approval.

Inject six: the online service is stable, but a backlog contains conflicting payment records and missed appointments. Ask who owns reconciliation and how consequential cases are prioritized. Success is a documented resolution process with remaining exceptions visible to leadership.

At the end, review the handoffs rather than scoring participants on jargon. Which decision lacked an owner? Which evidence was unavailable? Which temporary process created a new risk? Which public instruction was hard to follow? The answers should produce a short improvement backlog with retest dates and accountable people.

## Editorial checklist and conclusion

Keep Atlanta-specific figures separate from campaign-wide allegations. Preserve the date and scope of the mayor's recovery-cost estimate. Do not call a ransom demand the cost of the incident or imply that paying it would have eliminated investigation, restoration and reconciliation work. The available record supports a serious public-service disruption without unsupported claims of total citywide collapse.

Keep attribution specific and qualified. A criminal charge is not a conviction, and an individual's nationality is not proof of a government's direction. Do not invent an initial exploit, equate encryption with confirmed exfiltration or transform generic phishing advice into a forensic finding. The companion deck should retain these distinctions even when it condenses the narrative.

The enduring lesson is that municipal resilience is a service capability. Technical restoration matters, but residents experience recovery through accurate records, accessible processes, fair treatment and reliable information. A city is better prepared when it can explain who owns each decision, how evidence supports reopening and how temporary work becomes trustworthy permanent records.

## Sources and reading notes

[1] U.S. Attorney's Office, Northern District of Georgia. Atlanta U.S. Attorney Charges Iranian Nationals for City of Atlanta Ransomware Attack. 5 December 2018. Dated charging account, not conviction or full forensic report. https://www.justice.gov/usao-ndga/pr/atlanta-us-attorney-charges-iranian-nationals-city-atlanta-ransomware-attack

[2] United States v. Savandi and Mansouri. District of New Jersey indictment, November 2018. Primary legal document; campaign-wide allegations must not be assigned wholesale to Atlanta. https://www.justice.gov/usao-nj/press-release/file/1114791/dl

[3] Keisha Lance Bottoms. Written testimony to the House Subcommittee on Cybersecurity, Infrastructure Protection and Innovation, 25 June 2019. Original testimony preserved by the National Security Archive; recovery cost is explicitly to date. https://nsarchive.gwu.edu/sites/default/files/documents/6826634/National-Security-Archive-088-Testimony-Of.pdf

[4] U.S. Treasury. Designation of Iran-based Financial Facilitators of Malicious Cyber Activity. 28 November 2018. Financial-facilitation context, not independent proof of state direction for the Atlanta incident. https://home.treasury.gov/news/press-releases/sm556

