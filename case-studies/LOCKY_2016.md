# Locky 2016: Ransomware Distribution as an Adaptable System

*A TeamStarWolf case study. Published 15 November 2026.*

[All case studies](/case-studies/README.md) · Related: [Ransomware Defense Reference](/RANSOMWARE_DEFENSE_REFERENCE.md), [Malware Analysis Reference](/MALWARE_ANALYSIS_REFERENCE.md), [Email Security Reference](/EMAIL_SECURITY_REFERENCE.md), [Attack Campaigns Reference](/ATTACK_CAMPAIGNS_REFERENCE.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Email and endpoint security teams, ransomware defenders, detection engineers and incident responders

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 20 min (4,627 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You want an evidence-bounded account of Locky's 2016 delivery system, you need to separate delivery, execution, reachable data and recovery as different stages, or you are countering a single-lure view of ransomware

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Executive assessment](#executive-assessment), [Delivery, execution, and impact are different stages](#delivery-execution-and-impact-are-different-stages), [Payment is not a recovery test](#payment-is-not-a-recovery-test)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Ransomware Defense Reference](/RANSOMWARE_DEFENSE_REFERENCE.md), [Malware Analysis Reference](/MALWARE_ANALYSIS_REFERENCE.md), [Email Security Reference](/EMAIL_SECURITY_REFERENCE.md), [Attack Campaigns Reference](/ATTACK_CAMPAIGNS_REFERENCE.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

Key takeaways (reviewed 2026-11-17):

- Locky challenges the idea that a ransomware family has one delivery method, one operator and one simple preventive control. ([Executive assessment](#executive-assessment))
- Reporting described malicious documents, script attachments, intermediate downloaders and exploit-kit delivery, different routes to the same outcome. ([Executive assessment](#executive-assessment))
- Prevention, containment and restoration are separate responsibilities. ([Executive assessment](#executive-assessment))
- Removing a malicious executable does not reconstruct encrypted data. ([Executive assessment](#executive-assessment))

<!-- meta:end -->

## Executive assessment

Locky is a useful case study because it challenges the comfortable idea that a ransomware family has one delivery method, one operator, and one simple preventive control. Contemporary reporting described malicious documents, script attachments, intermediate downloaders, and exploit-kit delivery. Those are different routes to a damaging outcome, not interchangeable descriptions of the same event. A defender who recognizes a ransomware name but misses the surrounding delivery system can remain exposed after blocking yesterday's attachment type.

This study focuses on documented observations during the early 2016 emergence and adaptation of Locky. It is not an account of a single victim's complete incident. It does not estimate worldwide infections, ransom revenue, or total financial loss. The available sources support a campaign and malware-family case study, with stronger evidence for particular observed delivery chains than for a complete view of the criminal organization. Later operational lessons below are original analysis, not claims that named victims implemented them.

The central conclusion is operational: prevention, containment, and restoration are separate responsibilities. Blocking an entry path does not prove that already affected machines are clean. Removing a malicious executable does not reconstruct encrypted data. A backup that exists but cannot be restored within a tolerable interruption is not a completed recovery capability. These distinctions are more useful than treating ransomware defense as a single antivirus purchase or a reminder to employees to be careful.

## Scope and evidence rules

The reconstruction rests on primary sources: two contemporary Proofpoint investigations, a Unit 42 exploit-kit report, a Canadian government alert, and Microsoft's malware-family entry. Vendor reporting is primary evidence for what the vendor observed and analyzed. It is not automatically independent confirmation of every other vendor's observation. Government advice establishes what authorities communicated at a particular time; it does not supply a census of victims.

Dates are handled conservatively. Proofpoint explicitly identified February 16, 2016 as its first observation in the early report. Microsoft's page displays an earlier publication date and a later update date. These are different records, not a basis for inventing a universal discovery day. The defensible narrative is that Locky was documented in early 2016, with specific campaign observations attached to their reporting organizations. [1, 5]

The case avoids live malicious infrastructure, executable samples, and reproduction instructions. Historical indicators are not reproduced as an operational blocklist because their continuing relevance has not been tested. No current product effectiveness claim follows from a 2016 description. Source-backed history is kept compact; the longer response framework and exercises are expressly analytical additions for readers assessing their own environment.

## What the early reporting established

Proofpoint's initial report described invoice-themed Word attachments whose macros retrieved Locky. It connected the observed spam distribution to infrastructure used for Dridex campaigns and described a related Neutrino observation. The researchers treated a common actor or affiliate distribution as possible explanations for the relationship. They also documented ransom instructions and file encryption, while explicitly stating they had not confirmed that payment would produce a decryptor. [1]

This supports an association between observed distribution activity. It does not establish that Locky and Dridex are the same malware, that every Locky campaign had the same controller, or that the researchers had identified every participant. In a case study, those distinctions prevent an appealing but unsupported shortcut: converting shared delivery into a complete attribution claim.

A later Proofpoint investigation documented changes in attachments and an intermediate downloader called RockLoader. Its March 31 observation involved compressed JavaScript; the report also described variation in archive types and filenames. The useful finding is adaptation across the delivery chain, not a claim that every Locky infection passed through RockLoader. [2]

Unit 42 separately documented Nuclear exploit-kit traffic delivering Locky on March 15 and 16. Its account placed these observations alongside earlier malicious email and Neutrino delivery. It described both direct payload delivery and a downloader stage. This is evidence against defining Locky exclusively as a macro-email problem. It is not evidence that every browser visit was dangerous or that every infection exploited a browser vulnerability. [3]

## A bounded chronology

| Period or date | Evidence | What the date does not establish |
|---|---|---|
| Early 2016 | Government and vendor accounts document Locky | A universal first infection date |
| February 16, 2016 | Proofpoint's stated first observation in its early report | First observation by every researcher |
| March 15-16, 2016 | Unit 42 Nuclear delivery observations | The only exploit-kit campaign |
| March 31, 2016 | Proofpoint compressed-script campaign observation | All Locky delivery switched permanently |
| April 1, 2016 | Canadian alert AL16-005 | A global victim total or final assessment |
| January 10, 2018 | Update date displayed on Microsoft's family page | A new 2018 origin for Locky |

Sources: [1-5]. This chronology is deliberately an observation timeline. It does not fill gaps with presumed attacker actions. A campaign may begin before a researcher sees it, and a web page may be updated after its original publication. Precision requires naming which event each date represents.

## The Canadian warning in context

The April 1 Canadian alert identified Locky as an early-2016 ransomware concern affecting individuals and organizations, including healthcare. It described malicious Office documents and compressed files, and emphasized that payment did not guarantee restored access. It also distinguished decrypting data from removing malware. Its defensive advice included tested backups, offline protection, patching, application controls, and least privilege. [4]

The alert mentioned Samas as another ransomware variant. That context should not be rewritten into a statement that Samas and Locky were aliases or that their delivery methods were identical. Broad ransomware warnings often group several threats to communicate common precautions. An analyst must separate those shared precautions from family-specific evidence.

The alert's backup emphasis matters because the resource being defended is a usable business process, not merely the operating system on one laptop. Original analysis: if shared working data becomes unavailable, a relatively small number of compromised clients can interrupt a much larger group of employees. Counting infected computers alone can therefore understate business disruption. This is a risk model, not a measured loss estimate for a particular Locky victim.

## Delivery, execution, and impact are different stages

A useful analytical model divides the episode into five questions. How did material reach the organization? What caused code to execute? What additional components or external services did execution involve? Which data and systems could the resulting process affect? What evidence demonstrates that operations can safely resume? This model is original to the study and is not a claim about an invariant Locky sequence.

The first question belongs partly to messaging and browsing controls. The second involves endpoint execution policy and the context in which a user interacts with a file. The third requires investigation beyond the visible attachment. The fourth depends on permissions, data placement, and accessible services. The fifth requires recovery validation. Different teams may own each boundary, which is exactly why an incident can fall between organizational responsibilities.

A prevention report should name the stage it measured. Quarantining an email is not evidence that an endpoint executed the payload. An endpoint detection is not automatically proof that encryption completed. A ransom note is a useful incident artifact but is not a complete forensic account. The response team should preserve these distinctions even when leadership requests a single headline number.

## Why the macro-only explanation fails

The sources show that malicious macros were important to early observations, but not sufficient to describe the family. Microsoft's entry lists multiple downloader and exploit-kit routes as well as Office attachments. It describes ransomware-related file artifacts and communication before encryption in its analyzed behavior. These are historical family-entry observations, not a guarantee that every sample behaves identically. [5]

Original analysis: a narrow lesson such as "disable macros and the problem is solved" confuses a useful control with complete coverage. A control can be highly valuable against one route while leaving another route unaffected. The right question is which execution paths remain after a policy change, and who is responsible for testing them safely.

An organization can document this without exposing itself to malware. Build an inventory of permitted attachment classes, script execution needs, browser dependencies, and exception owners. Use benign test content approved by the security team to establish whether expected blocks and logging occur. Record an exception's business justification and expiry. Avoid the opposite error of disabling everything without considering essential workflows, because unmanaged workarounds can create new blind spots.

## Distribution relationships and attribution discipline

A shared sender pattern, overlapping infrastructure, or a common downloader can support an investigative link. It does not by itself identify the legal person operating a campaign. Criminal services can be reused, rented, or shared. An analyst should therefore distinguish the malware family, the observed delivery cluster, the infrastructure owner, and the person or group responsible for particular conduct.

For this case, the strongest bounded wording is that Proofpoint associated its observed Locky distribution with an actor and botnet activity it had previously tracked around Dridex. Do not silently upgrade that reporting into a criminal conviction or a complete map of the ecosystem. The article does not name a country as definitively responsible and does not equate language artifacts with nationality. [1]

For internal intelligence, maintain a confidence field and a reason field. A label is useful when it helps correlate evidence, but a label can also conceal uncertainty if it is copied into every subsequent report. A later finding should be able to revise the relationship without requiring a rewrite of all known endpoint facts. That separation improves both analytical honesty and practical incident handling.

## Scope: affected data is not the same as propagation

Original analysis: an endpoint can damage data it has permission to modify without installing malware on the machine that stores the data. Conversely, a shared folder's visible damage does not prove that every client using that folder is infected. These are different hypotheses requiring different evidence. A response plan that assumes self-propagation from encrypted shared files may overstate the mechanism; a plan that ignores other endpoints may miss additional entry events.

Investigators should establish the identity and device associated with suspicious file activity where logs permit. They should identify which accounts had write access, which shares were reachable, and whether timestamps align with endpoint observations. Missing logs should be recorded as a limitation, not filled with certainty. The result can be a bounded statement such as "these folders were affected during this interval; the initiating host remains under investigation."

Permissions deserve attention before an incident. Broad write access can convert a compromised routine account into an organization-wide data problem. Reducing unnecessary access is not an accusation against employees. It is a way to ensure that ordinary work does not require the ability to alter unrelated departments' critical data. Exceptions should be documented rather than assumed to be harmless because they are longstanding.

## Encryption does not answer the exfiltration question

The sources used here do not establish a universal Locky data-theft or double-extortion model. An account of encrypted files should not automatically import the practices of later ransomware groups. Equally, the absence of a data-theft allegation in these historical sources is not a forensic guarantee that no information left any victim environment.

Original response guidance: treat confidentiality and availability as separate investigative workstreams. Availability asks what stopped working and what is recoverable. Confidentiality asks what data might have been accessed or transferred, with what supporting evidence. Teams should resist both premature reassurance and unsupported declarations of theft. A communications lead needs the difference between "not observed," "not yet assessed," and "ruled out within a stated evidentiary scope."

This distinction also affects recovery sequencing. Restoring files may reduce operational interruption without resolving questions about account misuse or external communication. A declaration that the business is functioning again should not be presented as closure of every security question. Each conclusion needs an owner, evidence, and a defined scope.

## The first response decision record

The following is an original decision framework, not a reconstruction of a named victim's response. At initial recognition, appoint an incident lead and establish an independent communications path if normal systems may be affected. Record the trigger, reporting time, systems involved, and immediate business concerns. Avoid forcing employees to keep using potentially affected tools merely to complete the reporting process.

Containment should follow the organization's approved incident procedures and the operational importance of the systems involved. The objective is to stop further harmful activity while preserving enough evidence to understand scope. The appropriate action can differ between an ordinary workstation and a system supporting a safety-sensitive operation. This study is not a substitute for site-specific incident command.

Maintain a running list of what is known, what is inferred, and what requires validation. Include who authorized isolation, restoration, or changes to access. A technically correct action can still create confusion if it is not recorded and communicated. The decision log is especially important when several teams work simultaneously and hand off responsibility between shifts.

## Restoring service requires acceptance criteria

Original analysis: a backup catalog entry is a starting point, not proof of recoverability. A useful restoration exercise identifies the data version, recovery environment, application dependencies, and business owner who can validate the result. A file that opens may still be the wrong version or may be insufficient to resume a process whose database, configuration, or external integration is missing.

Define recovery acceptance criteria before pressure builds. For a shared document service, that might mean selected files open correctly, permissions match approved roles, recent required work is accounted for, and ordinary users can complete a representative task. For an application, it might require transaction consistency and reconciliation by the responsible department. These are examples for local design, not claims that one test suits every system.

Keep the restored environment separated from unresolved sources of risk until the incident team approves reconnection. Record the restoration point and any accepted data loss. Provide employees clear instructions about which files are authoritative, where to report discrepancies, and which systems remain unavailable. Recovery becomes much harder when users unknowingly mix restored and unverified versions of the same material.

## Payment is not a recovery test

Contemporary sources explicitly warned that payment did not guarantee restored access. The early Proofpoint investigators had not verified delivery of a decryptor after payment. Those observations justify caution; they do not quantify a universal probability of successful recovery. [1, 4]

Original analysis: organizations should prepare a decision process rather than improvise one around a countdown displayed by an attacker. That process should involve authorized leadership, legal and incident-response advisers, and any relevant contractual or reporting obligations. This historical study does not offer legal advice or recommend a transaction. It also does not contact an extortion service or test a payment pathway.

Separate the decision from technical promises. Even possession of a functioning decryption tool would not, by itself, demonstrate removal of all malicious components, restoration of trust in accounts, or completeness of recovered data. Leadership should understand the remaining work rather than treating payment, malware removal, and business restoration as alternative names for the same milestone.

## Detection and measurement without inflated numbers

Original detection planning should combine contextual signals rather than rely on an old domain list. Useful categories include unexpected execution after receipt of suspicious content, unusual access to shared data, abnormal file changes, and endpoint alerts consistent with the investigated activity. Analysts must evaluate those categories against normal administrative and business behavior. This is a defensive planning outline, not a tested detection rule or a claim of complete coverage.

Campaign messages, recipients, executed attachments, affected endpoints, encrypted files, and interrupted business services are different units. A report should not add them together. A million attempted deliveries would not mean a million infections; one infected endpoint would not necessarily mean one affected person. State the time window, source, deduplication method, and measurement limitation for any number included.

Useful readiness metrics include time from employee report to triage, time to identify the responsible data owner, proportion of critical services with a validated restoration exercise, and overdue access exceptions. Avoid universal targets unsupported by the organization's needs. Improvement is demonstrated when the same exercise produces faster, more reliable decisions without sacrificing evidence or creating avoidable operational harm.

## A ninety-minute tabletop exercise

This original exercise uses synthetic records only. The scenario begins with several employees reporting unreadable working files and a finance employee forwarding a suspicious invoice message. The facilitator supplies a fictional endpoint alert, an incomplete share-access log, and a backup report whose most recent job succeeded but whose restore test is overdue. No live malicious files, executable payloads, or attacker infrastructure are required.

During the first twenty minutes, ask participants to state their initial scope and competing hypotheses. Which observations support an email-linked event? What additional evidence would connect a particular host to shared-file damage? Who can authorize containment? The facilitator should challenge any leap from a family label to a complete explanation.

During the next thirty minutes, introduce a second affected department with no matching email report. Participants must consider another entry route, a separate delivery event, or a shared-data dependency without assuming one answer. The point is disciplined investigation, not guessing the facilitator's intended malware path. Record what evidence would resolve the disagreement and whether the organization can actually collect it.

During the final forty minutes, require a restoration decision and a leadership update. The update must distinguish confirmed impact, unresolved confidentiality questions, and expected next steps. The exercise succeeds when owners, acceptance criteria, and evidence gaps are explicit. It fails if the group declares victory solely because an antivirus scan is clean or a backup job is green.

## An evidence matrix for a real investigation

The following matrix is an original investigative aid. It does not claim that the historical researchers had access to every listed artifact. Its purpose is to turn an attractive narrative into questions that can be answered, challenged, and updated. A responder should maintain the distinction between evidence that a delivery attempt occurred and evidence that a particular system experienced impact.

| Question | Evidence to request | Important limitation |
|---|---|---|
| Was suspicious material delivered? | Message trace, retained attachment metadata, recipient report | Delivery alone does not prove execution |
| Did a device execute related content? | Endpoint process history and relevant alert context | Retention gaps can prevent a firm conclusion |
| Which data was affected? | File-service logs, affected-file inventory, owner validation | File timestamps alone can be ambiguous |
| Were other devices involved? | Correlated endpoint and identity records | A common share does not imply common infection |
| Can the service be restored? | Isolated restore result and business acceptance test | Backup-job success is not acceptance |
| What remains uncertain? | A documented gap list with owners | Missing evidence is not evidence of safety |

An investigation should retain the raw record separately from the analyst's interpretation where policy allows. If an employee reports that a file was an invoice, that is useful testimony, but it is not the same as an independently examined message and attachment. If a security product names Locky, record the product, detection label, and supporting context. The label may guide investigation without being treated as a complete explanation of every observed symptom.

Time normalization is another practical issue. Email systems, endpoints, and file services may show different time zones or formats. A timeline that silently mixes local time and UTC can imply a sequence that did not occur. Preserve the original timestamp and the normalized value, noting uncertainty where clocks or collection delays matter. This is particularly important when trying to decide whether a file change preceded or followed a containment action.

Evidence preservation also has limits. Teams should follow retention, privacy, and access policies rather than collecting every employee's content without purpose. The goal is enough relevant evidence to answer the incident questions. A disciplined collection plan identifies the system, authorized collector, time range, and reason. That makes later review easier and reduces the risk of creating an unnecessary second store of sensitive information.

## Control ownership and exception management

Original analysis: a control with no accountable owner often becomes an assumption. Messaging administrators may believe endpoint policy prevents risky execution; endpoint administrators may believe the gateway removes all dangerous attachments. Neither assumption demonstrates coverage. Write down which team owns each boundary, how the control is verified, and who approves exceptions.

For email controls, the owner should know which content is inspected and what happens when inspection is unavailable or inconclusive. For endpoint execution, the owner should understand the legitimate business uses that require exceptions. For shared data, the owner should be able to explain why an account needs modification rights. For backups, the owner should be able to demonstrate a restoration outcome rather than merely report completed scheduled jobs.

An exception should identify a business sponsor, affected systems, compensating measures, expiry date, and review condition. A department that needs an unusual attachment workflow should not receive an undocumented permanent exemption simply because a help-desk ticket was urgent. Conversely, removing a necessary workflow without providing a safe replacement may encourage employees to move work into unapproved channels. Security design has to address the job being done, not just the file type being blocked.

A practical review can select one important workflow and follow it end to end. Ask how an external document arrives, how it is opened, where its outputs are stored, who can alter those outputs, and how the service is restored. The resulting control map is not a malware simulation. It is a way of testing whether the organization's stated responsibilities match the actual work. Document disagreements because they often reveal the most consequential gaps.

## Business interruption beyond encrypted files

This section is original impact analysis, not a reported Locky loss calculation. A ransomware incident can interrupt work even when some required data remains available. Employees may be unable to trust a shared folder, use a normal application, access a dependency, or distinguish a safe restored system from one still under investigation. Technical availability and operational confidence can recover at different times.

Build the impact assessment around services and tasks. A finance team may need a specific ledger, approval workflow, and contact route to complete payments. A design team may need project files plus specialized software and license access. A support team may need customer records and communication tools. These examples illustrate dependencies; they do not establish which organizations were affected by Locky or how severely.

For each critical task, identify the minimum acceptable service, tolerable interruption, acceptable data loss, and person authorized to approve a workaround. A manual workaround should have its own reconciliation plan. Otherwise, work completed during the outage can be lost, duplicated, or inconsistently entered when systems return. Recovery planning should include the transition back to normal operations, not stop at the first successful login.

Financial reporting should separate categories. Direct response spending, restoration labor, delayed transactions, lost revenue, and longer-term effects are not automatically additive or equally measurable. Some are expenditures, some are estimates, and some may overlap. Any loss figure added later should state currency, period, accounting basis, and whether it is gross or net of reimbursement. This study deliberately supplies no invented total.

## Communications that preserve uncertainty

Original guidance: a useful internal update states the affected service, known scope, immediate instructions, and next scheduled review. It should not bury the practical instruction under a speculative attribution narrative. Employees need to know whether to stop using a location, preserve a suspicious message, or contact a particular support route. They do not need to diagnose the malware family themselves.

A leadership update can use three short categories: confirmed facts, working hypotheses, and decisions required. For example, confirmed facts might concern inaccessible files; a working hypothesis might connect a delivery event to an endpoint; a decision might concern a business workaround. Keeping these categories separate allows the investigation to change without making every prior update look misleading.

External communications require the appropriate organizational review and applicable obligations. This study supplies no universal reporting deadline or legal conclusion. A historical ransomware label alone does not determine whether a particular notification duty applies. The responsible advisers need facts about affected systems and data, the organization's role, relevant jurisdictions, and the evidence available at the time.

Avoid language that promises more than the investigation can support. "The affected service has been restored and validation is continuing" is different from "the incident is fully resolved." "No transfer was observed in the retained records" is narrower than "no data was stolen." Precise wording is not evasiveness when it accurately explains the evidence boundary and what work remains.

## A practical improvement backlog

The following prioritization is an original planning suggestion, not a standard compliance checklist. Begin with gaps that prevent a sound incident decision: unknown system owners, unavailable contacts, missing service dependencies, and an untested restoration process. These weaknesses can obstruct response even when preventive tools are present. Assign each issue an owner and a completion artifact that another person can inspect.

Next address unnecessary exposure that has a clear business alternative. Examples include outdated exception lists, broad shared-data write permissions, and workflows that depend on users bypassing warnings. The goal is not to remove legitimate functionality indiscriminately. It is to reduce avoidable authority and execution paths while giving employees a workable approved process.

Finally, repeat a small exercise after improvements. Compare the evidence gathered, decisions made, and recovery validation with the earlier run. A revised policy document is useful, but it does not prove that people can execute the process under pressure. Treat unfinished actions as unfinished; do not award completion for purchasing a tool whose deployment and acceptance tests are still pending.

This backlog should remain proportionate. A small organization may combine several roles; a large one may need explicit coordination across departments and suppliers. Both need named accountability, a realistic restoration path, and honest scope statements. Locky's historical importance here is a concrete reminder that changing delivery methods can expose assumptions between those responsibilities.

## Scope discipline as the record grows

Named victim accounts belong in this record only with reliable first-party disclosures, or clearly attributed secondary reporting. Do not attach a famous hospital's loss figure to Locky merely because a ransomware incident occurred during the same month. The malware identification, operational interruption, payment report, and financial estimate each need their own evidence.

Similarly, a technical description should identify the sample or campaign to which a behavior applies. A family label can span changes over time. Avoid presenting one ransom amount, extension, process name, or network requirement as universal. If a later version differs, retain the historical observation and add the dated change rather than rewriting the past as if only the latest behavior existed.

The useful enduring lesson is not that defenders should memorize one 2016 attachment lure. It is that delivery, execution, reachable data, and recovery form a connected system with different owners and different evidence requirements. Locky's early reporting illustrates why a change in one part of that system can invalidate an overly narrow defensive explanation. The response is disciplined scope, layered control ownership, and demonstrated recovery, not exaggerated certainty.

## Sources and reading limits

[1] Proofpoint, early Locky investigation, including its stated February 16 observation. https://www.proofpoint.com/us/threat-insight/post/Dridex-Actors-Get-In-the-Ransomware-Game-With-Locky

[2] Proofpoint, follow-up distribution and RockLoader investigation. https://www.proofpoint.com/us/threat-insight/post/dridex-actors-get-in-ransomware-with-locky

[3] Palo Alto Networks Unit 42, Locky delivery through Nuclear exploit kit. https://unit42.paloaltonetworks.com/locky-ransomware-installed-through-nuclear-ek/

[4] Canadian Centre for Cyber Security, AL16-005, April 1, 2016. https://www.cyber.gc.ca/en/alerts/recent-ransomware-variant-locky

[5] Microsoft Security Intelligence, Ransom:Win32/Locky family entry; displayed publication February 11, 2016 and update January 10, 2018. https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=Ransom:Win32/Locky

Research accessed November 15, 2026. Substantive reporting and selected technical passages were read. No original malware was executed, no victim environment was examined, and no global prevalence or revenue calculation was attempted. Microsoft product recommendations and older platform references are historical context, not current deployment instructions. The source register records claim scope and limitations. The briefing is a condensed companion, not a replacement for this article.
