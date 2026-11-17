# Robinhood, November 2021: Remote Support Abuse, Bulk Data and the Unfinished Corrective Action

*A TeamStarWolf case study. Published 15 November 2026.*

[All case studies](/case-studies/README.md) · Related: [Data Security Reference](/DATA_SECURITY_REFERENCE.md), [Social Engineering Reference](/SOCIAL_ENGINEERING_REFERENCE.md), [Identity and Access Management Reference](/IDENTITY_ACCESS_MANAGEMENT_REFERENCE.md), [Incident Response Reference](/INCIDENT_RESPONSE_REFERENCE.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Identity, support-operations and security teams, incident responders and detection engineers

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 20 min (4,620 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You want an evidence-bounded account of the November 2021 Robinhood incident, you need to separate downloaded, visible and merely reachable data or a regulatory fund from a per-person payment, or you are hardening support against social engineering

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Executive assessment](#executive-assessment), [6. The exposed populations require separate labels](#_6-the-exposed-populations-require-separate-labels), [7. Downloaded, visible and merely reachable](#_7-downloaded-visible-and-merely-reachable)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Data Security Reference](/DATA_SECURITY_REFERENCE.md), [Social Engineering Reference](/SOCIAL_ENGINEERING_REFERENCE.md), [Identity and Access Management Reference](/IDENTITY_ACCESS_MANAGEMENT_REFERENCE.md), [Incident Response Reference](/INCIDENT_RESPONSE_REFERENCE.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

Key takeaways (reviewed 2026-11-17):

- Robinhood's November 2021 breach shows why social engineering cannot be reduced to an employee making a bad decision. ([Executive assessment](#executive-assessment))
- An outsider persuaded an employee to allow remote control of a company computer that already had access to internal systems. ([Executive assessment](#executive-assessment))
- A June 2021 warning involving remote-access software went unheeded; a known signature was blocked but the broader restriction stayed incomplete. ([Executive assessment](#executive-assessment))
- Central to the case: the failure to generalize a lesson from one observed tool to the underlying access capability. ([Executive assessment](#executive-assessment))

<!-- meta:end -->

Historical focus: the November 3, 2021 customer-information incident, contemporaneous disclosures, and relevant findings in the Massachusetts January 2024 consent order and SEC January 2025 order. This is defensive research, not investment advice, a present-day compliance assessment or a complete review of Robinhood litigation.

## Executive assessment

Robinhood's November 2021 breach demonstrates why social engineering cannot be reduced to an employee making a bad decision. The public record describes an outsider persuading an employee to allow remote control of a company computer. That endpoint already had access to internal systems. The consequence depended on software-installation controls, the reach of the employee's permissions, the ability to obtain bulk information and the practical availability of incident reporting. The initial conversation mattered, but it did not explain the whole loss.

The later SEC order makes an earlier warning especially important. It describes a June 2021 incident involving remote-access software, an investigation that found no evidence of sensitive-information access in that earlier event, and an identified corrective action to prevent and detect unapproved remote tools. A known digital signature was blocked, but the broader restriction remained incomplete before the November incident. The failure to generalize a lesson from one observed tool to the underlying access capability is central to this case. [3]

The Massachusetts order contributes a different layer: detailed reporting difficulties, the structure of the exposed information and the legal admissions applicable to its cybersecurity section. These records should be compared, not silently fused. One describes the caller as impersonating human resources, while the SEC describes impersonation of IT. Both support an internal-authority pretext and remote access, but the exact pretext remains source-dependent in this study. [3-4]

The defensible conclusion is narrower and more useful than a headline about millions of hacked trading accounts. Millions of people's contact information were involved, with smaller groups experiencing more extensive exposure. The record does not establish that all those individuals had their trading accounts taken over or their funds stolen. It also shows that affected people could include applicants who never became customers. Protection must follow the information, not only the active-account relationship.

## 1. Sources and evidentiary posture

The November 8, 2021 disclosure, preserved as an SEC filing exhibit, establishes what Robinhood publicly said at that time. The November 16 update adds information about phone-number entries. These are company statements made while investigation continued. The filing location does not convert the company's words into independent SEC findings. Where the company expressed a belief about excluded data or financial loss, this study preserves the attribution and date. [1-2]

The January 13, 2025 SEC administrative order is a later enforcement record. Its relevant sections describe unauthorized remote access and remediation. The order resolved a broad collection of matters, not only this breach. Certain recordkeeping and reporting findings were admitted, but the cybersecurity findings discussed here were among the other findings resolved without admission or denial. They are SEC findings in a settled proceeding, not a criminal conviction or a finding after a contested trial. [3]

The January 2024 Massachusetts consent order has a different admission structure. Robinhood Financial admitted the factual allegations in Section VI(B), the cybersecurity section, while neither admitting nor denying the violations of law. That distinction prevents a generic statement that Robinhood admitted everything or nothing. The order also addressed other business practices, making it unsuitable to treat the entire monetary penalty as a priced assessment of this breach alone. [4-5]

This research reads the cybersecurity sections, relevant definitions, remedy provisions and legal posture of the orders. It does not claim to have independently audited the underlying forensic evidence or exhaustively analyzed every unrelated trading, recordkeeping or digital-engagement issue. The SEC's announcement supplies a useful overview of the broad settlement, but the order controls the detailed description used here. [3,6]

## 2. Chronology: warning, recurrence and disclosure

On June 14, 2021, according to the SEC order, an unauthorized party persuaded an employee to install remote-access software and permit control of a company computer. After that session ended, the security team investigated and found no evidence that sensitive Robinhood or customer information had been accessed. The absence of evidence of sensitive access in June did not eliminate the demonstrated ability to obtain an employee's desktop. [3]

The SEC describes an official incident report around June 28 identifying prevention and detection of remote-desktop tooling as a corrective action. Robinhood blocked the known digital signature of the tool used in that event, among other actions. The order says it did not block all unapproved remote-access software on company computers until after November 3. This is an important distinction between a response to a specific artifact and a restriction on the broader risky behavior. [3]

On November 3, another unauthorized party carried out a similar attack against a different employee. The SEC describes a different version of the same remote-access software and roughly four hours of remote access. The Massachusetts account supplies the local event sequence: an initial call around 6:07 p.m., installation around 6:31 p.m., further calls and a reboot at 11:33 p.m. that ended the remote connection. The document does not label these timestamps with a time zone, so this study does not convert them to UTC. [3-4]

Robinhood publicly disclosed the incident on November 8. It said an extortion demand followed containment, law enforcement had been informed and Mandiant was assisting. Its November 16 update added that several thousand entries contained telephone numbers and that other text entries remained under analysis. Neither notice establishes a payment amount or proves that an extortion payment was made. [1-2]

The January 2024 Massachusetts resolution and January 2025 SEC resolution are later milestones in accountability. They must not be treated as contemporaneous November 2021 knowledge. A well-constructed timeline shows when information became public, when an event occurred and when a regulator later described it. Otherwise, a reader may mistakenly assume that the original announcement contained all the detail revealed years later.

## 3. What the caller could influence

Both enforcement records describe an impersonation attack using an apparently internal phone number. The Massachusetts order says the caller claimed to be a human-resources employee conducting a supposed authorized investigation and demonstrated internal knowledge, including a supervisor's name and a nonpublic system name. The SEC characterizes the caller as posing as an IT employee. The record available here does not establish why those descriptions differ. This study retains the difference rather than inventing a transition between the two roles. [3-4]

The common mechanism is nevertheless clear enough for defensive analysis. A display of familiarity made the request appear connected to legitimate organizational authority. The employee then installed a remote-access application on the employer-issued laptop and allowed the outsider to use it. The Massachusetts order identifies the software as AnyDesk. Its use in this incident does not mean the application is inherently malicious or that all legitimate remote-support work is unsafe. [4]

The boundary crossed was authorization. A remote-support application becomes dangerous when an unverified outsider can operate an endpoint that already holds legitimate access. The software can work exactly as designed while serving the attacker's purpose. This matters because a security program that detects only malware may overlook abuse of tools whose ordinary business use is benign.

A trustworthy support workflow needs an independent way to establish that a request is real. Caller identification and knowledge of coworkers are insufficient on their own. The defensive principle is to reconnect through an established internal channel or a verified support process before granting control. This study does not provide a persuasive script for impersonation or instructions for reproducing the historical access.

## 4. Why the June lesson did not close the November path

The SEC's sequence illustrates a familiar remediation problem. An investigation identifies a technique, but implementation focuses on the particular file or signature observed. Blocking that artifact can be a useful immediate measure. It is weaker than verifying that the organization's policy now prevents unapproved remote control regardless of the particular version used. The later event described in the order used a different version, showing why the scope of the corrective action mattered. [3]

The appropriate engineering question is what behavior the organization intends to prohibit and how that behavior can occur through approved and unapproved routes. A software list, installation policy and endpoint control should agree. If policy requires engineering approval, the technical environment should either enforce that approval or detect and rapidly interrupt exceptions. A policy that depends entirely on perfect compliance leaves the employee as the last effective barrier.

Closure evidence should test a representative class of unapproved remote tools in an isolated, authorized environment. That does not require publishing evasion methods. It requires verifying that the restriction applies beyond one previously encountered executable. Test results should record which employee device groups are covered, how exceptions work and whether alerts reach someone with authority to respond.

A corrective-action ticket should also have a named owner, implementation deadline and acceptance criterion. If the broader control cannot be deployed promptly, leadership should explicitly approve and monitor interim risk. The case does not establish every internal decision made after June. The lesson is therefore a proposed governance improvement, not an invented account of who rejected which budget request.

## 5. The employee session as an access bridge

The SEC order states that the unauthorized party accessed confidential front-end systems after gaining control of the employee's computer. This is different from proving compromise of a database administrator account or a vulnerability in the public trading application. An already authorized endpoint and its session can bridge an attacker into business tools without requiring the attacker to authenticate directly to each underlying service in the same way a normal remote user would. [3]

That distinction limits what multifactor authentication alone can guarantee. Strong login authentication is valuable, but it does not automatically stop someone controlling a device after a legitimate user has signed in. The case does not provide enough detail to declare that a particular multifactor mechanism failed. It instead supports reviewing the conditions under which sensitive actions are possible inside an existing session.

Sensitive actions may warrant fresh verification, narrower permissions or a separate approval. Examples include downloading a bulk contact file, changing account-recovery information or revealing unusually extensive account details. These are proposed controls for comparable organizations. The public record does not enumerate every action available through Robinhood's interface or establish that every example occurred in this incident.

The Massachusetts order says the employee left the device unattended during part of the event while remote access continued. That fact makes session duration and visibility relevant, but it does not justify blaming the employee alone. Good controls should limit the damage when a user is deceived, distracted or unsure whether an apparent authority can be challenged. The system should make an unauthorized remote session difficult to start and easy to report. [4]

## 6. The exposed populations require separate labels

The SEC order describes email addresses for approximately five million people and full names for a different group of approximately two million. For about 310 people, additional information included names, dates of birth and ZIP codes. Within that group, approximately ten customers had more extensive account details exposed. These categories have different sensitivity and must not be flattened into seven million identical records containing every field. [3]

The November 16 company update adds several thousand phone-number entries to the description of the list. It does not present these as a wholly separate population that can simply be added to the initial estimates. A count of entries also needs care: it is not automatically a count of unique people. The revised disclosure demonstrates why incident communications need a versioned scope table rather than one headline number that never changes. [2]

The Massachusetts order identifies at least 117,763 individuals who had supplied a Massachusetts address in the bulk file. It explicitly says the names, email addresses and phone numbers did not appear together as associated fields. It also says the individuals could include current customers, former customers and applicants who never became customers. Those qualifications are important: a geographic population is not an additional nationwide breach total, and the file is not described as a complete linked profile for each person. [4]

The state order separately describes three Massachusetts individuals with additional identifying information. It describes internal screens containing information about roughly eight other customers, none Massachusetts residents, which the outsider may have seen. That is not identical wording to the nationwide estimate of approximately ten customers with extensive details. The two accounts have different scope and precision. This study does not force them into an exact arithmetic reconciliation the sources do not supply. [3-4]

## 7. Downloaded, visible and merely reachable

The Massachusetts order distinguishes the bulk file obtained from information in internal systems that was not downloaded. It also preserves uncertainty about information the outsider may have seen on screens. These are three different evidentiary states. A downloadable export, a viewed record and a record theoretically reachable through an account may require different investigation and notification analyses. [4]

A forensic scope matrix should therefore record both the data category and the evidence of access. It should not assume that a lack of a download event proves that nobody viewed a record. Conversely, it should not assume that every record in a reachable application was necessarily read. Browser activity, application logs, export logs and endpoint evidence can support different conclusions, and each source has coverage limits.

The matrix should include timestamps and confidence. For example, an exported file may have a strong record count but uncertain deduplication, while a screen-access event may identify a small number of records with uncertain viewing duration. Investigators should preserve those distinctions in internal working papers so that external summaries can be concise without becoming misleading.

The record reviewed here does not expose the entire logging architecture or every forensic artifact. This case study cannot reconstruct exact attacker navigation, prove a complete exfiltration inventory or assign a precise exposure probability to every person. It can show why a business should retain the evidence needed to answer those questions before an incident occurs.

## 8. Reporting friction after recognition

One of the most instructive portions of the Massachusetts order concerns the employee's attempts to raise the alarm. It describes difficulty finding a reporting telephone number, unsuccessful attempts through a general contact number, an ethics hotline that reached an automated service, and several messages requesting urgent help. A relative also attempted to locate a suitable contact route. These details show a reporting process that existed in principle but was difficult to use under pressure. [4]

The order places the first general-number attempts at 11:13 p.m. and 11:20 p.m., before the 11:33 reboot that terminated the remote connection. It then describes later messages through internal channels, an automated help response, a security ticket at 12:52 a.m. and a callback at 12:55 a.m. The timeline must not be retold as if every reporting attempt began only after the reboot. [4]

This is a practical usability problem as well as an organizational one. A worker who suspects compromise may not know the incident category, may fear consequences or may have lost access to the normal help portal. A reporting route should accept uncertainty, recognize urgency and reach a person able to isolate the endpoint or revoke a session. An automated acknowledgment is not the same as effective escalation.

A useful exercise is to ask a representative employee to report a simulated compromise outside normal business hours without advance coaching. The test should measure the time to find a route, the time to human acknowledgment and the time to a containment decision. The purpose is to repair the process, not to embarrass the participant. A successful daytime demonstration by the security team does not establish that the process works for everyone.

## 9. Training chronology and the danger of simplistic blame

The Massachusetts order records that the employee had completed onboarding security training, annual privacy training and customer-service social-engineering training. It also records that the 2021 annual security course had not yet been completed. That course had been released on November 1 and was due November 12, after the November 3 breach. Describing the employee as having ignored an overdue annual requirement would therefore be inaccurate. [4]

Training can teach employees to question an unexpected request, but it cannot guarantee that every plausible call will be rejected. In this case the broader record includes remote-software controls and reporting difficulties. The correct lesson is to combine education with enforceable restrictions and usable escalation, not to choose between technical controls and human preparation.

Training effectiveness should be measured by the decisions employees can make and the help they can obtain. A completion percentage says that a module was finished, not that a person can authenticate a caller during a stressful interaction. Scenario exercises should include a safe way to stop, verify and report without penalty for challenging an apparent internal authority.

Managers also need preparation. An employee who reports a possible compromise should not have to navigate ordinary queue priorities repeatedly. Supervisors should know which channel reaches the security responder and what minimal facts to collect. They should avoid demanding an elaborate narrative before initiating containment. The case's reporting history makes that managerial layer as relevant as the employee's initial recognition.

## 10. Containment, extortion and customer harm

The contemporaneous notice said the intrusion had been contained and that an extortion demand followed. It also said Robinhood believed that Social Security numbers, bank-account numbers and debit-card numbers were not exposed, and that the incident had caused no customer financial loss. These are dated company representations, not an unlimited guarantee about all future misuse. The notices do not establish that ransomware encrypted systems or that Robinhood paid the demand. [1-2]

Contact-data exposure can still create risk without direct theft from a brokerage account. A message that refers to a real service relationship may be more credible than a generic scam. A phone number can create another contact route. Additional identifying details may help an attacker make a pretext seem familiar. These are plausible consequences of the exposed data categories, not claims that every affected person experienced a subsequent fraud.

Containment should also be defined technically. Ending one remote session is an immediate action. A broader response must determine whether other sessions, tools or access paths remain, preserve evidence and establish the scope of data access. The public documents do not provide a complete minute-by-minute containment record. This study does not treat the endpoint reboot as proof that every possible incident consequence ended at that moment.

Customer communication should identify the recipient's actual data category when the evidence allows. Someone whose email address appeared in a bulk file should not receive language implying that trading history was definitely stolen. Someone with more extensive exposure should not receive a reassurance tailored only to contact information. The state order's varied populations show why one generic notice may not answer every individual's most important question.

## 11. Regulatory consequences without misleading totals

The Massachusetts consent order imposed a $7.5 million administrative fine as part of a resolution addressing digital-engagement practices, infrastructure and supervision as well as cybersecurity. Its consultant-review provisions specifically included employee access controls, the ability to download third-party software and bulk files, incident reporting and reliance on the parent company's cybersecurity policies. The amount is a settlement-wide fine, not a breach-only damage estimate. [4-5]

The SEC's January 2025 action imposed combined civil penalties of $45 million: $33.5 million for Robinhood Securities and $11.5 million for Robinhood Financial. The action covered numerous securities-law issues, including reporting, recordkeeping and short-sale requirements in addition to safeguarding information. Adding those penalties to the Massachusetts figure and calling the result the cost of the November breach would falsely allocate unrelated portions to this incident. [3,6]

The SEC order does allocate $1 million of each entity's penalty to the combined violations of Regulation S-P safeguarding and Regulation S-ID identity-theft requirements. That is more precise than the $45 million headline, but it still combines distinct regulatory findings. It should not be relabeled as a separately calculated November 2021 breach cost or customer compensation award. [3]

The SEC order also records remediation relevant to remote access: blocking installation and use of remote-access software on company devices, additional access controls for front-end systems containing customer information, and updated social-engineering training. This is the regulator's description of remediation in the settled record. It is not this researcher's independent test of those controls or assurance about their continuing operation today. [3]

Legal posture matters throughout. The cybersecurity facts in the Massachusetts section were admitted. The SEC cybersecurity findings were resolved without admission or denial, while other identified SEC findings were admitted. A study that uses one generic label for both proceedings loses information about the evidentiary basis. It should also distinguish a requirement to pay from independent verification of payment, which this study does not perform.

## 12. Original defensive architecture

For organizations with customer-support tools, the first control objective is to separate an employee's ordinary assistance role from bulk extraction. A worker may need to see enough information to resolve a specific customer's issue without needing unrestricted exports covering millions of people. The precise design depends on the business, but the risk review should require a justification for broad access and record the approving owner.

Bulk exports should have an explicit workflow. That can include a business purpose, scoped fields, a bounded population, approval for unusual requests and logs linking the export to the person and device that initiated it. Alerts should consider both volume and context. A small export of highly sensitive account details may deserve attention even when it is far below a large contact-list threshold.

Remote assistance should use an approved channel with controlled enrollment, session visibility and a defined support identity. The endpoint policy should prevent unapproved alternatives where feasible and rapidly surface attempted use. Exceptions need owners and expiration dates. The goal is to preserve legitimate support while making a cold call insufficient to create broad control over a sensitive workstation.

Application access should consider the device and the current action, not only the fact that a login previously succeeded. A sensitive export or reveal operation can require additional verification through a channel an outsider controlling the screen cannot trivially satisfy. Such controls require usability testing: a design that staff routinely bypass because it blocks ordinary work will not provide durable protection.

## 13. Corrective-action verification plan

A credible remediation plan begins with a baseline inventory. The organization should identify all device groups used for customer support, the remote tools they can run and the internal applications reachable from them. The output should reveal exceptions rather than hide them in an average coverage percentage. A single unmanaged subgroup with broad data access can undermine a program that appears nearly complete.

The next stage is an authorized test of installation restrictions and session detection. The test should use harmless tools and synthetic data in a controlled environment. Reviewers should verify that policy reaches representative devices and that attempted exceptions generate an actionable alert. The result should document what failed safely and what still requires manual intervention. This is validation of defenses, not a recipe for bypassing them.

A separate test should examine data access. A representative support role should be able to perform required customer work but unable to obtain an unjustified bulk file. Where bulk access is legitimate, the reviewer should trace approval and audit records. The acceptance criterion must describe the permitted business outcome as well as the prohibited action so that security does not accidentally make the support function unusable.

Incident reporting needs its own acceptance test. The organization should simulate loss of access to the employee's normal device and verify an alternative route. After-hours testing should reach a human responder with a clear escalation path. Metrics should include time to acknowledgment, time to a containment decision and the percentage of test reports that reach the correct team without repeated redirection.

Finally, an independent reviewer should sample completed corrective actions and challenge their closure evidence. A blocked historical signature is not enough to close a broader promise about unapproved remote access. A training assignment is not enough to close a promise about usable reporting. The lesson from the June-to-November sequence is to verify the intended security property, not merely the existence of a completed task.

## 14. Fictional tabletop exercise

This exercise is fictional and introduces no new allegation about Robinhood. A support employee receives an unexpected call from someone claiming an internal role. The employee begins a remote-support session and later becomes suspicious. The first exercise objective is whether the employee can stop and verify the request through a trusted channel without needing to identify the exact technical threat.

The second inject is an alert showing an unusual export from an internal support application. Responders must connect the endpoint event to application activity, preserve relevant logs and distinguish downloaded records from merely reachable ones. They should identify the fields and populations before drafting a customer notice. The exercise should not reward a fast but unsupported claim that all accounts are safe or all accounts are compromised.

The third inject is a prior incident ticket that recommended broader remote-tool restrictions but closed after one signature was blocked. Leadership must decide how to reopen the corrective action, assess coverage and document interim risk. The exercise ends when owners can show evidence of restricted remote access, controlled exports and a working reporting route, rather than when they finish a slide describing lessons learned.

## 15. Final judgment and research limits

The strongest lesson is the interaction between known risk and incomplete implementation. A plausible call opened the path, but the later record shows multiple opportunities to reduce the consequence: broader restrictions on unapproved remote control, narrower access to customer information, controls on bulk files and a reporting process that works under pressure. None depends on assuming that every employee will always recognize deception.

The sources retain meaningful uncertainties. The pretext differs between the state and federal accounts. The populations and exposure descriptions do not form a single exact reconciled ledger. The public record does not establish a complete forensic timeline, an extortion payment or a universal customer-loss outcome. This study preserves those limits and does not infer malicious intent by the employee.

Robinhood's case is therefore best taught as an access-control and response-design study grounded in a documented social-engineering incident. It demonstrates how a legitimate workstation can become a route to information and how a near miss can remain dangerous when the corrective action addresses only the last observed artifact. The measure of improvement is whether the next comparable attempt is prevented, limited or rapidly contained, with evidence that survives review.

## Source register

[1] Robinhood, November 8, 2021 security notice, preserved as Exhibit 99.1. Read full notice; dated company account and beliefs, not independent SEC findings. https://www.sec.gov/Archives/edgar/data/1783879/000178387921000073/exhibit991november82021blo.htm

[2] Robinhood, November 16, 2021 incident update. Read substantive update and original notice; additional phone entries and investigation caveats. https://robinhood.com/newsroom/robinhood-announces-data-security-incident-update/

[3] SEC, Release 34-102170, January 13, 2025. Read legal posture, summary, paragraphs 74-79 and 102, and relevant penalty/remedy material; unrelated trading sections not fully analyzed. https://www.sec.gov/files/litigation/admin/2025/34-102170.pdf

[4] Massachusetts Securities Division, Robinhood consent order, January 2024. Read preliminary statement, Section VI(B), relevant legal posture and order provisions. Cybersecurity facts admitted; violations of law neither admitted nor denied. https://www.sec.state.ma.us/divisions/securities/download/RH-Consent-Order.pdf

[5] Massachusetts Secretary of the Commonwealth, enforcement announcement, January 18, 2024. Read Robinhood announcement; broad settlement context. https://www.sec.state.ma.us/divisions/news/enforcement-news.htm

[6] SEC, announcement of combined $45 million penalties, January 13, 2025. Read full announcement; broad settlement includes multiple unrelated securities-law matters. https://www.sec.gov/newsroom/press-releases/2025-5
