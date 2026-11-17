# Home Depot 2014: Payment Data, Vendor Access and the Cost of Unverified Boundaries

*A TeamStarWolf case study. Published 15 November 2026.*

[All case studies](/case-studies/README.md) · Related: [Network Security Architecture](/NETWORK_SECURITY_ARCHITECTURE.md), [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md), [Data Security Reference](/DATA_SECURITY_REFERENCE.md), [Vendor Prevention Policies](/VENDOR_PREVENTION_POLICIES.md), [Target, 2013](/case-studies/TARGET_2013.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Retail and payment security engineers, vendor-access and identity owners, detection engineers and risk leaders

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 21 min (4,718 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You want an evidence-bounded account of the 2014 Home Depot breach, you need to separate cards from email addresses from people or gross cost from net and settlement figures, or you are reviewing vendor access, payment-environment boundaries and EMV and encryption claims

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Executive assessment](#executive-assessment), [4. Initial credentials and subsequent authority](#_4-initial-credentials-and-subsequent-authority), [10. Financial accounting and the danger of a single total](#_10-financial-accounting-and-the-danger-of-a-single-total)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Network Security Architecture](/NETWORK_SECURITY_ARCHITECTURE.md), [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md), [Data Security Reference](/DATA_SECURITY_REFERENCE.md), [Vendor Prevention Policies](/VENDOR_PREVENTION_POLICIES.md), [Target, 2013](/case-studies/TARGET_2013.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## Executive assessment

Home Depot's 2014 payment-data compromise is a useful case for studying how a legitimate business relationship can become an entry point without being the entire cause of a breach. The important analytical question is what authority an intruder acquires after entering. An account that does not itself permit access to payment terminals can still become consequential when subsequent actions cross additional security boundaries. This study examines that distinction while refusing to fill gaps in the public record with an invented exploit chain.

The case also demonstrates why a breach should have several ledgers. A technical ledger describes affected systems and data. A population ledger distinguishes cards, email addresses and people. A financial ledger separates recorded expense, expected insurance recoveries, cash reimbursements and subsequent regulatory settlements. Combining those categories into one impressive headline obscures the information that decision makers need. Different figures can all be accurate while answering different questions.

The historical evidence below comes from company announcements and securities filings, a state regulator's announcement, and the executed multistate assurance posted by New Jersey. Contemporary PCI Security Standards Council and EMVCo explanations provide limited conceptual context. They do not establish which standards applied in 2014 or certify the retailer's past implementation. Recommendations, control tests and the fictional exercise are original defensive analysis for comparable organizations. They are not additional findings about Home Depot.

## 1. Evidence boundaries and reading method

An official company statement is strong evidence of what the company disclosed on that date. It is not a substitute for the underlying forensic record. A financial filing is particularly useful for the accounting period and the categories it reports, but it may deliberately leave losses unquantified. A regulatory settlement can establish agreed obligations without proving every historical allegation. These differences matter throughout the study.

The selected record does not establish a named vendor, the method by which that vendor's credentials were stolen, or a specific privilege-escalation vulnerability. It also does not provide enough evidence here to assign the intrusion to a particular named criminal group or malware family. Readers should resist importing details from another retailer's incident simply because both involved payment systems and a third party. Similar business models do not establish identical attack paths.

The financial filings were reviewed for relevant breach disclosures rather than audited in their entirety. Likewise, the settlement analysis focuses on the security obligations, payment provisions and legal qualifications relevant to this case. This is a historical research synthesis, not a legal opinion or an assessment of Home Depot's current security. No present-day penetration testing, account access or internal-document review was performed.

A useful reading convention is to ask whether each paragraph reports a dated fact or proposes a lesson. Sections introducing an official source identify it explicitly. The surrounding operational discussion explains what a comparable retailer could test, how to interpret the result, and which uncertainties would remain. That structure prevents a reasonable security recommendation from silently turning into an unsupported accusation about a historical organization.

## 2. Discovery, containment and disclosure chronology

On 8 September 2014, Home Depot confirmed a payment-system breach. Its filing said the investigation began on 2 September after information from banking partners and law enforcement, and potentially affected customers who used cards in United States and Canadian stores from April onward. It reported no evidence at that time of an impact on Mexican stores, online purchases or debit PINs. Those were dated investigation statements, not permanent guarantees. [1]

On 18 September, the company said it had eliminated the malware, removed compromised terminals from service and closed the entry route. It estimated that approximately 56 million unique payment cards were at risk. The announcement also said a payment-encryption project begun in January had completed its United States rollout on 13 September, with Canadian deployment expected later. The public account describes company-reported containment, not independent verification performed for this study. [2]

The later New York attorney general announcement identified 10 April through 13 September 2014 as the relevant United States self-checkout exposure window. Its 2020 regulatory perspective should not be mistaken for something that was publicly known on the first day of disclosure. A defensible timeline preserves both the event date and the date on which a source reported it. [6]

For incident managers, discovery, first malicious activity, last observed malicious activity and notification are separate timestamps. A long observed window does not prove continuous attacker presence at every terminal. Conversely, the absence of an event in a particular log does not establish that nothing happened during a period when the log was unavailable. Reports should explain the evidence supporting each boundary and assign an owner to unresolved time intervals.

A practical chronology should include the time zone, source system, confidence level and whether the timestamp represents occurrence or observation. Banking intelligence, endpoint evidence and executive announcements can be accurate while using different clocks. Analysts should reconcile those clocks before measuring detection or containment performance. The objective is not a cosmetically precise timeline. It is a sequence that another investigator can reproduce and that leadership can use without misunderstanding its limits.

## 3. Cards, addresses and consumers are different units

Home Depot's November update described a separate set of approximately 53 million email addresses. It said those files did not contain passwords, payment-card information or other sensitive personal information. That limitation referred to the email files, not to every dataset involved in the incident. The company warned customers about phishing. The email count should not be added to the payment-card count to produce a total number of distinct victims. [3]

The 2020 state announcement described approximately 40 million consumers nationwide. That is a different geographic and counting unit from unique payment cards across the United States and Canada. The reviewed material does not provide a complete reconciliation. A person can use multiple cards, share contact information or appear in more than one dataset, but those general possibilities do not establish the actual overlap here. [6]

For a comparable investigation, the population workbook should have one row per asserted population, rather than one row per press release. Useful columns include the data object counted, geography, time window, deduplication method and source date. The workbook should explicitly distinguish a payment account from a person and an email address from an authenticated account. A total should be published only when the underlying linkage and exclusions support it.

Notification teams need a second view of the same evidence: what each recipient may have lost and what action is useful. A customer whose address appears in a separate email file should not automatically receive a message asserting that their card was taken. Equally, uncertainty about linkage must not become a reason to omit a warning that the evidence does support. The process needs a documented rule for uncertain membership and a way to correct earlier messages.

Metrics should preserve both the initial estimate and subsequent revisions. Replacing an old number without a dated explanation makes the investigation appear inconsistent and prevents reviewers from understanding how the evidence improved. The better presentation is a small history of estimates, with the reason for each change. Precision is valuable only when it reflects the quality of the underlying evidence rather than the number of digits in a dashboard.

## 4. Initial credentials and subsequent authority

The November company findings said attackers used a third-party vendor's username and password to enter the network perimeter. Those credentials did not themselves provide direct access to point-of-sale devices. The company described a subsequent elevation of rights, movement through its environment and installation of custom malware on self-checkout systems in the United States and Canada. It did not identify the specific escalation mechanism in that announcement. [3]

The defensive implication is a sequence of authority transitions. First, an external identity receives some permitted connection. Second, an intruder acquires capabilities beyond the purpose of that connection. Third, those capabilities reach a payment-processing system. Each transition deserves its own control and evidence. A review that stops after recommending stronger vendor passwords misses the independent question of why a compromised low-trust relationship can approach a more sensitive environment.

A useful architecture review starts with the vendor's business task. Does the vendor need to retrieve invoices, maintain equipment or administer a particular service? Each task implies different access. The approval should specify permitted systems and operations, not merely membership in a broad access group. If an account can perform actions unrelated to its approved task, the owner should either remove them or explain and accept the exception for a limited period.

Testing should proceed with authorized synthetic identities in a controlled environment. Reviewers can check whether a vendor account can enumerate resources unrelated to the contract, request unnecessary privileges or reuse a session after access is revoked. These are defensive acceptance tests, not instructions to reproduce the historical intrusion. A failed test identifies a boundary requiring repair. It does not prove that the same boundary failed in the 2014 incident.

## 5. Vendor access as a continuing relationship

A procurement questionnaire records what a supplier says about its controls. It does not demonstrate what the retailer's own infrastructure permits that supplier to do. For a comparable enterprise, supplier assurance should therefore connect commercial ownership with technical access. Someone needs authority to say that a maintenance contract has ended, while someone else needs evidence that the corresponding identities and sessions no longer function.

The access register should include named human users, service accounts and any emergency paths. Shared accounts complicate attribution because a successful login may identify an organization rather than the individual who acted. If a legacy service genuinely requires a non-human identity, its allowed operations should be narrow and its credential lifecycle should have an accountable owner. Exceptions need a review date, not indefinite acceptance disguised as documentation.

Offboarding should test more than whether a directory entry is disabled. A supplier may have active sessions, cached credentials, remote-management agents or delegated access in another system. The organization should know which mechanisms terminate automatically and which require separate action. A sample of closed engagements can establish whether the process works in practice. Testing only new onboarding leaves the growing population of forgotten relationships unexamined.

Operational teams also need a workable emergency alternative. If the normal process takes too long to restore a failed checkout service, staff may improvise broad access under pressure. A safer design provides a supervised, time-limited emergency path with explicit approval and retrospective review. Security becomes more durable when it acknowledges the real service obligation rather than assuming that retail operations can simply wait indefinitely for administrative convenience.

## 6. Payment-environment boundaries

A payment terminal is part of a wider operational system. Software distribution, remote support, identity services and logging can influence its security even when those systems do not normally store card data. The architectural question is which components can change payment behavior or obtain sensitive material. Drawing a boundary only around machines labeled as payment devices can overlook the management systems that exercise authority over them.

A comparable retailer should maintain two diagrams. One shows the payment-data path from acceptance to processing. The other shows the administrative path through which configuration and software reach the devices. The diagrams should meet wherever administrative authority can affect payment handling. A clean transaction diagram cannot compensate for an unrestricted management route, and a restricted management route cannot protect unnecessary readable copies elsewhere.

Segmentation tests should include the business operations that staff actually perform. An approved support session may legitimately reach one terminal for a repair while having no reason to reach every store. The evidence should demonstrate the narrow permission and the rejection of broader access. Reviewers should also test whether a central management identity can create a new path that bypasses the intended separation.

These recommendations do not establish the retailer's historical network design. They explain why the publicly described progression deserves more analysis than a single firewall diagram. The desired result is an independently tested boundary that survives a plausible compromise of an adjacent system. If the boundary depends on all adjacent identities always behaving correctly, leadership should understand that dependency rather than treating the payment environment as isolated by definition.

## 7. Detection and terminal integrity

Detection design should start with meaningful changes to the payment environment. A new executable, an unexpected administrative connection or a modification outside the maintenance schedule can be more useful than a large undifferentiated stream of alerts. The challenge is to connect a change to its business authorization and its effect on the payment process. A system that records everything but cannot answer those questions may offer little help during an incident.

For a comparable organization, terminal software should have an approved baseline and an identified distribution owner. Investigators need to distinguish the expected release from local variations and emergency fixes. When a legitimate update changes a file, the change record should explain why. When a change has no matching authorization, the responder needs a defined route to investigate without waiting for several unrelated teams to determine who owns the device.

Alert testing should measure the response, not only signal generation. A synthetic unauthorized change can establish whether the alert reaches the correct queue, whether an analyst understands the terminal context, and whether containment is possible within the business constraints. An alert acknowledged by automation is not equivalent to a human decision or an effective isolation action. Those stages deserve separate timestamps and outcome fields.

The public company description of custom malware should not be stretched into a conclusion that conventional controls could never have helped. Nor does it justify claiming that a particular modern product would certainly have prevented the event. Prevention depends on deployment, configuration, coverage and the adversary's path. The useful lesson is to test layered controls against the organization's own high-value operations and preserve the evidence of how each layer behaves.

## 8. Encryption and EMV solve different problems

Payment encryption seeks to reduce the availability of readable transaction data along a protected path. EMV chip processing uses a transaction-specific cryptographic value to help authenticate the card, reducing the usefulness of copied transaction material for counterfeit activity. EMVCo's current explanation supports that conceptual distinction. It does not establish the precise behavior of every historical terminal or imply that all transaction data becomes confidential merely because a chip reader is present. [9]

The current PCI SSC FAQ states that encryption alone does not remove cardholder data from PCI DSS scope. This is contemporary context, explicitly referring to current requirements, rather than a retroactive finding about 2014 compliance. Likewise, the company encryption announcement should not be relabeled as proof of a particular PCI-listed point-to-point encryption certification without separate evidence. A product description and a formal validation status are different claims. [8]

For a retailer planning a payment upgrade, acceptance criteria should specify where readable data first exists, where encryption begins and where decryption is permitted. The review should ask who controls keys and what happens during terminal replacement, support or fallback operation. A successful transaction proves availability, but it does not prove that every unintended readable copy has disappeared. Security testing needs observations at the relevant boundaries.

Rollout reporting should distinguish installed equipment, enabled functionality and verified protection. A device may contain the necessary hardware before the intended feature is active. A feature may operate in normal conditions while a fallback route behaves differently. Executives should therefore receive coverage figures tied to tested transaction paths, including exceptions. That approach allows a migration to proceed while making residual exposure visible rather than hiding it behind a broad completion percentage.

## 9. Email exposure and secondary harm

An address list can be useful to an impostor even when it contains no passwords. The original analytical concern is credibility: a message that references a real retailer and a real breach may seem more convincing than an unrelated solicitation. The recipient may be induced to disclose credentials or payment information somewhere else. That possible secondary abuse must be described as a risk, not as proof that every exposed address was later used fraudulently.

A well-designed notice gives people a trusted way to verify the message independently. It should explain which categories of information are implicated, avoid requesting sensitive data through an unexpected link, and identify where further updates will appear. The organization should prepare its support staff to answer the same questions using the same dated facts. Conflicting scripts can make legitimate communications resemble scams.

Privacy teams should also review why a large address collection existed and how long it needed to remain available. Retention is a business decision with security consequences. A historical campaign export may offer little operational value while remaining accessible to an intruder. Deletion policies are useful only when they include secondary stores and when an owner can demonstrate that the intended records actually expired.

A post-incident customer strategy should avoid promising complete protection against every future misuse. It can offer clear evidence-based advice and monitor reports of impersonation without claiming to control unrelated criminals. The appropriate measure is whether customers can understand their situation and act through trustworthy channels. Sending the greatest possible volume of notification messages is not, by itself, evidence that the communication worked.

## 10. Financial accounting and the danger of a single total

For fiscal 2014, which ended on 1 February 2015, the company reported $63 million in pretax gross breach expense and $30 million in expected insurance proceeds, yielding $33 million net expense. These are accounting figures for a specified period. They do not mean that every possible claim had been resolved or that the insurance amount was necessarily received as cash during that period. [4]

By 29 January 2017, the fiscal 2016 filing reported cumulative pretax gross expense of $298 million and $100 million in expected insurance recoveries, leaving $198 million net. It separately reported $80 million in insurance reimbursements received and a remaining $20 million receivable. The disclosure included accruals and anticipated further legal and professional costs. Thus the cumulative amount was neither an all-cash figure nor a demonstrated lifetime total. [5]

The later state settlement should remain a separate dated line unless a reconciliation establishes how it interacts with prior accruals. Adding every press-release number to every annual-report number can double count amounts already recognized. Subtracting the full insurance limit as though it were immediately available cash creates the opposite distortion. A careful case study explains the accounting relationship instead of manufacturing a larger or smaller headline.

A response budget should preserve gross cost even when insurance reduces net expense. Operational teams still need to fund investigation and service restoration, while coverage decisions may occur later. The cash-flow view should track invoices, reimbursements and receivables separately. The legal view should track claims and settlements. The accounting view should track recognized expense and accruals. Those views can be reconciled, but they are not interchangeable.

For board reporting, the most useful question is often what remains uncertain. A range of unresolved exposure can be more honest than a single number that quietly excludes material categories. Finance and legal teams should agree on the meaning of each figure before it enters a presentation. The slide title should contain the period and basis, so that the number remains understandable even when copied into another document.

## 11. The 2020 multistate resolution

The New York attorney general announced a $17.5 million multistate settlement in November 2020 involving 46 states and the District of Columbia. The announcement also described security-program commitments. It should be read as a settlement of an investigation rather than a trial verdict. The payment was not described as a simple per-person compensation formula, and dividing it by a breach population would not produce an individual entitlement. [6]

The executed assurance posted by New Jersey provides the more precise obligations. Its effective date was 21 December 2020. It includes governance, account review, risk-based authentication, logging, file integrity, payment-data protection, testing and vendor-access provisions. It also includes a nonadmission clause and states that the agreement does not represent regulatory endorsement. The document calls for an independent assessment on its specified schedule, not an invented requirement for perpetual quarterly assessments. [7]

For a comparable enterprise, the interesting question is how an obligation becomes operational evidence. A policy requiring account review should lead to a population of accounts, a reviewer with sufficient context, a record of decisions and confirmation that removals took effect. A logging obligation should lead to a tested collection path and a process for following up on meaningful events. The existence of the policy alone answers only whether someone wrote it.

Settlement deadlines should be treated as legal milestones with their own owners. The announcement date, effective date, implementation deadline and assessment deadline may differ. A compliance tracker should preserve the exact trigger in the agreement rather than replacing it with a convenient calendar assumption. This study does not establish whether the historical obligations were later fulfilled or assess present compliance. It explains what the public agreement required and how evidence-based follow-through would work.

## 12. Recovery as a set of verifiable claims

A statement that malware has been removed is narrower than a statement that every attacker-controlled capability has been eliminated. Recovery should consider credentials, remote access and administrative changes as well as malicious files. For a comparable retailer, the closure record should list each claimed containment action and the evidence supporting it. Where verification is incomplete, the remaining uncertainty should have an owner and an interim safeguard.

Terminal restoration needs a trusted baseline and a reproducible process. Rebuilding one affected device may be straightforward, while confirming consistent recovery across a large estate is more difficult. Sampling can help, but leadership must understand what the sample represents and what it cannot prove. Exceptions, disconnected devices and devices awaiting replacement should remain visible rather than being omitted from the denominator.

Business recovery and forensic preservation can conflict if restoration destroys useful evidence. The response plan should identify which records must be preserved before a device is rebuilt and how to obtain them without delaying every checkout unnecessarily. This requires prior agreement among operations, security and legal staff. During an incident, ambiguous ownership can force improvised decisions that neither preserve evidence well nor restore service efficiently.

Closure should also include a replay of the relevant authorization tests. If access was restricted, can the former identity still establish a session? If a deployment channel was repaired, can an unauthorized change still reach a terminal? These tests should use safe fixtures and approved environments. The purpose is to demonstrate the repaired boundary, not to reconstruct a live attack or expose customer data in the name of validation.

## 13. A management scorecard with useful denominators

A practical scorecard for a comparable retailer could track the proportion of active supplier relationships whose access has a current business owner. The denominator should include emergency and non-human access, not just easily reviewed employee-style accounts. A second measure could track elapsed time from contract termination to verified loss of access. Both measures are more informative when accompanied by the oldest unresolved exceptions and their business reasons.

Payment protection should be measured against transaction paths rather than purchased devices. The organization should know which routes have been verified, which use fallback behavior and which remain outside the current migration. Administrative separation should have a parallel measure: how many critical management paths have passed an authorized boundary test? A high hardware deployment percentage cannot answer either question by itself.

Detection measures should track successful analyst interpretation and containment, not simply the number of generated alerts. A scheduled exercise can test whether a suspicious terminal change reaches a responder with enough information to act. The result should record missed events and excessive delay as well as success. Otherwise, a dashboard may reward increasing alert volume while making actual response less manageable.

Financial reporting can have a matching discipline. Every breach-related amount should have a period, a category and a reconciliation owner. Insurance receivables should remain distinct from cash reimbursements. Open legal matters should not vanish merely because no reliable estimate is available. A board can make better decisions when the dashboard makes uncertainty explicit and connects each unresolved item to a next action rather than implying that unknown means zero.

## 14. Fictional tabletop: the maintenance account

This exercise is fictional and adds no facts about Home Depot. A retailer receives a payment partner's report of suspicious activity associated with several stores. Around the same time, a maintenance account logs in outside its approved service window. The account owner says no work was scheduled. A terminal-integrity alert exists, but the first analyst cannot tell whether it corresponds to an authorized emergency update.

The first discussion should establish what evidence is needed before restricting access and who can authorize the restriction. Participants should separate uncertainty about the full breach population from the narrower decision to suspend an unexplained maintenance session. They should also identify which business services depend on the account, so that containment does not accidentally disable the only safe path for restoring affected equipment.

A second inject reveals an old marketing export in a location accessible through the same administrative environment. Its relationship to payment activity is unknown. The team must decide how to preserve and examine the export, how to avoid adding incompatible population counts, and what preliminary language can be used with executives. The correct response does not require a final number immediately. It requires a transparent counting method and a plan for resolving overlap.

A third inject concerns money: leadership asks for the total cost while insurers request supporting documentation and counsel has not assessed all claims. Participants should produce separate operational, accounting and cash-flow views. They should explain which amounts are incurred, accrued, estimated or reimbursed. The exercise succeeds when a decision maker can distinguish those categories without needing to reconstruct the spreadsheet from memory.

The final inject tests recovery. Operations reports that affected terminals have been rebuilt, but one supplier session remains active and a small group of offline devices has not been checked. Participants should define the remaining risk and an explicit release decision. Declaring the entire estate clean would exceed the evidence. Keeping the uncertainty visible while applying proportionate restrictions demonstrates a more mature response than waiting indefinitely for impossible certainty.

## 15. Conclusions and research limitations

The enduring lesson is the need to verify transitions of authority. A supplier relationship, an internal privilege, a management path and a payment process should not inherit trust merely because the previous step appeared legitimate. The historical public account supports examining those transitions, while its gaps require restraint about the precise exploit and the individuals responsible. Good defensive analysis can be useful without pretending to possess an unpublished forensic report.

The second lesson is disciplined accounting of both data and money. Cards, addresses and consumers have different meanings. Gross expense, insurance recovery and regulatory payment have different meanings. Preserving those distinctions makes the research more useful for technical staff, privacy teams and leadership. It also reduces the chance that a presentation will convert a qualified historical statement into an unsupported claim.

This draft does not resolve every source discrepancy, assess current company defenses or claim a complete lifetime cost. It does not infer a present entitlement from historical customer offers or settlement announcements. The proposed controls and exercise are intended for authorized defensive planning. A future expansion should add primary evidence only where it genuinely answers an unresolved question, and should retain the dates and qualifications that make the existing record interpretable.

## Source register

[1] Home Depot, Form 8-K, 8 September 2014: confirmation and initial scope. https://www.sec.gov/Archives/edgar/data/354950/000035495014000034/hd_8-kx982014.htm

[2] Home Depot, 18 September 2014: malware elimination, card estimate and encryption rollout. https://ir.homedepot.com/news-releases/2014/09-18-2014-014517752

[3] Home Depot, 6 November 2014: investigation findings and separate email files. https://ir.homedepot.com/news-releases/2014/11-06-2014-014517315

[4] Home Depot, fiscal 2014 Form 10-K: targeted breach expense and insurance disclosure. https://www.sec.gov/Archives/edgar/data/354950/000035495015000008/hd-212015x10xk.htm

[5] Home Depot, fiscal 2016 Form 10-K, printed page 56: cumulative expense and insurance. https://ir.homedepot.com/~/media/Files/H/HomeDepot-IR/documents/2016-10k.pdf

[6] New York Attorney General, 24 November 2020: multistate settlement announcement. https://ag.ny.gov/press-release/2020/attorney-general-james-helps-secure-175-million-after-data-breach-home-depot

[7] New Jersey Attorney General, executed multistate Assurance of Voluntary Compliance, effective 21 December 2020: obligations and legal qualifications. https://www.nj.gov/oag/newsreleases20/The-Home-Depot-AVC.pdf

[8] PCI Security Standards Council, FAQ 1086, March 2026: contemporary encryption and scope context, not retroactive requirements. https://www.pcisecuritystandards.org/faqs/1086/

[9] EMVCo, EMV Contact Chip: contemporary explanation of transaction cryptograms. https://www.emvco.com/emv-technologies/emv-contact-chip/
