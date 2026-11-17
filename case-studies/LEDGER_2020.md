# Ledger Customer-Data Breaches, 2020: Commerce Records, Phishing and the Limits of Product Security

*A TeamStarWolf case study. Published 15 November 2026.*

[All case studies](/case-studies/README.md) · Related: [Data Security Reference](/DATA_SECURITY_REFERENCE.md), [Social Engineering Reference](/SOCIAL_ENGINEERING_REFERENCE.md), [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md), [Incident Response Reference](/INCIDENT_RESPONSE_REFERENCE.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Commerce and product security teams, data-protection and support owners, incident responders and anti-phishing leaders

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 20 min (4,571 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You want an evidence-bounded account of the 2020 Ledger customer-data breaches, you need to separate product security from customer security or a confirmed minimum from an established maximum or overlapping datasets, or you are reviewing API-credential scope, support-access risk and phishing trust

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Executive assessment](#executive-assessment), [3. December disclosure and the revised estimate](#_3-december-disclosure-and-the-revised-estimate), [6. Product security and customer security](#_6-product-security-and-customer-security)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Data Security Reference](/DATA_SECURITY_REFERENCE.md), [Social Engineering Reference](/SOCIAL_ENGINEERING_REFERENCE.md), [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md), [Incident Response Reference](/INCIDENT_RESPONSE_REFERENCE.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

Key takeaways (reviewed 2026-11-17):

- Protecting a security product and protecting the people who buy it are related but different responsibilities. ([Executive assessment](#executive-assessment))
- A device can keep its technical boundary while commerce records expose its owner to deception, harassment or unwanted attention. ([Executive assessment](#executive-assessment))
- The study does not describe the leaked commerce database as a repository of wallet private keys. ([Executive assessment](#executive-assessment))
- Estimates need dates and denominators: email addresses, customer records, customers and merchants are not interchangeable units. ([Executive assessment](#executive-assessment))

<!-- meta:end -->

Historical focus: the June-December 2020 customer-data incident and the related Shopify disclosure in January 2021. This study distinguishes company statements, a contemporaneous court record and original defensive analysis. It does not identify victims, reproduce stolen records, assess current Ledger products or provide investment advice.

## Executive assessment

The central lesson of this case is that protecting a security product and protecting the people who purchase it are related but different responsibilities. A device can retain its intended technical boundary while commerce records expose its owner to deception, harassment or unwanted attention. An organization that evaluates only the product can miss the customer relationship around it.

This study treats the incident as a customer-data and trust problem. It does not describe the commerce database as a repository of wallet private keys. It also avoids converting a statement about the absence of direct wallet compromise into a promise that every affected customer faced no financial risk. Those claims answer different questions. The relevant question for a defensive review is how leaked context can make an unrelated request appear credible.

The historical record also shows why estimates need dates and denominators. Email addresses, detailed customer records, customers and merchants are not interchangeable units. A later, larger estimate does not necessarily describe a second intrusion. Conversely, a later disclosure can concern a separate access path even when the exposed records overlap heavily. Both distinctions matter here.

The recommendations below are original analysis intended for commerce operators, security teams and researchers. They are not assertions that a particular unreported configuration existed at Ledger or Shopify. The public notices establish a limited incident history. They do not provide a complete forensic image, full loss ledger or independently verified account of every downstream scam.

## 1. Evidence and scope

The principal sources are Ledger's dated incident communications and Shopify's original announcement and quarterly filing. These are first-party accounts of what the companies reported. Their institutional proximity makes them valuable, but it does not make every characterization independent evidence. A statement of confidence, a commitment to improve and proof that an improvement worked are three different kinds of material.

The court source is a November 2021 amended order in Baton v. Ledger SAS. Its introduction and background distinguish allegations from jurisdictional declarations. It is useful for explaining legal-record reading, not for treating every allegation as a proven fact. This article does not attempt a current litigation docket or a complete regulatory history. [8]

No stolen database was downloaded, searched or reproduced for this research. Reviewing identifiable customer records would create additional exposure without being necessary to explain the case. The evidence base instead consists of public notices and public institutional records. Counts therefore remain attributed estimates rather than a fresh independent census.

Later customer-security events, later hardware models and unrelated product debates are outside scope. A reader should not use this case study as evidence that a current product is safe or unsafe. Its enduring subject is the relationship between retained customer information, privileged access, investigation quality and incident communication.

## 2. The initial disclosure

Ledger's July 29, 2020 notice said a bounty researcher reported the issue on July 14. Investigation identified unauthorized access on June 25 through an API key, which Ledger disabled. The initial scope was approximately one million email addresses and about 9,500 records with additional contact or order information. Ledger excluded payment information and passwords from that disclosure and said the hardware-wallet and Ledger Live security boundary was unaffected. [1]

This account supports an access-path description, not a complete exploit narrative. It does not justify inventing a vulnerable endpoint, credential exposure location, database query or sequence of attacker commands. The defensible technical statement is narrower: the company attributed unauthorized commerce-data access to an API key. Any deeper reconstruction would require additional evidence.

An API credential should be assessed by its effective authority. Whether a key belongs to an internal integration or a third party, the important questions concern which records it can retrieve, which operations it can perform, how its use is logged and how quickly its access can be revoked. Merely counting credentials says little about the amount of customer information each credential can expose.

For an investigator, the reporting date and the access date belong in separate fields. A security researcher can discover a weakness after an adversary has used it. A patch can stop future use without identifying every earlier query. A customer notice can follow both events while still carrying incomplete scope. Combining these dates into a single label such as "the July hack" conceals the sequence that responders need to evaluate.

## 3. December disclosure and the revised estimate

On December 21, Ledger's CEO said a publicly released database revealed approximately 272,000 detailed customer records. The company explained that its earlier log review had specifically identified 9,532 such records and that the additional detail was absent from the logs it had analyzed. It also acknowledged phishing and customers' concerns about exposed shipping addresses. These statements are the company's explanation of the revision, not independent validation of its investigation. [2]

The distinction between a confirmed minimum and an established maximum is crucial. If available evidence demonstrates access to some records, it may support a minimum known exposure. It does not automatically show that other records were inaccessible. A missing log entry can have several explanations, including a logging gap, an unreviewed source or genuinely absent activity. The investigator must establish which explanation applies before using absence as assurance.

A good internal scope register would therefore contain at least four categories: demonstrated exposure, plausible exposure requiring investigation, excluded exposure with supporting evidence, and unresolved scope. These categories should not collapse into a single reassuring number simply because the communications team needs a headline. Where uncertainty materially affects the recipient's next action, it belongs in the notice.

The public release also changed the response problem. Stopping the original access does not retract copies that already exist elsewhere. The defender's task shifts toward reducing subsequent misuse, maintaining a trustworthy support channel and explaining what can and cannot be reversed. It is important to avoid implying that deleting a database internally erases a copy previously acquired by an adversary.

## 4. Shopify's separate incident and the overlap problem

Shopify's September 22 announcement described two members of its support team improperly obtaining merchant transactional records. It stated that fewer than 200 merchants were involved, denied a technical vulnerability in its platform as the cause and excluded complete payment-card numbers. Its quarterly report repeated the fewer-than-200 figure and described an ongoing investigation. These were contemporaneous statements with a defined reporting horizon. [3][4]

Ledger's January 13, 2021 update said Shopify notified it on December 23 of exports occurring in April and June. Ledger described approximately 292,000 affected customer records, around 93 percent overlap with the earlier exposed data and about 20,000 additional records. It also described plans to reduce retention and segregate necessary records. These were reported figures and announced measures, not proof of completed remediation. [5]

The notices contain a numerical discrepancy worth retaining: Ledger's January account characterized the wider Shopify event as involving more than 200 merchants, whereas Shopify's original announcement and quarterly filing said fewer than 200. This article does not silently choose a universal total. For Shopify's September reporting position, its own dated documents provide the relevant figure. [3][4][5]

The customer populations must not be added mechanically. Substantial overlap means that adding every dataset size would double-count many records. Nor does a rounded percentage establish an exact union: the meaning of "similar," the matching keys and duplicate handling are not fully specified in the notice. A careful researcher preserves the company's reported additional-record figure without claiming to have independently reconciled unique people across both datasets.

Separate paths can converge on the same data. That does not establish that the same actor controlled both paths, that both incidents shared a root cause or that one intrusion caused the other. Those propositions require evidence beyond record overlap. For the defensive model, however, multiple paths are already important: closing one route does not eliminate the need to assess support access and other routes to the same customer information.

## 5. A chronology that keeps the clocks separate

The core sequence is June access identified retrospectively, July discovery and disclosure, September platform-provider reporting, December public release and revised scope, and January notification about the additional provider-related exposure. These are different milestones. Their order explains why a customer's understanding could change without a new hardware-wallet compromise being announced. [1-5]

A production incident tracker should store the event date, the date the organization learned about it and the publication date separately. Each entry also needs an evidence reference and a confidence label. For example, an investigator's later conclusion about an earlier export should not be presented as if customers knew of that export at the time it happened.

This separation also improves accountability. A review can ask what evidence supported a statement on the date it was made, what new evidence changed it and how quickly the organization corrected the record. That is more useful than judging every early estimate only against hindsight. It does not excuse an unsupported assurance; it creates a method for determining whether the assurance was supported when issued.

A small discrepancy should remain small. Ledger's notices refer to forensic involvement on July 21 in the first statement and July 20 in the later recap. This article does not rely on a one-day precision claim about that engagement. The material questions concern the completeness of the evidence and the evolution of scope. The dates are preserved in the source register for an editor who needs a more granular chronology. [1][5]

## 6. Product security and customer security

A useful threat model contains several assets: the device, its associated secrets, the customer's contact information, the order record and the credibility of support communications. Protecting one asset does not necessarily protect the others. A commerce record may say little about actual holdings while still identifying a person as someone with an interest in a particular product category.

That distinction cuts both ways. An order is not proof that the purchaser still owns the device, uses it, controls a wallet of a certain value or lives at the shipping address today. Researchers should not treat a customer list as a reliable map of wealth. At the same time, an attacker need not possess a correct balance estimate to send a deceptive message or a threatening demand.

For security teams, this suggests a broader definition of harm. Confidentiality loss can cause repeated verification work, anxiety and a need to reassess contact channels. These effects should not disappear from an incident review because no direct cryptographic failure has been demonstrated. Conversely, those effects do not justify inventing a total monetary loss or claiming every recipient suffered the same outcome.

The communication challenge is to hold both boundaries at once. Explain exactly which product component the evidence does not show compromised, then separately explain which personal data escaped and what kinds of unwanted contact customers may face. An absolute statement about all funds or all future attacks is broader than the forensic conclusion about a particular database.

## 7. Phishing as a trust problem

Ledger's December communications described repeated phishing warnings, including a July email notice and an October warning. It reported open rates of 40 percent and 27 percent respectively and said it had taken down more than 170 phishing sites by its December 21 account. These are company-reported communication and response measures. They do not measure how many people understood a warning or how many losses were prevented. [6]

An email address paired with an authentic-looking order detail can make a message feel specific. The defensive lesson is not that all personalized communication is malicious. It is that personal detail is weak evidence of the sender's authority when those details may have escaped. A support process should use an independent, known channel for verification rather than asking a recipient to trust the same message that created the urgency.

This principle should shape legitimate notifications too. A genuine incident notice should not demand secrets or create an artificial emergency that resembles the attack it warns about. It should explain the issue, identify safe ways to reach support and describe actions that do not depend on following an unexpected link. Organizations should test whether recipients can distinguish their own process from an imitation using only the information they actually see.

The result should be a repeatable verification habit rather than a list of stylistic clues. Scammers can correct spelling, copy logos and reproduce a real address. A warning based only on poor grammar or an unfamiliar design is brittle. A stronger approach explains what the organization will never request and provides a trusted route through which the recipient can verify a claim independently.

## 8. Recovery secrets and safe customer assistance

Ledger's December 22 guidance warned customers not to disclose their recovery words and acknowledged personal threats. It directed people who believed they were physically endangered to local authorities. This article uses that notice as historical evidence of the company's response, without adopting its broad product-superiority claims or treating its entire advice page as current universal guidance. [7]

The response workflow itself must avoid collecting the secret it is trying to protect. A support ticket should not ask the customer to paste a recovery phrase, upload a recovery sheet or demonstrate possession by revealing private material. An investigator can document that a suspicious request occurred without retaining the secret requested by the scammer.

For this case study's exercises, no real wallet, account balance or recovery phrase is needed. Use a fictional message and a clearly marked synthetic identifier. The exercise should test verification and escalation, not whether a participant can move assets under pressure. Training that asks people to enter genuine secrets into a simulated portal undermines the boundary it is supposed to teach.

Customer support should also distinguish several states: a customer received a suspicious message, interacted with it, disclosed ordinary information, disclosed an authentication secret or reports an unauthorized transaction. These are different reports requiring different follow-up. The first state alone does not prove account compromise. The last state should not be dismissed merely because the original incident concerned commerce information.

## 9. API access and the customer-data estate

The following controls are original recommendations, not a claim about Ledger's unpublished implementation. Begin with a data-flow map that names each system holding contact and order data. Include integrations, email services, analytics exports, support tools and archived reports. A map confined to the primary database misses copies generated by routine business activity.

For every automated credential, record an accountable owner, a business purpose and the data it can access. A service that needs to confirm shipment status should not automatically inherit authority to retrieve the entire historical customer list. Scope should follow the minimum workflow requirement, and exceptions should have an owner who can explain why a narrower permission cannot meet the need.

Revocation should be tested as a business operation. The team needs to know which process will fail when a credential is disabled and which alternate route remains available. Otherwise, fear of disrupting orders can delay containment. A rehearsed rotation process can preserve essential operations without leaving the compromised authority active indefinitely.

Monitoring should make investigations answerable. A useful event records which identity made the request, the operation, the relevant data scope and a trustworthy timestamp. It should avoid dumping full customer records into logs merely to improve visibility. The design goal is evidence sufficient to reconstruct access while reducing the number of sensitive copies that investigators must protect.

## 10. Support access and insider risk

The Shopify notice makes support access a separate review subject. A patch program alone cannot address misuse of legitimate privileges. This does not mean that support personnel should be presumed malicious. It means that workflows should constrain authority and leave evidence when a person accesses data outside the needs of an active customer or merchant issue.

A support console can mask fields until a task requires them, limit bulk exports and require a recorded reason for exceptional access. Reviews should focus on what the console permits in practice rather than what a policy document says employees ought to do. Test whether a normal role can obtain an unusually broad dataset, and whether that action produces a reviewable event.

Approval is useful only when the reviewer has enough context. A generic "export requested" prompt encourages routine acceptance. A better approval explains the purpose, the fields, the population and the destination. For a rare high-volume extraction, a second person's authorization should be coupled with a durable record, not merely an informal message that disappears later.

The supplier relationship must cover investigative cooperation. A merchant needs to know who will preserve logs, how affected records will be scoped and how revised findings will reach it. A contract naming a notification obligation is not the same as a tested workflow for identifying which merchant and which customers were involved. Joint exercises can reveal this gap before a real incident requires an urgent answer.

## 11. Retention and the limits of deletion

Retention is a design decision with several owners. Fulfillment, accounting, disputes and marketing may each have different needs. A blanket promise to delete everything immediately can conflict with an actual obligation or an unresolved customer transaction. A blanket promise to keep everything for convenience creates a different risk. Each retained field should have a purpose, an appropriate access boundary and a review point.

Segregating records can reduce routine exposure if it meaningfully changes who can access them. Moving a database to a different server while leaving the same broad credential and support permissions in place does not demonstrate a smaller access surface. The acceptance test should examine permissions, retrieval paths and exceptional access, not just the label attached to the storage location.

Deletion also needs an evidence trail. A policy may remove a row from the primary application but leave it in a recurring export, a staff download or an email template. A test using synthetic records can follow the full lifecycle and check where copies persist. The test should distinguish active systems from backups with a separately defined expiry and restoration process.

None of this retracts an adversary's earlier copy. The value of retention controls is prospective: they reduce what remains available to a future unauthorized request and limit routine exposure. Incident communication should not describe a retention reform as if it undid the past disclosure. It should explain the protection the reform is intended to provide and the evidence needed to verify that protection.

## 12. Forensic scope and a correction-ready register

A scope register should associate every numerical estimate with its unit and method. Was the count produced from access logs, an exported file, a database query or a customer-notification list? Does one person appear more than once? Does a shared email address represent one account or several orders? These questions are not statistical decoration; they determine what the number can honestly mean.

Record matching should also preserve uncertainty. Identical emails can help identify overlap, but changed addresses, duplicate orders and incomplete fields can complicate the comparison. An analyst should describe the matching rules and report unresolved cases instead of presenting a precise unique-person count that the evidence cannot support. Approximate inputs should not produce a falsely exact conclusion.

A correction procedure should be prepared before it is needed. The organization should retain the earlier notice, publish the revision with a date and explain what changed. Quietly replacing a number can leave customers and journalists with conflicting copies and no way to reconcile them. Version history makes the organization more accountable and the recipient better informed.

The review should separate errors in facts from changes in evidence. A number may have been reasonable under a clearly disclosed limitation, or it may have been presented with confidence that the evidence never supported. Both cases require correction, but they call for different process improvements. One concerns investigation coverage; the other also concerns how uncertainty was communicated.

## 13. Threat reports and customer harm

An incident response team should provide a route for reporting threats that does not require victims to repeat sensitive information across many channels. Collect the minimum evidence needed to understand the contact and preserve the original message securely when appropriate. Public discussion boards are a poor place to ask someone to post a home address or detailed financial circumstances.

Reported harm should be classified carefully. A threatening email, a credible immediate physical danger and a completed theft are different events. Treating every report as a confirmed attack overstates the evidence; dismissing every report as a generic scam understates the person's experience. The response needs both an evidence standard and a humane escalation process.

Aggregate reporting can describe categories and trends without exposing individuals. It should distinguish reports received from verified outcomes and avoid adding unrelated complaints into an incident-loss total. Where the organization cannot establish a causal connection, it can still assist the reporter and state the uncertainty plainly. Assistance does not require an unsupported attribution claim.

The same restraint applies to public case studies. This article does not estimate victims' holdings, identify their locations or search for leaked personal details. Those actions would add risk without strengthening the lessons. A serious study can analyze the harm mechanism and the limitations of the record without turning affected customers into exhibits.

## 14. A legal-record boundary

The November 2021 amended order dismissed the then-current case for lack of personal jurisdiction. Its factual background recites plaintiffs' allegations and defendants' declarations, including a declaration describing support personnel as contractors. A jurisdictional disposition is not a finding that no breach occurred or that all security practices were adequate. This is a historical procedural snapshot, not a claim about the ultimate or current result of the litigation. [8]

For researchers, the document illustrates why source type matters. An allegation can establish what a party claimed. A sworn declaration can establish what a declarant stated. A judicial ruling can establish what the court decided within the question before it. These uses are different from treating every sentence in a court-hosted PDF as a final finding on the incident's merits.

The same discipline should apply to company terminology. Calling someone a member of a support team does not, by itself, settle their employment relationship. The defensive issue may be privileged access regardless of that relationship, while a legal analysis can depend heavily on the specific entity and contractual role. This article avoids collapsing those purposes into a single unsupported label.

A full legal follow-up would require later orders, appellate developments and any relevant regulatory records. That work is outside the present package. The limitation is explicit so that a future editor does not turn a 2021 order into a statement about current rights, remedies or liability. Readers seeking those answers need a separate, up-to-date legal review.

## 15. Original tabletop exercise

Use a fictional security-device retailer with synthetic customers and a pretend commerce platform. The exercise begins when a researcher reports that a service credential can access more customer data than expected. The incident commander must assign containment, preserve evidence and determine which business processes depend on that credential. No real records or working secrets enter the exercise.

The first inject is an incomplete log set. Participants must decide what they can confirm, what remains possible and what they will tell customers before the investigation is complete. A successful response does not require a confident total. It requires a clearly bounded statement, a plan to resolve uncertainty and an accountable owner for the next update.

The second inject is a larger synthetic dataset appearing months later. The communications team must explain the revised estimate without erasing the original notice. Investigators must reconcile the new population with earlier findings and identify the evidence gap. Leadership must decide how to sustain support after the initial containment work has ended.

The third inject is a provider notification about a separate support-access event with substantial overlap. Participants must avoid double-counting, preserve separate causal paths and request a documented matching method. The exercise should test the supplier's ability to revise merchant-specific findings, rather than assuming that one early provider notice settled every customer's exposure.

The final inject is a threatening message reported by a fictional customer. Support must respond without collecting a recovery secret or publishing personal details. The evaluation should examine whether staff recognize escalation needs, maintain a trustworthy channel and distinguish what is known from what is feared. End with named owners and retest dates for concrete findings.

## 16. Acceptance evidence and final assessment

A remediation plan should produce evidence that someone other than its author can inspect. For credential scope, demonstrate a denied request outside the intended purpose. For support access, show that bulk retrieval requires an accountable exception. For retention, trace a synthetic record through active systems and scheduled expiry. For notification, test whether a recipient can verify the message without trusting an unexpected link.

Measure the process rather than substituting activity counts for outcomes. The number of training emails sent does not establish comprehension. The number of blocked requests does not establish that every route is covered. The number of deleted rows does not establish that copies disappeared. Each metric should state its denominator, the tested boundary and the residual uncertainty.

Ledger's 2020 customer-data disclosures provide a durable case study in security outside the product itself. The most useful lessons concern scoped access, evidence quality, overlap-aware reporting and communications that remain credible after an estimate changes. None requires exaggerating the hardware impact or minimizing the significance of customer information.

The final standard is clarity: identify the data, the access path, the date, the evidence and the remaining uncertainty. Explain what changed and what customers can verify safely. That approach gives a researcher a defensible narrative and gives an organization a better way to protect people after the original technical problem has been contained.

## Sources and reading boundaries

[1] Ledger, July 29, 2020, initial leadership notice. Read the incident narrative and response sections. The July 21 forensic-engagement date differs from the July 20 date in the later recap; no one-day precision conclusion is drawn. https://www.ledger.com/addressing-the-july-2020-e-commerce-and-marketing-data-breach

[2] Ledger CEO, December 21, 2020, revised scope and explanation of log limitations. Company account, not an independently reproduced forensic result. https://www.ledger.com/message-ledgers-ceo-data-leak

[3] Shopify, September 22, 2020, original community announcement and staff replies. Read the original dated post, not the modern AI-generated summary or user speculation. https://community.shopify.com/t/what-happened-in-the-recent-data-incident-involving-less-than-200-shopify-merchants/21195/1

[4] Shopify third-quarter 2020 report, Data Incident section, page 28 of management discussion. Targeted section read; unrelated financial sections not fully reviewed. https://d18rn0p25nwr6d.cloudfront.net/CIK-0001594805/838c6860-7fd5-435d-845b-a03e8b2d02cd.pdf

[5] Ledger, January 13, 2021, update on prior breach, Shopify exposure, overlapping records and planned measures. Read incident and next-steps sections. Estimates and commitments remain attributed. https://www.ledger.com/blog/update-efforts-to-protect-your-data-and-prosecute-the-scammers

[6] Ledger, December 21, 2020, communication history and reported outreach/takedown measures. Read dated narrative and embedded chronology. https://www.ledger.com/blog/our-communications-about-data-breach

[7] Ledger, December 22, 2020, customer response guidance. Read recovery-secret warning and threat-response sections; marketing claims and blanket financial assurances are not adopted. https://www.ledger.com/blog/6-ways-to-face-the-data-breach

[8] U.S. District Court, Northern District of California, Baton v. Ledger SAS, November 9, 2021 amended order, case 21-cv-02470, document 79. Introduction and background pages 1-4 read for procedural and allegation boundaries; not a full docket review or current legal-status assessment. https://www.govinfo.gov/content/pkg/USCOURTS-cand-3_21-cv-02470/pdf/USCOURTS-cand-3_21-cv-02470-1.pdf
