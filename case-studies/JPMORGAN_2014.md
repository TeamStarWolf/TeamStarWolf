# JPMorgan Chase 2014: Contact-Data Theft and the Wider Fraud Economy

*A TeamStarWolf case study. Published 15 November 2026.*

[All case studies](/case-studies/README.md) · Related: [Data Security Reference](/DATA_SECURITY_REFERENCE.md), [Fraud Framework Reference](/FRAUD_FRAMEWORK_REFERENCE.md), [Identity and Access Management Reference](/IDENTITY_ACCESS_MANAGEMENT_REFERENCE.md), [Incident Response Reference](/INCIDENT_RESPONSE_REFERENCE.md), [Target, 2013](/case-studies/TARGET_2013.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Financial-sector security engineers, data-protection and fraud teams, incident responders and risk leaders

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 21 min (4,818 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You want an evidence-bounded account of the 2014 JPMorgan Chase breach, you need to separate contact-data exposure from account compromise or campaign-wide figures from one bank's loss, or you are reviewing bulk-access boundaries and fraud response

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Executive assessment](#executive-assessment), [1. What the bank disclosed](#_1-what-the-bank-disclosed), [4. Contact information as an input to fraud](#_4-contact-information-as-an-input-to-fraud)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Data Security Reference](/DATA_SECURITY_REFERENCE.md), [Fraud Framework Reference](/FRAUD_FRAMEWORK_REFERENCE.md), [Identity and Access Management Reference](/IDENTITY_ACCESS_MANAGEMENT_REFERENCE.md), [Incident Response Reference](/INCIDENT_RESPONSE_REFERENCE.md), [Target, 2013](/case-studies/TARGET_2013.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## Executive assessment

The 2014 JPMorgan Chase breach is an important example of why contact information deserves serious protection even when an investigation finds no evidence that account passwords or account numbers were taken. A financial institution's relationship with a customer can make a contact record useful to criminals. The value may lie in later deception rather than an immediate unauthorized withdrawal. A narrow view of breach harm can miss that second stage.

The bank's disclosures and the later criminal proceedings answer different questions. The disclosures describe the institution's understanding of affected information and customer impact at particular dates. The criminal record describes a broader campaign involving multiple organizations and fraud schemes. A careful case study connects those perspectives without treating every campaign-wide fact as a finding about the bank's specific systems or every criminal dollar figure as a loss suffered by its customers.

This study uses the October 2014 bank filing, relevant quarterly-report sections, the 2015 indictment and charging announcement, and official reports of Andrei Tyurin's 2019 guilty plea and 2021 sentence. The January 2021 announcement explicitly names JPMorgan Chase, whereas earlier documents use anonymized victim labels. That later identification provides a primary-source connection while preserving the scope and procedural status of the earlier record.

The defensive analysis focuses on customer-data inventories, bulk access, privilege boundaries, fraud response and the discipline of incident reporting. It does not provide exploit instructions, a stock-manipulation playbook or investment recommendations. No customer records were accessed. Recommendations and the fictional tabletop are original analysis for comparable institutions, not additional forensic findings about JPMorgan Chase.

## 1. What the bank disclosed

On 2 October 2014, JPMorgan Chase disclosed compromised names, addresses, telephone numbers, email addresses and internal information relating to users. It estimated approximately 76 million households and 7 million small businesses were affected. The filing said there was no evidence at that date that specified account information, including account numbers, passwords, user IDs, birth dates or Social Security numbers, had been compromised. It also said the firm had not seen unusual customer fraud related to the incident. [1]

Those statements should be read with their dates and their categories intact. No evidence of a particular kind of compromise is not the same claim as proof that no harm could occur. Similarly, contact information is not equivalent to an account credential, but it is not valueless. The appropriate analysis explains what was observed and what remained outside the observation, rather than replacing a qualified statement with either reassurance or alarm.

The quarterly report later repeated the absence-of-evidence statements as of its own date. It said the cyberattacks experienced to that point had not caused material operational disruption or a material adverse effect on results of operations. It also described board and audit-committee reporting and cooperation with government and other businesses. These are dated company disclosures, not an independent certification of complete recovery or a final lifetime-cost calculation. [2]

For a comparable institution, a disclosure should separate information categories, operational consequences and observed fraud. Each may have a different evidence base and update cycle. A service can remain available while confidentiality has failed. Fraud can remain unobserved while the investigation is incomplete. Presenting those dimensions independently allows readers to understand the incident without assuming that one favorable metric resolves every other question.

## 2. Households, businesses and customer records

The bank's two population categories should not be silently converted into a count of distinct individuals. A household can contain multiple people, and a business can have multiple contacts. The public filing does not provide a full deduplication method or an overlap analysis. A simple sum may describe the stated categories arithmetically, but it does not establish a precise number of unique human victims.

The 2015 indictment described more than 83 million customer records at an anonymized bank, Victim-1, during an alleged June-to-August 2014 intrusion. The 2021 sentencing announcement identified JPMorgan Chase and described more than 80 million customers. Those descriptions have different units and levels of precision from the bank's household and business figures. This study preserves them rather than pretending that the public material supplies a complete reconciliation. [3,6]

A sound population workbook should record the object counted, the period, the source date and the inclusion rule. It should distinguish a contact record from a customer relationship and a customer relationship from a legal entity. If the same address appears in several systems, the investigator should document whether deduplication is possible and what assumptions it requires. The resulting estimate should retain those assumptions when copied into a presentation.

Population analysis also affects notification. A business contact may receive information on behalf of an organization, while a household record may represent several relationships. The institution should avoid sending contradictory notices merely because different systems use different identifiers. At the same time, uncertain overlap should not be used to suppress a warning supported by the evidence. The process needs a defensible rule for ambiguous membership.

A later estimate should be presented as a dated revision or a differently scoped figure, not as an unexplained replacement. Readers need to know whether the investigation found additional records, changed its counting method or simply adopted a less precise public description. That history is part of the evidence. Removing it can make an improving investigation look inconsistent and can conceal the limits of the final number.

## 3. A chronology from disclosure to sentencing

The bank's quarterly report identifies a 10 September 2014 disclosure and the more detailed 2 October update. The later criminal chronology spans charging in 2015, Tyurin's guilty plea in September 2019 and sentencing in January 2021. These are different stages of organizational reporting and criminal process. A public disclosure date should not be treated as the first date of attacker access. [2,4,5,6]

The 2015 indictment alleged a June-to-August window for the intrusion at Victim-1. It separately described Heartbleed exploitation at Victim-2. That distinction is important: the presence of a named vulnerability elsewhere in a multi-victim indictment does not establish that it caused the JPMorgan Chase breach. This study does not assign a specific initial exploit or an exact missing-authentication configuration to the bank without primary evidence supporting that claim. [3]

For historical analysis, a timeline should have parallel tracks. One records the alleged or observed technical activity. Another records when the victim organization disclosed information. A third records charges, pleas and sentencing. Combining those tracks into a single story is useful only if the labels remain visible. Otherwise, an allegation from an early indictment can be mistaken for a later adjudicated fact, or a later sentence can be projected backward onto every defendant.

Time windows should also preserve uncertainty. An allegation that an intrusion occurred over several months does not prove continuous access to every system during that entire period. A disclosure that a breach had occurred does not identify the moment of discovery unless the source says so. The disciplined approach is to state the available interval and the kind of evidence supporting it, then leave unresolved boundaries explicit.

A chronology can still be operationally useful without reconstructing every day. It can show the delay between public awareness and legal accountability, identify which statements were made before later evidence emerged, and explain why early absence-of-evidence claims must remain dated. The goal is a record that supports decisions and further research, rather than a dramatic sequence whose precision exceeds the sources.

## 4. Contact information as an input to fraud

The November 2015 charging announcement alleged that stolen customer contact information supported deceptive stock promotions and a wider criminal enterprise. It described securities manipulation alongside other schemes. Those campaign-wide allegations explain a possible economic purpose for data theft, but they do not establish that every stolen record was used, that every recipient acted on a solicitation or that all illicit proceeds came from the JPMorgan Chase intrusion. [4]

The September 2019 plea announcement described Tyurin's admitted participation in a broader hacking campaign and its connection to fraud. It referred to more than 100 million customers across victim companies and to stolen contact data used in misleading promotions. The scope was larger than one bank. A case study should therefore resist assigning the whole campaign's scale or proceeds to a single incident. [5]

The defensive implication is that a customer directory can have value even when it lacks transaction authority. A message that reaches a plausible financial customer can support deception outside the compromised institution's own account systems. The institution may not see that later activity in its transaction-monitoring tools. A narrow measure of unauthorized withdrawals can therefore miss a meaningful part of the potential exposure.

For a comparable bank, risk classification should include the context attached to contact data. A list associated with a particular business line may reveal a relationship or suggest an audience to a criminal. That does not make every contact field equivalent to a password, but it does justify controls beyond those used for a public mailing list. The classification should reflect the record's use and scale, not only whether it contains a traditionally sensitive identifier.

Customer guidance should remain evidence-based. It can explain why unexpected messages deserve independent verification without claiming that every message is connected to the breach. It should avoid directing customers to new third-party services that collect more information than necessary. The useful outcome is a clear, trusted route for verifying communications and reporting suspicious activity, not a broad instruction that leaves the customer unsure whom to trust.

## 5. The criminal record and attribution limits

The January 2021 Justice Department announcement reported a 144-month prison sentence for Tyurin, following his guilty plea, and a forfeiture order of $19,214,956. It explicitly identified JPMorgan Chase among the victims and described his role in a campaign spanning several sectors. The announcement left restitution for a later hearing. This study does not infer the later restitution outcome or current custody status from that historical release. [6]

The 2015 charges against other named defendants should retain their status as allegations when discussing that announcement. Tyurin's plea and sentence do not automatically establish the current disposition of every co-defendant's case. Similarly, a defendant's nationality or location does not prove state sponsorship. The selected record supports a financially motivated criminal context, not an unsupported claim that a government directed this specific incident.

Attribution should be evaluated at several levels. Technical infrastructure may link activity without identifying the human operator. Communications or financial evidence may support a stronger link, while a criminal proceeding can establish a person's admitted or adjudicated conduct. These forms of evidence complement one another, but they should not be flattened into a single confidence label. A report should identify what the source actually establishes.

This matters for defenders because controls should not depend entirely on naming an adversary. An institution can reduce bulk export privileges, improve identity monitoring and preserve evidence even when the operator remains unknown. Attribution can help law enforcement and strategic planning, but uncertainty about the actor is not a reason to delay containment or to invent a more familiar threat label.

A future revision could examine later primary court records for additional dispositions. Until then, the correct approach is to retain the historical procedural language and the date of each source. Research quality improves when an unresolved point is stated honestly. It does not improve when a case study fills a gap with an assumption based on a headline, an alias or another defendant's outcome.

## 6. The customer-data estate

A comparable institution should know where contact information exists beyond its core account platform. Copies may support service, analytics, marketing, fraud investigations or legacy integrations. Each copy can have a legitimate purpose, but each also creates an access and retention obligation. Protecting the system of record while overlooking exports and secondary stores leaves the institution unable to describe its true exposure.

The inventory should connect datasets to business owners and operational uses. A table name alone rarely explains why a large population is accessible or who can authorize its export. The record should specify which fields are needed, how often the data is refreshed and which destinations are approved. It should also identify whether a copy is authoritative or derived, so that incident responders understand what a record represents.

Retention deserves particular attention for contact datasets. A team may keep historical exports because storage is inexpensive and deletion has no immediate revenue benefit. Yet old copies can remain useful to an adversary and can complicate notification years later. A defined expiry and an accountable owner make the tradeoff visible. Exceptions should be justified by a current purpose rather than by the possibility that someone might need the file someday.

Access reviews should include service identities and scheduled jobs. A human employee may have limited interactive access while an automated process can extract a much larger population. The organization should know who can change that process, where its credentials are stored and whether its output can be redirected. Reviewing only employee group membership can miss the authority exercised through automation.

This is original architectural analysis, not a description of undisclosed bank systems. Its purpose is to make a contact-data incident actionable for a reader. The question is not merely where personal data is stored, but which paths can collect it at scale and under whose authority. That is the inventory needed for meaningful prevention and rapid scoping.

## 7. Bulk access as a separate authorization boundary

A legitimate need to view one customer record does not necessarily justify exporting millions. For a comparable institution, bulk operations should have their own authorization model. The approval should connect the requested population, fields, destination and duration to a business task. A broad role that happens to permit both routine lookup and unrestricted export can create avoidable exposure.

The design should distinguish human access from batch processing. A recurring job may need a large dataset, but its destination and schedule can still be constrained. Changes to those properties should trigger review. A temporary analytical project may need an exception, but the exception should expire and its output should have a retention rule. These controls can preserve useful work without treating all data movement as equally acceptable.

Detection should focus on deviations that analysts can interpret. A large export may be routine for one service and unusual for another. The alert needs the identity owner, expected task and approved destination, not only a byte count. Without that context, responders may either ignore a legitimate warning or interrupt essential operations repeatedly until staff learn to work around the control.

Testing should use synthetic records in an authorized environment. Reviewers can establish whether a lookup role can invoke bulk export, whether an approved job can write to an unapproved destination and whether an expired exception remains usable. The results should be recorded as pass, fail or incomplete with an explanation. A policy statement alone cannot demonstrate that the boundary exists.

The institution should also plan the response to a suspicious export. Who can pause the job? What evidence must be preserved first? Which business process may be interrupted? Answering those questions before an incident makes containment faster and more proportionate. A control that detects a problem but has no workable response path may provide reassurance without materially reducing exposure.

## 8. Privilege, identity and monitoring

The public sources reviewed here do not support a complete, bank-specific technical reconstruction. That limitation should not prevent a useful defensive review. Comparable institutions can examine how ordinary identities gain access to sensitive services, how privileged actions are approved and how an unexpected change becomes visible. Those questions remain relevant across many possible initial-access mechanisms.

Identity controls should account for the entire session lifecycle. Authentication is only the beginning. A session may persist after a role change, a token may retain authority after a password reset, or a service identity may be used from an unexpected environment. The institution should test revocation and privilege reduction rather than assume that changing one credential closes every path.

Administrative authority should be separated from routine business use where feasible. A person who needs occasional elevated access can receive a limited session tied to a specific task. The record should identify the approver and the systems affected. This does not eliminate all risk, but it makes the authority easier to review and the resulting actions easier to attribute.

Monitoring should connect identity, action and destination. A login from a familiar location can still precede an unusual export. Conversely, travel or infrastructure changes can produce benign location anomalies. A useful detection model considers the task being performed and the population accessed. Analysts need enough context to make a decision without assuming that a single indicator conclusively proves compromise.

Evidence preservation should anticipate adversarial interference. Important records should have controlled retention and access independent of the systems they describe. The organization should test whether an administrator of one environment can silently alter the evidence used to investigate that environment. This is a defensive assurance question, not a claim that the bank's historical logging had a particular weakness.

## 9. Operational resilience and confidentiality

The bank's disclosure of no material operational disruption should not be interpreted as a statement that confidentiality remained intact. Availability and confidentiality are separate dimensions. A service can continue processing legitimate business while an unauthorized party accesses information. The absence of a visible outage may make the incident less obvious to customers, but it does not reduce the need for investigation and appropriate notice.

For a comparable institution, resilience reporting should include the ability to continue essential services during containment. Disabling a large identity platform may stop an intruder while also disrupting customers. A better response architecture provides scoped isolation, alternative workflows and clearly assigned emergency authority. Those capabilities should be exercised before a real incident forces staff to choose between uncontrolled access and broad interruption.

Recovery should be defined through verifiable claims. If the institution says an access path is closed, it should have evidence that the old identity or session can no longer use it. If it says a dataset is protected, it should identify the repaired boundary and any exceptions. A general declaration of recovery can conceal unresolved issues unless each underlying claim has a concrete acceptance test.

Business continuity also includes communications and support. Customers may receive suspicious messages long after the technical investigation ends. The institution needs a trusted channel that can distinguish current advisories from stale information and that can route new reports to the appropriate team. Closing the infrastructure incident should not automatically terminate the process for learning about downstream harm.

The practical objective is to preserve service while reducing exposure and improving understanding. That requires coordination among technology, operations, fraud, privacy and legal staff. A narrow technical team may repair systems successfully while missing the broader customer consequences. The case is therefore useful for testing how those functions share evidence and how leadership receives a coherent account of the incident.

## 10. Financial figures and what they do not measure

The selected criminal sources describe proceeds across a broad enterprise, while the bank filings discuss the institution's own operations. Those are different financial perspectives. Criminal proceeds do not automatically equal bank losses, and forfeiture does not automatically equal restitution to customers. The same dollar figure can appear in several summaries while referring to only one legal or accounting category.

The 2021 forfeiture amount belongs to Tyurin's sentencing context. It should not be presented as money removed from JPMorgan Chase accounts during the 2014 intrusion. Likewise, a campaign-wide description of hundreds of millions in illicit proceeds includes activity beyond the bank breach. A case study should state that scope whenever the figures are discussed, rather than rely on a footnote to correct a misleading headline.

A comparable incident cost ledger should separate investigation expense, customer-support cost, remediation investment, litigation, insurance and confirmed fraud losses. Some items may remain unquantified. That uncertainty is informative and should not be replaced with zero. Costs incurred to improve security more broadly may also be difficult to attribute entirely to one incident. The ledger should explain the basis of any allocation.

The public sources reviewed do not establish a complete lifetime cost for this breach. This study therefore does not manufacture one by combining unrelated criminal amounts with general security spending. A defensible financial section can be useful even without a grand total: it can identify what is known, what the known amounts represent and which missing records would be required for a fuller calculation.

For decision makers, the most important financial question may be what resources are required now to reduce a specific exposure. That question can be answered through a scoped remediation plan and evidence of its effectiveness. It does not require pretending that a historical event has a single precise price. Accurate categories are more valuable than false completeness.

## 11. Cooperation without uncontrolled sharing

The official plea announcement credited information sharing among victim institutions through the Financial Services Information Sharing and Analysis Center. This is evidence of a cooperative role in the investigation, not proof that every participant shared all customer data or that any particular indicator alone identified the perpetrators. The source supports the value of coordinated investigation while leaving operational details unspecified. [5]

For a comparable institution, sharing should begin with a defined purpose and a verified recipient. Technical indicators, patterns and timing information can be useful without including a complete customer dataset. The institution should identify which facts are necessary for the recipient's task and which should remain internal. Sharing more information than needed can create a new privacy risk during the response.

Evidence packages should distinguish observation from inference. A suspicious server connection is an observation; a claim about the operator behind it may require additional support. Recipients need that distinction to avoid propagating an uncertain attribution as fact. A well-structured package includes timestamps, collection method, confidence and relevant limitations, allowing another organization to assess the finding in its own environment.

Legal and privacy review should be integrated into the process rather than improvised after a crisis begins. The institution should know who can authorize sharing, how requests from law enforcement are verified and how sensitive material is transferred. These controls should support timely cooperation, not create an indefinite administrative barrier. Clear procedures can make both speed and protection more achievable.

Finally, the institution should retain a record of what was shared and why. That record supports later investigation, regulatory questions and correction if an early assessment changes. Cooperation is more reliable when participants can update one another's understanding rather than treating the first report as final. The objective is a shared picture that improves with evidence.

## 12. Customer communication and downstream fraud

A useful customer notice should identify the information involved and the current evidence about account security. It should not imply that contact-data exposure is harmless, but it should also avoid claiming that account credentials were stolen when the investigation does not support that statement. The message needs a clear date so that a reader can distinguish a historical finding from a current update.

The institution should provide an independent verification route for unexpected communications. Customers should not need to follow a link in an unsolicited message to determine whether the message is genuine. Support staff should use consistent scripts and avoid requesting unnecessary secrets. A poorly designed response can train customers to disclose more information at the exact moment criminals may be exploiting their concern.

Fraud teams should look beyond the compromised institution's own transaction systems when assessing potential downstream consequences. Reports of deceptive solicitations may be relevant even when no unauthorized account transaction appears. At the same time, a suspicious message should not automatically be attributed to the breach. The investigation needs evidence linking it to the exposed population or other relevant activity.

Customer reports should be collected in a way that supports analysis without creating another uncontrolled archive of personal information. Staff can preserve the necessary message details, timestamps and routing information while limiting access to unrelated content. The organization should explain how reports will be used and should not promise an outcome that depends on another institution or law-enforcement process.

The communication strategy should evolve as evidence changes. A later finding may narrow a category, identify a new concern or clarify a previous uncertainty. Updates should explain the change rather than quietly replacing the old statement. That approach helps preserve trust and gives customers a coherent history of what the institution knew and recommended at each stage.

## 13. Fictional tabletop: the unexplained directory export

This exercise is fictional and adds no historical facts. A financial institution detects an unusually broad export from a customer-contact service. The identity belongs to a scheduled business process, but the destination differs from its approved configuration. At the same time, several customers report unsolicited investment messages. The team does not yet know whether the two observations are connected.

The first decision is whether and how to pause the export. Participants should identify the business owner, the service dependency and the evidence that must be preserved. They should avoid assuming that a valid service credential makes the export legitimate. They should also avoid asserting a customer-fraud connection before the evidence supports one. Containment and attribution can proceed at different speeds.

A second inject reveals that the dataset includes household records and small-business contacts with overlapping addresses. Executives ask for a single number of affected people. Participants should explain the counting units, propose a deduplication method and state the uncertainty. The correct response is not necessarily the largest available number. It is a reproducible estimate that preserves the meaning of the source data.

A third inject concerns public messaging. The institution has found no evidence of account-number or password access, but investigators have not finished reviewing secondary stores. Participants should draft a dated statement that describes the known scope without implying a universal guarantee. They should also identify the next evidence needed to update the message and who is responsible for approving that update.

The final inject introduces a criminal investigation involving several other organizations. A public announcement includes campaign-wide proceeds and an anonymized victim count. Participants should determine which facts can be connected to their institution and which cannot. The exercise succeeds when the team maintains clear boundaries between its own evidence, another organization's findings and allegations in a legal proceeding.

## 14. Verification priorities and conclusion

A comparable institution can begin by selecting one high-volume contact dataset and tracing its lifecycle. The review should identify where it originates, which copies exist, who can export it and when each copy expires. The objective is a concrete map of authority and movement. A broad statement that customer data is protected is less useful than a tested answer for a specific important path.

The next priority is a bulk-access test using synthetic records. A reviewer should establish whether routine lookup permissions permit an export, whether a scheduled job can change destination without approval and whether revocation ends an active session. Each test should have an expected result and a documented owner for failures. The exercise should be safe, authorized and designed to improve controls rather than demonstrate an attack.

A third priority is reporting discipline. The institution should rehearse how it communicates population counts, absence-of-evidence statements and financial categories. These may appear to be editorial concerns, but they affect decisions during an incident. A poorly labeled number can misdirect notification work, while an overbroad reassurance can undermine later updates. Precision is part of operational readiness.

The JPMorgan Chase case shows why a data-theft investigation should extend beyond immediate account compromise. Contact information can contribute to a wider fraud ecosystem, and later criminal proceedings may reveal a purpose that was not visible in the first disclosure. Yet that broader context does not justify collapsing every victim, transaction and defendant into one undifferentiated story.

The strongest conclusion is a disciplined one: protect customer relationships as well as credentials, test bulk-access boundaries, and preserve the meaning of each source. The public record supports serious concern and concrete defensive work without an invented exploit chain, a falsely reconciled population or an unsupported loss total. Good case-study writing makes those limits visible while still giving readers useful actions to take.

## Source register

[1] JPMorgan Chase, Form 8-K, 2 October 2014: contact data, population categories and dated exclusions. https://www.sec.gov/Archives/edgar/data/19617/000119312514362173/d799478d8k.htm

[2] JPMorgan Chase, third-quarter 2014 Form 10-Q, operational-risk section: disclosure chronology, operational impact and governance. https://www.sec.gov/Archives/edgar/data/19617/000001961714000451/corpq32014.htm

[3] United States v. Shalon et al., 2015 superseding indictment, selected paragraphs 22–24: anonymized victims and distinct intrusion allegations. https://www.justice.gov/d9/press-releases/attachments/2015/11/10/us_v_shalon_et_al_indictment.pdf

[4] DOJ SDNY, November 2015 charging announcement: alleged multi-victim enterprise and fraud context. https://www.justice.gov/usao-sdny/pr/attorney-general-and-manhattan-us-attorney-announce-charges-stemming-massive-network

[5] DOJ SDNY, 23 September 2019 Tyurin plea announcement: admitted campaign and investigative cooperation. https://www.justice.gov/usao-sdny/pr/russian-hacker-pleads-guilty-involvement-massive-network-intrusions-us-financial

[6] DOJ SDNY, 7 January 2021 Tyurin sentencing announcement: named bank, sentence, forfeiture and unresolved restitution at that date. https://www.justice.gov/usao-sdny/pr/russian-hacker-sentenced-12-years-prison-involvement-massive-network-intrusions-us
