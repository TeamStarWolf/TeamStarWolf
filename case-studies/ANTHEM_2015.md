# Anthem, 2015: Health Identity, Privileged Access and the Enterprise Data Warehouse

*A TeamStarWolf case study. Published 15 November 2026.*

[All case studies](/case-studies/README.md) · Related: [Healthcare Security Reference](/HEALTHCARE_SECURITY_REFERENCE.md), [Identity Security Reference](/IDENTITY_SECURITY_REFERENCE.md), [Data Security Reference](/DATA_SECURITY_REFERENCE.md), [Identity and Access Management Reference](/IDENTITY_ACCESS_MANAGEMENT_REFERENCE.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Healthcare and health-plan security leaders, identity and data-warehouse owners, detection engineers, incident responders and privacy teams

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 22 min (5,142 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You want an evidence-bounded account of the 2015 Anthem breach, you need to separate a stolen password from the privileged path into a consolidated data warehouse, or you are reviewing bulk-extraction controls and breach-population language

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Executive assessment](#executive-assessment), [4. The alleged intrusion chain, without an exploit recipe](#_4-the-alleged-intrusion-chain-without-an-exploit-recipe), [7. A warehouse is a concentration of authority](#_7-a-warehouse-is-a-concentration-of-authority)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Healthcare Security Reference](/HEALTHCARE_SECURITY_REFERENCE.md), [Identity Security Reference](/IDENTITY_SECURITY_REFERENCE.md), [Data Security Reference](/DATA_SECURITY_REFERENCE.md), [Identity and Access Management Reference](/IDENTITY_ACCESS_MANAGEMENT_REFERENCE.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

Historical scope: the intrusion disclosed in 2015, the 2018 federal HIPAA resolution, the 2019 criminal indictment and the 2020 multistate settlement. This study distinguishes allegations, regulator accounts, settlement provisions and original defensive analysis. It is not a current security assessment, medical guidance or legal advice. No live systems were tested.

## Executive assessment

Anthem demonstrates why a health-data incident cannot be understood solely as a stolen password or a malicious email. The important security question is how an initial foothold can acquire enough authority to reach a consolidated repository of identity information. A mature defense must interrupt that progression at several points: endpoint compromise, credential misuse, privileged access, bulk retrieval and transfer outside the organization. Training is useful, but it is not a substitute for those boundaries.

The incident also requires careful language about the data itself. Health-plan identifiers and other identity information can be protected health information even when the disclosed evidence does not establish theft of clinical histories. Describing all exposed information as medical records can mislead readers about the actual categories. Describing it as merely contact information makes the opposite mistake. This study keeps legal classification, technical content and possible individual consequences separate.

The resulting recommendation is a data-centered control program: map the paths into the warehouse, restrict authority to genuine business needs, record sensitive operations, govern bulk extraction and verify that corrective actions work. These are original proposals for comparable organizations, not a reconstruction of every undocumented Anthem system. The public record is substantial, but it does not provide raw forensic evidence or establish the ultimate use of every stolen identity record.

## 1. Source hierarchy and evidentiary boundaries

The study uses eight primary sources. HHS's settlement page and report to Congress explain the federal regulatory response. A 2019 indictment supplies the government's detailed criminal allegations, while the DOJ announcement explains the procedural status. New York's announcement and signed assurance document the later multistate resolution. Anthem's SEC filing preserves the company's contemporaneous description, and California's insurance regulator preserves consumer-facing information and warnings. The sources answer different questions and should not be treated as interchangeable. [1–8]

An indictment is an accusation, not a conviction. A settlement can impose obligations without admitting liability. A regulator's account of investigative findings is not the same as a jury determination. A company statement about the absence of evidence is time-bound and does not establish impossibility. Those distinctions appear throughout the article because the sequence spans several years and several institutions. None of the reviewed materials justifies treating every later claim as something known at the initial disclosure.

The original federal resolution-agreement link returned unavailable, and an attempted third-party mirror was also inaccessible. Accordingly, this package does not claim to have read the full federal agreement or its detailed corrective-action schedule. It relies on HHS's accessible official summary and relevant report-to-Congress section for that resolution. The separate 2020 state assurance was available and reviewed for its relevant chronology, security terms, payment provisions and non-admission clause. This distinction prevents an accessible later agreement from silently substituting for an unread earlier one.

## 2. Chronology: intrusion, discovery, disclosure and later action

The indictment alleges a phishing message to employees of an Anthem subsidiary on approximately 18 February 2014, followed by unauthorized Anthem access on approximately 13 May. It describes warehouse reconnaissance in October and November, collection and encrypted archiving in December and January, and transfers during January 2015. It alleges that incident-response measures terminated the defendants' Anthem access on approximately 31 January 2015. These are alleged milestones, not independently verified timestamps from this research. [3]

The 2020 assurance identifies discovery around 29 January 2015 and public announcement on 4 February. HHS's report records a breach report to OCR on 13 March. The federal settlement was announced in October 2018. DOJ announced the unsealed indictment on 9 May 2019. New York announced the multistate resolution on 30 September 2020, while the assurance specifies an effective date of 30 October 2020. Announcement and contractual effective date are therefore distinct. [1–6]

A chronology should not compress this sequence into one date labeled attack. Earliest alleged activity, discovery, containment, public notice, regulatory reporting, settlement and criminal charging are different events. Nor should the elapsed period from the first alleged email to containment automatically be described as continuous activity by every named participant on every system. A source can support a campaign window without providing evidence of uninterrupted presence on each host throughout that window.

For a comparable response, the proposed timeline should record the event, source, confidence and timezone where available. A later discovery can change the estimated beginning without changing the actual date of organizational awareness. Preserving those revisions helps an investigator explain what was known when decisions were made. It also protects against a simplistic retrospective narrative in which the organization is assumed to have known the full later indictment on the first day of response.

## 3. What was exposed, and what was not established

Anthem's filing for the year ended December 2014, submitted after the incident became public, described identity and employment information involving current and former members and employees. It said that, at that point, there was no evidence that credit-card information or clinical material such as claims, test results and diagnostic codes had been targeted, accessed or obtained, while retaining a caveat that further information might be identified. That is a dated company statement, not a guarantee about all possible data. [7]

HHS described the affected information as electronic protected health information. Its report also notes that the data served affiliated and other covered-entity health plans. The term therefore does not require this article to claim that detailed clinical files were stolen. The data categories and the context in which an organization holds them matter. This study does not reproduce personal records or infer any individual's condition, treatment or insurance eligibility from the incident. [2]

California's consumer page, relaying Anthem's account, says not every affected person had every listed field taken. It includes former enrollees and people associated with independent Blue Cross and Blue Shield plans, including minors. This is why the approximately 78.8 million affected-person figure should not be described as the number of Anthem's then-current subscribers. Historical retention and inter-plan relationships can make a breach population broader than a current membership count. [8]

For analytical purposes, a data-category matrix is more useful than one broad label. It should identify which fields were present, which populations held them and how confidently access or extraction is established. The matrix should separate national totals from geographic subsets and people from rows. It should not imply that every affected individual lost an identical bundle of information. This is a proposed research and incident-response method, not a new factual finding about a particular individual's record.

## 4. The alleged intrusion chain, without an exploit recipe

The indictment's model moves from a targeted email and malware to remote access, credential acquisition, lateral movement, reconnaissance, collection and exfiltration. It alleges use of a commercial file-transfer service and intermediate computers, including transfer toward China, as well as deletion intended to obscure activity. Its allegations also cover three other victim businesses. This study does not import all conduct involving those businesses into the Anthem-specific sequence, nor does it publish operational instructions for reproducing the intrusion. [3]

The useful defensive interpretation is a series of authority transitions. A user action can expose a workstation; workstation control can expose a credential; a credential can open a service; that service can provide a path to sensitive data. Each transition has different evidence and different potential controls. The final data loss cannot be explained adequately by examining only the first user action. Conversely, later broad access does not prove that the initial user account began with warehouse-administrator privileges.

A security review should ask what evidence would connect those transitions in a real environment. Endpoint telemetry can explain execution, identity logs can explain authentication, authorization records can explain permitted operations, and warehouse audit records can explain sensitive retrieval. None of those sources alone necessarily establishes the entire chain. The proposed objective is to preserve the relationships among user, device, session, service and data operation so that investigators can test hypotheses rather than merely accumulate isolated alerts.

The appearance of a legitimate commercial service in an allegation should not be read as a finding that the service provider participated in the attack. A familiar domain or encrypted connection can carry either authorized or unauthorized activity. The relevant questions are who controlled the account, whether the destination was approved and what information the organization permitted to leave. These questions lead to defensible governance without turning the historical account into a catalog of attacker techniques.

## 5. Attribution and criminal status

DOJ's May 2019 announcement names Fujie Wang and a second defendant charged as John Doe, describing alleged participation in a hacking group operating in China. The announcement repeatedly presents the conduct as allegations. That is a narrower claim than a proven statement that a particular state agency directed the operation. This study does not infer state sponsorship solely from nationality, geography, infrastructure location or the size of the victim population. [4]

The distinction is operationally important. Defensive controls should not depend on knowing an adversary's final organizational affiliation. A warehouse access policy remains necessary whether the intruder seeks fraud, resale, intelligence or another objective. Attribution may affect law-enforcement cooperation and strategic threat analysis, but it does not change the basic requirement to limit unnecessary privilege and detect unexpected extraction. A defender can act on observed unauthorized behavior while preserving uncertainty about motive.

This article does not claim a current conviction, arrest, trial outcome or final disposition of the criminal case. Its criminal-history discussion is bounded to the indictment and the official announcement reviewed. An educational case should not turn an older charge into a present-tense claim about a person's legal status without fresh court evidence. It should also avoid identifying unnamed victims or defendants by guessing from other reporting. The source labels are part of the analysis, not merely cautious phrasing added at the end.

## 6. OCR's control concerns and the federal resolution

HHS's report to Congress describes deficiencies in risk analysis, password practices, detection, timely incident response and minimum access controls. It connects the event to phishing directed at a subsidiary and reports that Anthem agreed to corrective action, including revised policies and workforce training. These are HHS's retrospective findings and resolution summary. They should not be embellished into a full list of missing products, exact system settings or detailed contract deadlines that this review did not retrieve. [2]

The settlement page identifies a $16 million resolution and corrective action to settle potential HIPAA Privacy and Security Rule violations. It is more precise to call this the federal settlement amount than a criminal fine. The source does not establish that the payment measures total individual harm, the complete cost of recovery or every subsequent legal exposure. The article also does not treat the settlement as evidence that all controls were completed at the moment the amount was announced. [1]

The control concerns suggest a governance problem broader than employee awareness. A documented risk analysis should identify the systems and data flows under review, evaluate plausible threats and connect findings to funded remediation. A policy on paper needs an owner and evidence of use. Training should support that system, not act as the sole explanation when privileged access or enterprise monitoring is ineffective. These are original implications drawn from the public concerns, not an assertion of additional findings by OCR.

A useful corrective-action record would therefore preserve the deficiency, intended security property, responsible person, implementation evidence and independent verification. If a finding concerns enterprise-wide coverage, closing one local ticket does not settle it. If it concerns response, buying a logging tool does not prove that analysts can interpret or act on its signals. The form of the evidence must match the failed control rather than the easiest administrative task to complete.

## 7. A warehouse is a concentration of authority

An enterprise data warehouse supports legitimate analytical and operational work by combining information that might otherwise remain distributed. That utility also makes it a high-consequence security boundary. The question is not simply whether the warehouse is inside a corporate network. It is which users and services can reach it, which datasets they can query, which operations they can perform and where the results may go. The analysis here is a proposed model for comparable environments, not a diagram of Anthem's unpublished implementation.

Access design should start with business tasks rather than job titles alone. A routine support function, a reconciliation job and an approved research export need different fields, volumes and durations of access. A broadly named analyst role can obscure those differences. A good review asks whether the user needs identifiable data, whether an aggregate or masked result serves the purpose, and whether the same permission should persist after the task ends. Those decisions should be recorded so that a later access review can test the original rationale.

Bulk retrieval deserves its own authorization boundary. Permission to look up one account should not silently authorize an export of an entire historical population. A comparable organization can require a defined purpose, approved destination, limited dataset and accountable recipient for large extracts. This does not mean every analytical query needs manual approval. It means the design should distinguish routine bounded work from operations whose scale changes the consequence of credential compromise.

The warehouse's supporting systems also belong in scope: scheduled jobs, service identities, management consoles, staging areas and retained exports. Protecting the principal database while leaving a duplicate extract broadly accessible only moves the risk. An inventory should show where sensitive results are created and how long they remain. The useful unit of protection is the full data path, not just the server listed on an architecture slide.

## 8. Privileged identity requires independent control

The California regulator's historical page describes a database administrator noticing use of his credentials without his consent. It relays Anthem's account of shutting down database access and requiring employee password resets. This is an important detection narrative, but it is not a substitute for a full forensic explanation of how every credential was obtained or which sessions persisted. The page should be read as a historical consumer account, not an assertion that password resets alone completed eradication. [8]

For a comparable organization, administrative authority should be separated from ordinary browsing and email activity. The proposed design should give privileged tasks a constrained path, a clear approval basis and an auditable session. Shared administrative accounts make it harder to distinguish legitimate work from misuse and should be avoided where individual accountability can be provided. Emergency access still needs logging, post-use review and a process for ending temporary authority.

Revocation must be tested as a workflow. A password change may address one credential but leave active sessions, service tokens or other access paths unaffected. The appropriate scope depends on the actual environment and evidence; this article does not assert those specific mechanisms were used in the incident. The recommendation is to identify all relevant authority held by a compromised identity and verify that response actions terminate the intended access without accidentally breaking essential business processes.

A useful test uses synthetic accounts and documented expected behavior. Confirm that ordinary users cannot enter privileged workflows, that temporary approval expires, that a revoked session loses access where intended and that the analyst can see the relevant events. Record which systems were included and which were not. That evidence is more useful than a blanket assurance that privileged access is protected because one authentication feature has been enabled somewhere in the organization.

## 9. Encryption is necessary context, not a universal answer

The state assurance describes information accessed in unencrypted form. The indictment separately alleges that the attackers placed extracted information into encrypted archives. These refer to different stages and purposes. Neither statement means that the defenders' protection and the attackers' packaging were the same mechanism. In particular, an attacker encrypting stolen files for transport does not establish that the original records were protected from that attacker at the point of retrieval. [3,6]

For a proposed architecture, encryption should be considered at rest, in transit and in relation to key access. Its effectiveness depends on the threat being addressed. Storage encryption can protect a lost medium or an unauthorized reader of raw storage, but an authorized application path may legitimately return readable information. If an intruder controls an identity that the application accepts, additional authorization and monitoring boundaries remain necessary. The design must explain which adversary capabilities the chosen protection actually constrains.

The same caution applies to external transfer monitoring. An encrypted connection is not proof of an approved destination or authorized business purpose. Conversely, encryption should not be disabled merely to make a diagram look easier to monitor. A comparable organization should govern permitted transfer channels, approved accounts, information classes and exceptions. The objective is to preserve confidentiality while retaining enough accountable metadata to investigate suspicious movement and enforce policy.

This section does not conclude that one encryption deployment would certainly have prevented the historical incident. Such a claim would require details about identity control, keys, application behavior and extraction paths that the public record does not fully supply. The defensible lesson is to connect cryptographic protection with authorization and operational evidence, rather than treating the word encrypted as a complete description of safety.

## 10. The 2020 assurance and its limits

The state assurance was entered without a trial, adjudication or admission of liability. It calls for a written security program, consideration and adoption of zero-trust principles where reasonably feasible, governance reporting, incident-response planning and specified technical controls. Its privileged and remote-access provisions include multifactor authentication or reasonably equivalent technology in defined contexts. Those qualifications matter: the document is not a blanket historical finding that every account lacked every factor, nor is it a product certification. [6]

New York's announcement describes the $39.5 million multistate penalties-and-fees resolution, more than $2.7 million for New York, and third-party assessments over three years. It also notes California's similar but separate agreement. A reader should not multiply the announced multistate amount by the number of participating jurisdictions or add California again without checking the governing allocation documents. The release is a summary of the resolution, not an audited reconciliation of every dollar associated with the incident. [5]

The original interpretation developed here is that a security program must connect architecture, operating procedures and executive accountability. Requirements about access, logging, testing and reporting are useful only if they produce observable behavior. A compliance calendar can help organize deadlines, but it cannot prove the controls work. A comparable organization should use the document as a case-specific illustration of enforceable corrective work, not as a universal legal checklist for every health organization today.

The agreement also should not be mistaken for a current assurance report. A promise to obtain an assessment is different from a published assessment result. This study did not receive the private reports or independently evaluate their findings. It therefore makes no claim that the company passed every later test, or that the absence of a public report implies failure. The distinction between an obligation and its verified fulfillment is essential in long-term incident research.

## 11. Money: separate remedies from total loss

There are several distinct monetary categories in this history. The federal HIPAA resolution is one; the later state resolution is another. New York's release also describes an earlier $115 million class-action settlement fund for consumer-related benefits and reimbursement, and says the claim deadlines had already passed at the time of the 2020 announcement. These are not interchangeable amounts, and this article is not an invitation to submit a new claim under an old program. [1,5]

Anthem's early SEC filing said it could not quantify the eventual incident expense and expected further investigation and remediation costs. It also described uncertainty about litigation and insurance sufficiency. Its statement that the attack did not affect the results for the year ended December 2014 should not be turned into a claim that the breach had no subsequent financial effect. Reporting periods and subsequent events matter when interpreting that sentence. [7]

A proposed cost register should distinguish announced settlement obligations, amounts confirmed paid, legal defense, investigation, technical restoration, consumer support, insurance recovery and other business effects. It should preserve the date and source for each figure and identify overlaps. Summing selected public amounts can produce a number, but not necessarily a defensible total cost. Without a complete reconciliation, that sum may omit large categories, mix gross and net values or count the same benefit twice.

Individual consequences need a separate assessment. A settlement fund does not directly measure each person's harm, and a maximum payment is not a statement that every affected person received it. The time needed to resolve an identity issue, the anxiety created by disclosure and the risk of later misuse can differ substantially across individuals. This study does not invent an average victim loss or a lifetime fraud projection to fill that evidence gap.

## 12. Long-lived identity and safe communication

A password can be replaced relatively quickly; an individual's date of birth and historical identity relationships cannot be treated the same way. The analytical concern is therefore persistence: information copied during a breach can remain useful for recognition, impersonation or linkage long after the original system is restored. Those are possible consequences, not proof that every Anthem record was used for fraud or a particular intelligence purpose. The distinction prevents a genuine privacy risk from becoming an unsupported certainty.

A comparable response plan should explain data categories in plain language and avoid using the exposed information itself as proof that a caller is legitimate. An impersonator's knowledge of an address or plan relationship should not be enough to approve a sensitive change. Support processes should offer independent verification paths and avoid collecting unnecessary additional identifiers from worried individuals. The incident should not create a second avoidable privacy exposure through poorly designed assistance.

California's historical page warned of fraudulent messages offering help after the incident. This reinforces a communication-design lesson: an organization's notice should tell recipients how to verify the support route without depending on an unsolicited link. Historical phone numbers, enrollment sites and service terms are not reproduced here as current advice because their availability and rules may have changed. The document is a case study rather than a live assistance directory. [8]

Children and former members create particular scope-management questions. A person may not recognize the brand or may no longer have an active account, yet their historical information may still be present in retained datasets. A proposed notification process should account for those relationships without assuming that the current customer list is complete. It should also avoid exposing minors' information in ordinary support exchanges or in public examples used to explain the incident.

## 13. Proposed detection and containment workbench

The workbench proposed here begins with a small number of high-value questions rather than a large list of isolated indicators. Which identities can query the warehouse? Which operations retrieve unusually broad or sensitive results? Which endpoints and services can create exports? Which external destinations are approved? Which events can analysts connect across those systems? A team should establish that the necessary evidence exists before promising it can detect every stage of the modeled threat.

For identity activity, a record should connect the account, device or originating service, session and relevant authorization decision. For warehouse activity, it should capture enough context to distinguish expected work from anomalous access without unnecessarily duplicating the sensitive result in logs. For transfer activity, the system should identify destination ownership and business approval where feasible. Log access itself should be restricted, because a monitoring platform can become another repository of sensitive relationships.

Containment should be a coordinated decision among incident responders, identity administrators, data owners and business operators. If a suspicious identity supports a scheduled process, disabling it may interrupt a legitimate service. That does not justify leaving it active without limits; it means the response plan needs an alternative and an accountable decision. Preserve evidence, restrict unnecessary paths and document residual access while the investigation establishes the appropriate scope.

A test should exercise both technical behavior and human workflow. Use a controlled synthetic export to confirm that the expected signal reaches an analyst with enough context to act. Then test revocation and verify the access actually ends. Record the result, elapsed response interval and any blind spots. This is an original validation proposal for authorized environments, not a claim that a particular commercial tool would certainly have detected the real incident sooner.

## 14. Board reporting and corrective-action closure

A board report should describe exposure in terms a decision-maker can challenge. Useful proposed measures include the number of sensitive data paths without an accountable owner, the proportion of privileged roles with verified review, the age of unresolved high-consequence findings and the scope of extraction monitoring. Each measure needs a denominator and a description of what is excluded. A favorable percentage based on an incomplete inventory can conceal the most important risk.

Corrective actions should progress through distinct states: planned, implemented, awaiting verification and verified within a defined scope. The person implementing a change should not be able to declare enterprise-wide closure solely by closing a local ticket. Independent reviewers should sample evidence and test whether the intended property holds. If the environment changes, the old result may need to be revisited rather than remaining permanently green in a dashboard.

Executive escalation should be tied to consequence and decision need, not only to technical severity labels. An unexpected broad query by a privileged identity may matter even when no machine is visibly unavailable. A response team should be able to explain what is known, what remains uncertain, what action is underway and which decision requires leadership. That report should avoid speculation about motive while still communicating the potential scale of the data exposure.

The proposed closure package would include the scoped timeline, data-category assessment, authority changes, monitoring evidence, consumer communication decisions and remaining exceptions. It would also assign responsibility for keeping the improvements effective after the incident team disbands. Recovery is not merely a return to ordinary activity; it is a documented state in which the organization understands the relevant risk and can show why the restored operation is acceptable.

## 15. Fictional tabletop: the unexpected warehouse export

This fictional exercise adds no historical Anthem facts. A health-plan administrator receives an alert about a broad export associated with a privileged identity. The identity owner says they did not initiate it. A related endpoint recently received a suspicious message, but the team has not yet established whether the events are connected. Participants must decide what evidence to preserve, which access to restrict and which business functions could be affected by immediate revocation.

The first inject is a dataset containing current members, former members and people associated with partner plans. The team must produce a scope model that does not simply copy the current enrollment number. The second inject is an archive sent through a familiar cloud service. Participants must determine whether the account and destination were authorized rather than treating the provider's brand as proof of legitimacy. The third inject is an executive request for a single total cost before the investigation has stabilized.

A successful team should respond with a clear separation of confirmed facts, hypotheses and decisions. It should avoid announcing a motive, a clinical-data category or a monetary loss unsupported by the available evidence. The communications group should draft a notice that explains uncertainty and gives a verifiable support route. The technical group should demonstrate how it would confirm that containment terminated the relevant authority, including any exceptions required for essential operations.

The final exercise product is a short decision record, a data-category ledger, a restoration gate and a list of unresolved questions with owners. Scoring should reward sound evidence handling and accountable choices, not speed alone. A team that identifies a consequential unknown and assigns a bounded investigation has performed better than one that invents certainty to finish the exercise. This makes the case useful without reenacting an attack or disclosing operational exploitation steps.

## 16. Final judgment and limitations

Anthem is a case about the relationship between identity, authority and concentrated data. An initial compromise becomes much more consequential when the surrounding environment permits broad access and the organization cannot promptly distinguish legitimate use from abuse. The most valuable defensive lesson is to make those boundaries explicit and verifiable. A slogan about awareness or a single security product cannot replace the decisions about who may retrieve which information for which purpose.

The public record supports a serious account of the incident and several later institutional responses. It does not provide every forensic detail, establish the final destination or use of every record, or justify claims about current controls. This study preserves the criminal allegations as allegations, distinguishes settlements from adjudicated liability and keeps historical support information separate from current advice. The detailed federal corrective-action agreement was not retrieved; that limitation remains visible rather than being filled with assumptions.

For a comparable organization, the practical next step is to select one important data path and test it end to end: business purpose, approved identity, permitted query, export destination, monitoring signal and revocation behavior. Record what succeeds and what remains unverified. Then expand the coverage deliberately. That approach turns an enormous historical breach into a manageable set of security responsibilities while keeping the people behind the records at the center of the analysis.

## Source register

[1] HHS OCR, Anthem settlement page, 15 October 2018. Official summary reviewed; linked full federal agreement and archived press release were unavailable during retrieval. https://www.hhs.gov/hipaa/for-professionals/compliance-enforcement/agreements/anthem/index.html

[2] HHS OCR, Annual Report to Congress for Calendar Year 2018. Targeted Anthem section on printed pages 14–15 reviewed; not an exhaustive review of all unrelated enforcement cases. https://www.hhs.gov/sites/default/files/hipaa-compliance-report-to-congress-2018.pdf

[3] United States v. Fujie Wang and John Doe, indictment filed 7 May 2019. Alleged conduct and chronology reviewed, particularly paragraphs 12–16; indictment is not a conviction. https://www.justice.gov/d9/press-releases/attachments/2019/05/09/anthem_indictment_0.pdf

[4] DOJ, indictment announcement, 9 May 2019. Official charging account; no current case disposition inferred. https://www.justice.gov/archives/opa/pr/member-sophisticated-china-based-hacking-group-indicted-series-computer-intrusions-including

[5] New York Attorney General, multistate settlement announcement, 30 September 2020. Monetary categories and historical class-action context reviewed. https://ag.ny.gov/press-release/2020/attorney-general-james-helps-secure-395-million-after-anthems-2014-data-breach

[6] Anthem multistate Assurance of Voluntary Compliance, effective 30 October 2020. Relevant introduction, control provisions, payment terms and paragraph 43 non-admission reviewed. https://ag.ny.gov/sites/default/files/anthem-_final_multistate_assurance_ny.pdf

[7] Anthem Form 10-K for year ended 31 December 2014. Targeted Data Breach disclosure, printed pages 129–130; company statements dated to filing, not a current assessment. https://www.sec.gov/Archives/edgar/data/1156039/000115603915000003/antm-20141231x10k.htm

[8] California Department of Insurance, consumer information on Anthem breach. Historical scope, detection narrative and scam warnings reviewed; old enrollment and contact details not offered as current advice. https://www.insurance.ca.gov/0400-news/0100-press-releases/anthemcyberattack.cfm
