# Cambridge Analytica and Facebook: Consent, Data Provenance and Platform Accountability

*A TeamStarWolf case study. Published 15 November 2026.*

[All case studies](/case-studies/README.md) · Related: [Privacy Engineering Reference](/PRIVACY_ENGINEERING_REFERENCE.md), [API Security Reference](/API_SECURITY_REFERENCE.md), [Data Security Reference](/DATA_SECURITY_REFERENCE.md), [Regulatory Landscape Reference](/REGULATORY_LANDSCAPE_REFERENCE.md), [Ashley Madison 2015](/case-studies/ASHLEY_MADISON_2015.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Platform and application security engineers, privacy and data-governance owners, API reviewers and disclosure leaders

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 21 min (4,744 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You want an evidence-bounded account of the Cambridge Analytica and Facebook matter, you need to separate consent from a working permission flow or distinct enforcement tracks and populations, or you are reviewing application permissions, data lineage and deletion evidence

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Executive assessment](#executive-assessment), [3. Technical permission and meaningful consent](#_3-technical-permission-and-meaningful-consent), [5. Data lineage across organizational boundaries](#_5-data-lineage-across-organizational-boundaries)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Privacy Engineering Reference](/PRIVACY_ENGINEERING_REFERENCE.md), [API Security Reference](/API_SECURITY_REFERENCE.md), [Data Security Reference](/DATA_SECURITY_REFERENCE.md), [Regulatory Landscape Reference](/REGULATORY_LANDSCAPE_REFERENCE.md), [Ashley Madison 2015](/case-studies/ASHLEY_MADISON_2015.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

Key takeaways (reviewed 2026-11-17):

- It is a cybersecurity case even though the collection mechanism did not resemble ransomware or a conventional network intrusion. ([Executive assessment](#executive-assessment))
- It concerns the authority to collect information, what people were told, and the movement of data between organizations. ([Executive assessment](#executive-assessment))
- Access through a functioning application interface is not proof of meaningful consent. ([Executive assessment](#executive-assessment))
- The study separates adjudicated FTC and SEC findings from allegations resolved by settlement. ([Executive assessment](#executive-assessment))

<!-- meta:end -->

## Executive assessment

The Cambridge Analytica controversy is a cybersecurity case even though the central collection mechanism did not resemble ransomware or a conventional network intrusion. It concerns the authority to collect information, what people were told about that collection, the movement of data between organizations, and the ability to verify that downstream copies and derived products have been removed. These are security and privacy questions that cannot be answered by checking whether a password was stolen.

The public controversy intensified in 2018, but the relevant collection and transfer activity originated earlier. Treating 2018 as the date of a single technical breach obscures that chronology. Equally, treating access through a functioning application interface as proof of meaningful consent confuses a software capability with an individual's understanding and with the permitted purpose of processing. A platform can operate as designed while the resulting data practices create serious harm.

This study uses the United States Federal Trade Commission's Cambridge Analytica opinion and order, related FTC announcements, the Securities and Exchange Commission's disclosure case, Facebook's contemporaneous statements and an ICO statement preserved by an official-release distributor. It separates adjudicated findings from allegations resolved by settlement. It does not claim that a dataset determined an election, that every potentially affected person was profiled, or that a reported population was a verified count of successful persuasion.

The practical focus is defensive governance. Original recommendations address application permissions, consent testing, downstream data lineage, deletion evidence, incident escalation and executive reporting. The fictional tabletop concerns investigation and containment rather than political targeting. No voter-selection strategy or persuasion instructions are provided. The objective is to help organizations recognize and prevent misuse of personal information across legitimate-looking business processes.

## 1. Source roles and legal posture

The FTC's November 2019 opinion found Cambridge Analytica liable on three deception counts. The company had not answered the complaint or opposed the motion for summary decision, and the Commission proceeded on the undisputed record under its rules. That procedural history matters: this was an administrative finding following default, not a criminal conviction or a fully contested trial. The opinion described deceptive collection representations and separate Privacy Shield representations. [1]

The individual proceedings were distinct. In December 2019, the FTC finalized settlements with former chief executive Alexander Nix and app developer Aleksandr Kogan concerning allegations about the collection of Facebook data. The announced restrictions included prohibitions on deceptive privacy representations and deletion of collected information and related work product. Those settlements should not be described as the same procedural outcome as the Commission's finding against the company. [8]

A source register needs to preserve that distinction at claim level. An analyst should not label an entire folder simply as confirmed or alleged. A court filing can contain allegations, a final order can establish obligations, and a company statement can establish what the company publicly said without independently proving the underlying assertion. The useful unit of review is the specific proposition and the authority supporting it.

This research does not audit the current status of every order, bankruptcy proceeding or later lawsuit. Historical Privacy Shield references describe the framework addressed by the 2019 proceeding, not a recommendation to use that framework today. The direct ICO report retrieval failed, and the original 2019 ICO statement URL was unavailable. The UK discussion therefore relies narrowly on the preserved ICO release, not on a claim that the complete investigation report was reviewed.

## 2. A chronology with more than one starting point

The July 2019 FTC complaint describes earlier Graph API access to app users' and friends' data, a 2014 transition period for existing apps, and collection arrangements in 2014 and 2015. These were allegations when filed, preceding the company opinion discussed above. [10]

Facebook's March 2018 statement said it had learned in 2015 that Kogan had passed information to third parties contrary to platform policy. It said it removed the app and requested deletion certifications. The company then announced suspensions after receiving reports that some information might not have been deleted. These are Facebook's dated descriptions of its own response, not independent proof that every recipient complied or that every later report was correct. [3]

The chronology should therefore distinguish collection, transfer, organizational awareness, public disclosure and regulatory action. An event can be old from the perspective of the data holder while being new to the person whose information was involved. A date attached to a newspaper revelation is not necessarily the first date on which a company had notice. Similarly, a policy announcement does not establish that every existing integration changed on that day.

For comparable organizations, an incident timeline should include the source of each timestamp and its confidence level. A developer ticket, contract, export log and public statement may describe different stages of one transaction. Investigators should reconcile those stages rather than forcing them into an artificial single date. This helps legal and communications teams explain what became known, when it became known, and what action followed.

An unresolved interval should remain visible. If logs cannot establish when the last copy was created, the report should say so and identify the next source that might answer the question. Hiding the interval behind a broad phrase such as historical activity makes it harder to determine whether containment was effective. Precision should follow the evidence, not the desire for a clean narrative.

## 3. Technical permission and meaningful consent

Facebook's March statement argued that the incident did not involve infiltrated systems or stolen passwords and emphasized access through its developer channels. That description of the technical route must be read alongside the later FTC findings about deceptive representations to app users. A functioning permission flow does not settle whether the explanation was accurate or whether downstream uses were authorized. The two questions operate at different levels. [3]

The Commission record identified an assurance that the app would not collect identifying information, despite collection of persistent Facebook user identifiers. An identifier that links back to a profile can carry identifying significance even when a particular display-name field is absent. The central issue was not merely whether the user clicked a button, but what the user was led to understand when doing so. [1]

For a comparable platform, consent review should compare the interface text with actual data behavior. Reviewers should inspect what the application requests, what the service returns and what the recipient stores. A concise interface can still be accurate, but important uses should not appear only in a distant document that contradicts the immediate explanation. Testing the wording without testing the data path leaves the core claim unverified.

A useful acceptance test presents a synthetic user with the real permission flow, then compares that person's reasonable understanding with the resulting record. The exercise should ask who receives the data, for which purpose and for how long. It should also ask whether information about other people is included. The objective is to identify a mismatch before launch, not to optimize the interface for the highest possible acceptance rate.

Consent can also become stale when a product changes. An app originally described as a research tool may acquire a commercial purpose, a new owner or a new recipient. The organization should have a review trigger for those changes. Treating the original click as an unlimited license makes the permission record increasingly disconnected from the actual service. A defensible process requires renewed evaluation when the purpose materially changes.

## 4. Friends, app users and population estimates

Facebook's April 2018 update estimated that information about up to 87 million people, mostly in the United States, may have been improperly shared with Cambridge Analytica. The words up to and may are important. The announcement also described changes to application access and notices to users. It was a company estimate of possible sharing, not a count of people proved to have received a particular advertisement or changed a vote. [4]

The FTC complaint used a different population description: roughly 250,000 to 270,000 direct app users and 50 million to 65 million friends, including at least 30 million identifiable United States consumers. Those figures describe a particular evidentiary record and different categories. They should not be added to Facebook's upper estimate or treated as a precise reconciliation of every potentially affected person. [10]

For an investigation team, the first task is to label the counting unit. A direct participant, a friend record, a matched profile and a person receiving a message are not interchangeable. Different datasets may overlap, and a record may be incomplete or duplicated. The population worksheet should therefore retain the source date, geographic scope, inclusion rule and deduplication method for every figure presented to leadership.

The second task is to separate collection from use. A database may contain a record without that record being included in a later model or campaign. Conversely, a derived output may remain after an original row has been removed. Investigators need evidence for each stage rather than assuming that possession proves every possible downstream activity. This protects both accuracy and the credibility of any remediation plan.

A notification process should communicate uncertainty without making it meaningless. If the evidence supports possible inclusion but not exact field-level exposure, the notice can explain that boundary. It should not present the largest available number as a definitive count merely because it is memorable. Clear units and qualified estimates help affected people understand the issue and allow later corrections without making the investigation appear arbitrary.

## 5. Data lineage across organizational boundaries

The most useful analytical model is a sequence of data transformations. Information begins with a platform and its users, moves through an application, enters a recipient's storage, may be linked with other records, and may contribute to a derived product. Every transition can change who controls the information and what purpose it serves. An organization that records only the first export cannot reliably describe the rest of that lifecycle.

A comparable data-sharing program should maintain a lineage record for each significant collection. That record should identify the originating system, the authority for collection, permitted uses, recipient organizations and expected retention. Where a derived artifact exists, the relationship should be recorded in a way that supports later investigation. The aim is not to preserve more personal information than necessary, but to preserve enough provenance to govern the information already held.

Business contracts should align with technical behavior. A contractual restriction on onward transfer is more useful when the provider can identify recipients and when the contract grants proportionate verification rights. A recipient's promise should not be the only available evidence if the data is particularly consequential. At the same time, verification should avoid unnecessary collection of customer information into a second audit repository.

The governance problem extends to internal transfers. A research team may share data with an analytics group that assumes the original purpose has already been cleared. A later commercial team may inherit a dataset with no record of the original limits. Clear ownership and machine-readable restrictions can reduce that ambiguity, but only if someone is responsible for interpreting exceptions and stopping uses that exceed the documented purpose.

Lineage also helps answer a difficult incident question: what must be frozen while the investigation proceeds? If the organization can identify which outputs depend on disputed inputs, it can apply targeted restrictions. Without that map, it may either stop far more activity than necessary or continue using derived products that remain implicated. Better provenance improves both protection and operational precision.

## 6. Application review and legacy exceptions

A platform's application review should examine the reason for every requested field. The fact that an interface can return a field does not mean that every application needs it. A permission request should connect to a visible user benefit and to a defined processing purpose. Reviewers should be able to reject broad access without preventing the application from performing its legitimate core function.

Legacy exceptions deserve their own risk register. A migration that tightens access for new apps while preserving old behavior can leave a significant population under the previous rules. The exception should have an owner, an expiry condition and a way to measure actual use. Otherwise, the public description of a new policy may diverge from the technical behavior experienced by existing users and integrations.

For comparable platforms, testing should include an old application, a newly registered application and an application whose ownership has changed. The review should establish whether permissions persist across upgrades or transfers and whether the user receives a meaningful explanation. These are ordinary lifecycle events, but they can preserve authority long after the original context has disappeared.

Review should continue after approval. A service that changes its collection volume, adds recipients or begins asking for unrelated fields may require renewed scrutiny. Monitoring must be proportionate and respect privacy, but it should provide enough context to distinguish legitimate growth from a change in purpose. A platform that only checks an application once may lose visibility over the very behavior its approval process was meant to control.

A strong program also gives reviewers authority to act. If an app cannot justify its access, there should be a defined route to suspend or narrow it, with business escalation when necessary. The decision record should state what evidence would permit restoration. That avoids both arbitrary enforcement and a system in which commercial importance silently overrides the stated rules.

## 7. Deletion certificates and derived work

The FTC's final order against Cambridge Analytica required identification of recipients and destruction of covered app information and related work product, including algorithms or equations derived from it. It included exceptions and timing provisions for material held by authorities or subject to legal preservation duties, plus sworn confirmations. An order requiring deletion establishes an obligation. It does not itself prove that every copy or derivative was subsequently removed. [2]

This is a broader remediation problem than deleting one database table. A comparable organization may have backups, extracts, feature stores, model artifacts or archived research outputs. Whether a particular artifact must be removed depends on the relevant legal and contractual obligations, but the organization first needs to know that it exists. A deletion certificate without a defined scope can conceal uncertainty rather than resolve it.

A useful verification package identifies the systems searched, the responsible owners, the deletion methods and the exceptions. It should distinguish immediate removal from production use, scheduled expiry in backups and material retained under a legal hold. Each exception should have access restrictions and a trigger for later review. Calling all of these states deleted would make the record easier to read but less truthful.

Derived artifacts require careful technical analysis. A model may depend on disputed data in ways that are not captured by a simple row count. Teams should document training inputs, versions and downstream dependencies before deciding whether retraining, retirement or another remedy is appropriate. This study does not claim that deleting source data always removes its influence or that every model can be repaired through a universal unlearning procedure.

Verification should also avoid creating a new breach. Auditors may need evidence of deletion without receiving the full sensitive dataset. Logs, controlled samples and accountable attestations can provide assurance when designed for the specific environment. Where technical verification is incomplete, the residual uncertainty should be explicit. The goal is evidence proportionate to the obligation, not an impossible promise that no unknown copy exists anywhere.

## 8. Distinct United States enforcement tracks

The FTC announced a $5 billion Facebook settlement in July 2019 to resolve charges concerning violations of its 2012 privacy order. The matter was broader than Cambridge Analytica alone. The announcement described independent privacy governance, executive certifications and stronger outside assessment. It also addressed other alleged practices, including uses of information collected for security. The amount should not be presented as a Cambridge Analytica-specific damages award or a payment by Cambridge Analytica. [5]

The SEC separately announced a $100 million settlement with Facebook over disclosure allegations. It alleged that the company continued to describe data misuse as a hypothetical risk after learning of actual misuse, and lacked appropriate procedures to evaluate the investigation for disclosure purposes. Facebook agreed to resolve that case without admitting or denying the allegations. The securities case concerned investor communications, a distinct issue from the FTC privacy proceeding. [6]

The FTC later reported that the federal court entered the Facebook settlement order on 23 April 2020, after which the Commission approved amendments to its administrative order. The July 2019 announcement and the 2020 court and administrative steps should therefore remain separate milestones. A case study should not compress announcement, judicial entry and administrative modification into one event merely to simplify the timeline. [9]

For analysts, the proper financial presentation is a ledger by proceeding. Each entry should identify the payer, currency, legal basis, procedural status and date. A sum across different penalties may be arithmetically possible but still fail to answer a useful question. It would not establish the cost of the controversy, the amount of consumer compensation or the value of data involved. Those require different evidence.

The governance implications also differ. A privacy review asks whether processing matches what individuals were told and what the organization permits. A disclosure review asks whether public statements accurately reflect material information known internally. An organization needs both processes and a reliable connection between them. Otherwise, an investigation may produce important findings that never reach the people responsible for external representations.

## 9. The United Kingdom outcome and its limits

The preserved ICO statement says the regulator issued a £500,000 monetary penalty under the Data Protection Act 1998 in October 2018. In October 2019, the parties agreed to withdraw their respective appeals, and Facebook agreed to pay without admitting liability. The statement says the money went to the Treasury's consolidated fund. It was not a GDPR percentage-of-turnover penalty or a direct compensation fund for individual users. [7]

The same release contains separate statements from the regulator and Facebook. A claim appearing inside a company's quotation should retain that attribution rather than being presented as an independent finding by the regulator. This is a small editorial distinction with major consequences: a release can preserve multiple positions without resolving every factual dispute between them.

The original ICO page and the full investigation report were not accessible through the attempted retrieval paths. This draft therefore does not present a complete account of every UK investigative conclusion. The limitation should remain visible in the research package. A future revision can expand the section if the full primary documents become available, but should not silently treat a summary or a broken link as if it were a complete review.

For comparable organizations operating across jurisdictions, this case illustrates why incident counsel should maintain a jurisdiction-specific map. Applicable law, enforcement powers and resolution mechanisms differ. A later legal regime should not be retroactively attached to an earlier penalty simply because it is more familiar. Likewise, agreeing to pay after an appeal is a distinct event from admitting every alleged failure or losing after a full merits hearing.

## 10. Harm without exaggerated causal claims

Misleading collection and loss of control can be important harms even when a researcher cannot measure an individual's later behavior. People may care about who holds their information and the purposes for which it is used. A security case does not need to prove a changed election result in order to explain why deceptive collection and unverified downstream handling deserve scrutiny.

At the same time, the existence of a dataset does not demonstrate its effectiveness. A claimed personality score is not automatically an accurate description of a person. A match to a record is not proof that a message reached that person, and exposure to a message is not proof of persuasion. The reviewed enforcement materials do not establish a causal estimate of an election outcome, and this study makes none.

A responsible analysis should separate capability claims, deployment evidence and measured outcomes. Commercial marketing language may describe an ambitious service, but it is not an independent evaluation. If a future study addresses efficacy, it should define the outcome and comparison method and explain uncertainty. It should not infer effectiveness from controversy, dataset size or the confidence of a sales presentation.

The same discipline applies to personal risk. The record does not justify saying that every potentially affected individual suffered financial fraud or had a password compromised. Notices should describe the actual categories and purposes at issue. Exaggerating a different kind of harm may attract attention, but it distracts from the privacy and accountability failures the evidence does support.

## 11. An incident process for data misuse

A comparable platform should have an incident category for suspected misuse through authorized interfaces. If the response process only activates after malware, stolen credentials or abnormal network traffic, it can miss a serious problem carried out through ordinary business channels. Reports from researchers, users or employees should have a route to investigators who can examine purpose, permissions and downstream recipients.

Initial containment can include restricting future access, preserving relevant logs and preventing further transfers while facts are established. Those actions should have clear authority and a documented business impact. They should not destroy evidence that may be needed to understand prior processing. The team needs a plan for preserving proof while limiting continued exposure, rather than assuming that immediate deletion is always the first safe step.

The investigation should compare four records: the user-facing representation, the granted permission, actual collection and actual downstream use. A mismatch between any two can identify a different failure. Broad permissions may be unnecessary even if the recipient did not use them. Accurate collection may still lead to an unauthorized transfer. A good report describes the specific mismatch rather than placing every issue under a vague label such as privacy incident.

Escalation should include the people responsible for external statements. Technical investigators may know that a risk has materialized while public documents continue to use conditional language. A structured handoff can identify which statements need review without requiring investigators to make legal materiality decisions themselves. The important control is that relevant facts reach the decision makers promptly and with their evidentiary limits intact.

Closure should require more than an app suspension. The organization should address previous exports, recipient obligations, derived products and the accuracy of user communications. Some issues may remain unresolved, but each should have an owner and a next step. This creates an honest closure record instead of treating the absence of new API calls as proof that historical misuse has been fully remediated.

## 12. A control-testing plan

The first test is a permission-to-purpose review. Select a representative application and trace each requested field to a documented function. Remove fields that lack a current justification and confirm that the application still works. If an exception is necessary, record its owner and expiry. The result should be a specific access decision, not a generic statement that the developer agreed to platform terms.

The second test concerns representations. Compare the actual permission screen and nearby explanations with a synthetic collection trace. Reviewers should identify any material recipient, purpose or retention condition that the interface obscures. Testing should include a person who did not directly install the app if the design can expose information about connected individuals. This tests the real boundary of the product rather than only its easiest user journey.

The third test concerns lifecycle changes. Simulate an ownership transfer, a purpose change and a permission expansion using a non-production fixture. Determine whether the platform triggers a review and whether the old access remains usable. The expected result should be specified before testing. Otherwise, teams may reinterpret whatever happens as acceptable after the fact.

The fourth test is downstream removal. Use synthetic records to establish whether the organization can find exports and related artifacts, restrict use and obtain appropriate confirmation from recipients. Record what cannot be verified technically. That uncertainty should influence future sharing decisions. A program that cannot determine where a harmless test record went should be cautious about making strong deletion promises for real personal information.

The fifth test addresses disclosure escalation. Give the response team a fictional finding that contradicts an existing public risk statement. Measure whether the fact reaches legal, finance and communications owners with enough context to support a decision. The test should evaluate routing and evidence quality, not require a predetermined legal conclusion. The point is to ensure that the organization can update its understanding when a hypothetical becomes an observed event.

## 13. Fictional tabletop: the repurposed research app

This scenario is fictional and adds no historical claims. A platform approves an application for a limited research purpose. Months later, an employee reports that the application's operator has changed and that a commercial partner possesses a dataset derived from earlier collection. The operator says all collection was technically permitted and provides a brief deletion certificate from one recipient.

The first exercise question is what must be preserved and what access should be restricted. Participants should identify the authority for containment, the relevant logs and the contracts governing previous exports. They should avoid assuming that a valid token proves an acceptable purpose. They should also avoid deleting all evidence before determining whether a preservation obligation applies.

A second inject reveals that the permission screen described non-identifying research while the stored records include persistent identifiers. The team should compare the representation with the data and determine who needs to review the mismatch. The exercise should not jump directly to a public accusation. It should produce a clear factual record that distinguishes observed behavior from unresolved intent and legal interpretation.

A third inject reveals a model artifact and an old export held by another partner. Participants must decide how to trace lineage, suspend disputed uses and document exceptions to deletion. They should explain why the initial certificate is insufficient to answer every question, without asserting that the certificate was necessarily false. Scope and evidence matter more than the reassuring label on the document.

A final inject asks for a public population count and a total financial impact. The team should preserve separate categories for direct users, connected individuals, transferred records and verified downstream use. Financial estimates should distinguish investigation expense from possible claims and regulatory exposure. The exercise succeeds when leadership receives a usable, qualified account rather than a dramatic but unsupported headline.

## 14. Conclusion and research limits

The case expands the conventional idea of a security boundary. Authentication and API permission are necessary controls, but they do not by themselves establish truthful representations, legitimate purpose or acceptable onward use. A platform that distributes personal information needs governance capable of following the data after a technically successful request. That includes evidence about recipients and derived artifacts, not just the initial permission grant.

The historical record also requires procedural discipline. The FTC finding against Cambridge Analytica, individual settlements, Facebook's FTC resolution, the SEC disclosure case and the UK agreement are separate outcomes. Their populations, dates and monetary figures should remain attached to the proceedings that produced them. Keeping those distinctions visible makes the study more accurate and more useful for people designing controls.

This draft does not evaluate current platform security, claim that every deletion obligation was fulfilled or quantify political effectiveness. Its strongest practical recommendation is to test the gap between what a product says, what it permits and what recipients actually do. Where the evidence cannot close that gap, the organization should retain the uncertainty and act proportionately rather than substituting a certificate, a policy or a confident narrative for verification.

## Source register

[1] FTC, Opinion of the Commission, 25 November 2019: default, findings, collection mechanism and population. https://www.ftc.gov/system/files/documents/cases/d09389_comm_final_opinionpublic.pdf

[2] FTC, Final Order against Cambridge Analytica, 25 November 2019: deletion, derived work and preservation qualifications. https://www.ftc.gov/system/files/documents/cases/d09389_comm_final_orderpublic.pdf

[3] Facebook, March 2018 suspension statement: contemporaneous company account and technical characterization. https://about.fb.com/news/2018/03/suspending-cambridge-analytica/

[4] Facebook, April 2018 access update: qualified population estimate and access changes. https://about.fb.com/news/2018/04/restricting-data-access/

[5] FTC, July 2019 Facebook settlement announcement: scope and privacy governance. https://www.ftc.gov/news-events/news/press-releases/2019/07/ftc-imposes-5-billion-penalty-sweeping-new-privacy-restrictions-facebook

[6] SEC, 24 July 2019: disclosure allegations and separate settlement without admission or denial. https://www.sec.gov/newsroom/press-releases/2019-140

[7] ICO, October 2019 agreement statement, preserved by WiredGov; original ICO URL unavailable during review. https://www.wired-gov.net/wg/news.nsf/articles/Statement%2Bon%2Ban%2Bagreement%2Breached%2Bbetween%2BFacebook%2Band%2Bthe%2BICO%2B30102019151000

[8] FTC, December 2019: final approval of Nix and Kogan settlements. https://search.ftc.gov/news-events/news/press-releases/2019/12/ftc-grants-final-approval-settlement-former-cambridge-analytica-ceo-app-developer-over-allegations

[9] FTC, April 2020: administrative order modification after court entry. https://search.ftc.gov/news-events/news/press-releases/2020/04/ftc-gives-final-approval-modify-ftcs-2012-privacy-order-facebook-provisions-2019-settlement

[10] FTC, administrative complaint against Cambridge Analytica, July 2019: alleged API mechanism and earlier chronology. https://www.ftc.gov/system/files/documents/cases/182_3107_cambridge_analytica_administrative_complaint_7-24-19.pdf
