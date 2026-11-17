# Ashley Madison 2015: Sensitive Context, False Associations and the Meaning of Deletion

*A TeamStarWolf case study. Published 15 November 2026.*

[All case studies](/case-studies/README.md) · Related: [Privacy Engineering Reference](/PRIVACY_ENGINEERING_REFERENCE.md), [Data Security Reference](/DATA_SECURITY_REFERENCE.md), [Identity and Access Management Reference](/IDENTITY_ACCESS_MANAGEMENT_REFERENCE.md), [GRC Reference](/GRC_REFERENCE.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Privacy and security engineers for sensitive-data services, data-retention and deletion owners, incident responders and communications leaders

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 21 min (4,920 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You want an evidence-bounded account of the 2015 Ashley Madison breach, you need to treat sensitive context, false associations and the meaning of deletion carefully, or you are reviewing access control, retention and the evidence behind product and security claims

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Executive assessment](#executive-assessment), [3. Sensitive context and false association](#_3-sensitive-context-and-false-association), [6. Deactivation, inactivity and deletion](#_6-deactivation-inactivity-and-deletion)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Privacy Engineering Reference](/PRIVACY_ENGINEERING_REFERENCE.md), [Data Security Reference](/DATA_SECURITY_REFERENCE.md), [Identity and Access Management Reference](/IDENTITY_ACCESS_MANAGEMENT_REFERENCE.md), [GRC Reference](/GRC_REFERENCE.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

Key takeaways (reviewed 2026-11-17):

- Severity cannot be measured only by the number of payment cards or identity documents involved; context makes ordinary identifiers consequential. ([Executive assessment](#executive-assessment))
- An email address tied to a sensitive service can cause reputational harm even when the association is false. ([Executive assessment](#executive-assessment))
- Product promises carry security weight: a deletion option creates an expectation about what remains after the user leaves. ([Executive assessment](#executive-assessment))
- The study relies on the joint Canadian and Australian privacy investigation and US FTC and state materials. ([Executive assessment](#executive-assessment))

<!-- meta:end -->

## Executive assessment

The Ashley Madison incident demonstrates that the severity of a data breach cannot be measured only by the number of payment cards or identity documents involved. Context can make ordinary identifiers deeply consequential. An email address associated with a sensitive service can expose someone to reputational harm even when the association is false. Security planning must therefore consider what a record implies, how reliable that implication is and how disclosure could affect the person it appears to describe.

This case also connects technical security with product promises. A service that emphasizes discretion invites users to rely on its handling of information. A deletion option creates an expectation about what remains after the user leaves. A security badge implies some basis for assurance. Those representations need evidence behind them. Otherwise, the gap between the interface and the actual system becomes part of the risk rather than merely a marketing issue.

The study relies on the joint Canadian and Australian privacy investigation, Canadian guidance and compliance terms, and United States FTC and state materials. It distinguishes investigative findings, allegations and settlement obligations. It does not identify private users, inspect leaked records, reproduce intimate material or treat an address in a database as evidence of a person's conduct. The defensive recommendations and fictional exercise are original analysis for organizations handling sensitive personal information.

The central lesson is a combined control problem. Access protection must limit unauthorized entry, retention must limit unnecessary exposure, accuracy must prevent false associations, and communication must avoid repeating the harm. A successful response requires all four. Rebuilding servers alone cannot undo copies already published or correct every mistaken inference drawn from them.

## 1. Evidence boundaries and scope

The joint investigation explicitly said it made no conclusion about the cause of the breach itself. Its technical narrative drew on company interviews and documentation, describing a believed credential-based entry path and an incomplete reconstruction. It assessed the adequacy of information-handling practices under Canadian and Australian law. That distinction prevents the report's security findings from being misrepresented as a fully resolved forensic attribution. [1]

The United States complaint contains allegations, while the filed stipulated order resolves matters without a general admission or denial of those allegations, subject to its specific provisions. The Canadian compliance agreement likewise records acknowledgment of the findings without admission of their truth. These procedural qualifications matter even where different regulators identified overlapping concerns. Settlement obligations can be binding without converting every allegation into a contested judicial finding. [4,5]

A responsible case study should also distinguish the organization operating a service from the individuals who used or appeared to use it. The public record supports analysis of company practices and regulatory outcomes. It does not authorize an investigator to expose users or evaluate their personal relationships. This study therefore works from institutional sources and does not access the leaked material or any search tool built from it.

The source review focused on the incident narrative, safeguards, accuracy, retention, representations and enforcement provisions relevant to this analysis. It is not a complete history of every lawsuit or a current assessment of the company's security. References to statutes and remedies describe the historical proceedings. They should not be read as current legal advice or as a claim that all later obligations have been fulfilled.

## 2. Discovery and publication were separate events

The joint report places organizational awareness on 12 July 2015, a public threat by a person or group calling itself the Impact Team on 15 July, and major publications on 18 and 20 August. It described approximately 36 million user accounts. The account count does not establish an equal number of verified identities or actual relationships, and the name used by the intruders is not a verified attribution to specific individuals. [1]

The FTC complaint separately alleged unauthorized network access during late 2014 and early 2015, and unauthorized logins at a payment processor in May and June 2015. It said employees detected a large data transfer on 12 July. These allegations should remain distinct from the later publication dates and from the joint report's explicit limit on conclusions about the breach's cause. [2]

For a comparable response team, the chronology should have separate fields for first known access, detection, containment and publication. Public release can occur after access has ended, and an attacker may retain copies even after credentials are revoked. A containment report should therefore specify what it means: stopping current access, removing persistence, preventing further export or addressing information already outside organizational control.

The timeline should also preserve uncertainty. A log may show that an identity authenticated without proving who controlled it. A missing log may limit reconstruction without proving that the relevant event did not happen. The analyst should record those limitations alongside the timestamp. This makes the timeline useful for decisions while preventing later readers from treating an estimate as an exact forensic fact.

Different official summaries may compress the chronology differently. The preferred approach is to use the more specific primary narrative for event dates and to avoid turning a broad description into a contradiction that the evidence does not support. Publication, announcement and compromise are different verbs. Choosing the correct verb often resolves more confusion than adding another date to a slide.

## 3. Sensitive context and false association

The Canadian regulator reported that inadequate email checks allowed non-users' addresses to appear in exposed databases. It also identified a fabricated trustmark and deficient safeguards. A database entry therefore cannot establish that the associated person registered or engaged in any activity. [3]

For an organization handling sensitive information, accuracy is therefore part of harm prevention. An incorrect association may be as damaging as a correct disclosure, and the affected person may have no account through which to request correction. A privacy program that only considers authenticated customers can miss people whose identifiers were supplied by someone else, whether accidentally or deliberately.

A useful threat model starts with the possible inference. What would a recipient conclude from seeing the record, and how reliable would that conclusion be? The organization should identify whether the record contains verified facts, user-entered claims or automatically inferred attributes. Those categories should remain distinguishable internally. If they are flattened into one authoritative profile, errors become harder to identify and easier to propagate.

The same discipline should govern external research. A breach database is not a reliable public directory. Even a correctly associated account does not prove every inferred personal behavior. Researchers should avoid reproducing names or searching for acquaintances. The legitimate analytical purpose can be fulfilled through aggregate institutional evidence, without amplifying the exposure or turning uncertain records into accusations.

Correction channels need protection against abuse. A person should be able to report a false association without submitting unnecessary intimate information or creating a new visible account. Staff should receive guidance on verifying the request proportionately, limiting access to the disputed record and avoiding messages that disclose the sensitive service to another household member or workplace contact.

## 4. Remote access and credential handling

The FTC complaint alleged weak remote-access controls, unrevoked credentials for former service-provider employees, password reuse and inadequate monitoring. It described a shared remote-access secret and plaintext credentials or keys in internal files. Those are allegations in that proceeding, not evidence that every account was equally exposed or that one specific credential explains the entire intrusion. [2]

The Canadian regulator's technical guidance explains that a password plus another shared secret still relies on the same kind of factor: knowledge. It does not become independent multifactor authentication simply because the user types two values. The guidance also connects documented safeguards with consistent implementation. The lesson is to examine the independence and protection of controls, rather than count the number of prompts on a login screen. [7]

For a comparable service, remote administration should be designed around individually attributable access. Each person needs permissions tied to a current role, and the organization needs a reliable way to revoke them when the role ends. An access register should include contractors and service providers, not merely employees in the human-resources system. The offboarding process must identify active sessions and delegated access as well as directory accounts.

Shared secrets create an additional rotation problem. When one person leaves or one device is compromised, the organization needs to know which other systems depend on the same value. A poorly understood dependency can make rotation disruptive, encouraging staff to postpone it. A safer design reduces unnecessary sharing and maintains enough documentation to change access without losing control of production operations.

Testing should use approved synthetic identities. Reviewers can verify whether a former contractor can still establish a session, whether a low-privilege identity can reach unrelated systems and whether a suspicious login reaches an analyst. The objective is to prove the intended boundary and response, not to reproduce the historical intrusion or expose genuine customer records during an exercise.

## 5. Encryption is a system property

The Canadian release identified encryption in use but also plaintext key storage and weaknesses in password management. This is more nuanced than saying the organization had no security. A mechanism can exist while the surrounding access and operational practices undermine its protection. The analysis should preserve both facts rather than treating encryption as either a universal solution or an irrelevant label. [3]

For a comparable organization, the relevant question is who can obtain readable data under which conditions. That includes the application, administrators, support staff and any service that can use a decryption key. A diagram of encrypted storage is incomplete if it omits the identities that can request decryption or retrieve the key material. The operational authority around the mechanism is part of the protection.

Key management should have its own inventory and ownership. Teams need to know where keys reside, which services use them and how replacement works. A test of recovery should confirm that authorized services can resume while unauthorized identities remain excluded. The organization should also know what happens to archived data when a key changes, so that emergency rotation does not lead to uncontrolled copies or improvised workarounds.

Password hashing and encryption serve different purposes and should not be conflated in a report. A statement about protected passwords does not establish that profile information was unreadable to an intruder. Equally, evidence of plaintext administrative credentials does not justify claiming that every customer password was stored in plaintext. A precise case study names the category and the evidence rather than flattening all secrets into one condition.

Security verification should examine the full path with harmless fixtures. A reviewer can test whether a support role can retrieve data outside its task, whether access is logged and whether the log identifies the responsible individual. The test should produce a repeatable result that can be reviewed later. Product names and algorithm labels are useful context, but they do not substitute for evidence of actual access behavior.

## 6. Deactivation, inactivity and deletion

The Canadian compliance agreement required an end to indefinite retention for inactive and deactivated accounts, a justified schedule covering existing as well as future records, and clearer information for users. It also required a no-cost route to withdraw consent for holding account-profile information, while distinguishing some additional premium deletion services. These were specific remedial obligations, not a blanket statement that every possible record must always disappear immediately. [5]

The FTC announcement described allegations that information remained for people who had paid for the site's Full Delete service. It also described allegations about misleading security and profile representations. The distinction matters: whether a limited retention period could be justified is a different question from whether a customer was accurately told what a paid deletion option would accomplish. [6]

A comparable service should define account states in operational terms. Deactivated might mean hidden from other users but retained internally. Inactive might mean unused for a specified period. Deleted should identify which records are removed, which narrowly defined exceptions remain and when they expire. If staff cannot explain those differences consistently, customers are unlikely to understand them from a short settings label.

Retention should follow a demonstrable purpose. A general preference to keep data in case it becomes useful is not an operationally bounded rationale. The organization should specify the fields needed for a particular obligation, the period required and the access allowed during that period. A billing dispute record may have a different purpose and retention period from intimate profile content. Keeping them together indefinitely makes targeted protection harder.

Deletion testing should include primary databases, search indexes, analytics copies and routine exports. It should also explain backup handling. Some backup systems cannot remove an individual record immediately without compromising their function, but the organization can restrict restoration, apply deletion again after recovery and expire backups on a defined schedule. The user-facing promise should reflect the actual process rather than an idealized instantaneous purge.

## 7. The product promise as a security commitment

The fabricated trustmark identified by the Canadian regulator is important because it shaped the assurance presented to prospective users. A badge can imply independent review even when the organization created it itself. A privacy disclaimer elsewhere does not necessarily correct the impression made at the point of decision. Security claims should therefore be reviewed as product behavior with consequences, not merely as decorative language. [3]

A comparable organization should maintain an evidence register for public assurances. For each claim, the register should identify the supporting assessment, its scope, its date and the owner responsible for keeping the statement accurate. If a certification applies only to one component, marketing should not imply that it covers every service. If an assessment expires or the product changes materially, the claim needs review.

Absolute promises deserve particular scrutiny. A system may offer strong safeguards without being risk free. The purpose of reviewing wording is not to make every statement so vague that it becomes useless. It is to explain the protection accurately enough that a person can make an informed decision. Specific, supportable statements are more valuable than broad guarantees that no realistic system can substantiate.

Deletion claims need the same discipline. A button's label, confirmation message and actual backend action should agree. If some information remains for a lawful purpose, the explanation should identify the category and duration without exposing unnecessary technical detail. A customer should not have to infer the meaning of deletion from scattered policy passages or discover the limitation only after an incident.

The review process should include security, privacy, product and customer support. Each sees a different part of the promise. Engineering knows what the system does, legal and privacy teams understand obligations, product staff control the interface, and support hears where customers are confused. A claim should be approved only when those perspectives align, with a clear owner for later changes.

## 8. Harm beyond monetary loss

The Canadian regulator's guidance emphasizes that breach harm can include reputation, relationships, employment and personal safety, not just financial fraud. It also stresses that safeguards need a coherent governance framework. That perspective is especially relevant when the sensitivity arises from association with a service rather than from a single traditionally regulated identifier. [7]

For a comparable organization, the harm assessment should consider how an adversary or an ordinary observer might use the information. A record can enable harassment or coercion even if it cannot be used to open a bank account. A false record can create a demand for explanation that the affected person has no easy way to satisfy. The assessment should therefore include the consequences of both accurate disclosure and inaccurate association.

This does not justify sensational claims about every person affected. The study does not attribute particular deaths, relationship outcomes or financial losses to the incident. Such claims would require specific, reliable evidence and careful treatment of causation. The defensible lesson is that serious nonfinancial harm is foreseeable and should influence design, response and communication before an incident occurs.

Support processes should minimize further exposure. Staff should avoid asking someone to repeat intimate details when a case identifier and limited verification will suffice. Messages should use a channel appropriate to the person's circumstances, and the organization should consider whether a notification itself could reveal sensitive information to someone else. A technically correct notice can still be harmful if delivered without attention to context.

Internal access should reflect the same principle. An incident does not give every employee a reason to browse affected records. Investigators should use the minimum information needed for the task, maintain access logs and separate aggregate analysis from individual support cases. Curiosity-driven access during a breach response is a preventable secondary risk, especially when the subject matter attracts public attention.

## 9. The United States monetary resolution

The District of Columbia's December 2016 announcement described a combined payment of $1,657,000, with a larger $17.5 million amount subject to the financial conditions of the resolution. Those figures should not be treated as two separate payments or as a complete lifetime cost of the breach. The announcement concerned a coordinated consumer-protection settlement involving federal and state authorities. [8]

The FTC announcement provides the split: $828,500 to the Commission and another $828,500 to the participating states and District. Its rounded description of $1.6 million should be read alongside the exact combined figure. A rounded headline is not necessarily a conflicting estimate. The important distinction is between the agreed payment and the larger judgments whose balance was conditionally suspended. [6]

The filed federal order set an $8.75 million judgment, with partial suspension tied to payment and financial representations, and provisions concerning possible trust remittances. It also prescribed a documented security program and initial and biennial independent assessments. These provisions show why the federal judgment should not be confused with the entire coordinated settlement or with the cash payment announced across all jurisdictions. [4]

For a financial case-study ledger, each amount should have a payer, recipient, currency, legal instrument and status. A judgment, an amount due under a conditional settlement, a cash payment and a company expense are different entries. Adding them indiscriminately can double count the same obligation. Subtracting a suspended amount without explaining the conditions can make the resolution appear simpler than it was.

This study does not establish the final amount ultimately collected across every related proceeding or the company's total response expenditure. It also does not infer a current compensation entitlement. The selected enforcement amounts illustrate the structure of the resolution, not the value of an individual claim. A future expansion should use later primary records to reconcile subsequent developments rather than extrapolate from an initial announcement.

## 10. Remediation is not evidence of completion

The Canadian agreement required evidence supporting implementation, including policies, training material and an independent report. It allowed further information requests and verification. Its termination depended on the Commissioner's written confirmation that the specified measures were satisfied. A list of required changes therefore cannot be presented as proof that every change had already been completed on the announcement date. [5]

A comparable remediation program should use separate states for planned, implemented and verified work. A new policy can be planned before staff receive training. A technical control can be installed before its behavior is tested. A test can pass for one population while exceptions remain elsewhere. Combining those states into one completed checkbox hides the information that leadership needs to assess residual risk.

Each action should have an evidence requirement defined in advance. For account cleanup, the evidence might be a reconciled inventory and a failed login test for removed access. For retention, it might be a sample of expired records and proof that restored backups reapply deletion. For a public claim, it might be the current assessment supporting the exact wording. The evidence should match the claim being closed.

Independent review is valuable when it tests implementation rather than merely repeating management's description. Reviewers need enough access to inspect the relevant population and enough independence to report gaps. At the same time, the review should avoid unnecessarily copying sensitive records. The organization should be able to demonstrate control effectiveness through scoped evidence without turning the assessor's workspace into another high-risk repository.

The closure report should state what remains unknown. Historical data already published may be beyond the company's ability to retrieve. A repaired control may reduce future risk without undoing past exposure. A mature report distinguishes those realities and assigns practical next steps. It does not promise that a completed remediation project restores the world to its pre-incident state.

## 11. Accuracy without excessive identity collection

Email verification presents a design tradeoff. A service may want to confirm that a person controls an address, but demanding extensive identity documents can create a new collection risk. The objective should be to establish only the relationship necessary for the service. Proportionality matters: preventing false association does not automatically require proving a customer's entire real-world identity.

For a comparable service, the account-creation process should avoid attaching sensitive activity to an unverified address. If an address is optional, the product can explain the consequences for recovery. If it is required, verification should occur before the system treats it as a reliable contact or sends revealing messages. The details should be designed with privacy review, including the risk that a verification message itself exposes the service.

Recovery and correction flows need equal care. An attacker should not be able to learn whether a particular person has an account merely by submitting an address. Responses can avoid confirming membership while still helping the legitimate user recover access. The organization should test the full journey, including support scripts, because a careful interface can be undermined by an overly revealing customer-service response.

Data quality should be recorded rather than assumed. A field can be marked unverified, confirmed or disputed, with appropriate restrictions on use. Those states should follow the record into internal analytics and support tools. If an export drops the quality marker, downstream staff may treat an uncertain association as established fact. The accuracy control must survive movement between systems.

A test suite can use synthetic addresses and deliberately mismatched records to check those boundaries. Reviewers should confirm that the system does not make sensitive assertions to the wrong recipient and that correction does not require unnecessary disclosure. This is a preventive privacy test, not a method for searching real people or validating leaked accounts.

## 12. A response plan for sensitive-data exposure

The initial response should combine technical containment with a privacy assessment. Security staff need to restrict unauthorized access and preserve evidence. Privacy staff need to understand the categories involved and the reliability of associations. Customer support needs an approved route for urgent concerns. If those workstreams remain disconnected, the organization may restore systems while leaving affected people without usable information.

Evidence preservation should be selective and controlled. Investigators may need a forensic image or an export to understand the incident, but access should be limited and retention justified. Reports should use aggregate descriptions wherever possible. Screenshots containing intimate details should not circulate in ordinary project channels simply because they help explain the severity of the breach.

Communication should distinguish confirmed facts from investigation questions. A statement can identify the affected service, the relevant time period and the categories at issue without asserting that every record is accurate. It should explain where people can obtain updates through a trusted channel. It should not direct them to leaked-data search sites or encourage them to verify exposure by sharing more personal information with an unknown operator.

The organization should also prepare for impersonation and coercive messages. A response team can provide a safe reporting channel and preserve threatening communications for appropriate review. It should avoid guaranteeing that payment to an extortionist will remove information or stop further demands. Any external action must follow the affected person's authorization and applicable legal guidance rather than an improvised response driven by urgency.

After immediate containment, the team should review why the information existed, who could access it and what promises governed it. That broader review turns the event into a durable improvement. A patch or credential reset can be necessary without being sufficient. The case calls for an incident process that treats product design and data lifecycle as part of security rather than as unrelated follow-up work.

## 13. Fictional tabletop: the disputed account

This exercise is fictional and adds no facts about Ashley Madison. A service handling sensitive personal information detects a suspicious export. A caller then reports that their email address has been associated with an account they never created. A second caller says they previously selected a deletion option and wants to know why information may still exist. The organization has not yet established the complete scope.

The first decision is how to contain access while preserving relevant evidence. Participants should identify who can disable sessions, which records need protection and how to avoid broad internal exposure. They should distinguish the technical investigation from the callers' immediate needs. A person disputing an association should not be required to prove participation in the very service they deny using.

The second inject reveals that the product uses the same label for hiding a profile and deleting underlying information. Participants should map the actual backend states and identify which customer statements require correction. The exercise should produce an accurate description of what remains and why, not a defensive attempt to preserve ambiguous wording after the mismatch becomes visible.

The third inject concerns an internal assurance badge whose supporting assessment cannot be found. The team should determine who owns the claim, whether it should remain visible and what evidence would justify a revised statement. This tests the connection between security evidence and public representation. It should not become a debate about whether a badge is merely decorative if users reasonably interpret it as assurance.

The final inject asks executives to announce complete recovery. One access path has been repaired, but historical exports remain uncertain and a retention exception has no expiry. Participants should describe the verified changes and the residual risks separately. The exercise succeeds when leadership can communicate honestly without waiting for impossible certainty or claiming more than the evidence supports.

## 14. A practical assurance checklist

A comparable organization can begin with a short inventory of its most consequential data associations. For each one, identify the source, verification status, permitted purpose and retention period. Include non-users whose information might be supplied by others. This exercise often reveals that the greatest privacy risk comes from a relationship between fields rather than from any single field considered alone.

Next, select one privileged access path and test it end to end. Confirm who approves access, how the person authenticates, which systems they can reach and how access ends. Include service-provider identities and emergency arrangements. Record any shared secret or informal workaround that makes revocation difficult. The result should be an actionable control finding with an owner, not simply a diagram.

Then test one deletion journey. Follow a synthetic account through deactivation, deletion and backup restoration. Compare the actual state with every customer-facing message. Identify exceptions and verify that their expiry can be demonstrated. If the system cannot support the current promise, change the system or the promise before relying on it as a privacy safeguard.

Finally, review the evidence behind public security claims and the process for incident communication. Confirm that someone can update a claim when its support changes and that staff know how to handle a disputed association. These tests do not certify an entire organization. They provide focused evidence about the specific promises and boundaries most likely to matter when sensitive information is exposed.

## Conclusion

Ashley Madison is a case about the consequences of context. The exposure of an identifier can be harmful because of what observers infer from its association, and that inference may be wrong. Security, accuracy and retention therefore need to be designed together. A system that protects an unnecessary or inaccurate record poorly creates several opportunities for harm, not merely one technical vulnerability.

The regulatory record also shows why careful language matters. Findings about inadequate practices do not resolve every question of forensic causation. A settlement obligation does not prove completion. A conditionally suspended judgment is not the same as cash paid. A database account is not proof of a person's conduct. Preserving those distinctions makes the research more useful and avoids repeating the injuries it seeks to explain.

The durable recommendation is to make every consequential promise testable. Access should have a demonstrable boundary, retention a defensible end, deletion an observable process and assurance a verifiable basis. Where evidence remains incomplete, the organization should state the limitation and assign responsibility for resolving it. That approach provides a stronger foundation than a reassuring badge or an absolute claim of discretion.

## Source register

[1] OPC/OAIC, joint investigation, PIPEDA Report of Findings 2016-005, 22 August 2016: chronology, scope and explicit causation limitation. https://www.priv.gc.ca/en/opc-actions-and-decisions/investigations/investigations-into-businesses/2016/pipeda-2016-005/

[2] FTC, complaint filed 14 December 2016: alleged access failures and incident sequence. https://www.ftc.gov/system/files/documents/cases/161214ashleymadisoncmplt1.pdf

[3] OPC, 23 August 2016 release: security, trustmark and inaccurate email associations. https://www.priv.gc.ca/en/opc-news/news-and-announcements/2016/nr-c_160823/

[4] FTC, filed stipulated order: nonadmission, security assessments and monetary provisions. https://www.ftc.gov/system/files/documents/cases/161214ashleymadisonorder1.pdf

[5] OPC, compliance agreement with Avid Life Media/Ruby: retention, accuracy and verification obligations. https://www.priv.gc.ca/en/opc-actions-and-decisions/investigations/investigations-into-businesses/2016/2016_005_ca/

[6] FTC, December 2016 settlement announcement: allegations and federal/state payment split. https://www.ftc.gov/news-events/news/press-releases/2016/12/operators-ashleymadisoncom-settle-ftc-state-charges-resulting-2015-data-breach-exposed-36-million

[7] OPC, Ashley Madison investigation takeaways: authentication, governance and nonfinancial harm. https://www.priv.gc.ca/en/privacy-topics/privacy-for-businesses/appropriate-handling-of-personal-information/2016_005_ta/

[8] District of Columbia Attorney General, 15 December 2016 settlement announcement: exact combined amount and conditional larger resolution. https://oag.dc.gov/release/owners-ashley-madison-enter-settlement-district
