# Zynga 2019: Player Credentials, Notification and the Court Record

*A TeamStarWolf case study. Published 16 November 2026.*

[All case studies](/case-studies/README.md) · Related: [Data Security Reference](/DATA_SECURITY_REFERENCE.md), [Password Security Reference](/PASSWORD_SECURITY_REFERENCE.md), [Regulatory Landscape Reference](/REGULATORY_LANDSCAPE_REFERENCE.md), [Incident Response Reference](/INCIDENT_RESPONSE_REFERENCE.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Data-protection and security teams, incident responders and anyone separating breach facts from accumulated legal claims

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 14 min (3,188 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You want an evidence-bounded account of the 2019 Zynga breach, you need to separate a company notice, a breach index, a complaint and a court ruling, or you are avoiding inflated counts and invented technical causes

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Executive assessment](#executive-assessment), [4. Hashing is not encryption, and storage is not initial access](#_4-hashing-is-not-encryption-and-storage-is-not-initial-access), [5. Keep the OMGPOP history separate](#_5-keep-the-omgpop-history-separate)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Data Security Reference](/DATA_SECURITY_REFERENCE.md), [Password Security Reference](/PASSWORD_SECURITY_REFERENCE.md), [Regulatory Landscape Reference](/REGULATORY_LANDSCAPE_REFERENCE.md), [Incident Response Reference](/INCIDENT_RESPONSE_REFERENCE.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## Executive assessment

Zynga's 2019 breach is a useful case in separating an account-data incident from the many claims that accumulate around it. A company notice, a breach-index entry, a complaint and a court ruling can describe related events while establishing different things. Treating all of them as interchangeable produces inflated counts, invented technical causes and misleading legal conclusions.

This study emphasizes the original notification and the procedural history. The available record supports a chronology of discovery disclosures, published data analysis, litigation, arbitration-related discovery and dismissal decisions. It does not support an independently reconstructed entry technique, a complete incident cost or a claim that every affected user suffered the same harm.

The account also demonstrates that an early procedural win or loss may not remain the final posture. A motion can be denied because the record is incomplete, renewed after discovery and then granted. Omitting that sequence can reverse the meaning of the history.

## 1. What the original notification actually said

The California Attorney General's archive preserves a Zynga sample notice in a file dated September 30, 2019. It described possible unauthorized access around August 31 and told the recipient that a username and password might have been obtained. Zynga reported engaging forensic specialists, taking precautions against invalid logins and contacting law enforcement. It said it did not collect player Social Security numbers, believed financial information had not been accessed, and stated that law-enforcement investigation had not delayed this notice. [1]

This is a company-authored notice hosted by a regulator. Its presence in the archive does not mean the regulator independently verified each sentence. It is strong evidence of what Zynga communicated, with useful specificity about the information the notice addressed.

It is not a complete inventory for every game or every account. A notice written for one affected category can identify fewer fields than a broader investigative record. Conversely, a larger list elsewhere cannot automatically be applied to every recipient. Exposure must be assessed at the level of the relevant records and account systems.

The date also deserves care. An approximate access date, a public announcement date and a document filename are different evidence. None should silently replace the others in a timeline.

## 2. September disclosure and later investigative language

Zynga's 2021 annual filing dates the public announcement to September 12, 2019. It reports that the investigation found unauthorized access to certain player-account and other company information in the third quarter, with no financial information accessed. It also describes notifications, regulatory correspondence and responses to European data-subject requests. [2]

A historical summary should retain the difference between an early tentative account and a later reported finding. The change is not necessarily evidence of contradiction; it can reflect investigation. The proper approach is to identify who made the statement and when.

At the same time, a company conclusion is not an independent forensic replication. This study did not inspect server logs, database access records or the outside investigators' full report. It therefore does not assign a particular vulnerability, initial credential, malware family or network path to the incident.

The absence of financial fields does not make account information irrelevant. Authentication data can have value independent of payment-card information. The task is to describe the actual exposure rather than either minimize it as non-financial or inflate it into a financial-data breach unsupported by the sources.

## 3. What the breach index adds

Have I Been Pwned describes roughly 173 million unique email addresses in the Zynga data supplied to it by dehashed.com, alongside usernames and salted SHA-1 password hashes. Its entry lists phone numbers among the compromised-data categories and records December 19, 2019 as the date it was added to the service. [3]

That is a report about a particular corpus assessed by a breach-index operator. The count is not automatically a count of unique human beings, active players, paid customers or notified recipients. Nor is the date of index inclusion the date the intrusion began.

A single person can use multiple email addresses. An address can appear in more than one product or record. The analyst needs a unit of measurement before comparing totals. A headline that changes unique addresses into people changes the claim rather than merely shortening it.

The public index description is sufficient for this discussion. No exposed passwords, user records or bulk breach data were acquired, searched or redistributed. Research does not need a copy of the stolen corpus to explain the distinction between an index population and a verified company-wide population.

## 4. Hashing is not encryption, and storage is not initial access

A hash is a verifier derived from an input, not an encrypted password intended to be decrypted. Salting and computational cost concern resistance to guessing when verifiers are exposed. They do not explain how an intruder first reached a database.

This distinction prevents two common errors. First, describing a hash as encryption can imply that a secret decryption key is the central issue. Second, learning a hash format from exposed data can tempt a writer to present it as the cause of the intrusion. These are separate questions.

The relevant analysis here is bounded. HIBP supplies a storage-format description for its corpus. The reviewed company notice supplies a warning about account credentials. Neither supplies a complete technical chain for initial access, privilege escalation or extraction.

A defensive review would distinguish protection of the stored verifier from protection of the online login and from containment after a breach. Stronger storage can reduce some consequences without preventing every access incident. Login controls can reduce online abuse without making a previously copied verifier disappear. These are analytical distinctions, not additional findings about Zynga's unpublished implementation.

## 5. Keep the OMGPOP history separate

HIBP's separate OMGPOP entry describes an approximately 2013 incident involving more than seven million email/password pairs, with plaintext passwords, later leaked in 2019. It was added to HIBP in November 2023. [4]

This is an important historical boundary. The fact that two data sets are associated with related gaming businesses and circulated in the same general period does not establish that they came from one intrusion. It also does not establish that their populations are disjoint.

Combining the entries would create several potential errors: adding overlapping accounts, assigning an older storage practice to a newer system, or moving an older intrusion forward to the date its data circulated. Each changes the underlying claim.

The appropriate practice is to maintain separate incident identifiers, original dates, exposure descriptions and source roles. A later comparison can discuss the relationship, but should not merge the evidence into a single narrative without a documented basis.

## 6. The first wave of litigation

The 2021 annual filing records five federal consumer class complaints beginning in March 2020. It identifies the initial action on March 3, another on March 23, a third on April 15, the Maryland Oeste action on June 9 and a fifth in August. Plaintiffs alleged inadequate protection, deficient notice and related harms. The filing describes these as allegations, not conceded liability. [2]

This chronology establishes an accountability phase distinct from the security investigation. A complaint may describe suspected deficiencies and requested remedies, but filing it does not prove all asserted facts. A company's summary of the complaint also does not substitute for the court's eventual reasoning.

The named plaintiffs do not define the full technical exposure population. Their accounts, allegations and procedural positions matter to the lawsuit. A technical researcher should not assume that the data fields affecting one litigant are representative of every player.

The study avoids reproducing unnecessary personal details about litigants, particularly a plaintiff identified by initials as a minor. The legal issue can be explained without amplifying personal account information.

## 7. January 2021: evidence of assent was missing

The January 6, 2021 order denied Zynga's arbitration motions without prejudice and allowed limited discovery. The court lacked sufficient verified account information to determine which terms, if any, the plaintiffs accepted. It ordered account-identification information to be supplied within fourteen days. [5]

The phrase without prejudice is consequential. It meant the denial was not a permanent ruling that arbitration could never apply. The court was addressing an evidentiary gap before making the requested determination.

The case therefore illustrates a nontechnical record problem: matching a person to an account and an account to a particular interaction with contract terms. A generic description of how a product normally works may not prove what happened for a specific account.

This observation is not a recommendation to collect unlimited data. It points instead to precise retention and provenance: what version was shown, what event was recorded, and whether the record can be reliably linked to the relevant account. Those questions matter when a later proceeding depends on historical user interactions.

## 8. May 2021: transfer was not a breach-liability decision

The Maryland court's May 5, 2021 Oeste opinion transferred the case to the Northern District of California and denied jurisdictional discovery as moot. It explicitly treated the complaint's background allegations as true for its analysis. That background included an account-count assertion and criticism of the notification channel. [6]

The opinion should not be cited as if a trial established the exact breach population or every claimed notification failure. Its operative task was where the litigation should proceed, not a final determination of the cybersecurity merits.

This matters because the archived sample notice and complaint allegations can appear inconsistent when stripped of context. The existence of a sample recipient notice does not prove that every player received one. A complaint's assertion about lack of direct notice does not establish that no notice of any kind existed. Scope, timing and recipient category must be investigated before asserting a contradiction.

A responsible audit would retain both records, describe what each says and identify the unresolved delivery question. It would not silently discard the source that makes the story less simple.

## 9. July 2021: the renewed motions had a different result

On July 23, the court allowed additional briefing concerning the Supreme Court's TransUnion decision and said the forthcoming dismissal hearing would focus on standing. [7] The July 30 order then compelled arbitration for three plaintiffs and dismissed the remaining claims for lack of Article III standing with leave to amend. It set August 27 for the amended complaint and September 20 for Zynga's response. [8]

The order found agreement to the relevant terms for the arbitration plaintiffs and addressed delegation of arbitrability questions. For the other plaintiffs, the court found the then-pleaded injury insufficiently concrete. These are distinct determinations, not one uniform conclusion about all players or all claims. [8]

Standing concerns the basis for invoking federal judicial power. A finding that a complaint inadequately pleads the required injury does not mean that the underlying data access never happened or that every security practice was sound. Conversely, recognizing a breach does not automatically establish every element of every claimant's requested relief.

The sequence from January to July shows why legal outcomes should be read chronologically. Describing only the initial denial would omit the renewed motion's success. Describing only the later order would obscure the role of discovery and account-specific evidence.

## 10. The final order recovered: April 29, 2022

Zynga's first-quarter 2022 filing states that the amended complaint was dismissed with prejudice and describes an effective dismissal of the collective claims. It dates that event March 29, 2022. [9] A later government-hosted judicial opinion cites the published Zynga decision as April 29, 2022. [10]

The follow-up recovered the original 23-page ECF 105 order from a Courthouse News-hosted copy. Its filing stamp and signed final page both establish April 29, 2022. This article therefore uses April 29 for that final order; the company's March 29 statement remains a conflicting source statement, not an equally supported alternative date. The review does not invent a reason for the discrepancy or claim a separate March order existed. The new source resolves the order's own date without rewriting what the SEC filing actually says. [11]

The court granted the renewed motion without leave to amend and expressly dismissed the case with prejudice for lack of subject-matter jurisdiction. Those are the order's terms. Its basis was Article III standing, not a trial finding that Zynga's security was adequate or that no player's information was exposed. It closed the case and terminated motion docket 96. The distinction between a jurisdictional disposition and an adjudication of underlying safeguards is essential when describing this result. [11]

### What the final standing analysis actually addressed

The second consolidated complaint asserted 29 state-law causes of action. In discussing standing, the court grouped the asserted harms into increased identity-theft risk, mitigation time, emotional distress, reduced value of personal information and privacy injury. It considered standing for each form of relief, including damages and forward-looking relief, rather than assuming one sufficient allegation would establish every requested remedy. This is a description of the historical order, not advice about present litigation requirements. [11]

Although Zynga cited a technical director's declaration, the court explained that its jurisdictional analysis did not turn on a factual dispute and treated the motion as a facial challenge. That matters to the evidence hierarchy: background descriptions of the alleged breach in the opinion are not equivalent to findings after a forensic trial. The court was assessing whether the allegations could establish federal jurisdiction, not publishing an independent incident-response report. [11]

For damages, the opinion applied TransUnion's distinction between a future risk and a separate concrete harm. It found the pleadings did not plausibly allege successful identity theft or fraud. It distinguished alleged phishing, spam and attempted credential abuse from an allegation that those attempts actually succeeded. That is narrower than a universal claim that phishing never causes harm or that stolen game credentials cannot be dangerous. It concerns what these plaintiffs had alleged in this complaint. [11]

The court also rejected the presented mitigation-cost and emotional-distress theories because it regarded the associated risk as insufficiently imminent or substantial. Its analysis of credential reuse required several unsupported steps connecting an exposed password, a remaining vulnerable account and an unauthorized transaction. The case study does not reproduce personal examples about individual plaintiffs, particularly minors, to make that chain vivid. The legal reasoning can be explained without redistributing those details. [11]

On economic value, the opinion found that the complaint did not adequately explain how the breach reduced the value of the plaintiffs' specific information or impaired their ability to derive economic benefit from it. A general assertion that information has a market was insufficient for the theory presented. The order also dismissed the requested injunctive relief because the risk was not sufficiently imminent or substantial, and independently addressed declaratory relief despite the absence of a specific defense challenge to that form of relief. [11]

The conclusion expressly avoided a blanket rule that people must always wait for identity theft before seeking relief after a breach. It nevertheless found these allegations insufficient and declined another opportunity to amend. This caution should travel with any summary of the outcome: the disposition does not erase the acknowledged incident, establish a global absence of harm, or determine undisclosed arbitration outcomes. No appeal disposition or complete compensation record is established by this newly recovered document. [11]

The limitation is narrow but important. The corporate report supports the reported disposition. It does not support a detailed reconstruction of reasoning that was not inspected. Nor does it establish every later appeal, arbitration or individual outcome through the current review date.

The nearby $12 million settlement described in the same filing concerns a Washington social-casino case, not this data breach. [9] It must not be reused as a breach settlement amount merely because it appears in the same legal-matters section.

## 11. What an incident audit should preserve

For the notification workstream, preserve the population definition for each notice, the information categories addressed and the evidence of delivery. That would help distinguish a public web announcement from a recipient notice and identify who remained uncontacted.

For the technical workstream, distinguish initial access, data extraction, password-storage format and subsequent account-abuse risk. The public record does not justify collapsing these into one inferred exploit.

For the research workstream, label each number by its unit and source. An index of addresses, a complaint's account estimate and a company notice are not interchangeable population measurements.

For the legal workstream, retain the date and procedural scope of each order. Arbitration, venue, standing, amendment and merits are different questions. A later writer should be able to see exactly what was decided without having to guess from a headline.

These recommendations are original analysis linked to the documentary issues in this case. They are not additional court findings or claims that every recommended practice was absent at Zynga.

## Conclusion and limits

The strongest account of Zynga 2019 is not the one with the largest number or the most elaborate attack diagram. It is the one that preserves the distinction between the company warning, the independently described data corpus, separate older incidents and the changing litigation posture.

No attacker identity is independently established here. No original forensic report or complete cost assessment was obtained. The final-order text has now been recovered and inspected for the disposition and analysis discussed above. Historical statements about no financial access remain attributed to the company; allegations remain allegations. The final order is dated April 29, 2022; the conflicting March date in the company filing is retained as a source discrepancy, not the operative order date.

The result is a bounded case study of account-data exposure and the evidence needed to explain its consequences. It is intentionally not padded with a speculative entry method or a generic control catalogue.

## Source register

[1] Zynga, California sample breach notice, archived September 2019 filename. Full notice inspected; company-authored regulatory submission. https://oag.ca.gov/system/files/CA%20Notification%202019.09.30.pdf

[2] Zynga, 2021 Form 10-K, relevant incident and legal-matters passages. Company investigative account and complaint chronology. https://www.sec.gov/Archives/edgar/data/1439404/000156459022007217/znga-10k_20211231.htm

[3] Have I Been Pwned, Zynga breach entry, reviewed November 16, 2026. Operator's corpus description and inclusion date. https://haveibeenpwned.com/breach/Zynga

[4] Have I Been Pwned, OMGPOP breach entry, reviewed November 16, 2026. Separate earlier incident, not added to Zynga population. https://haveibeenpwned.com/breach/OMGPOP

[5] Northern District of California, January 6, 2021 arbitration/discovery order, Document 60. Full order inspected. https://www.govinfo.gov/content/pkg/USCOURTS-cand-4_20-cv-01539/pdf/USCOURTS-cand-4_20-cv-01539-3.pdf

[6] District of Maryland, Oeste v. Zynga, May 5, 2021, Document 20. Background, procedural ruling and transfer passages inspected. https://www.govinfo.gov/content/pkg/USCOURTS-mdd-1_20-cv-01566/pdf/USCOURTS-mdd-1_20-cv-01566-0.pdf

[7] Northern District of California, July 23, 2021 hearing/briefing order, Document 88. Full order inspected. https://www.govinfo.gov/content/pkg/USCOURTS-cand-4_20-cv-01539/pdf/USCOURTS-cand-4_20-cv-01539-4.pdf

[8] Northern District of California, July 30, 2021 arbitration and standing order. Full extracted order inspected; renewed motion and leave to amend. https://www.govinfo.gov/content/pkg/USCOURTS-cand-4_20-cv-01539/pdf/USCOURTS-cand-4_20-cv-01539-5.pdf

[9] Zynga, first-quarter 2022 commitments and contingencies disclosure. Relevant breach disposition and separate social-casino settlement passages inspected. https://www.sec.gov/Archives/edgar/data/1439404/000156459022018907/R22.htm

[10] Northern District of California, Case 4:22-cv-03506-KAW, Document 28, November 2, 2022. Cited Zynga date passage inspected only; earlier citation evidence, now supplemented by original ECF 105 in source [11]. https://www.govinfo.gov/content/pkg/USCOURTS-cand-4_22-cv-03506/pdf/USCOURTS-cand-4_22-cv-03506-0.pdf

[11] Northern District of California, I.C. v. Zynga, ECF 105, filed and signed April 29, 2022, 23-page order. Original court document mirrored by Courthouse News; disposition and relevant analysis inspected, signed final page visually verified. https://www.courthousenews.com/wp-content/uploads/2022/04/zynga-ruling.pdf
