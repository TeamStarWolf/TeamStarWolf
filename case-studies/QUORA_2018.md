# Quora 2018: Breach Discovery, Private Activity and the Boundaries of Public Evidence

*A TeamStarWolf case study. Published 16 November 2026.*

[All case studies](/case-studies/README.md) · Related: [Data Security Reference](/DATA_SECURITY_REFERENCE.md), [Privacy Engineering Reference](/PRIVACY_ENGINEERING_REFERENCE.md), [Password Security Reference](/PASSWORD_SECURITY_REFERENCE.md), [Incident Response Reference](/INCIDENT_RESPONSE_REFERENCE.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Data-protection and security teams, incident responders, and anyone reconstructing a breach from a litigation record

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 21 min (4,807 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You want an evidence-bounded account of the 2018 Quora breach, you need to separate discovery, intrusion and notification dates or a court ruling from a technical verdict, or you are judging what a public record can and cannot establish

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Executive assessment](#executive-assessment), [3. The affected-population estimate and its denominator](#_3-the-affected-population-estimate-and-its-denominator), [10. Summary judgment, expenses and the meaning of a surviving claim](#_10-summary-judgment-expenses-and-the-meaning-of-a-surviving-claim)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Data Security Reference](/DATA_SECURITY_REFERENCE.md), [Privacy Engineering Reference](/PRIVACY_ENGINEERING_REFERENCE.md), [Password Security Reference](/PASSWORD_SECURITY_REFERENCE.md), [Incident Response Reference](/INCIDENT_RESPONSE_REFERENCE.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## Executive assessment

Quora's 2018 breach deserves a more careful treatment than a headline about a large password list. The affected service combined public writing with private interactions and linked-account information. Its public response therefore raised several different questions: what an intruder could retrieve, which capabilities needed revocation, what users could infer from the warning and what evidence could later establish harm. The answer to one question did not settle the others.

Contemporaneous reporting placed the affected population at about 100 million users. Reuters attributed that estimate to Quora and reported the company's notification, logout and investigation efforts. This is a dated company estimate conveyed through contemporary reporting, not a fresh count independently verified for this study. The original company blog and FAQ were inaccessible during this research pass. They are identified as unavailable sources rather than represented as documents personally inspected. [1]

The stronger contribution of this study is its examination of the subsequent court record. Official orders reveal a longer incident chronology and a substantial dispute about evidence, discovery and mitigation expenses. They also demonstrate why a public researcher must distinguish a procedural ruling from a final liability finding. A court may allow a claim to continue without finding that every allegation is true, and may protect material from disclosure without endorsing a company's entire security program.

The article concentrates on the incident's documented timeline, the information categories at issue, the development of the litigation and the limits of what those records support. Interpretations are identified as analysis. It does not reconstruct an exploit, name an unsupported attacker, acquire leaked records or claim a final settlement amount. It is historical cybersecurity research rather than advice about a present legal claim.

## 1. Discovery, intrusion and notification are different dates

The December 2020 summary-judgment order states that Quora learned of the breach on November 30, 2018, approximately six months after the underlying intrusion. It records email disclosure on December 3. Its background also expressly notes a concession about the plaintiff's claimed stolen data for purposes of that motion only. Those qualifications matter as much as the dates. [2]

The interval changes the historical interpretation. A report that associates the breach with the Friday on which it was discovered can leave a reader imagining a short event immediately before the announcement. The court record instead supports an earlier intrusion and a later discovery. This does not establish continuous access throughout the intervening months. It also does not supply an exact initial timestamp, a sequence of repeated visits or the date of every extraction. A defensible chronology preserves the approximate interval without converting it into a precise dwell-time statistic.

The distinction is particularly important when teaching detection. The first event visible to the public is often a notification, while the first event visible to the defender may be an alert or a report. Neither necessarily identifies the first unauthorized action. Evaluating response speed requires an explicit starting point. A discovery-to-notice interval measures a different part of the response from intrusion-to-detection, and neither alone proves that all affected people received and understood a warning.

For Quora, the source record is sufficient to show that these clocks diverged. It is insufficient to diagnose which monitoring control should have discovered the event earlier. The case should therefore be used to examine chronological discipline rather than to assign a missing product or an unreported configuration error as the cause. That restraint prevents a useful detection lesson from becoming a fabricated forensic explanation.

## 2. What the disclosure record says about information

The original December 2018 complaint preserved the company's announcement link and described the claimed information categories: account details, public contributions and activity, imported linked-network data, private actions and non-public content. The filing included examples such as messages and drafts. Its assertions about inadequate security and notice were plaintiffs' allegations, not findings made by filing a lawsuit. [3]

These categories explain why a question-and-answer service can carry consequences beyond login credentials. A public answer is deliberately visible to an audience. A draft may reflect an unfinished thought that the author never chose to publish. A private message involves expectations shared between participants rather than the public. A vote or request may disclose an interest without disclosing a written statement. Treating all of these as interchangeable rows of personal information obscures what exposure would mean to the people concerned.

The distinction also affects scope reporting. Saying that information already available on the website was involved does not answer whether non-public associations or activity were involved. Conversely, listing a category in a notification does not show that every affected account contained every category. Some members may never have sent messages, linked another service or written drafts. A precise account of the breach needs both the possible data types and the population to which each conclusion applies.

The study does not attempt to infer the contents of individual users' messages, interests or histories. Those details would add privacy intrusion without improving understanding of the system failure. The useful analytical unit is the relationship between visibility, identity and access. Quora's mix of public and private participation makes that relationship central to the case, even where the exact contents of the stolen collection remain unavailable to the researcher.

## 3. The affected-population estimate and its denominator

A large published estimate is useful only if its unit remains intact. The approximately 100 million figure in the contemporaneous account was a user estimate attributed to the company. It should not be silently rewritten as a count of cracked passwords, identity-theft victims, private messages or active monthly visitors. None of those quantities follows automatically from an affected-user headline. [1]

This distinction is more than editorial precision. A count of account records can include members with very different authentication methods and levels of activity. A notification population may be deliberately broader than a confirmed extraction population. A list of potential data fields may describe the structure of a dataset without measuring how often every field was populated. A researcher who compresses these differences into one spectacular number creates certainty that the underlying evidence does not provide.

For this study, the estimate serves as context for response scale. It does not establish the total number of people who incurred a measurable expense, received a fraudulent message or had another account entered. The subsequent civil case involves particular claims and evidence. Its existence cannot be multiplied across the entire reported population to calculate a global financial loss. Equally, the experience of one plaintiff cannot demonstrate that other users experienced no consequences.

An incident-specific open question remains: what reconciliation connected the reported population, affected data categories and authentication actions? The reviewed public documents do not provide a complete account-level reconciliation. That is an investigative limit, not a reason to invent a more precise count. The reading tracker should retain the original unit and attribution until a stronger source changes it.

## 4. Response actions and their limits

The contemporary account reports that Quora was notifying affected users, logging out potentially affected accounts, retaining forensic assistance and notifying law enforcement. It also reported the company's statement that anonymous questions and answers were unaffected because author identities were not stored with that content. These are company statements as reported at the time, rather than independent forensic certifications. [1]

The anonymity point should remain narrow. A design that avoids retaining a particular association may reduce exposure of that association. It does not justify a general claim that every possible route to identifying an author has been eliminated. Writing style, details voluntarily included in content or information available elsewhere raise different questions. This study makes no claim that anyone used those routes in this incident. It simply avoids converting a scoped design explanation into a promise about universal anonymity.

Likewise, logout is an action with a particular target. It can interrupt established access, but the word alone does not describe every session type, device or third-party authorization. A password change protects a different capability from deletion of an imported record. The public response should therefore be read as a set of protective steps, not as a single action that reverses every consequence of exposure.

The exact intrusion vector, exploit chain and responsible actor remain outside the established account presented here. A company's statement that it believes it has addressed the root cause is not a public description of that cause. The absence of technical detail prevents a defensible mapping to a specific vulnerability or attacker technique. No ransomware payment, destructive encryption or state sponsorship is established in the reviewed materials, and none is added for narrative drama.

## 5. The civil case becomes a consolidated proceeding

An April 11, 2019 order consolidated the Huynh and Musgrave actions, noting overlapping claims about the same alleged breach and the earlier consolidation involving Cooper. The court declined to appoint interim class counsel at that stage and required a consolidated complaint by April 25. Consolidation addressed the organization of related litigation; it was not class certification or a finding of security liability. [4]

This matters because the case appears under different participant names and document labels. A search result headed with one plaintiff's name can be mistaken for a separate breach or a separate final outcome. The docket number and procedural position are more reliable anchors. The historical incident remains the same while the representation and structure of the lawsuit evolve.

The analytical lesson is to keep the litigation timeline alongside, rather than inside, the intrusion timeline. Consolidating cases does not reveal a new attacker action. Filing an amended complaint does not establish newly discovered technical evidence simply because it occurs later. A procedural order can help explain which questions are being tested, but its function must be preserved when summarizing it for a cybersecurity audience.

For an incident archive, this suggests a useful reading method: identify the decision requested, the evidence the court considered and the decision actually made. Those three items prevent a document title from doing too much work. Here the order contributes organizational history and shows that overlapping claims were brought into one proceeding. It does not supply an exploit narrative, a damages award or a verified measure of downstream misuse.

## 6. Why important technical material is absent from the public account

The September 22, 2020 sealing order approved protection for specified summary-judgment materials. Its reasons included proprietary technical information and the plaintiff's personal information. It addressed entire exhibits as well as selected declaration and briefing passages. The order evaluated whether the designated material should be public, not whether every underlying assertion proved the merits of the case. [5]

This is a concrete reason to avoid treating the publicly accessible record as the complete investigation. A reader can know that technical evidence existed in the proceeding while still being unable to inspect that evidence. The correct conclusion is limited visibility. It is not that investigators necessarily lacked evidence, nor that the concealed portions must contain a particular vulnerability or a damaging admission.

Sealing also creates an asymmetry between institutional and individual information. Technical declarations may be protected because disclosure could affect a company, while deposition exhibits may be protected because they contain a person's information. Both can disappear from the public version for different reasons. A case-study writer should not collapse those reasons into a single suggestion of secrecy or wrongdoing.

The practical consequence for this account is that the attack-path section remains bounded. There is no diagram showing invented entry, privilege escalation and exfiltration stages. Instead, the evidence map distinguishes publicly described effects from unavailable implementation details. That choice makes the study less cinematic, but more useful to someone who needs to know which conclusions can survive source checking.

## 7. Security-sensitive response information and public access

An October 26, 2020 order granted a request to seal portions of exhibits concerning the response to the 2018 attack. The stated concern was that public disclosure could help malicious actors attack Quora's systems. The plaintiff filed the sealing request for material designated by the defendant, illustrating that the filing party and the party seeking confidentiality can differ. [6]

This detail helps prevent a common interpretive error. Seeing a plaintiff request sealing does not by itself mean that the plaintiff independently chose to conceal the entire factual story. The procedural record describes whose designation prompted the request and the court's reasons for granting it. Those distinctions matter when assigning responsibility for what the public can and cannot read.

The order also sharpens the difference between transparency and operational exposure. A useful public incident account can disclose the affected information, key dates and protective actions without publishing details that would help repeat the intrusion. In this case, the court recognized a security concern for particular material. That does not answer whether every public statement was sufficient, but it does establish a documented reason for some limits in the accessible record.

For readers studying incident communication, the question is therefore not simply whether technical details were published. It is whether the available statements support the decisions users needed to make, and whether the withheld material is being mistaken for evidence that no meaningful investigation occurred. The public archive supports discussion of those tensions. It does not authorize guessing the hidden technical content.

## 8. The consultant-identity dispute

On November 3, 2020, the court denied relief from a magistrate judge's refusal to compel disclosure of a consulting expert's identity. It found no clear error and accepted that the plaintiff had not shown the exceptional circumstances required for the requested disclosure. The order referred to other available discovery avenues and evidence concerning retention timing and the absence of a prior consultant relationship. [7]

The significance is narrower than a claim that an investigation was never scrutinized. A dispute over the identity of one consultant is a dispute over one discovery request. Denial of that request does not mean all evidence relating to the incident was immune from examination. Conversely, the existence of other discovery avenues does not give a public reader access to whatever those avenues produced.

This distinction is particularly relevant to cybersecurity reports that use the phrase independent investigation. Without a named public report, a reader may be unable to assess the investigator's methods, scope or evidentiary standards. The appropriate response is to state the limitation, not to confer an independent assurance rating merely because outside assistance was involved. This study does not name the consultant or infer its conclusions.

The case also demonstrates how the legal record can become a source about evidence access rather than about attack mechanics. That is still valuable incident-specific information. It explains why an account based only on public material may remain incomplete even after years of litigation, and why a careful author should preserve unanswered questions rather than treating the passage of time as proof that all relevant facts are known.

## 9. The investigation record and privilege-log protection

A November 13, 2020 order permitted redactions to a deposition transcript and columns of a privilege log. Its reasons included commercially sensitive investigation information, potential security consequences and non-public information about people associated with the investigation. The log concerned an internal investigation conducted at counsel's direction. The court's ruling addressed disclosure of these materials. [8]

For this case study, that finding provides context without supplying the contents of the protected communications. It supports saying that there was a documented dispute over access to the investigation record. It does not support attributing a technical conclusion to a particular lawyer, engineer or consultant whose work is not publicly available. The distinction keeps a procedural description from becoming an invented account of internal decision-making.

A privilege log also serves a different purpose from an incident timeline. It identifies withheld material for a legal process; it is not necessarily a complete operational account of detection, containment and recovery. Even an accessible log would require careful interpretation before its dates could be used to sequence attacker activity. A communication date is not an intrusion timestamp, and an investigation document's title may not reveal the evidence it contains.

The broader analytical point remains specific to Quora's archive: several public orders explain why parts of the record are unavailable. Together they support an explicit evidence boundary. They do not support a conspiracy narrative, nor do they prove that every security decision was correct. A mature case study can acknowledge both limits without forcing the material into an accusation or an exoneration.

## 10. Summary judgment, expenses and the meaning of a surviving claim

The December 21, 2020 decision denied summary judgment on negligence and granted it on the California Unfair Competition Law claim. The order discussed claimed monitoring time and paid monitoring, while recording that the remaining plaintiff did not allege actual identity theft or fraud since the breach. These were issues considered in a pretrial decision, not a final award to the reported affected population. [2]

This is one of the most important distinctions in the case. Expenses incurred after a warning are observable in a different way from a future risk. A receipt can establish that someone purchased a service, while additional evidence is needed to explain why the expense followed from the event and whether it was reasonable. The court's treatment of a disputed issue does not turn every possible defensive purchase into an automatically recoverable loss.

The same distinction prevents overstatement in the other direction. An absence of alleged completed fraud for a particular plaintiff does not make all claimed response effort imaginary. People can spend time and money responding to uncertainty. Evaluating those effects requires attention to what they knew, when they knew it and what they actually did. The case provides a setting for examining that evidentiary problem without treating anxiety, exposure, expense and completed theft as identical categories.

A cybersecurity case study should preserve the procedural posture because readers may otherwise misinterpret the result as a technical verdict. The court was not publishing a complete forensic certification of Quora's systems. A surviving negligence claim meant that the motion did not dispose of that claim on the grounds addressed. The separate result on another claim likewise should not be rewritten as a universal finding that the breach caused no harm.

## 11. January 2021: two different disputes

On January 12, 2021, the court upheld denial of a request for further document production based on an asserted implied waiver of work-product protection. The order described why selective witness testimony had not, in the circumstances presented, required production of the disputed documents. It noted that the witnesses did not rely on those documents in their declarations and that the testimony could be challenged without piercing the protection. [9]

This is an evidence-access ruling. Its usefulness to the incident history lies in explaining another boundary of the public and discoverable record. It should not be translated into a finding that privileged material confirmed the company's position. Material can remain protected without the court disclosing or endorsing the technical propositions a researcher imagines it contains.

A separate order filed January 13 denied leave to seek reconsideration of a factual issue from summary judgment. The court explained that it had identified disputed facts rather than made the factual determination Quora attributed to it. The document's final date line says 2020, while its filing metadata and the subsequent February order establish the 2021 procedural sequence. This study uses the filing date and records that inconsistency rather than silently hiding it. [10]

The two orders illustrate different safeguards against overreading. One concerns the availability of documents; the other clarifies what an earlier decision actually decided. Neither adds a new intrusion event. Both improve the historical account by showing that uncertainty and contested evidence persisted after the main disclosure, and that a later order may be necessary to interpret an earlier one accurately.

## 12. Interlocutory appeal and the limits of broad propositions

On February 3, 2021, the court denied Quora's request to certify questions for an interlocutory appeal and vacated the scheduled hearing. The proposed questions addressed mitigation expenses, causation and the relationship between the parties. The court treated them as mixed factual and legal questions tied to this record, rather than suitable pure questions of law for the requested immediate review. [11]

For a cybersecurity reader, the significance is methodological. Broad statements such as no financial identifiers means no harm can conceal several different propositions: whether a certain statute applies, whether an identity-theft risk exists, whether an expense was incurred and whether that expense was caused by the incident. Those propositions need different evidence. A label attached to one data category does not necessarily resolve them all.

The opposite shortcut is equally unreliable. A denial of immediate appeal does not itself prove the plaintiff's entire account, quantify damage or establish that every affected person has the same claim. It leaves the dispute in a particular procedural position. In a historical study, that position should be stated plainly without presenting an intermediate decision as the final endpoint of the case.

The subsequent June 2021 stipulated judgment, now recovered as an original filed court document, supplies the endpoint missing from an account limited to pretrial orders. It is described below separately from the earlier contested rulings. [13,14]

## 13. Device examination and proportional evidence gathering

The May 19, 2021 order denied Quora relief from a magistrate judge's refusal to compel a forensic examination of the plaintiff's devices used to access the service. The district judge found no clear error or contrary legal conclusion and did not accept the attempt to relitigate the factual determination. This was a discovery decision concerning a proposed examination, not evidence that the plaintiff's devices caused the breach. [12]

That last distinction deserves emphasis. The existence of a request to inspect a device does not establish that the device contains malware, that its owner behaved improperly or that it explains the original incident. An examination can be sought to test a claim or investigate an alternative explanation. The proposal and its justification must be kept separate from whatever an authorized examination might later establish.

The order makes the case relevant to evidence minimization as well as breach response. A device can contain information far beyond the issue being litigated. Investigative value must be considered alongside scope and the showing required for access. This article does not provide instructions to image private devices, bypass access controls or gather unrelated personal material. The documented point is the court's refusal of the proposed route on the record presented.

The May discovery ruling was not the final disposition. Within weeks, the parties requested entry of judgment. Keeping those two events separate prevents the discovery dispute from being mistaken for the endpoint of the lawsuit. [12-14]

## 14. June 2021: the recovered stipulated judgment

The original two-page stipulation, ECF 240, was filed June 4, 2021. The signatures and filer attestation bear June 1. Those dates identify different procedural actions: the parties' dated agreement and its appearance on the court docket. Through counsel, plaintiff Jeri Connor and Quora jointly requested entry of judgment in Quora's favor using a concurrently submitted proposed judgment. The document does not set out an incident reconstruction, compensation schedule or explanation of the parties' negotiating decisions. [13]

On June 7, Judge Beth Labson Freeman signed the judgment, filed as ECF 241. It enters judgment for Quora on all claims in the captioned action and provides that each party bears its own costs, including attorneys' fees. These are the operative terms visible in the recovered document. Its first-page heading retains the word Proposed, but the second page contains the judge's signature and June 7 date, and both pages have the ECF 241 filing stamp. Reading only the title would therefore misclassify an entered, signed judgment as an unapproved draft. [14]

This changes the study's procedural endpoint. The December 2020 refusal to end the negligence claim on summary judgment did not become a plaintiff trial victory. Nor did the February 2021 refusal to certify an immediate appeal determine the ultimate result. The later judgment favored Quora, pursuant to the parties' stipulation. The distinction between a contested merits finding after trial and an agreed procedural disposition must remain explicit: the two-page judgment contains no new factual findings about the attacker's entry method, password security, extraction volume or the adequacy of Quora's response. [13,14]

The costs provision should be described at its actual scope. It allocates costs and attorneys' fees between the parties; it does not quantify their expenditure, establish a global breach-loss figure, or disclose a payment to affected users. Neither recovered document supplies a class-wide compensation fund or private agreement terms. It would be unsupported to invent a settlement amount, infer a secret payment, or claim that no separate arrangement could have existed. Those propositions require evidence beyond the stipulation and judgment. [13,14]

The result also does not erase the earlier public orders. Their explanations remain useful evidence of what the court decided about discovery, claimed mitigation expenses and the issues presented at each stage. They should now be read as intermediate decisions in a case that reached a stipulated judgment for the defendant in June 2021, rather than as an indefinitely pending negligence action. The judgment's stated scope is this captioned action; this study does not extrapolate its effect to every person whose account information was affected or every possible proceeding elsewhere.

## 15. Evidence map and remaining questions

The resulting evidence map has several layers. Contemporary reporting supplies the broad company estimate and response account. A filed complaint preserves the initial dispute and claimed information categories. Official orders establish procedural decisions, some chronology and specific limits on access to evidence. Original analysis connects these records without pretending that their evidentiary status is interchangeable.

The principal unresolved technical questions are the exact entry method, the sequence and duration of unauthorized activity, the completeness of extraction and the detailed relationship between affected account types and protective actions. The reviewed public material does not justify naming a vulnerability, calculating a password-cracking duration or identifying an attacker. The absence of those details is itself important when deciding what a case study can responsibly teach.

The unresolved impact questions are different. The reported population does not establish a deduplicated global victim count or a total economic loss. Particular litigation expenses do not establish loss for all users. A negative statement about one type of harm should not erase other categories of consequence, but a plausible consequence should not be described as an observed event without supporting evidence.

The central recommendation for this incident archive is therefore editorial and evidentiary: retain source dates, procedural status and units alongside every major claim. A reader should be able to tell which statement came from the company, which came from a litigant, which the court actually decided and which is the author's interpretation. That discipline produces a more durable study than a generic list of security products or an invented attack diagram.

Quora's case demonstrates that a breach can remain consequential through disputes about evidence and response long after the public announcement. It also shows that depth does not require pretending every question has an answer. The most useful account identifies the specific decisions, documents the limits and leaves a clear path for incorporating stronger evidence later.

## Source register

[1] Reuters, 3 December 2018, contemporaneous reporting of Quora's population estimate and public response. Original company blog was inaccessible during this research pass. https://www.investing.com/news/technology-news/quora-says-100-million-users-affected-by-security-breach-1709372

[2] US District Court, Document 210, filed 21 December 2020, summary-judgment order, official 35-page PDF. Procedural background, motion-only concession and disposition; selected relevant portions read. https://www.govinfo.gov/content/pkg/USCOURTS-cand-5_18-cv-07597/pdf/USCOURTS-cand-5_18-cv-07597-11.pdf

[3] Huynh complaint, filed 18 December 2018, primary party pleading preserved by Courthouse News. Allegations and reproduced announcement references, not merits findings. https://www.courthousenews.com/wp-content/uploads/2018/12/Quora.pdf

[4] US District Court, 11 April 2019 consolidation order, official PDF. https://www.govinfo.gov/content/pkg/USCOURTS-cand-5_18-cv-07597/pdf/USCOURTS-cand-5_18-cv-07597-0.pdf

[5] US District Court, 22 September 2020 sealing order, official PDF. https://www.govinfo.gov/content/pkg/USCOURTS-cand-5_18-cv-07597/pdf/USCOURTS-cand-5_18-cv-07597-4.pdf

[6] US District Court, 26 October 2020 sealing order concerning response information, official PDF. https://www.govinfo.gov/content/pkg/USCOURTS-cand-5_18-cv-07597/pdf/USCOURTS-cand-5_18-cv-07597-7.pdf

[7] US District Court, 3 November 2020 consultant-identity discovery order, official PDF. https://www.govinfo.gov/content/pkg/USCOURTS-cand-5_18-cv-07597/pdf/USCOURTS-cand-5_18-cv-07597-9.pdf

[8] US District Court, 13 November 2020 transcript and privilege-log sealing order, official PDF. https://www.govinfo.gov/content/pkg/USCOURTS-cand-5_18-cv-07597/pdf/USCOURTS-cand-5_18-cv-07597-10.pdf

[9] US District Court, 12 January 2021 work-product discovery order, official PDF. https://www.govinfo.gov/content/pkg/USCOURTS-cand-5_18-cv-07597/pdf/USCOURTS-cand-5_18-cv-07597-13.pdf

[10] US District Court, filed 13 January 2021, denial of leave for reconsideration, official PDF. Final date line says 2020; filing metadata and February order establish 2021 sequence. https://www.govinfo.gov/content/pkg/USCOURTS-cand-5_18-cv-07597/pdf/USCOURTS-cand-5_18-cv-07597-14.pdf

[11] US District Court, 3 February 2021 denial of interlocutory-appeal certification, official PDF. https://www.govinfo.gov/content/pkg/USCOURTS-cand-5_18-cv-07597/pdf/USCOURTS-cand-5_18-cv-07597-15.pdf

[12] US District Court, 19 May 2021 device-examination discovery order, official PDF. https://www.govinfo.gov/content/pkg/USCOURTS-cand-5_18-cv-07597/pdf/USCOURTS-cand-5_18-cv-07597-16.pdf

[13] Connor v. Quora, ECF 240, stipulation for entry of judgment, filed June 4, 2021; signatures dated June 1. Original two-page filed document preserved in RECAP/Internet Archive; full document read. https://archive.org/download/gov.uscourts.cand.336099/gov.uscourts.cand.336099.240.0.pdf

[14] Connor v. Quora, ECF 241, judgment signed and filed June 7, 2021. Original two-page court document preserved in RECAP/Internet Archive; full text read and signed operative page visually verified. https://archive.org/download/gov.uscourts.cand.336099/gov.uscourts.cand.336099.241.0.pdf
