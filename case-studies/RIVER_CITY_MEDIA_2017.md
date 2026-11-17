# River City Media 2017: Exposure Claims, a Mailing Dataset, and Research Litigation

*A TeamStarWolf case study. Published 16 November 2026.*

[All case studies](/case-studies/README.md) · Related: [Data Security Reference](/DATA_SECURITY_REFERENCE.md), [Privacy Engineering Reference](/PRIVACY_ENGINEERING_REFERENCE.md), [OSINT Reference](/OSINT_REFERENCE.md), [Incident Response Reference](/INCIDENT_RESPONSE_REFERENCE.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Data-protection and privacy teams, security researchers, disclosure-policy owners and incident responders

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 9 min (2,079 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You want a shorter, evidence-bounded account of the 2017 River City Media exposure, you need to separate total records from unique addresses or a procedural order from a merits finding, or you want a careful account of contested security-research litigation

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Scope and status](#scope-and-status), [March-August 2017: the lawsuit and the jurisdiction ruling](#march-august-2017-the-lawsuit-and-the-jurisdiction-ruling), [What the case demonstrates, and what it does not](#what-the-case-demonstrates-and-what-it-does-not)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Data Security Reference](/DATA_SECURITY_REFERENCE.md), [Privacy Engineering Reference](/PRIVACY_ENGINEERING_REFERENCE.md), [OSINT Reference](/OSINT_REFERENCE.md), [Incident Response Reference](/INCIDENT_RESPONSE_REFERENCE.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## Scope and status

River City Media is not a straightforward story in which a court confirmed that a criminal organization left a database open and was then shut down. It is a documented public disclosure, a dataset cataloged by an independent breach service, a forceful company denial, and litigation that ended through a stipulated dismissal. The public sources support those events. They do not support treating every allegation on either side as a finding of fact.

This package is a bounded account of the disclosure and its legal aftermath. The technical reconstruction remains incomplete because the underlying acquisition evidence and a definitive merits finding resolving the contested access mechanism were not retrieved. The paper deliberately avoids using the litigation's procedural orders to certify either the researcher's account or River City Media's counter-allegations.

The central editorial requirement is to preserve three distinctions: total records versus unique email addresses; files containing a proposed technique versus proof that the technique was deployed; and a ruling about where a lawsuit may proceed versus a ruling that the conduct alleged actually happened. Losing any one of these distinctions changes the case materially.

## January-March 2017: the disclosure account

Chris Vickery's March 6, 2017 MacKeeper article said a collaboration with CSOOnline and Spamhaus began in January after he encountered publicly exposed files lacking a password. He characterized the collection as River City Media operational material and a roughly 1.4-billion-record mailing dataset. The article described spot checks that appeared to match real people, while noting that some addresses were outdated. It alleged abusive mailing practices based on documents, scripts and conversations, and announced intended Spamhaus blacklisting. These are the researcher's published observations and conclusions, not a criminal judgment. The original URL now redirects elsewhere; this study inspected an archived 2017 copy. [1]

Have I Been Pwned records the exposure in January 2017 and addition to its service on March 8. Its entry describes nearly 1.4 billion records but approximately 393 million unique email addresses after deduplication, with names, physical addresses and IP addresses among the data categories. The registry supports the existence and characterization of the collection it processed. It does not independently resolve every disputed statement about how Vickery obtained the source material or how River City Media operated. Passwords are not among the entry's listed compromised categories. [2]

The numeric distinction is especially important here. Repeated appearances of an address in a mailing collection can increase the row count without adding another unique address, much less another unique person. A database with several lists, snapshots or sources may contain substantial repetition. This study does not identify the exact reason for every duplicate; it records that deduplication materially changed the published measure.

Consequently, "1.4 billion people breached" is not an acceptable shorthand for this case. Neither the gross record count nor the distinct-address count is a verified census of unique individuals. The smaller number is not a correction proving that the original collection was tiny; it is a different measurement. Both can be retained if their units remain visible.

## March 9: the company's specific rebuttal

River City Media's own March 9 release denied that its backups had been left on an open server. It challenged claims about illegal mailing techniques and daily volume. In particular, it said a document called Project X1 came from an unaffiliated applicant, not an implemented company method, and denied using a separate technique described in chat material. The company also defended third-party data licensing and said the publications caused serious damage. This was a company-authored press release distributed through PR Newswire, not an independent news investigation or a court finding. [3]

The rebuttal matters because it identifies disputes more precise than "the story was wrong." One concerns acquisition: exposed backup access versus unauthorized intrusion. Another concerns inference: possession of a proposal versus operational deployment. A third concerns characterization: whether mailing and data-licensing practices were unlawful. Each requires different evidence, so a fact that resolves one does not automatically resolve the others.

For example, a document found in a business repository can establish that the repository contained that document, assuming its authenticity and custody are sound. It does not alone establish that the business approved, executed or successfully used its contents. Conversely, describing something as an outside proposal does not itself prove it was never implemented. The public dispute is exactly where that additional evidentiary step matters.

This study does not reproduce the alleged mailing-abuse mechanism or operational scripts. They are unnecessary to understand the dispute and would distract from the unproven deployment question. It also does not use the company's list of recognizable commercial relationships as proof of legal compliance. A relationship with a known brand is not a substitute for evidence about specific conduct.

## March-August 2017: the lawsuit and the jurisdiction ruling

The public docket records a March 21, 2017 filing in the Eastern District of Washington, case 2:17-cv-00105-SAB. River City Media and individual plaintiffs sued Kromtech, Vickery, media companies and reporter Steve Ragan. The docket is a map to filings, not a verdict about the underlying incident. [4]

The August 28 order described computer-access, communications, trade-secret and state-law claims. It addressed personal jurisdiction, found sufficient grounds regarding the individual researchers/reporters discussed, and allowed discovery concerning corporate defendants. Several dismissal motions were denied with leave to renew; Ragan's motion was denied. Because amendment was allowed, the court did not resolve the failure-to-state-a-claim arguments at that stage. The order recounts plaintiffs' accusations, including a claimed intrusion, but those narrative passages are not final adjudicated technical findings. [5]

This is an unusually easy document to misuse. A paragraph written in a judicial order can look more authoritative than the complaint from which its allegations originate. But the document's procedural purpose controls what it establishes. The question before the court concerned its authority over defendants and the adequacy of the jurisdictional record, not a completed trial of whether exposed backups existed or whether any specific mailing practice was deployed.

Accordingly, this package does not say that the court proved Vickery hacked the company, proved the company ran an illegal operation, or approved the researchers' methods. It reports what the court actually did and leaves the technical allegations attributed. The distinction is essential to a fair account of identifiable people and organizations.

## April 2018: a narrower order and a wider policy debate

On April 9, 2018, the court granted a joint motion dismissing International Data Group with prejudice. The same order recorded CXO Media's agreement to submit to personal jurisdiction and vacated the earlier order compelling jurisdictional discovery from that company as moot. This was not dismissal of the entire action: its scope was a particular defendant and a particular discovery dispute. [6]

A separate April 10 expert statement hosted by the Center for Democracy & Technology cited the River City Media case as an example of litigation threatening security research. Its signatories argued that such cases could discourage vulnerability disclosure and harm the public interest. That is a primary source for the researchers' policy response and advocacy, not a judicial conclusion about authorization in this particular case. [7]

The juxtaposition is instructive. The litigation involved disputed access and publication conduct; the policy debate concerned the effect that litigation can have on legitimate research more broadly. One can document the latter without assuming every disputed factual allegation in the former has been resolved. Equally, recording a company's legal claims does not establish that the wider concern about deterrence is unfounded.

This case study is historical analysis, not legal advice about testing an exposed service. It offers no general permission to collect data merely because a system responds without a password. Authorization, privacy, acquisition scope and publication choices remain separate questions. No live River City Media systems or exposed records were accessed in preparing this package.

## August-September 2018: the verified disposition

The parties filed a stipulation dated August 31, 2018 agreeing that all plaintiffs' claims against all defendants would be voluntarily dismissed with prejudice, with each party bearing its own costs and attorney fees. This study retrieved and read the actual stipulation rather than relying only on a later blog's statement that the case settled. The document does not disclose a payment amount or a merits admission. [8]

On September 4, Judge Stanley A. Bastian accepted the stipulation, dismissed the matter with prejudice and without costs to any party, dismissed pending motions as moot, struck trial and pretrial dates, and ordered the file closed. The final order was also retrieved directly from the public court-record copy. This provides a verified endpoint for the federal action. [9]

The endpoint should not be rewritten as either side winning a factual verdict. A stipulated dismissal can end litigation without establishing the truth of disputed allegations. The reviewed stipulation and order do not disclose private negotiating terms, if any, and this study does not invent them. There is no basis here for attaching a damages award, criminal conviction, or judicially approved technical reconstruction to the dismissal.

The same caution applies to the word "settlement." A secondary account may use that word broadly, but the primary documents retrieved establish the narrower, concrete facts: the parties stipulated, the claims were dismissed with prejudice, each side bore its own costs and fees, and the court closed the file. Those facts are sufficient to describe the outcome without implying undisclosed financial terms.

## What the case demonstrates, and what it does not

The distinctive privacy issue is not a customer choosing an account at a familiar service and then receiving a password-reset notice. It is an aggregated contact collection whose subjects may not recognize the collector's name. A person can therefore appear in a dataset without having an obvious account relationship through which to understand or manage the exposure. That is an analytical implication of the mailing-list context, not proof that every record was collected unlawfully.

The distinctive research issue is provenance. A reliable account would preserve how the material was obtained, which observations were directly reproduced, which documents were merely present, and how interpretations were tested. Without that separation, a dramatic internal document can be mistaken for operational proof and an open-service claim can be mistaken for a complete access history.

The distinctive legal issue is procedural scope. This record has a jurisdiction decision, a partial dismissal, advocacy during the case, a stipulation, and a final closure order. Those events supply a real chronology but do not form a merits judgment on the disputed technical facts. A case-study timeline should say what each event did, not just assign "won" or "lost" labels.

Several major questions remain unanswered in the materials reviewed: the complete authenticated acquisition trail, whether every alleged technique was deployed, a verified total of malicious third-party acquisitions, and a quantified harm census for individuals in the mailing data. No final forensic report or adjudicated resolution of those technical disputes was retrieved. Those gaps keep the attack reconstruction incomplete even though the public lawsuit's disposition is verified.

The strongest conclusion is therefore deliberately bounded. River City Media illustrates the scale of an exposed aggregated dataset and the difficulty of writing accurately about contested security research. The documents support careful attribution, deduplicated measurement and a clear legal chronology. They do not justify converting a researcher's allegation, a company denial or a procedural order into an unqualified finding about the entire episode.

## Source register

[1] Chris Vickery, Spammergate: The Fall of an Empire, March 6, 2017, archived original MacKeeper article. Participant account and allegations. https://web.archive.org/web/20170426084052/https://mackeeper.com/blog/post/339-spammergate-the-fall-of-an-empire

[2] Have I Been Pwned, River City Media Spam List. Independent dataset catalog; distinguishes gross records and unique addresses. https://haveibeenpwned.com/Breach/RiverCityMedia

[3] River City Media, March 9, 2017, company-authored response via PR Newswire. Denials and counterclaims, not independent findings. https://www.prnewswire.com/news-releases/river-city-media-response-to-defamatory-and-false-articles-300421410.html

[4] Public docket, River City Media v. Kromtech, No. 2:17-cv-00105-SAB, Justia mirror. Filing identity and chronology. https://dockets.justia.com/docket/washington/waedce/2:2017cv00105/76115

[5] Eastern District of Washington, ECF 60, August 28, 2017, jurisdictional dismissal-motion order, GovInfo. Procedural findings distinguished from recited allegations. https://www.govinfo.gov/content/pkg/USCOURTS-waed-2_17-cv-00105/pdf/USCOURTS-waed-2_17-cv-00105-0.pdf

[6] Eastern District of Washington, ECF 107, April 9, 2018, order dismissing IDG and vacating jurisdictional discovery order, Justia copy. https://docs.justia.com/cases/federal/district-courts/washington/waedce/2:2017cv00105/76115/107

[7] Expert Statement: Support for Security Research, April 10, 2018, CDT-hosted original. Policy advocacy, not adjudication. https://cdt.org/wp-content/uploads/2018/04/2018-04-09-security-research-expert-statement-final.pdf

[8] ECF 117, August 31, 2018, stipulation and voluntary dismissal, CourtListener RECAP copy. Full document inspected. https://storage.courtlistener.com/recap/gov.uscourts.waed.76115/gov.uscourts.waed.76115.117.0.pdf

[9] ECF 118, September 4, 2018, order dismissing case and closing file, CourtListener RECAP copy. Full document inspected. https://storage.courtlistener.com/recap/gov.uscourts.waed.76115/gov.uscourts.waed.76115.118.0.pdf
