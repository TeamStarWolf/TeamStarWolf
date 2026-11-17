# MySpace 2016 Disclosure: Old Credentials, New Exposure, and a Disputed Breach Date

*A TeamStarWolf case study. Published 15 November 2026.*

[All case studies](/case-studies/README.md) · Related: [Password Security Reference](/PASSWORD_SECURITY_REFERENCE.md), [Data Security Reference](/DATA_SECURITY_REFERENCE.md), [Incident Response Reference](/INCIDENT_RESPONSE_REFERENCE.md), [Identity and Access Management Reference](/IDENTITY_ACCESS_MANAGEMENT_REFERENCE.md), [LinkedIn 2012-2016](/case-studies/LINKEDIN_2012_2016.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Security and privacy engineers, incident communicators, threat-intelligence analysts and researchers of breach evidence

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 11 min (2,588 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You want a shorter, evidence-bounded account of the 2016 MySpace disclosure, you need to keep a disputed breach date and competing population figures honest, or you are reviewing legacy-credential risk and the limits of a targeted reset

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Executive assessment](#executive-assessment), [The later SEC filings materially complicate the date](#the-later-sec-filings-materially-complicate-the-date), [What independent dataset analysis can and cannot date](#what-independent-dataset-analysis-can-and-cannot-date)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Password Security Reference](/PASSWORD_SECURITY_REFERENCE.md), [Data Security Reference](/DATA_SECURITY_REFERENCE.md), [Incident Response Reference](/INCIDENT_RESPONSE_REFERENCE.md), [Identity and Access Management Reference](/IDENTITY_ACCESS_MANAGEMENT_REFERENCE.md), [LinkedIn 2012-2016](/case-studies/LINKEDIN_2012_2016.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## Executive assessment

The MySpace incident belongs in a 2016 cyber-history collection because that is when the large credential dataset became publicly known and the company issued notices. Calling it simply a "2016 hack," however, obscures the central uncertainty. The age of the accounts, the age of the copied data, the date of unauthorized extraction, and the date of public sale are not necessarily the same. In this case, primary company filings and independent dataset analysis do not support one unqualified historical breach date.

This study preserves that discrepancy rather than selecting the most familiar year. It also distinguishes account records from unique people, password hashes from plaintext passwords, a seller's alias from a proven intruder identity, and a company's materiality statement from a finding that users suffered no harm. Those distinctions are the substance of the case, not caveats to append after a dramatic headline.

There is substantial primary documentation for the disclosure and response, but no publicly retrieved forensic report reconstructing the original entry method. The package is therefore complete as a bounded disclosure-and-evidence study, not as a definitive technical reconstruction. It contains no stolen records, password-cracking workflow, or instructions for accessing illicit datasets.

## The public discovery and initial company position

Time Inc.'s May 31, 2016 announcement said Myspace's security team learned shortly before Memorial Day weekend that stolen login data was circulating in an online forum. It identified legacy-platform usernames, passwords and email addresses associated with the period before the June 11, 2013 relaunch. The company said other Time Inc. systems and subscriber information were not affected, financial information did not appear involved, affected passwords had been invalidated, and user notification and law-enforcement cooperation were underway. This is an original company disclosure, preserved in its corporate-news archive, rather than a later summary. [1]

The California Attorney General's archive preserves a notification email dated May 31. It described affected accounts as created before the relaunch, told returning users they would need to authenticate and reset their passwords, and recommended changing the same or similar passwords used elsewhere. It also said automated monitoring was being used and stated that Myspace did not collect or store user financial information. The notice is evidence of the content sent to users; its presence in the archive does not establish that every recipient read it or that every reused password was changed. [2]

The matching company blog post described the investigation as ongoing and attributed the breach, as a company belief, to an alias called Peace. It contrasted the legacy data with post-relaunch password protection described as double-salted hashes. That attribution and security description are company assertions. The blog did not disclose a complete forensic chain identifying the original intruder or enough implementation details to evaluate the newer password-storage design. [3]

This initial response separates two practical responsibilities. Myspace could invalidate credentials on its own service. It could not automatically invalidate the same secret at another service where a user had reused it. The notification's advice about similar passwords therefore addressed a risk beyond the boundaries of the breached platform. The public record does not quantify how many users had reused credentials or how many subsequent account takeovers resulted.

## The later SEC filings materially complicate the date

Time Inc.'s Form 10-Q for the quarter ended June 30, 2016 reported approximately 360 million accounts offered for sale. It said Viant retained a specialist forensics firm and, based on that firm's analysis of available systems and data, considered the likely breach interval June 2013 through mid-2015, while not absolutely excluding a later compromise. The filing also recorded a March 2, 2016 acquisition of certain Viant assets. These statements make the incident relevant to acquired legacy data as well as to password security. The forensic conclusion is reported by the issuer; the underlying report was not retrieved. [4]

The annual Form 10-K for 2016 repeated the same likely intrusion interval. It said notices had been sent to impacted users and again stated that other Time Inc. systems, subscriber information and media properties were unaffected and that the event had no material impact on the company's business. The repeated date range means the quarterly statement cannot responsibly be dismissed as an isolated transcription error without further evidence. The materiality statement is the company's business assessment, not a measurement of each affected user's privacy loss or downstream account risk. [5]

A later Viant Form 10-K for 2021 described the discovered 2016 attack using pre–June 11, 2013 language and reiterated roughly 360 million accounts in its risk discussion. It also separately described a 2019 server-migration loss of older media files. The later filing does not explain the earlier Time Inc. forensic date range. Its migration disclosure is a different event and is not evidence that the credential breach destroyed users' photographs, video or music. [6]

The correct chronology therefore has a firm 2016 discovery-and-disclosure anchor but an unresolved extraction date. The notices emphasize the legacy account population. The Time Inc. filings explicitly discuss a likely breach interval. Later disclosure wording returns to the pre-relaunch framing. Those are not interchangeable formulations, and this research did not locate an authoritative reconciliation.

## What independent dataset analysis can and cannot date

On June 1, 2016, Troy Hunt published a first-hand analysis of the dataset's apparent age. He compared email-provider proportions, sought users' account-creation evidence, and noted examples supported by retained welcome emails. His estimate favored roughly mid-2008 to early 2009, but he explicitly considered the possibility that an older dataset could have been frozen and stolen later. The analysis described 359,420,698 unique email addresses. It also cautioned that Peace might be a seller rather than the person who originally compromised the system. These are analytical observations and hypotheses, not findings from the company's servers. [7]

Have I Been Pwned's MySpace entry currently describes an approximately 2008 breach and a May 2016 sale. It displays 359.4 million affected addresses and a May 31, 2016 addition date, while its narrative says the exact breach date is unknown. It characterizes the password data as unsalted SHA-1 hashes of lowercased, ten-character-truncated passwords. The registry's date field is useful for cataloging, but its own explanatory text prevents treating the displayed month as a verified day of intrusion. [8]

The difference between data age and extraction time is not merely semantic. Imagine a copy containing no records created after a particular year. That could reflect an extraction in that year, a later extraction of an archival copy, an incomplete export, or a dataset filtered before publication. These are alternative interpretations, not claims that one of them occurred at Myspace. Without a trustworthy acquisition history, a population cutoff alone does not distinguish them.

Email-provider distribution is informative but also conditional. A platform's historical audience may not mirror the general population of email users. Users may retain an older address, create multiple accounts, or stop updating a profile. Registration examples provide narrower bounds for those individual records, while a small volunteer sample does not necessarily describe every record in a much larger collection. Hunt's analysis is valuable because it makes its reasoning visible; it should not be upgraded into a forensic timestamp it never claimed to supply.

## A chronology that keeps its evidence labels

The defensible sequence begins with a legacy account population and uncertain unauthorized extraction. It then moves to the public sale and company awareness in late May 2016, the May 31 company announcement and notices, the June 1 independent dating analysis, and the subsequent quarterly and annual corporate filings. The later Viant filing supplies a retrospective corporate description, not an independently resolved timestamp.

This sequence deliberately avoids calculating an exact "years undetected" figure. Such a calculation would require a reliable first-compromise date and a reliable internal detection date. The public announcement establishes when the company said it became aware of circulating data, which is narrower than proving that nobody in any predecessor organization had earlier suspicions or evidence. The record does not support an accusation of a precisely measured multi-year cover-up.

For the reading tracker, 2016 is the disclosure year. The incident-date field should say disputed or uncertain, with the company filing range and independent data-age estimate retained in notes. That is more useful than forcing an apparently exact date into a sortable column and allowing the precision of the column to obscure uncertainty in the evidence.

## Password representation and the limits of the relaunch

The legacy representation described by HIBP has three conceptually different weaknesses: a fast hash, lack of per-record salt, and normalization that removes distinctions in user input. They should not be compressed into the misleading statement that encryption was broken. A one-way password hash is not encrypted text intended to be decrypted with a secret key.

Lowercasing removes the distinction between uppercase and lowercase versions. Truncation means characters beyond the stored limit do not affect the represented value. Consequently, the user's apparent choice of a longer or mixed-case password need not be fully reflected in the legacy verifier. A salt can prevent identical inputs from having identical stored outputs across records when correctly applied, but merely saying a scheme uses salt does not disclose its work factor or prove a strong password-storage design.

These are explanations of the reported data format, not an operational recipe for attacking the dataset. This research did not acquire the dump or attempt password recovery. It also does not claim that every hash was cracked or that every affected password remained valid in 2016. The risk depends on the original representation, the user's actual secret, subsequent changes, and reuse elsewhere.

The relaunch presents a separate lifecycle question. A newer authentication system may protect future logins better while an older copy remains vulnerable to later disclosure. Upgrading a live password verifier does not retroactively transform copies already outside the organization's control. Nor does a statement that the production platform improved establish when every legacy store or backup was retired. The reviewed sources do not reveal a complete storage inventory, so this study does not invent one.

## Scope: accounts, addresses and people

The approximate corporate account total and HIBP's distinct-address count are close in magnitude but have different definitions. One person may have several addresses or accounts; one address may be reused across records. A count of distinct addresses is not automatically a count of living, reachable individuals. A count of credentials is not automatically a count of active users at disclosure.

These distinctions do not diminish the scale. They make the scale interpretable. Calling the incident a theft affecting hundreds of millions of account records is different from claiming that an exact number of unique people suffered a documented financial loss. The latter would require additional identity resolution and harm evidence that this package does not contain.

The same discipline applies to comparisons with other breaches. A chart ranking incidents by "victims" should not combine account rows, unique emails, payment cards and people without labeling those units. For Myspace, the source-specific measures are retained rather than converted into a synthetic universal victim count.

## Attribution: the seller is not necessarily the intruder

The company notice's attribution and the independent researcher's caution should be read together. Someone who advertises stolen data may have stolen it, purchased it, obtained it through intermediaries, or repackaged a previously circulating set. Possession and sale are evidence of access to a copy, not by themselves proof of the original intrusion method or identity.

This case study does not adopt the nationality label in the original notice as an independently established identity. It does not attach a state sponsor, named malware family, insider culprit, or criminal conviction to the incident. No public investigative finding retrieved here closes that attribution gap. An insider explanation mentioned in independent analysis remains a hypothesis, not a documented personnel incident.

For a technical history, that restraint matters. If an unverified actor description is repeated in a title, slide and tracker, it can eventually look like three independent confirmations. Keeping the attribution attached to its original source prevents the presentation format from manufacturing certainty.

## The separate FTC privacy matter

In September 2012, the FTC finalized a settlement over Myspace's representations about personal-information protection. The order required a privacy program and periodic independent assessments for twenty years and barred future privacy misrepresentations. The agency's earlier announcement described the dispute over sharing user identifiers with advertisers. This was a different privacy-practices matter, not a penalty announced for the dataset that surfaced in 2016. [9]

The existence of the earlier order is relevant institutional background, but it is not proof that regulators later found this credential incident violated the order. Similarly, the risk language in later filings lists potential consequences; it does not mean every listed consequence actually occurred. A case study should distinguish a prior legal obligation, a possible enforcement risk, and a completed enforcement finding.

No incident-specific final damages award, quantified user-loss census, or public prosecution resolving the original extraction was retrieved in this pass. That is a limit of this research, not a guarantee that no private claim or nonpublic investigative action existed. The public record supports the disclosure history more strongly than a complete legal aftermath.

## What remains unresolved and why it matters

The main unresolved question is when and from which system the data was actually copied. Resolving it would require more than another article repeating the approximate 2008 label. The highest-value evidence would be the forensic report referenced by Time Inc., an authoritative explanation of the dataset's custody, or a later finding that reconciles the corporate and independent timelines.

The initial entry method is also unestablished here. There is no basis to fill the missing stage with a familiar SQL injection, phishing message, administrator compromise or malicious insider narrative. Any of those would produce a more cinematic attack chain, but none follows from the documents reviewed. The same applies to persistence, lateral movement and exfiltration tools: a large stolen dataset does not identify how each stage happened.

The case's practical value is nevertheless substantial. It shows why legacy credentials can remain consequential after a platform's popularity or architecture changes, why a password reset has a narrower reach than the reuse problem, and why disclosure histories need multiple dates. It also demonstrates a research habit that should be visible to readers: when authoritative records conflict, preserve the conflict and explain what evidence would resolve it.

## Source register

[1] Time Inc., May 31, 2016, original corporate announcement, preserved in People Inc. archive. https://news.people.inc/time-inc-archives?item=64

[2] Myspace user notification email, May 31, 2016, California Attorney General archive. Primary notice; no claim that all recipients read it. https://oag.ca.gov/system/files/Myspace%20user%20notification%20email_0.pdf

[3] Myspace blog notice, May 31, 2016, California Attorney General archive. Company attribution and security assertions. https://oag.ca.gov/system/files/Myspace%20blog%20post_0.pdf

[4] Time Inc., Form 10-Q for quarter ended June 30, 2016, Myspace Data Breach and acquisition sections. Reports likely June 2013–mid-2015 interval, with uncertainty. https://www.sec.gov/Archives/edgar/data/1591517/000159151716000057/timeinc2q2016.htm

[5] Time Inc., Form 10-K for 2016, Myspace Data Breach section. Repeats forensic date range; the underlying report is not public. https://www.sec.gov/Archives/edgar/data/1591517/000159151717000010/timeinc4q2016.htm

[6] Viant Technology, Form 10-K for 2021, Myspace and cybersecurity risk sections. Later description does not reconcile earlier range; migration loss separate. https://www.sec.gov/Archives/edgar/data/1828791/000156459022009695/dsp-10k_20211231.htm

[7] Troy Hunt, June 1, 2016, Dating the ginormous MySpace breach. Original dataset analysis with explicit uncertainty. https://www.troyhunt.com/dating-the-ginormous-myspace-breach/

[8] Have I Been Pwned, MySpace breach entry, reviewed November 16, 2026. Dataset characterization and approximate date, not an exact intrusion timestamp. https://haveibeenpwned.com/Breach/MySpace

[9] FTC, finalization of Myspace privacy settlement, September 2012. Separate earlier privacy-practices case. https://www.ftc.gov/news-events/news/press-releases/2012/09/ftc-finalizes-privacy-settlement-myspace
