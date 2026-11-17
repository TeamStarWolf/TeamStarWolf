# ProLock 2020: A Ransomware Operation with an Unreliable Recovery Promise

*A TeamStarWolf case study. Published 16 November 2026.*

[All case studies](/case-studies/README.md) · Related: [Ransomware Defense Reference](/RANSOMWARE_DEFENSE_REFERENCE.md), [Malware Analysis Reference](/MALWARE_ANALYSIS_REFERENCE.md), [Attack Campaigns Reference](/ATTACK_CAMPAIGNS_REFERENCE.md), [Incident Response Reference](/INCIDENT_RESPONSE_REFERENCE.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Ransomware defenders, malware analysts, detection engineers and incident responders

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 19 min (4,459 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You want an evidence-bounded account of ProLock, you need to separate a predecessor's recoverable weakness from a successor's unreliable decryptor or containment from impact, or you are judging what a credible recovery result would demonstrate

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Executive assessment](#executive-assessment), [The predecessor: PwndLocker recovery was conditional](#the-predecessor-pwndlocker-recovery-was-conditional), [The first 8,192 bytes were not a recovery service](#the-first-8192-bytes-were-not-a-recovery-service)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Ransomware Defense Reference](/RANSOMWARE_DEFENSE_REFERENCE.md), [Malware Analysis Reference](/MALWARE_ANALYSIS_REFERENCE.md), [Attack Campaigns Reference](/ATTACK_CAMPAIGNS_REFERENCE.md), [Incident Response Reference](/INCIDENT_RESPONSE_REFERENCE.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

Key takeaways (reviewed 2026-11-17):

- The key questions are not answered by naming the final executable: predecessor, successor, intrusion paths and operator changes differ. ([Executive assessment](#executive-assessment))
- The criminal promise to reverse encryption could itself add more corruption to the files. ([Executive assessment](#executive-assessment))
- A damaged file might still keep a normal-looking beginning, hiding the loss. ([Executive assessment](#executive-assessment))
- One ransomware name disappearing would not necessarily remove the access operations that had delivered it. ([Executive assessment](#executive-assessment))

<!-- meta:end -->

## Executive assessment

ProLock is a particularly useful ransomware case because the most important questions are not answered by identifying its final executable. The historical record separates a predecessor with a recoverable weakness, a successor associated with unreliable criminal decryption software, several different intrusion paths, and operators who apparently changed the ransomware they deployed. These are related developments, but they are not interchangeable explanations.

The evidence examined here centers on original investigations by Group-IB, Sophos and Intrinsec; Emsisoft's recovery announcement; public institutional alerts; and a later ANSSI assessment. The named corporate example is deliberately limited to Diebold Nixdorf's statements as reproduced in a contemporaneous interview report. This is a historical analysis, not an assertion that a particular recovery product or criminal operation remains active today.

The central conclusion is narrower than "ransomware is dangerous." In this case, the promise to reverse encryption could itself introduce additional corruption. A damaged file might still retain a normal-looking beginning. And the disappearance of one ransomware name would not necessarily remove the access operations that had delivered it. The study therefore follows evidence across development, intrusion, encryption, recovery and later attribution, rather than treating the ransom note as a complete incident history.

## Scope and evidence rules

The core period is 2020. A 2021 French intelligence report provides retrospective context, not evidence that every 2020 incident belonged to its named cluster. Source numbers refer to the register at the end. Technical descriptions identify behavior and investigative significance without providing deployment commands or reproducing malware. No malware, criminal portal or stolen victim dataset was accessed for this study.

Three distinctions govern the analysis. An observed action in one response engagement is not automatically a family-wide capability. A vendor's assessment of relationships is not proof of a defendant's identity. A company's statement about operational effects is evidence of what the company reported, not an independent audit of every affected system.

Where this article develops an evidentiary implication or proposes a validation method, it is original analysis rather than an additional historical finding. That separation matters for ProLock because the public sources describe different samples, different customers and different dates. Combining them into one smooth attack chain would make a more dramatic narrative, but a less accurate case study. The useful task is to identify where the accounts reinforce each other and where their boundaries must remain visible.

## The predecessor: PwndLocker recovery was conditional

Emsisoft announced a recovery solution for PwndLocker. Its announcement described a customized service, not a universally downloadable decryptor. Recovery required the executable used in the particular attack; that file normally deleted itself, though investigators could sometimes recover it. The announcement therefore joined a promising cryptographic result to a concrete evidence requirement. It did not establish free decryption for every subsequent ransomware carrying a related name. [1]

This distinction changes how a responder should interpret a family identification. A label is a starting point for testing applicability, not a substitute for it. If the historical recovery method depends on a particular executable, retaining an encrypted file alone may not satisfy the recovery conditions. Conversely, failure to locate the executable immediately does not prove it never existed or cannot be recovered.

The case also demonstrates why retrospective writing should not compress separate events into "researchers cracked ProLock." That phrase would erase both the predecessor's identity and the conditions of the successful intervention. A useful recovery record would identify the examined artifact, the affected data, the method's prerequisites and the actual result. It would not simply attach a success story to a later family name.

## March to May: a successor and multiple access paths

Group-IB's May 14 analysis placed ProLock's appearance in March 2020 after PwndLocker's late-2019 activity. It described QakBot-assisted intrusions and weakly protected Remote Desktop Protocol access as different routes. Its cases also involved directory reconnaissance, administrative execution mechanisms and data collection. A ransomware payload could be concealed in an image file and activated through a separate loading sequence. [2]

That account makes ProLock an operation with preparatory stages, not merely a malicious attachment that instantly encrypts an enterprise. It does not mean every ProLock event involved QakBot, or that every QakBot infection proceeded to ProLock. The relationship is conditional: one component can provide access that another operator or stage later uses.

For chronology, this requires separate timestamps. The first suspicious email, first unauthorized login, first recorded discovery action and first encrypted file may mark different phases. A report that gives only an encryption date leaves the earlier exposure interval unresolved. That is not a reason to invent dwell time. It is a reason to preserve the distinction between what the timeline shows and what the available logging cannot reconstruct.

## The Diebold Nixdorf account: operational disruption without an ATM claim

KrebsOnSecurity's May 11 report reproduced Diebold Nixdorf's account of suspicious activity discovered on April 25. The company said it disconnected corporate systems, contained the spread and experienced disruption to a system automating field-service requests. It said ATMs and customer networks were not affected and denied paying a ransom. These are company statements preserved in the report. The article's ProLock identification should not be recast as a separate company-published forensic finding. [10]

The distinction between a corporate support system and a customer ATM is essential. An organization can suffer a real service interruption without the incident reaching every product bearing its name. The reverse inference is also invalid: absence of an ATM impact does not make the corporate outage imaginary. The appropriate unit of analysis is the affected business process, not the size or visibility of the company brand.

This example is useful precisely because the available public account is limited. It supports a discussion of containment and support-workflow disruption. It does not establish the initial access vector, a complete list of compromised hosts, the contents of any stolen data, or an independently measured final loss. Those details should remain unresolved rather than borrowed from unrelated ProLock engagements.

## Why containment and impact should have separate entries

The Diebold account creates an important analytical distinction between harm caused by the intrusion and interruption caused by the response. Disconnecting a system can reduce exposure while making a legitimate workflow temporarily unavailable. A case study should record both without describing protective isolation as evidence that the attacker controlled every disconnected service.

An impact ledger for this historical example would therefore separate the reported malicious activity from the reported containment action and the resulting business interruption. It would also distinguish the company's assessment of materiality from the existence of a disruption. Materiality is not a synonym for whether anybody experienced inconvenience, nor is a press statement a measurement of every customer outcome.

This is an interpretation of the public account, not a reconstructed internal decision log. The source does not provide the actual incident command discussion or a minute-by-minute recovery schedule. A reader should come away understanding the evidentiary boundary: the company described a bounded corporate incident, while the research record examined here does not supply enough detail to certify that boundary independently. Both points can be stated without turning caution into an unsupported accusation.

## July technical analysis: the loader mattered

Sophos's July 27 investigation described a mid-March customer detection and assessed RDP as the most likely initial route in that case. Its recovered set included an image, a task definition and batch files. A PowerShell loading sequence extracted the payload into memory. Running an isolated executable without the expected context did not reproduce encryption. The research also described anti-analysis behavior and selective process or service termination. [3]

The investigative consequence is specific. An apparently inert executable does not necessarily refute a malicious execution history when the original invocation depended on surrounding artifacts. At the same time, that observation does not license an investigator to assert whatever behavior a sample might theoretically perform. The historical claim still needs the original execution context or reliable telemetry.

For this case, collecting the loading components is more informative than searching only for a conventional executable with an obvious ransomware name. The relationship between files, scheduled execution and memory activity explains why the individual artifact is insufficient. This is not a general claim that images are executable by themselves. The loading mechanism, not the visual appearance of the container, is what made the recovered image relevant to the intrusion.

## The first 8,192 bytes were not a recovery service

In the sample examined by Sophos, files smaller than 8,192 bytes were skipped, and the first 8,192 bytes of larger files remained unchanged. Its analysis also described exclusions and repeated ransom-note identifiers across examined samples. These are sample-bound observations, not a guarantee about every later build or every file on an affected host. [3]

An unchanged beginning has a concrete evidentiary consequence: a recognizable file signature cannot certify the integrity of the rest of the object. A database or document may still appear to be the expected type while the content needed for meaningful use has been altered. Counting recognizable filenames or icons would therefore answer a different question from whether the business data is usable.

The arithmetic also prevents an attractive but false interpretation of the research headline. Preserving the beginning of a file is not equivalent to possessing a key that can restore the encrypted remainder. The accessible portion may have evidentiary value, but it does not solve the recovery problem by itself. In a historical narrative, the appropriate wording is partial preservation under observed encryption behavior, not free recovery of the affected file.

## Public warnings about the criminal decryptor

The Cyber Swachhta Kendra public advisory dated August 3, 2020 warned that ProLock's criminal decryptor could corrupt files larger than 64 MB. It relayed information from other reporting, including the decryptor warning, rather than publishing an independent victim experiment. This study uses that openly published advisory for the warning and does not redistribute a separately encountered restricted-sharing FBI document. [4]

The important property is not simply that an attacker might refuse to provide a tool. Here the reported problem concerned the tool's operation after it was supplied. Possession of decryption material and correct implementation of a recovery process are separate requirements. A payment narrative that ends with "the victim received a decryptor" therefore leaves the actual restoration outcome unproven.

The size threshold is reported as a warning, not reproduced here as a universal corruption formula. File structure, the exact encrypted object and the tool version still matter when evaluating a particular recovery. The record does not justify predicting the exact number of damaged bytes in an unseen victim file. Nor does it justify treating smaller files as automatically trustworthy merely because one published warning emphasized larger ones.

## Recovery assistance: fixing software was not defeating every key

In the same May interview report, Emsisoft's Fabian Wosar described assistance for a ProLock decryptor defect that still required the attackers' decryption keys. That is distinct from the PwndLocker recovery announcement. The report preserves a direct expert explanation, but it is not a present-day guarantee that a service is available or that an arbitrary ProLock incident is recoverable. [10]

This creates two different recovery propositions. One concerns whether the original encryption can be reversed without the criminal's key material under particular conditions. The other concerns whether a flawed implementation can correctly use key material already available. Mixing them would mislead both a victim and a reader trying to understand the research contribution.

A retrospective outcome table should therefore distinguish "key obtained," "tool modified," "sample decrypted," and "production data validated." These are not cosmetic labels. Each answers a different question about whether the recovery process has advanced. In the absence of a documented final validation result, the article should not transform a technical possibility into a successful restoration claim. The available sources do not provide a universal ProLock recovery rate.

## What a credible ProLock recovery result would demonstrate

The following is original analytical guidance derived from the specific integrity problem, not an assertion about an undisclosed victim's actions. A credible recovery demonstration would preserve an untouched encrypted copy and document which tool and key material were used on a working copy. It would compare the resulting content with a trusted reference where one exists, rather than rely only on the disappearance of a ransomware extension.

For a database, useful evidence would include application-level consistency and reconciliation of records relevant to the business. For a large document, it would include more than opening the first page. For an archive, it would include validation of contents rather than its filename alone. These examples explain why the reported large-file defect mattered: a recovery process can appear to make progress while leaving consequential damage deeper in the data.

This does not imply that every historical ProLock recovery failed. It identifies the evidence needed to claim success responsibly. The strongest outcome statement would name what was validated and what remained unresolved. A broad statement that "the files decrypted" is weaker when the known historical failure mode concerns integrity after decryption, not simply whether a tool produced output.

## September: a broader intrusion toolkit

Group-IB's September 10 update described developments including hijacked email conversations, additional payload containers and use of established administration or offensive tools. In some cases it observed privilege escalation involving CVE-2019-0859. One sequence showed BloodHound followed later by AdFind; the researchers considered separate teams a possible explanation. Rclone appeared in some exfiltration activity. Its documented ransom figures were demands, not verified payment receipts. [5]

This update changes the study from a static malware profile into a dated account of operational variation. A technique observed later should not be inserted retroactively into every earlier incident. Similarly, a possibility offered to explain a change in tools should not become a proven organizational chart for the criminals.

The two directory-reconnaissance tools illustrate the point. Their presence can help describe what happened on a network. By itself, a change in tooling does not identify the person at the keyboard. An analyst needs additional evidence to distinguish different operators, a single operator changing tools, or separate stages of the same engagement. The report supplies a hypothesis worth tracking, not permission to erase the alternatives.

## Intrinsec's ProLock response evidence

Intrinsec's November 12 comparison of ProLock and Egregor described a ProLock chain involving Emotet and QakBot, directory discovery, RDP enablement and targeted deployment artifacts. Its responders could not recover one earlier executable after its download locations became unavailable. They also reported no Rclone observations in their ProLock responses, while acknowledging that other researchers had seen it. Analysis of an office.txt artifact remained incomplete; its suspected role was supported by event correlation. [6]

This is valuable casework because it preserves investigative gaps. Missing an earlier binary is not the same as proving the earlier stage did not occur. Nor does an unavailable download establish what every former copy contained. The researcher can explain the role suggested by surrounding evidence while leaving the unavailable material unverified.

The office.txt example is similarly important. A filename and adjacent execution events can support an assessment, but incomplete content analysis should remain visible in the final wording. The report does not become less useful because it exposes that limitation. It becomes more useful to another investigator, who can see which parts of the narrative rest on recovered content and which rely on relationships among events.

## Why the exfiltration accounts are not a simple contradiction

Group-IB reported collection and exfiltration behavior in its observed ProLock activity. Sophos stated it had no direct evidence of data theft in the incidents it described. Intrinsec did not observe Rclone in its own ProLock responses. Those findings have different subjects and are not logically equivalent to three mutually exclusive verdicts about every victim. [2][3][6]

The original analytical question is what each negative finding excludes. "No Rclone observed" is narrower than "no data transfer occurred." "No direct evidence of theft" is narrower than a complete forensic demonstration that no information left the environment. Conversely, evidence of theft in one case cannot establish theft in another merely because the same ransomware name appears.

A defensible case comparison therefore keeps a separate exfiltration status for each engagement: observed, assessed, not observed, or unresolved. It also records the basis for the label. This avoids both an overly reassuring account and an unsupported breach allegation. The historical record supports the need to investigate confidentiality independently of encryption. It does not support declaring every ProLock victim's data stolen without victim-specific evidence.

## The leak-site question has a date attached

The May Group-IB account did not identify a ProLock leak site at that time. The later public advisory also discussed the issue in the context of its reporting date. These observations should not be transformed into a permanent statement that ProLock operators could never publish stolen information, nor into proof that every claimed theft was genuine. [2][4]

The distinction is between an observable publication channel and the underlying possession of information. A public site can be absent even when a private extortion claim exists. A public claim can also exist without independently validating every file or alleged victim. Neither situation resolves the data-exposure question automatically.

For this case study, there is no need to visit criminal infrastructure to dramatize the point. The lawful public record already illustrates why publication evidence and theft evidence belong in separate columns. The article's conclusion does not depend on accepting an extortionist's marketing. It depends on preserving the scope of the original investigations and refusing to use an absent website as a substitute for examining what happened inside a particular organization.

## QakBot was a relationship, not an exclusive identity

An early-access malware family, a ransomware payload and an operator cluster answer different analytical questions. ProLock reporting repeatedly connects the first two, but this does not collapse them into a single actor. The original analytical model used here has separate entries for access, operational actions and final encryption. A relationship among entries can be strong without making every entry identical.

This model prevents a predictable attribution error. If a later incident contains QakBot, an analyst cannot simply copy a previous ProLock attribution into the new case. Additional evidence must connect that specific intrusion with the previously observed operation. The same caution applies in reverse: identifying ProLock does not reconstruct every earlier access event automatically.

The benefit is practical for historical comparison. It permits an operation to change its final ransomware without requiring the writer to claim that the entire underlying access ecosystem vanished overnight. It also permits different operators to use similar access tooling without forcing all of them into one group. This is a more restrained account than a single brand-based narrative, but it explains the later evidence much better.

## The Egregor transition: operational continuity without code identity

Group-IB's November assessment argued that QakBot-associated operators had likely shifted from deploying ProLock to Egregor. It based the relationship on operational similarities, including tooling and naming patterns. Its discussion also placed Egregor's code relationships nearer other ransomware families. The assessment therefore concerned continuity in operations, not proof that ProLock's executable had simply been renamed Egregor. [7]

That distinction resolves an otherwise confusing narrative. Two operations can share access practices while using different encryption software. Conversely, closely related software can be deployed by different people. A migration assessment needs to state which relationship the evidence supports instead of using "same gang" as a shortcut for every layer.

This article does not transfer Egregor victim counts, ransom demands or named incidents into ProLock's total. Such a transfer would inflate the apparent ProLock impact and conceal the family change that makes the transition interesting. The historical claim remains limited: researchers identified similarities that supported a likely operational shift in the activity they observed. It is not a claim that every QakBot operator made the same choice.

## The 2021 Lockean assessment

ANSSI's October 26, 2021 report connected multiple French ransomware incidents and earlier research through a broader cluster assessment called Lockean. The examined portions discuss relationships involving infrastructure, naming, QakBot affiliations and exfiltration configurations. The report includes the Intrinsec ProLock case in that comparison. It also cautions that a TA551-to-QakBot chain alone is insufficient to identify Lockean, because the relevant ecosystem is not exclusive to one affiliate. [8]

The retrospective value is the additional comparison across incidents. The report is not a warrant to attach all victims named elsewhere in it to ProLock. Some described events involve other ransomware families. Keeping those distinctions intact preserves the report's actual contribution: an assessment about operational relationships, rather than a newly expanded list of ProLock victims.

For attribution writing, the key issue is evidence combination. A common component may be weak in isolation but useful when accompanied by more discriminating similarities. That still produces an assessment with a stated basis, not an identity proof. The public material examined here does not establish the identities, organizational hierarchy or legal disposition of every person involved in the 2020 ProLock activity.

## Naming and publication-date traps

NHS Digital's alert uses ProLocker and identifies the earlier PwndLocker name. Its page carries a March 9, 2020 publication date and a June 29, 2021 edit date. The currently accessible text therefore cannot automatically be treated as an unchanged snapshot of what was known on the earlier date. Its threat summary is useful, but its page metadata must travel with any historical claim. [9]

This is a specific problem for reconstructing fast-changing ransomware research. A source published early and edited later can make later knowledge look contemporaneous if the writer cites only the first date. An accurate chronology should use a dated original announcement when establishing when a claim became public, or explicitly acknowledge the editable page.

The names also need a cross-reference rather than silent normalization. Readers may encounter PwndLocker, ProLock and ProLocker in different sources. The article can explain the relationship while still preserving the name used by a source in a particular recovery claim. That prevents a search result about the predecessor's successful recovery method from being mistaken for a promise about the successor.

## What the public record does not establish

This review does not establish a complete global victim total, an aggregate amount paid, or a uniform initial access method. It does not certify a family-wide cryptographic parameter across every version. It does not identify every operator behind the deployment activity. It also does not supply a present-day operational status for all associated malware or services. These are limits of the reviewed evidence, not findings that the underlying values were zero.

Several attractive figures are deliberately absent. A demand is not a payment. An example in one report is not the population of all victims. A count associated with a later ransomware operation is not a clean measure of ProLock. Leaving those figures out makes the article less sensational but more reusable in an audit or teaching setting.

The unresolved questions point toward evidence that would genuinely improve the study: victim-authorized technical reports, dated recovery validation results, original samples analyzed by qualified researchers, and independently corroborated operational outcomes. They do not justify searching stolen repositories or inventing details from a nearby incident. An expanded study should become more specific as evidence improves, not merely more confident as its word count grows.

## A case-specific teaching exercise

A fictional response team receives three pieces of evidence: a recognizable file header, a ransom note naming ProLock, and a directory containing remnants of a loader. Its first task is to state what each item proves. The header supports file-type recognition, not full integrity. The note supports a claimed identity, not a complete intrusion chain. The loader remnants may connect artifacts, but their significance depends on examination and surrounding events.

Next, the team receives an offer of recovery software and a report that another organization restored PwndLocker files. Participants must explain why neither fact alone establishes that their own data can be restored safely. They should distinguish family applicability, key requirements, implementation reliability and validated results. The exercise uses synthetic records and inert examples, not malware execution or contact with criminals.

Finally, a later intelligence report links similar access activity to a different ransomware family. Participants revise their operational hypothesis without rewriting every earlier fact. The desired result is a timeline with explicit confidence and gaps, not a triumphant attribution. This exercise tests the exact reasoning failures exposed by ProLock: confusing recognizable data with valid data, conditional recovery with universal decryption, and shared tooling with exclusive identity.

## Conclusion

ProLock's significance is not measured only by the prominence of a named victim or the size of a ransom demand. Its historical record exposes a series of separate evidentiary problems that affected the interpretation of the incident itself. A predecessor's recoverability did not guarantee the successor's recoverability. A supplied decryptor did not guarantee intact data. A common access component did not establish a single actor. And an operational migration did not prove a simple code rebrand.

The strongest account remains grounded in dated observations. It records what researchers actually recovered, where they lacked visibility, what the company said about operational impact, and how later assessments changed the interpretation of relationships. That approach produces a more useful case study than a generic list of controls. It gives the reader a way to evaluate a ransomware narrative when the sources are incomplete, the software changes, and the most important outcome is whether the affected organization can trust its data again.

## Sources and reading register

1. [Emsisoft: PwndLocker recovery announcement](https://www.emsisoft.com/en/blog/35879/pwndlocker-ransomware-decryption-now-available/). Recovery conditions and executable requirement read; original vendor announcement.
2. [Group-IB: ProLock initial investigation](https://www.group-ib.com/blog/prolock/). May 14, 2020. Substantive attack-chain and technical sections read; original research.
3. [Sophos: ProLock technical investigation](https://www.sophos.com/en-us/blog/prolock-ransomware-gives-you-the-first-8-kilobytes-of-decryption-for-free). July 27, 2020. Substantive technical findings read; original research.
4. [Cyber Swachhta Kendra: ProLock alert](https://www.csk.gov.in/alerts/ProLockRansomware.html). August 3, 2020. Public threat summary read; institutional relay, not independent victim forensics.
5. [Group-IB: ProLock evolution](https://www.group-ib.com/blog/prolock-evolution/). September 10, 2020. Substantive evolution and intrusion sections read; linked white paper not retrieved.
6. [Intrinsec: Egregor and ProLock](https://www.intrinsec.com/en/egregor-prolock/). November 12, 2020. Case narrative, artifacts and comparison read; original response research.
7. [Group-IB: Egregor assessment](https://www.group-ib.com/media-center/press-releases/egregor/). November 20, 2020. Operational migration and code-relationship discussion read.
8. [ANSSI: Lockean report](https://cert.cyber.gouv.fr/uploads/CERTFR-2021-CTI-009.pdf). October 26, 2021. Selected context, conclusion, infection-chain and comparison passages read; not a cover-to-cover review of the full report.
9. [NHS Digital: ProLocker alert CC-3385](https://digital.nhs.uk/cyber-alerts/2020/cc-3385). Published March 9, 2020; edited June 29, 2021. Substantive alert and metadata read.
10. [KrebsOnSecurity: Diebold Nixdorf interview report](https://krebsonsecurity.com/2020/05/ransomware-hit-atm-giant-diebold-nixdorf/). May 11, 2020. Used for directly attributed company and Emsisoft statements; not as independent technical attribution proof.

All sources accessed 16 November 2026. Public vendor summaries were used for the historical decryptor warning. A separately encountered TLP:GREEN document is not reproduced or attached. No criminal infrastructure or stolen data is included. Original interpretation and synthetic exercise content are identified in the article.
