# Dridex Enforcement 2019: Financial Malware, Criminal Charges and Sanctions

*A TeamStarWolf case study. Published 16 November 2026.*

[All case studies](/case-studies/README.md) · Related: [Malware Analysis Reference](/MALWARE_ANALYSIS_REFERENCE.md), [Fraud Framework Reference](/FRAUD_FRAMEWORK_REFERENCE.md), [Threat Intelligence Reference](/THREAT_INTELLIGENCE_REFERENCE.md), [Attack Campaigns Reference](/ATTACK_CAMPAIGNS_REFERENCE.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Threat intelligence analysts, financial-crime and fraud teams, malware analysts and incident responders

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 17 min (3,979 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You want an evidence-bounded account of the 2019 Dridex enforcement action, you need to separate disruption from arrest or sinkhole figures from a global victim total, or you need the earlier prosecution history behind the Evil Corp charges and sanctions

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Executive assessment](#executive-assessment), [Why the sinkhole figures are not a global victim total](#why-the-sinkhole-figures-are-not-a-global-victim-total), [December 5, 2019: two criminal matters, not one combined malware case](#december-5-2019-two-criminal-matters-not-one-combined-malware-case)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Malware Analysis Reference](/MALWARE_ANALYSIS_REFERENCE.md), [Fraud Framework Reference](/FRAUD_FRAMEWORK_REFERENCE.md), [Threat Intelligence Reference](/THREAT_INTELLIGENCE_REFERENCE.md), [Attack Campaigns Reference](/ATTACK_CAMPAIGNS_REFERENCE.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## Executive assessment

The December 5, 2019 action against the organization publicly called Evil Corp combined criminal charges, financial sanctions, a reward announcement and international investigative publicity. It was not an announcement that every Dridex infection had been removed or that every named defendant had been arrested. Understanding the action requires following the earlier technical disruption and prosecution history as well as the banking-fraud allegations that supported the 2019 cases.

This case study uses original government announcements, a published indictment, a civil-case filing and later original threat research. Its central distinction is between actions that had actually occurred, accusations awaiting adjudication, institutional assessments and measured technical outcomes. The difference is especially important when the same announcement discusses malware, named people, several countries and financial figures with different meanings.

The detailed record supports a more useful conclusion than either "the gang was stopped" or "the operation failed." The authorities had achieved concrete disruption and a conviction in an earlier case. They later exposed additional alleged participants and targeted the organization's financial relationships. Subsequent sources describe adaptation rather than permanent disappearance. Those outcomes must be evaluated separately, with the measurement window and subject attached to each.

## Scope and legal-status boundaries

The focus is the 2019 enforcement package. Events from 2011 through 2018 explain the alleged conduct and earlier prosecution. A bounded afterword uses 2022 research and a 2024 Treasury announcement to examine later adaptation. This is historical research, not a current sanctions clearance, payment recommendation or legal opinion.

Maksim Yakubets and Igor Turashev are described in relation to the allegations announced against them. Andrey Ghinkul's guilty plea and sentence are treated as a separately documented adjudicated outcome. A finding or admission involving one person is not automatically proof against another. The case does not convert government rhetoric about criminality into a claim that all named people had been convicted.

Source numbers refer to the register. The published indictment and civil filing were read in relevant sections, not represented as complete reviews of every page and procedural issue. The article does not include malware code, operational criminal infrastructure or victim account identifiers. Exact transaction amounts are included only where necessary to distinguish alleged attempts, transfers and broader estimates.

## October 2015: disruption and arrest were different events

The Justice Department's October 13, 2015 announcement described substantial disruption of the Bugat/Cridex/Dridex botnet and a nine-count indictment against Ghinkul. He had been arrested in Cyprus on August 28, and the United States was seeking extradition. A civil injunction separately authorized redirection of infected computers' automated requests to substitute servers. The FBI's contemporaneous estimate was at least $10 million in direct domestic losses. [1]

This sequence separates three milestones often collapsed into a single "takedown date." Arrest concerned a person. The indictment stated criminal allegations. The injunction supported a technical intervention against communications. Those actions could reinforce one another without having the same scope, legal basis or completion criteria.

The loss estimate was also date-bound and geographically bounded. It should not be placed beside a later worldwide figure as if the difference measured losses incurred between the two announcements. The sources do not provide a consistent accounting series that would support that calculation. The appropriate historical statement is what the authority estimated at the time, not an invented growth curve.

## December 2015: the status report documented both success and replacement

A government status report filed in December 2015 said the targeted botnet had been neutralized and its active infected computers were communicating with the substitute server. The same filing acknowledged apparent establishment of new infrastructure using a variant of the malware. It reported a decline from 3,469 communicating addresses on October 15 to 1,267 on December 9. It also explained that artificial bot identifiers generated by researchers complicated measurement, so the report used unique IP addresses. [2]

This is unusually valuable evidence because the limitation is in the original record, not supplied by hindsight. The operation could neutralize the infrastructure it targeted while the organization developed a replacement. Treating the replacement as proof that nothing was accomplished would ignore the reported intervention. Treating the intervention as permanent eradication would ignore the report's own footnote.

The measurement similarly needs its unit. The addresses were a proxy for communicating infected computers within the observed remediation effort. They were not an independently deduplicated global population of people or businesses. A decreasing communication count supports the reported direction of remediation, but it does not establish that every missing address represented a permanently cleaned device.

## Why the sinkhole figures are not a global victim total

The filing distinguishes its U.S.-authorized redirection from the British operation that had begun earlier. Its scope therefore cannot simply be expanded to every affected machine worldwide. The observed count concerns communications reaching a particular substitute-server arrangement. It is evidence about that intervention, not a universal census of the malware family. [2]

The original analytical lesson is to preserve both the numerator and the collection boundary. A statement such as "Dridex fell to 1,267 infections" would make the number look more complete than the record warrants. "The government reported 1,267 unique addresses communicating in the measured effort on December 9" better reflects the actual evidence.

This distinction matters for later enforcement evaluation. If a 2019 announcement describes continued criminal activity, it does not automatically falsify the earlier measured reduction. It may refer to different infrastructure, later infections or conduct outside the earlier observation window. The historical account should connect the events without pretending that all its measurements refer to one stable population.

## February 2017: an actual guilty plea

On February 8, 2017, the U.S. Attorney's Office reported that Ghinkul pleaded guilty to conspiracy and damaging a computer. The account described his participation in dissemination of Bugat and use of stolen banking credentials for fraudulent transfers. It scheduled sentencing and described a statutory maximum, but did not report that the maximum had been imposed. [3]

That last distinction is important in a case that includes several announcements over time. A maximum possible penalty is not a sentence, and a scheduled hearing is not proof that sentencing occurred on that date. The correct chronology keeps the plea, the proposed schedule and the later actual disposition separate.

The plea is also person-specific. It provides a documented adjudicated milestone in the broader history without resolving every later allegation against other participants. A careful article can recognize a concrete prosecution outcome while still using allegation language for the 2019 defendants. Doing so is not inconsistency; it reflects the different procedural records.

## December 2018: the sentence differed from the earlier maximum

The Justice Department's December 6, 2018 statement reported that Ghinkul was sentenced to time served for conspiracy and damaging a computer. It confirmed his August 2015 arrest in Cyprus and February 2016 extradition to the United States. The announcement did not supply a detailed explanation of sentencing considerations or a complete accounting of recovered victim funds. [4]

This is the outcome to use when describing the sentence, rather than repeating the maximum from the plea announcement. The time-served formulation should also not be replaced by an invented number of months derived from a simple calendar subtraction. Custody credits and the court's full calculation are not established by the short release alone.

The case therefore contains an actual conviction and sentence before the 2019 action, but not a finding that the entire criminal ecosystem had been dismantled. One prosecution can remove or constrain a participant without ending the capabilities and relationships that other people continue to use. The later chronology is intelligible only if those subjects remain distinct.

## December 5, 2019: two criminal matters, not one combined malware case

The Justice Department announced a Pittsburgh indictment against Yakubets and Turashev concerning Bugat, along with a Nebraska complaint connecting Yakubets to the online name "aqua" in a separate Zeus scheme. The Pittsburgh case contained ten counts. The coordinated announcement also included a reward of up to $5 million for information leading to Yakubets's arrest and/or conviction. The department expressly framed the charges as allegations. [5]

Combining the two malware names into one narrative would obscure the legal and evidentiary structure. A person may be alleged to participate in more than one operation, but that does not make the operations identical. A loss figure or victim example attached to the Nebraska matter should not be silently reassigned to the Pittsburgh indictment.

The reward was a separate investigative tool, not proof that the recipient had been apprehended or convicted. Likewise, public identification of an alias is an attribution claim in a proceeding, not a substitute for the entire evidence that would be tested in court. The announcement established a coordinated enforcement step and its stated allegations; it did not establish completion of every intended outcome.

## Alleged division of labor and the fraud chain

According to the 2019 DOJ announcement, Yakubets allegedly oversaw development, distribution, financial theft and money-mule activity, while Turashev allegedly handled administration, an internal control panel and botnet operations. The alleged scheme used captured banking credentials to initiate unauthorized transfers and intermediaries to move proceeds. [5]

The analytical significance is that malware installation was only one component of the alleged enterprise. Successful theft also required access to a banking interaction and a route for receiving or moving funds. Describing the case solely as malicious code misses the organizational functions that the financial sanctions later targeted.

That does not mean a writer can infer which named person performed every step in a particular transaction. The public role descriptions are broader allegations, not a minute-by-minute operational log. The stronger reconstruction identifies the alleged function, the supporting source and the specific incident evidence available. It leaves unobserved assignments unresolved rather than turning a group-level description into individualized proof.

## Sharon City School District: attempted transfer versus shorthand loss

The published indictment alleges a phishing message on November 8, 2011, resulting installation on November 10 and an attempted $999,000 transfer on December 16. Its bank-fraud count likewise labels the school-district transaction an attempt. The FBI's December 2019 narrative, however, described the district as having money wired out. This study retains the charging document's more precise attempt wording and flags the difference rather than asserting a proven final loss. [6][7]

The disagreement is consequential. A reader may reasonably understand "lost $999,000" to mean an unrecovered financial outcome. An attempted transfer does not establish that outcome, while an initial movement of funds would still not establish final loss after any intervention or recovery. The reviewed material does not supply a complete bank-reconciliation history.

The timeline also separates initial compromise from the later transaction attempt. It would be inaccurate to compress them into one moment or to infer continuous successful access throughout the entire interval. The indictment states the alleged milestones. The study does not add an unsupported explanation for everything that happened between them.

## Penneco Oil: amounts attached to specific transactions

The indictment describes two international Penneco transfers, $2,158,600 on August 31, 2012 and $1,350,000 on September 4, as well as a separate attempted $76,520 transfer. It also alleges communications arranging receipt through intermediaries. These are transaction allegations; the article does not convert their sum into a verified net loss, restitution amount or amount ultimately retained by the defendants. [6]

The distinction is more than financial caution. Different measures answer different incident questions. A transfer amount describes an event. A recovered amount describes a later intervention. Net loss requires both, along with a consistent accounting method. None should be substituted for another merely because an exact dollar figure is available.

The recipients' banking geography also does not, by itself, locate the people who caused the intrusion. Financial routing, residence, infrastructure hosting and operator location are different analytical dimensions. The case's attribution rests on the broader alleged evidence, not on assuming that a destination bank's country proves the location or identity of the attacker.

## The indictment reached into 2019 without proving ransomware at every victim

The charging document includes alleged malware installations involving 84 Lumber on February 18, Kurt J. Lesker Company on March 4 and JWF Industries on March 19, 2019. It also alleges broader ransomware activity. Those statements should not be combined into a claim that each named 2019 organization necessarily suffered a specified ransomware deployment or paid a ransom. [6]

The point is an evidentiary boundary between a general allegation and a particular count. A historical case study should not supply a payload name, operational outage, ransom demand or restoration timeline where the cited charge does not establish it. The named organizations provide concrete examples of the alleged campaign's reach, but they are not invitations to fill missing details with familiar ransomware patterns.

The available evidence supports a transition toward broader intrusion consequences. It does not support treating every later Dridex installation as identical. The article therefore records the dated allegations and leaves victim-specific operational outcomes unresolved unless separately documented.

## The NCSC explained why secure transport did not solve endpoint compromise

The UK's National Cyber Security Centre described Dridex on December 5, 2019 as a financial trojan delivered through routes including malicious email attachments and other malware such as Emotet. It said the malware could steal information even during otherwise secure HTTPS browsing and could support screenshots, file transfer and additional tools for movement through a network. Its statement described capabilities and risk, not a forensic report for each named American victim. [10]

The technical distinction is between protecting data in transit and protecting a compromised endpoint that handles the data. A secure connection does not itself establish that the software at either end is behaving legitimately. This is an explanatory inference from the capability description, not a claim that HTTPS encryption had been mathematically broken.

For the financial-fraud narrative, that distinction helps explain why a legitimate-looking banking interaction could be part of the attack. It does not identify the exact mechanism used in every alleged transfer. The article avoids retrofitting one capability to all victims simply because the family could support it.

## Treasury targeted a network wider than the two charged people

Treasury's December 5 action designated 17 individuals and seven entities, including Evil Corp, operators, businesses and financial facilitators. It attributed more than $100 million in theft to the Dridex activity and described a footprint involving banking credentials across more than forty countries. Treasury also stated that Yakubets had worked for the Russian FSB and had been tasked with state-related cyber activity. These are Treasury's designation findings and assessments, not criminal convictions. [8]

The scope shows why sanctions should not be narrated as simply another name for an indictment. The designation package addressed a wider set of relationships and functions. It sought to constrain an organization and its support network, while the criminal cases concerned particular charges and defendants.

The state-relationship claim requires especially careful attribution. It does not prove that every fraudulent transfer in the indictment was an intelligence operation, or that every use of Dridex was state-directed. The source supports Treasury's stated assessment about Yakubets and associated activity. A more expansive geopolitical conclusion would require evidence beyond the fact of the designation.

## The British contribution and the stated effect of sanctions

The NCA said a dedicated team had begun investigating Dridex in 2014 and supplied material supporting the American charges and sanctions. Its December 2019 account also reported eight money-laundering participants sentenced to more than forty years in aggregate. It described the sanctions as blocking designated persons' property under U.S. jurisdiction and restricting transactions by U.S. persons. These are the agency's historical description of the action, not a current transaction authorization or complete legal analysis. [9]

The investigative contribution was not limited to finding malware. The account connects technical inquiry with identification, financial relationships and international coordination. That is why the case is better understood as an enforcement campaign than a single technical takedown.

The aggregate sentencing figure also has a defined subject: the individuals described in the British money-laundering investigations. It should not be presented as the sentence imposed on Yakubets or Turashev, nor added to Ghinkul's sentence to create an undifferentiated total. Each proceeding has its own defendants and outcome. Preserving that structure prevents an impressive-looking statistic from becoming a false claim about who was actually convicted.

## Different loss figures should not be forced into one total

The sources contain figures describing domestic direct losses, wider theft, attempted transactions and losses in a separate Zeus matter. The 2019 DOJ announcement put the Zeus scheme at approximately $220 million attempted and $70 million in actual losses. Treasury's Dridex figure and the NCA's broader UK assessment concern differently framed activity. They are not compatible line items in a single spreadsheet total. [5][8][9]

The original analytical rule for this case is to retain the scheme, date, geography, currency and outcome category beside each number. If those dimensions differ, addition requires justification that the public releases do not provide. Converting currencies would not solve overlapping populations or different definitions of harm.

This study consequently does not announce a newly calculated "total Evil Corp loss." Such a number would imply a reconciliation that has not been performed. The documented figures still communicate substantial harm, but their evidentiary value comes from their stated scope, not from the largest possible combined sum. The same approach applies to claims about affected banks: targeted customers and breached bank infrastructure are not necessarily the same thing.

## Ransomware adaptation: what the 2022 research actually assessed

Mandiant's June 2, 2022 research described UNC2165, a cluster with substantial overlaps with publicly reported Evil Corp activity, shifting toward LockBit. It assessed with high confidence that the shift likely sought to hinder attribution and evade sanctions. It also described earlier movement away from exclusive ransomware variants and reduced reliance on Dridex. This is an original vendor assessment, not a court finding that every LockBit operation belonged to Evil Corp. [11]

The distinction matters because a shared ransomware service can be used by different actors. A payload label alone cannot resolve the organizational relationship. Mandiant's argument depended on observed overlaps and operational history, not merely the presence of the LockBit name.

For evaluating the 2019 package, the assessment supports adaptation under pressure as a plausible and evidence-backed interpretation. It does not supply a controlled estimate of how much crime the sanctions prevented or displaced. An operator's attempt to obscure affiliation can indicate that sanctions affected incentives without proving either total success or total failure. The case study preserves that narrower conclusion.

## The 2024 Treasury afterword: later allegations are not retroactive 2019 facts

On October 1, 2024, Treasury announced additional designations in coordination with the UK and Australia. Its account described assistance provided after the 2019 action and alleged work on "Dridex 2.0" during 2020. It also connected the announcement with a separately unsealed BitPaymer-related indictment. These later statements demonstrate continued enforcement and Treasury's expanded assessment, not a claim that all those details were publicly established in December 2019. [12]

The historical boundary is important. A retrospective account can use later information to explain what authorities subsequently alleged, but it should not write that information into an earlier press conference. Nor should it assume that a later named malware version establishes a verified lineage for every earlier sample.

This afterword does not attempt a current docket review or certify today's sanctions status for any transaction. It records a dated official action and leaves legal disposition beyond the reviewed record unresolved. The public evidence establishes that the enforcement story continued; it does not justify declaring all defendants convicted or all associated operations ended.

## What the enforcement record can reasonably demonstrate

The record supports several separate outcomes. A targeted botnet was disrupted under a civil intervention, with an explicitly bounded remediation measurement. Ghinkul pleaded guilty and was sentenced. The 2019 package publicized criminal allegations against additional people and applied financial designations to a wider network. Later sources described continued adaptation and additional action.

Those are not interchangeable metrics. A conviction measures a legal result for a defendant. A decline in sinkhole communications measures observed technical activity under a particular collection method. Sanctions change legal and financial constraints, while a reward seeks information that may assist an investigation. Calling all of them "the takedown" makes it difficult to evaluate what actually happened.

This is the study's principal original interpretation. Enforcement can achieve meaningful intermediate results without resolving every threat. A credible evaluation should name the achieved result, its boundary and the remaining uncertainty. It should neither dismiss documented progress because later activity occurred nor claim universal safety because an announcement used decisive language.

## A focused case-study exercise

Participants receive a synthetic briefing with three statements: a school "lost" a precise amount, a botnet's measured communications declined, and a group was sanctioned. They must identify the evidence needed to support each statement. The exercise then provides the indictment's attempt wording, the unique-IP measurement caveat and the historical designation scope. Participants revise the briefing rather than defend its original overstatements.

A second stage supplies a later ransomware attribution assessment. The task is to decide whether it proves the earlier sanctions failed, proves every user of that ransomware belongs to the sanctioned group, or supports a narrower conclusion about observed adaptation. The defensible answer preserves the cluster assessment and avoids both absolute claims.

No real banking data, malware or payment instructions are used. The exercise tests the specific errors exposed by the source comparison: converting attempts into final losses, treating observed addresses as a global census, confusing sanctions with convictions, and assigning a shared tool to one actor without supporting evidence.

## Conclusion

Dridex enforcement in 2019 is a case about connecting technical evidence to people, financial operations and legal mechanisms over time. Its strength as a study lies in the detailed differences among the records: the earlier disruption's own replacement-infrastructure caveat, the difference between a plea and a maximum penalty, the school-transfer wording discrepancy, and the separation of Dridex and Zeus financial figures.

A responsible account recognizes the concrete actions without exaggerating their scope. It preserves allegations as allegations, measurements as measurements and later assessments as later assessments. That approach gives the reader a usable framework for understanding a long-running cybercrime investigation without reducing it to either a victory headline or a claim that enforcement cannot matter.

## Sources and reading register

1. [DOJ: Bugat administrator arrested and malware disrupted](https://www.justice.gov/archives/opa/pr/bugat-botnet-administrator-arrested-and-malware-disabled). October 13, 2015. Substantive announcement read.
2. [Civil case 15-1315: December 2015 filing bundle](https://www.justice.gov/opa/file/801516/dl?inline=). Motion context and technical status report, including measurement footnotes, read; not a complete review of every bundled order provision.
3. [DOJ: Ghinkul guilty plea](https://www.justice.gov/usao-wdpa/pr/moldovan-pleads-guilty-distributing-bugat-malware). February 8, 2017. Full substantive release read.
4. [DOJ: Ghinkul sentence](https://www.justice.gov/usao-wdpa/pr/moldovan-sentenced-distributing-multifunction-malware-package). December 6, 2018. Full substantive release read.
5. [DOJ: Yakubets and Turashev charges](https://www.justice.gov/archives/opa/pr/russian-national-charged-decade-long-series-hacking-and-bank-fraud-offenses-resulting-tens). December 5, 2019. Substantive charges, separate schemes and reward sections read.
6. [Yakubets and Turashev indictment](https://www.justice.gov/d9/press-releases/attachments/2019/12/05/final_yakubetsturashev_indictment_wdpa_0.pdf). Unsealed December 5, 2019. Definitions, alleged manner and means, transaction chronology and relevant counts read; not a complete docket review.
7. [FBI: Charges announced in malware conspiracy](https://www.fbi.gov/news/stories/charges-announced-in-malware-conspiracy-120519). December 5, 2019. Substantive narrative read; school-transfer shorthand differs from indictment wording.
8. [Treasury: Evil Corp sanctions](https://home.treasury.gov/news/press-releases/sm845). December 5, 2019. Substantive designation and attribution sections read.
9. [NCA: International operation announcement](https://nca-newsroom.prgloo.com/news/international-law-enforcement-operation-exposes-the-worlds-most-harmful-cyber-crime-group). December 5, 2019. Official newsroom narrative and historical background read.
10. [NCSC: UK and US investigations](https://www.ncsc.gov.uk/news/uk-and-us-investigation-into-harmful-international-cyber-campaigns). December 5, 2019. Substantive technical explanation read.
11. [Mandiant: UNC2165 and LockBit](https://cloud.google.com/blog/topics/threat-intelligence/unc2165-shifts-to-evade-sanctions). June 2, 2022. Introduction and overlap assessment read; bounded afterword, not exhaustive technique review.
12. [Treasury: Additional trilateral designations](https://home.treasury.gov/news/press-releases/jy2623). October 1, 2024. Substantive action and historical relationship sections read; current legal status not certified.

Accessed 16 November 2026. Historical research only. No malware executed, criminal service contacted or victim financial data obtained. The original State Department archive page returned an error and was not relied upon; the contemporaneous DOJ announcement supports the reward detail.
